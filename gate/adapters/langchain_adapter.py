"""
LangChain Adapter

Wraps either a legacy ``AgentExecutor`` or a LangChain 1.x agent graph (the
object returned by ``langchain.agents.create_agent``). Every tool the agent can
reach is guarded in place, so ``monitor.validate_action`` runs before the tool
body on both the sync and async execution paths.
"""

import importlib
import logging
from typing import Any, List, Mapping, Optional, Sequence

from .base import BaseFrameworkAdapter, TimeoutError
from .enforcement import (
    ToolEnforcement,
    collect_graph_tools,
    install_tool_guard,
)
from ..core.config import gateConfig
from ..core.exceptions import AdapterError
from ..core.interfaces import SecurityMonitor, SecureAgent
from ..core.models import ToolCall, AgentState

logger = logging.getLogger(__name__)


def _agent_executor_classes() -> tuple:
    classes = []
    for module_name in ("langchain.agents", "langchain_classic.agents"):
        try:
            module = importlib.import_module(module_name)
        except ImportError:
            continue
        cls = getattr(module, "AgentExecutor", None)
        if isinstance(cls, type):
            classes.append(cls)
    return tuple(classes)


def _compiled_graph_class() -> Optional[type]:
    try:
        from langgraph.graph.state import CompiledStateGraph
    except ImportError:
        return None
    return CompiledStateGraph


def langchain_native_async(tool: Any) -> bool:
    """Whether a BaseTool has a genuine async implementation.

    ``StructuredTool._arun`` without a coroutine delegates back to ``_run``;
    treating it as native would validate the same call twice.
    """
    if getattr(tool, "coroutine", None) is not None:
        return True
    try:
        from langchain_core.tools import BaseTool, StructuredTool
    except ImportError:
        return False
    cls_arun = getattr(type(tool), "_arun", None)
    if cls_arun is None:
        return False
    if cls_arun is BaseTool._arun or cls_arun is StructuredTool._arun:
        return False
    return True


class LangChainSecureAgent(SecureAgent):
    """Secure wrapper for a LangChain agent."""

    def __init__(
        self,
        wrapped_agent: Any,
        monitor: SecurityMonitor,
        adapter: "LangChainAdapter",
        config: gateConfig,
        enforcement: ToolEnforcement,
        timeout_seconds: Optional[float] = None,
    ) -> None:
        self.wrapped_agent = wrapped_agent
        self.monitor = monitor
        self.adapter = adapter
        self.config = config
        self.enforcement = enforcement
        self.timeout_seconds = timeout_seconds or adapter.get_timeout_config(config)

    def _intent(self, input: Any) -> str:
        return input if isinstance(input, str) else str(input)

    def invoke(self, input: Any, **kwargs: Any) -> Any:
        logger.info(f"Invoking secure LangChain agent (timeout={self.timeout_seconds}s)")
        self.enforcement.begin_run(self._intent(input))
        try:
            return self.adapter.run_with_timeout(
                self.wrapped_agent.invoke,
                input,
                seconds=self.timeout_seconds,
                operation_name="LangChain agent invocation",
                **kwargs,
            )
        except TimeoutError:
            self.enforcement.abort("LangChain agent invocation timed out")
            raise
        finally:
            self.enforcement.finish_run()

    async def ainvoke(self, input: Any, **kwargs: Any) -> Any:
        logger.info(f"Async invoking secure LangChain agent (timeout={self.timeout_seconds}s)")
        self.enforcement.begin_run(self._intent(input))
        try:
            return await self.adapter.async_timeout_context(
                self.wrapped_agent.ainvoke(input, **kwargs),
                seconds=self.timeout_seconds,
                operation_name="LangChain agent invocation",
            )
        except TimeoutError:
            self.enforcement.abort("LangChain agent async invocation timed out")
            raise
        finally:
            self.enforcement.finish_run()

    def get_state(self) -> AgentState:
        return self.enforcement.state

    def terminate(self) -> None:
        logger.info("Terminating secure LangChain agent")
        self.enforcement.close()


class LangChainAdapter(BaseFrameworkAdapter):
    """Adapter for LangChain agents with per-tool enforcement."""

    def __init__(self, default_timeout_seconds: float = 300.0) -> None:
        super().__init__("langchain", default_timeout_seconds)

    def _resolve_tools(self, agent: Any, explicit: Optional[Sequence[Any]]) -> List[Any]:
        if explicit is not None:
            return list(explicit)

        agent_tools = getattr(agent, "tools", None)
        if isinstance(agent_tools, (list, tuple)):
            return list(agent_tools)

        graph_tools = collect_graph_tools(agent)
        if graph_tools:
            return graph_tools

        if _compiled_graph_class() is not None and isinstance(
            agent, _compiled_graph_class()
        ):
            # A compiled graph with no ToolNode has no tool surface to mediate.
            return []

        raise AdapterError(
            "Could not locate the agent's tools. Pass tools=[...] explicitly "
            "so GATE can install a guard on every executable tool."
        )

    def wrap_agent(
        self,
        agent: Any,
        config: gateConfig,
        *,
        tools: Optional[Sequence[Any]] = None,
        approval_queue: Optional[Any] = None,
    ) -> SecureAgent:
        """Wrap a LangChain AgentExecutor or agent graph with GATE security."""
        executor_classes = _agent_executor_classes()
        graph_class = _compiled_graph_class()

        is_executor = bool(executor_classes) and isinstance(agent, executor_classes)
        is_graph = graph_class is not None and isinstance(agent, graph_class)
        if not (is_executor or is_graph):
            expected = ["AgentExecutor"] if executor_classes else []
            if graph_class is not None:
                expected.append("CompiledStateGraph")
            raise AdapterError(
                f"Expected {' or '.join(expected) or 'a LangChain agent'}, "
                f"got {type(agent).__name__}"
            )

        logger.info("Wrapping LangChain agent with GATE security")

        from ..core.monitor import gateMonitor

        monitor = gateMonitor(config)
        if config.agent_profile:
            from ..security.privilege_enforcer import DefaultPrivilegeEnforcer

            enforcer = DefaultPrivilegeEnforcer()
            enforcer.register_profile(config.agent_profile)
            monitor.privilege_enforcer = enforcer

        enforcement = ToolEnforcement(monitor, config, approval_queue)
        resolved = self._resolve_tools(agent, tools)
        for tool in resolved:
            install_tool_guard(
                tool, enforcement, native_async=langchain_native_async(tool)
            )

        timeout_seconds = self.get_timeout_config(config)
        return LangChainSecureAgent(
            agent, monitor, self, config, enforcement, timeout_seconds
        )

    def extract_state(self, agent: Any) -> AgentState:
        enforcement = getattr(agent, "enforcement", None)
        if enforcement is not None:
            return enforcement.state
        return AgentState(agent_id=self.get_agent_id(agent))

    def inject_monitoring(self, agent: Any, monitor: SecurityMonitor) -> None:
        logger.debug("LangChain monitoring is installed by wrapping its tools")

    def get_tool_calls(self, agent: Any) -> List[ToolCall]:
        enforcement = getattr(agent, "enforcement", None)
        if enforcement is not None:
            return list(enforcement.state.tool_history)
        for tool in getattr(agent, "tools", None) or []:
            enforcement = getattr(tool, "_gate_enforcement", None)
            if enforcement is not None:
                return list(enforcement.state.tool_history)
        return []

    def get_agent_id(self, agent: Any) -> str:
        if hasattr(agent, "agent_id"):
            return agent.agent_id
        return f"langchain-agent-{id(agent) % 10000:04d}"
