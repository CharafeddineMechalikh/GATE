"""
LangGraph Adapter

Wraps a compiled LangGraph whose tools run in a ``ToolNode``. Tools are guarded
in place, so every invocation from any node is validated before dispatch.
"""

import logging
from typing import Any, Dict, List, Optional, Sequence

from .base import BaseFrameworkAdapter, TimeoutError
from .enforcement import (
    ToolEnforcement,
    collect_graph_tools,
    install_tool_guard,
)
from .langchain_adapter import langchain_native_async
from ..core.config import gateConfig
from ..core.exceptions import AdapterError
from ..core.interfaces import SecurityMonitor, SecureAgent
from ..core.models import ToolCall, AgentState

logger = logging.getLogger(__name__)


class LangGraphSecureAgent(SecureAgent):
    """Secure wrapper for a compiled LangGraph."""

    def __init__(
        self,
        wrapped_graph: Any,
        monitor: SecurityMonitor,
        config: gateConfig,
        adapter: "LangGraphAdapter",
        enforcement: ToolEnforcement,
        timeout_seconds: Optional[float] = None,
    ) -> None:
        self.wrapped_graph = wrapped_graph
        self.monitor = monitor
        self.config = config
        self.adapter = adapter
        self.enforcement = enforcement
        self.timeout_seconds = timeout_seconds or adapter.get_timeout_config(config)

    def _intent(self, input: Any) -> str:
        if isinstance(input, dict):
            value = input.get("input") or input.get("messages") or ""
            return str(value)
        return str(input)

    def _with_agent_id(self, kwargs: Dict[str, Any]) -> Dict[str, Any]:
        config = dict(kwargs.get("config") or {})
        configurable = dict(config.get("configurable") or {})
        configurable["agent_id"] = self.config.agent_profile.agent_id
        config["configurable"] = configurable
        kwargs["config"] = config
        return kwargs

    def invoke(self, input: Any, **kwargs: Any) -> Any:
        logger.info(f"Invoking secure LangGraph agent (timeout={self.timeout_seconds}s)")
        self.enforcement.begin_run(self._intent(input))
        kwargs = self._with_agent_id(dict(kwargs))
        try:
            return self.adapter.run_with_timeout(
                self.wrapped_graph.invoke,
                input,
                seconds=self.timeout_seconds,
                operation_name="LangGraph agent invocation",
                **kwargs,
            )
        except TimeoutError:
            self.enforcement.abort("LangGraph agent invocation timed out")
            raise
        finally:
            self.enforcement.finish_run()

    async def ainvoke(self, input: Any, **kwargs: Any) -> Any:
        logger.info(f"Async invoking secure LangGraph agent (timeout={self.timeout_seconds}s)")
        self.enforcement.begin_run(self._intent(input))
        kwargs = self._with_agent_id(dict(kwargs))
        try:
            return await self.adapter.async_timeout_context(
                self.wrapped_graph.ainvoke(input, **kwargs),
                seconds=self.timeout_seconds,
                operation_name="LangGraph agent invocation",
            )
        except TimeoutError:
            self.enforcement.abort("LangGraph agent async invocation timed out")
            raise
        finally:
            self.enforcement.finish_run()

    def get_state(self) -> AgentState:
        return self.enforcement.state

    def terminate(self) -> None:
        logger.info("Terminating secure LangGraph agent")
        self.enforcement.close()


class LangGraphAdapter(BaseFrameworkAdapter):
    """Adapter for compiled LangGraph agents with per-tool enforcement."""

    def __init__(self, default_timeout_seconds: float = 300.0) -> None:
        super().__init__("langgraph", default_timeout_seconds)

    def wrap_agent(
        self,
        agent: Any,
        config: gateConfig,
        *,
        tools: Optional[Sequence[Any]] = None,
        approval_queue: Optional[Any] = None,
    ) -> SecureAgent:
        """Wrap a compiled LangGraph with GATE security."""
        try:
            from langgraph.graph.state import CompiledStateGraph
        except ImportError as e:
            raise AdapterError(
                "LangGraph is required for LangGraphAdapter. "
                "Install with: pip install langgraph"
            ) from e

        self._validate_agent_type(agent, CompiledStateGraph)

        if tools is not None:
            resolved = list(tools)
        else:
            resolved = collect_graph_tools(agent)
            if not resolved:
                raise AdapterError(
                    "No ToolNode with registered tools was found in this graph. "
                    "Pass tools=[...] explicitly so GATE can install a guard on "
                    "every executable tool (use tools=[] only if the graph has "
                    "no tool surface)."
                )

        logger.info(
            "Wrapping LangGraph agent with GATE security (%d tools)", len(resolved)
        )

        from ..core.monitor import gateMonitor

        monitor = gateMonitor(config)
        if config.agent_profile:
            from ..security.privilege_enforcer import DefaultPrivilegeEnforcer

            enforcer = DefaultPrivilegeEnforcer()
            enforcer.register_profile(config.agent_profile)
            monitor.privilege_enforcer = enforcer

        enforcement = ToolEnforcement(monitor, config, approval_queue)
        for tool in resolved:
            install_tool_guard(
                tool, enforcement, native_async=langchain_native_async(tool)
            )

        timeout_seconds = self.get_timeout_config(config)
        return LangGraphSecureAgent(
            agent, monitor, config, self, enforcement, timeout_seconds
        )

    def extract_state(self, agent: Any) -> AgentState:
        enforcement = getattr(agent, "enforcement", None)
        if enforcement is not None:
            return enforcement.state
        return AgentState(agent_id=self.get_agent_id(agent))

    def inject_monitoring(self, agent: Any, monitor: SecurityMonitor) -> None:
        logger.debug("LangGraph monitoring is installed by wrapping ToolNode tools")

    def get_tool_calls(self, agent: Any) -> List[ToolCall]:
        enforcement = getattr(agent, "enforcement", None)
        if enforcement is not None:
            return list(enforcement.state.tool_history)
        return []

    def get_agent_id(self, agent: Any) -> str:
        return f"langgraph-agent-{id(agent) % 10000:04d}"
