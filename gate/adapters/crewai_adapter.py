"""
CrewAI Adapter

Wraps a ``Crew`` and guards every tool attached to its agents and tasks. CrewAI
dispatches tool calls through ``BaseTool._run``; the guard intercepts that
method on the live tool objects, so the monitor decides before the Python body
runs.
"""

import asyncio
import logging
from typing import Any, Dict, List, Optional

from .base import BaseFrameworkAdapter, TimeoutError
from .enforcement import ToolEnforcement, install_tool_guard
from ..core.config import gateConfig
from ..core.exceptions import AdapterError
from ..core.interfaces import SecurityMonitor, SecureAgent
from ..core.models import ToolCall, AgentState

logger = logging.getLogger(__name__)


def _crewai_native_async(tool: Any) -> bool:
    """Whether the tool has an async implementation that does not delegate to _run."""
    if getattr(tool, "_arun", None) is None:
        return False
    try:
        from crewai.tools import BaseTool as CrewBaseTool
    except ImportError:
        return False
    cls_arun = getattr(type(tool), "_arun", None)
    if cls_arun is None:
        return False
    return cls_arun is not getattr(CrewBaseTool, "_arun", None)


def _collect_tools(crew: Any) -> List[Any]:
    tools: List[Any] = []
    seen = set()

    def add(candidates: Any, owner: str) -> None:
        for tool in candidates or []:
            if not hasattr(tool, "_run"):
                raise AdapterError(
                    f"{owner} exposes {type(tool).__name__}, which has no _run "
                    "method for GATE to guard"
                )
            if id(tool) in seen:
                continue
            seen.add(id(tool))
            tools.append(tool)

    for agent in getattr(crew, "agents", None) or []:
        add(getattr(agent, "tools", None), f"Agent {getattr(agent, 'role', '?')!r}")
    for task in getattr(crew, "tasks", None) or []:
        add(getattr(task, "tools", None), f"Task {getattr(task, 'description', '?')[:40]!r}")
    return tools


class CrewAISecureAgent(SecureAgent):
    """Secure wrapper for a CrewAI crew."""

    def __init__(
        self,
        wrapped_crew: Any,
        monitor: SecurityMonitor,
        config: gateConfig,
        adapter: "CrewAIAdapter",
        enforcement: ToolEnforcement,
        timeout_seconds: Optional[float] = None,
    ) -> None:
        self.wrapped_crew = wrapped_crew
        self.monitor = monitor
        self.config = config
        self.adapter = adapter
        self.enforcement = enforcement
        self.timeout_seconds = timeout_seconds or adapter.get_timeout_config(config)

    def _inputs(self, input: Any, kwargs: Dict[str, Any]) -> Dict[str, Any]:
        inputs = dict(kwargs.get("inputs") or {})
        if isinstance(input, dict):
            inputs.update(input)
        elif input is not None:
            inputs.setdefault("input", input if isinstance(input, str) else str(input))
        return inputs

    def invoke(self, input: Any, **kwargs: Any) -> Any:
        logger.info(f"Invoking secure CrewAI crew (timeout={self.timeout_seconds}s)")
        inputs = self._inputs(input, kwargs)
        self.enforcement.begin_run(inputs.get("input") or str(inputs))
        try:
            return self.adapter.run_with_timeout(
                self.wrapped_crew.kickoff,
                seconds=self.timeout_seconds,
                operation_name="CrewAI kickoff",
                inputs=inputs,
            )
        except TimeoutError:
            self.enforcement.abort("CrewAI kickoff timed out")
            raise
        finally:
            self.enforcement.finish_run()

    async def ainvoke(self, input: Any, **kwargs: Any) -> Any:
        logger.info(f"Async invoking secure CrewAI crew (timeout={self.timeout_seconds}s)")
        inputs = self._inputs(input, kwargs)
        self.enforcement.begin_run(inputs.get("input") or str(inputs))
        kickoff_async = getattr(self.wrapped_crew, "kickoff_async", None)
        try:
            if kickoff_async is not None:
                coro = kickoff_async(inputs=inputs)
            else:
                coro = asyncio.to_thread(self.wrapped_crew.kickoff, inputs=inputs)
            return await self.adapter.async_timeout_context(
                coro,
                seconds=self.timeout_seconds,
                operation_name="CrewAI kickoff",
            )
        except TimeoutError:
            self.enforcement.abort("CrewAI kickoff timed out")
            raise
        finally:
            self.enforcement.finish_run()

    def get_state(self) -> AgentState:
        return self.enforcement.state

    def terminate(self) -> None:
        logger.info("Terminating secure CrewAI crew")
        self.enforcement.close()


class CrewAIAdapter(BaseFrameworkAdapter):
    """Adapter for CrewAI crews with per-tool enforcement."""

    def __init__(self, default_timeout_seconds: float = 600.0) -> None:
        super().__init__("crewai", default_timeout_seconds)

    def wrap_agent(
        self,
        agent: Any,
        config: gateConfig,
        *,
        approval_queue: Optional[Any] = None,
        **_unused: Any,
    ) -> SecureAgent:
        """Wrap a CrewAI Crew with GATE security."""
        try:
            from crewai import Crew
        except ImportError as e:
            raise AdapterError(
                "CrewAI is required for CrewAIAdapter. Install with: pip install crewai"
            ) from e

        self._validate_agent_type(agent, Crew)
        logger.info("Wrapping CrewAI crew with GATE security")

        tools = _collect_tools(agent)

        from ..core.monitor import gateMonitor

        monitor = gateMonitor(config)
        if config.agent_profile:
            from ..security.privilege_enforcer import DefaultPrivilegeEnforcer

            enforcer = DefaultPrivilegeEnforcer()
            enforcer.register_profile(config.agent_profile)
            monitor.privilege_enforcer = enforcer

        enforcement = ToolEnforcement(monitor, config, approval_queue)
        for tool in tools:
            install_tool_guard(
                tool, enforcement, native_async=_crewai_native_async(tool)
            )

        timeout_seconds = self.get_timeout_config(config)
        return CrewAISecureAgent(
            agent, monitor, config, self, enforcement, timeout_seconds
        )

    def extract_state(self, agent: Any) -> AgentState:
        enforcement = getattr(agent, "enforcement", None)
        if enforcement is not None:
            return enforcement.state
        return AgentState(agent_id=self.get_agent_id(agent))

    def inject_monitoring(self, agent: Any, monitor: SecurityMonitor) -> None:
        logger.debug("CrewAI monitoring is installed on agent and task tools")

    def get_tool_calls(self, agent: Any) -> List[ToolCall]:
        enforcement = getattr(agent, "enforcement", None)
        if enforcement is not None:
            return list(enforcement.state.tool_history)
        return []

    def get_agent_id(self, agent: Any) -> str:
        return f"crewai-crew-{id(agent) % 10000:04d}"
