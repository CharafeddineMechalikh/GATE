"""
OpenAI Agents SDK Adapter

Wraps ``agents.Agent`` objects and their handoff targets. Each ``FunctionTool``
keeps its native ``on_invoke_tool`` callback but the callback is guarded, so the
monitor decides before the Python function body runs. Hosted tools and MCP
servers execute outside the process and cannot be mediated, so the adapter
refuses to wrap an agent that declares them.
"""

import json
import logging
from typing import Any, Dict, List, Optional

from .base import BaseFrameworkAdapter, TimeoutError
from .enforcement import ToolEnforcement, marshal_tool_args
from ..core.config import gateConfig
from ..core.exceptions import AdapterError
from ..core.interfaces import SecurityMonitor, SecureAgent
from ..core.models import ToolCall, AgentState

logger = logging.getLogger(__name__)


def _collect_agents(root: Any) -> List[Any]:
    """Return the wrapped agent and every handoff target reachable from it."""
    agents: List[Any] = []
    stack = [root]
    seen = set()
    while stack:
        agent = stack.pop()
        if id(agent) in seen:
            continue
        seen.add(id(agent))
        agents.append(agent)
        for handoff in getattr(agent, "handoffs", None) or []:
            target = getattr(handoff, "agent", handoff)
            if target is not None:
                stack.append(target)
    return agents


def _install_function_tool_guard(tool: Any, enforcement: ToolEnforcement) -> None:
    owner = getattr(tool, "_gate_enforcement", None)
    if owner is not None:
        if owner is enforcement:
            return
        raise AdapterError(
            f"Tool {tool.name!r} is already guarded by another GATE enforcement instance"
        )

    original = tool.on_invoke_tool
    tool_name = tool.name

    async def guarded_on_invoke(ctx: Any, args: Any) -> Any:
        if isinstance(args, str):
            try:
                parsed = json.loads(args) if args.strip() else {}
            except json.JSONDecodeError:
                parsed = {"input": args}
        elif isinstance(args, dict):
            parsed = dict(args)
        else:
            parsed = marshal_tool_args(tool, (args,), {})

        action = await enforcement.before_call(tool_name, parsed)
        output = await original(ctx, args)
        return await enforcement.after_call(action, output)

    tool.on_invoke_tool = guarded_on_invoke
    tool._gate_enforcement = enforcement
    logger.debug("Installed GATE guard on OpenAI function tool %s", tool_name)


class OpenAIAgentsSecureAgent(SecureAgent):
    """Secure wrapper for an OpenAI Agents SDK agent."""

    def __init__(
        self,
        wrapped_agent: Any,
        monitor: SecurityMonitor,
        config: gateConfig,
        adapter: "OpenAIAgentsAdapter",
        enforcement: ToolEnforcement,
        timeout_seconds: Optional[float] = None,
    ) -> None:
        self.wrapped_agent = wrapped_agent
        self.monitor = monitor
        self.config = config
        self.adapter = adapter
        self.enforcement = enforcement
        self.timeout_seconds = timeout_seconds or adapter.get_timeout_config(config)

    async def invoke(self, input: Any, **kwargs: Any) -> Any:
        logger.info(f"Invoking secure OpenAI Agents agent (timeout={self.timeout_seconds}s)")
        self.enforcement.begin_run(input if isinstance(input, str) else str(input))
        try:
            from agents import Runner

            return await self.adapter.async_timeout_context(
                Runner.run(self.wrapped_agent, input, **kwargs),
                seconds=self.timeout_seconds,
                operation_name="OpenAI Agents invocation",
            )
        except TimeoutError:
            self.enforcement.abort("OpenAI Agents invocation timed out")
            raise
        finally:
            self.enforcement.finish_run()

    def get_state(self) -> AgentState:
        return self.enforcement.state

    def terminate(self) -> None:
        logger.info("Terminating secure OpenAI Agents agent")
        self.enforcement.close()


class OpenAIAgentsAdapter(BaseFrameworkAdapter):
    """Adapter for the OpenAI Agents SDK with per-tool enforcement."""

    def __init__(self, default_timeout_seconds: float = 300.0) -> None:
        super().__init__("openai-agents", default_timeout_seconds)

    def wrap_agent(
        self,
        agent: Any,
        config: gateConfig,
        *,
        approval_queue: Optional[Any] = None,
        **_unused: Any,
    ) -> SecureAgent:
        """Wrap an OpenAI Agents SDK agent with GATE security."""
        try:
            from agents import Agent
        except ImportError as e:
            raise AdapterError(
                "OpenAI Agents SDK is required. Install with: pip install openai-agents"
            ) from e

        self._validate_agent_type(agent, Agent)
        logger.info("Wrapping OpenAI Agents agent with GATE security")

        agents = _collect_agents(agent)
        for current in agents:
            if getattr(current, "mcp_servers", None):
                raise AdapterError(
                    f"Agent {getattr(current, 'name', '?')!r} declares MCP servers; "
                    "their tools execute outside the process and cannot be mediated. "
                    "Expose those tools as local FunctionTools before wrapping."
                )
            for tool in getattr(current, "tools", None) or []:
                if not hasattr(tool, "on_invoke_tool"):
                    raise AdapterError(
                        f"Agent {getattr(current, 'name', '?')!r} declares tool "
                        f"{type(tool).__name__}, which the SDK executes outside the "
                        "Python process. GATE can only mediate FunctionTool objects; "
                        "hosted tools must be replaced by local functions."
                    )

        from ..core.monitor import gateMonitor

        monitor = gateMonitor(config)
        if config.agent_profile:
            from ..security.privilege_enforcer import DefaultPrivilegeEnforcer

            enforcer = DefaultPrivilegeEnforcer()
            enforcer.register_profile(config.agent_profile)
            monitor.privilege_enforcer = enforcer

        enforcement = ToolEnforcement(monitor, config, approval_queue)
        for current in agents:
            for tool in getattr(current, "tools", None) or []:
                _install_function_tool_guard(tool, enforcement)

        timeout_seconds = self.get_timeout_config(config)
        return OpenAIAgentsSecureAgent(
            agent, monitor, config, self, enforcement, timeout_seconds
        )

    def extract_state(self, agent: Any) -> AgentState:
        enforcement = getattr(agent, "enforcement", None)
        if enforcement is not None:
            return enforcement.state
        return AgentState(agent_id=self.get_agent_id(agent))

    def inject_monitoring(self, agent: Any, monitor: SecurityMonitor) -> None:
        logger.debug("OpenAI Agents monitoring is installed on FunctionTool callbacks")

    def get_tool_calls(self, agent: Any) -> List[ToolCall]:
        enforcement = getattr(agent, "enforcement", None)
        if enforcement is not None:
            return list(enforcement.state.tool_history)
        return []

    def get_agent_id(self, agent: Any) -> str:
        if hasattr(agent, "name"):
            return f"openai-agent-{agent.name}"
        return f"openai-agent-{id(agent) % 10000:04d}"
