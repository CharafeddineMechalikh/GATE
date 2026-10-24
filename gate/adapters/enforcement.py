"""
Shared enforcement plumbing for the framework adapters.

Each adapter installs a guard on every executable tool. The guard marshals the
native call into a :class:`ToolCall`, obtains a decision from the monitor, and
invokes the original tool body only when the decision is ALLOW (or a human
approves an ESCALATE). Because the monitor is async and most framework tool
hooks are synchronous, synchronous hooks are bridged through one dedicated
event loop per secured agent; this keeps HITL approval events and D-CBF history
on a single loop instead of a fresh loop per call.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import threading
import uuid
from collections.abc import Mapping
from concurrent.futures import TimeoutError as FutureTimeoutError
from typing import Any, Callable, Dict, List, Optional, Tuple

from ..core.config import gateConfig
from ..core.exceptions import AdapterError, SecurityViolation
from ..core.interfaces import SecurityMonitor
from ..core.models import AgentState, ToolCall, ValidationResult

logger = logging.getLogger(__name__)

_CONTROL_KWARGS = frozenset(
    {
        "run_manager",
        "callbacks",
        "parent_run_id",
        "config",
        "configurable",
        "verbose",
        "start_color",
        "color",
        "tags",
        "metadata",
        "run_name",
        "run_id",
        "tool_call_id",
    }
)


class ToolExecutionBlocked(SecurityViolation):
    """Raised in place of a tool call that the monitor denied.

    The tool body is never invoked. ``result`` carries the monitor's decision
    so framework adapters and host agents can surface stage and reason.
    """

    def __init__(
        self,
        message: str,
        tool_name: str,
        result: Optional[ValidationResult] = None,
        *,
        post_execution: bool = False,
        stage: Optional[str] = None,
    ) -> None:
        details: Dict[str, Any] = {
            "tool_name": tool_name,
            "post_execution": post_execution,
        }
        if stage is not None:
            details["stage"] = stage
        if result is not None:
            details.update(
                {
                    "reason": result.reason,
                    "checks_failed": list(result.checks_failed),
                    "checks_passed": list(result.checks_passed),
                    "escalated": bool(result.escalated),
                }
            )
        super().__init__(message, details)
        self.tool_name = tool_name
        self.result = result
        self.post_execution = post_execution


def schema_field_names(tool: Any) -> List[str]:
    """Return the declared argument names for a tool, if it exposes them."""
    schema = getattr(tool, "args_schema", None)
    if schema is None:
        declared = getattr(tool, "args", None)
        if isinstance(declared, Mapping):
            return list(declared)
        return []
    if isinstance(schema, Mapping):
        properties = schema.get("properties")
        return list(properties) if isinstance(properties, Mapping) else []
    fields = getattr(schema, "model_fields", None)
    if isinstance(fields, Mapping):
        return list(fields)
    fields = getattr(schema, "__fields__", None)
    if isinstance(fields, Mapping):
        return list(fields)
    return []


def marshal_tool_args(
    tool: Any,
    args: Tuple[Any, ...],
    kwargs: Mapping[str, Any],
) -> Dict[str, Any]:
    """Bind a framework-native call to a name -> value argument mapping."""
    clean = {
        key: value
        for key, value in kwargs.items()
        if key not in _CONTROL_KWARGS and not str(key).startswith("_")
    }
    out: Dict[str, Any] = {}

    if args:
        if len(args) == 1:
            value = args[0]
            if hasattr(value, "model_dump"):
                value = value.model_dump()
            if isinstance(value, Mapping):
                out.update(value)
            else:
                out["input"] = value
        else:
            names = schema_field_names(tool)
            if names and len(args) <= len(names):
                out.update(zip(names, args))
            else:
                out.update({f"arg{i}": value for i, value in enumerate(args)})

    out.update(clean)
    return out


def _signature_parameters(func: Callable[..., Any]) -> Mapping[str, inspect.Parameter]:
    try:
        return inspect.signature(func).parameters
    except (TypeError, ValueError):
        return {}


def _invoke_sync_tool(
    func: Callable[..., Any],
    args: Tuple[Any, ...],
    kwargs: Dict[str, Any],
    run_manager: Any,
    config: Any,
) -> Any:
    params = _signature_parameters(func)
    extra: Dict[str, Any] = {}
    if "run_manager" in params:
        extra["run_manager"] = run_manager
    if "config" in params:
        extra["config"] = config
    return func(*args, **kwargs, **extra)


class ToolEnforcement:
    """Per-agent enforcement state shared by every guarded tool."""

    def __init__(
        self,
        monitor: SecurityMonitor,
        config: gateConfig,
        approval_queue: Optional[Any] = None,
    ) -> None:
        self.monitor = monitor
        self.config = config
        self.approval_queue = approval_queue
        self._state = AgentState(agent_id=config.agent_profile.agent_id)
        self._state.current_phase = "IDLE"
        self._finished = False
        self._aborted_reason: Optional[str] = None
        self._lock = threading.RLock()
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._loop_guard = threading.Lock()
        self._approval_loop: Optional[asyncio.AbstractEventLoop] = None
        self._approval_guard = threading.Lock()

    @property
    def state(self) -> AgentState:
        return self._state

    def begin_run(self, intent: Optional[str] = None) -> None:
        """Start a fresh agent run: new state, planning phase, fresh intent anchor."""
        with self._lock:
            self._state = AgentState(agent_id=self.config.agent_profile.agent_id)
            self._state.current_phase = "IDLE"
            self._finished = False
            self._aborted_reason = None
        firewall = getattr(self.monitor, "semantic_firewall", None)
        if intent is not None and firewall is not None:
            firewall.set_intent_anchor(str(intent))

    def finish_run(self) -> None:
        with self._lock:
            if not self._finished:
                self._state.current_phase = "ANSWERING"
                self._finished = True

    def abort(self, reason: str) -> None:
        """Stop accepting tool calls for the current run (used on timeouts)."""
        with self._lock:
            self._aborted_reason = reason
            self._finished = True

    def _advance_for_action(self, tool_name: str) -> None:
        """Move the DFA to ACTING for this call, recording legal transitions."""
        if self._finished or self._state.current_phase == "ANSWERING":
            detail = f": {self._aborted_reason}" if self._aborted_reason else ""
            raise ToolExecutionBlocked(
                f"Cannot call {tool_name}: agent run is already completed{detail}",
                tool_name,
                stage="dfa",
            )

        dfa = getattr(self.monitor, "dfa_supervisor", None)

        if self._state.current_phase == "ACTING":
            # A tool that calls another tool without returning to planning is an
            # ACTING self-loop; the supervisor's per-phase loop budget governs it.
            if dfa is not None:
                allowed, reason = dfa.validate_action_phase(self._state)
                if not allowed:
                    raise ToolExecutionBlocked(
                        f"DFA refused an ACTING loop for {tool_name}: {reason}",
                        tool_name,
                        stage="dfa",
                    )
            self._state.increment_loop("ACTING")
            return

        phases: List[str] = []
        if self._state.current_phase in ("IDLE", "OBSERVING"):
            phases.append("PLANNING")
        phases.append("ACTING")

        for phase in phases:
            if dfa is not None:
                allowed, reason = dfa.propose_transition(self._state, phase)
                if not allowed:
                    raise ToolExecutionBlocked(
                        f"DFA refused {self._state.current_phase} -> {phase} for {tool_name}: {reason}",
                        tool_name,
                        stage="dfa",
                    )
            self._state.current_phase = phase

    async def before_call(
        self,
        tool_name: str,
        tool_args: Mapping[str, Any],
        call_id: Optional[str] = None,
    ) -> ToolCall:
        """Validate a proposed tool call; return the ToolCall only if allowed."""
        with self._lock:
            self._advance_for_action(tool_name)
            action = ToolCall(
                tool_name=tool_name,
                tool_args=dict(tool_args),
                call_id=call_id or uuid.uuid4().hex,
                agent_id=self._state.agent_id,
            )
            result = await self.monitor.validate_action(action, self._state)

            if result.is_allowed:
                return action

            if result.escalated:
                approval = await self._await_human(action, result)
                action.metadata["hitl_approval"] = approval
                return action

            raise ToolExecutionBlocked(
                f"Blocked {tool_name}: {result.reason}",
                tool_name,
                result,
            )

    async def after_call(self, action: ToolCall, output: Any) -> Any:
        """Record an executed call and enforce the contract postcondition."""
        with self._lock:
            self._state.add_tool_call(action)
            self._state.resource_usage.api_calls += 1
            self._state.current_phase = "OBSERVING"

            validator = getattr(self.monitor, "validate_result", None)
            if validator is None:
                return output

            result = await validator(action, output, self._state)
            if not result.is_allowed:
                raise ToolExecutionBlocked(
                    f"Postcondition failed for {action.tool_name}: {result.reason}",
                    action.tool_name,
                    result,
                    post_execution=True,
                )
            return output

    async def _await_human(
        self, action: ToolCall, result: ValidationResult
    ) -> Dict[str, Any]:
        queue = self.approval_queue
        if queue is None:
            raise ToolExecutionBlocked(
                f"Withheld {action.tool_name}: {result.reason}; "
                "no human approval queue is configured",
                action.tool_name,
                result,
                stage="semantic",
            )

        loop = asyncio.get_running_loop()
        with self._approval_guard:
            self._approval_loop = loop
        try:
            approval = await queue.request_and_await_approval(
                action=action,
                agent_id=self._state.agent_id,
                risk_level="high",
                tenant_id=self.config.tenant_id,
            )
        finally:
            with self._approval_guard:
                self._approval_loop = None
        if not approval.approved:
            raise ToolExecutionBlocked(
                f"Human approver denied {action.tool_name}: {approval.justification or 'no justification'}",
                action.tool_name,
                result,
                stage="hitl",
            )
        logger.info(
            "HITL approved %s (%s) by %s",
            action.tool_name,
            approval.request_id,
            approval.approver_id,
        )
        return {
            "request_id": approval.request_id,
            "approver_id": approval.approver_id,
            "justification": approval.justification,
        }

    # -- sync bridging -----------------------------------------------------

    def approve(self, request_id: str, approver_id: str, justification: str = "") -> None:
        """Approve a pending escalation from outside the monitor's event loop."""
        if self.approval_queue is None:
            raise AdapterError("No approval queue is configured")
        self._resolve_on_approval_loop(
            self.approval_queue.approve(request_id, approver_id, justification)
        )

    def reject(self, request_id: str, approver_id: str, reason: str = "") -> None:
        """Reject a pending escalation from outside the monitor's event loop."""
        if self.approval_queue is None:
            raise AdapterError("No approval queue is configured")
        self._resolve_on_approval_loop(
            self.approval_queue.reject(request_id, approver_id, reason)
        )

    def _resolve_on_approval_loop(self, coro: Any) -> Any:
        with self._approval_guard:
            loop = self._approval_loop
        if loop is None:
            raise AdapterError("No human approval is currently pending")
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is loop:
            raise AdapterError(
                "approve/reject cannot block the monitor loop; "
                "await the approval queue method instead"
            )
        future = asyncio.run_coroutine_threadsafe(coro, loop)
        return future.result(timeout=10.0)

    def _ensure_loop(self) -> asyncio.AbstractEventLoop:
        with self._loop_guard:
            if self._loop is None or self._loop.is_closed():
                loop = asyncio.new_event_loop()
                ready = threading.Event()

                def _run() -> None:
                    asyncio.set_event_loop(loop)
                    ready.set()
                    loop.run_forever()

                thread = threading.Thread(
                    target=_run,
                    name=f"gate-monitor-{id(self):x}",
                    daemon=True,
                )
                thread.start()
                ready.wait()
                self._loop = loop
                self._thread = thread
            return self._loop

    def run_sync(self, coro: Any) -> Any:
        """Run a monitor coroutine to completion from a synchronous tool hook."""
        loop = self._ensure_loop()
        future = asyncio.run_coroutine_threadsafe(coro, loop)
        try:
            return future.result()
        except FutureTimeoutError:
            future.cancel()
            raise

    def sync_before_call(
        self, tool_name: str, tool_args: Mapping[str, Any]
    ) -> ToolCall:
        try:
            return self.run_sync(self.before_call(tool_name, tool_args))
        except FutureTimeoutError:
            result = ValidationResult(
                is_allowed=False,
                reason="Monitor decision timed out",
                checks_failed=["monitor"],
            )
            raise ToolExecutionBlocked(
                f"Monitor timed out before dispatching {tool_name}",
                tool_name,
                result,
                stage="monitor",
            ) from None

    def sync_after_call(self, action: ToolCall, output: Any) -> Any:
        try:
            return self.run_sync(self.after_call(action, output))
        except FutureTimeoutError:
            result = ValidationResult(
                is_allowed=False,
                reason="Postcondition check timed out",
                checks_failed=["postcondition"],
            )
            raise ToolExecutionBlocked(
                f"Postcondition check timed out for {action.tool_name}",
                action.tool_name,
                result,
                post_execution=True,
            ) from None

    def close(self) -> None:
        with self._loop_guard:
            loop, thread = self._loop, self._thread
            self._loop = None
            self._thread = None
        if loop is None:
            return
        if loop.is_running():
            loop.call_soon_threadsafe(loop.stop)
        if thread is not None:
            thread.join(timeout=5.0)
        if not loop.is_closed():
            loop.close()


def install_tool_guard(
    tool: Any,
    enforcement: ToolEnforcement,
    *,
    tool_name: Optional[str] = None,
    native_async: Optional[bool] = None,
) -> Any:
    """Intercept a tool's ``_run``/``_arun`` methods in place.

    Works for LangChain ``BaseTool`` and CrewAI ``BaseTool`` objects: both
    dispatch execution through these methods, and both allow instance-level
    method shadowing. The same object is mutated, so framework registries that
    already hold a reference (an executor, a ``ToolNode``, an agent) see the
    guard without being rebuilt.
    """
    name = tool_name or getattr(tool, "name", None) or type(tool).__name__

    owner = getattr(tool, "_gate_enforcement", None)
    if owner is not None:
        if owner is enforcement:
            return tool
        raise AdapterError(
            f"Tool {name!r} is already guarded by another GATE enforcement instance"
        )

    original_run = getattr(tool, "_run", None)
    if original_run is None or not callable(original_run):
        raise AdapterError(f"Tool {name!r} exposes no executable _run method")

    original_arun = getattr(tool, "_arun", None)
    has_coroutine = getattr(tool, "coroutine", None) is not None
    if native_async is None:
        native_async = has_coroutine and original_arun is not None

    def guarded_run(*args: Any, run_manager: Any = None, config: Any = None, **kwargs: Any) -> Any:
        call_args = marshal_tool_args(tool, args, kwargs)
        action = enforcement.sync_before_call(name, call_args)
        output = _invoke_sync_tool(original_run, args, kwargs, run_manager, config)
        return enforcement.sync_after_call(action, output)

    object.__setattr__(tool, "_run", guarded_run)

    if original_arun is not None:

        async def guarded_arun(
            *args: Any, run_manager: Any = None, config: Any = None, **kwargs: Any
        ) -> Any:
            call_args = marshal_tool_args(tool, args, kwargs)
            action = await enforcement.before_call(name, call_args)
            if native_async:
                output = await original_arun(*args, **kwargs)
            else:
                output = await asyncio.to_thread(
                    _invoke_sync_tool,
                    original_run,
                    args,
                    kwargs,
                    run_manager,
                    config,
                )
            return await enforcement.after_call(action, output)

        object.__setattr__(tool, "_arun", guarded_arun)

    object.__setattr__(tool, "_gate_enforcement", enforcement)
    object.__setattr__(tool, "_gate_tool_name", name)
    logger.debug("Installed GATE guard on tool %s", name)
    return tool


def guard_tool_list(
    tools: Any,
    enforcement: ToolEnforcement,
    *,
    native_async: Optional[bool] = None,
) -> None:
    """Guard every executable tool in a framework's tool list."""
    if not tools:
        return
    for tool in list(tools):
        install_tool_guard(tool, enforcement, native_async=native_async)


def collect_graph_tools(graph: Any) -> List[Any]:
    """Return the tools registered on every ToolNode in a compiled LangGraph.

    Both the builder's node specs and the compiled graph's Pregel nodes are
    inspected; ToolNode stores its tools in ``tools_by_name``.
    """
    candidates: List[Any] = []

    builder = getattr(graph, "builder", None)
    if builder is not None:
        for spec in getattr(builder, "nodes", {}).values():
            runnable = getattr(spec, "runnable", None)
            if runnable is not None:
                candidates.append(runnable)

    compiled_nodes = getattr(graph, "nodes", None)
    if isinstance(compiled_nodes, Mapping):
        for pregel in compiled_nodes.values():
            runnable = getattr(pregel, "bound", None)
            if runnable is not None:
                candidates.append(runnable)

    tools: List[Any] = []
    seen_nodes = set()
    seen_tools = set()
    for candidate in candidates:
        if id(candidate) in seen_nodes:
            continue
        seen_nodes.add(id(candidate))
        tools_by_name = getattr(candidate, "tools_by_name", None)
        if not isinstance(tools_by_name, Mapping):
            continue
        for tool in tools_by_name.values():
            if id(tool) in seen_tools:
                continue
            seen_tools.add(id(tool))
            tools.append(tool)
    return tools
