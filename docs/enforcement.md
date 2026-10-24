# Enforcement plumbing

The adapters share one enforcement layer. Understanding it is useful when writing a custom adapter, debugging why a contract sees different arguments than the framework passed, or handling blocks in host code.

## `ToolEnforcement`

`gate.adapters.enforcement.ToolEnforcement(monitor, config, approval_queue=None)` owns the state for one wrapped agent and exposes both async and synchronous entry points.

| Method | Purpose |
|---|---|
| `begin_run(intent=None)` | Replace the run state and set the semantic intent anchor |
| `finish_run()` | Move the run to `ANSWERING`; later tool calls are refused |
| `abort(reason)` | Mark the run finished because of a timeout or host cancellation |
| `before_call(tool_name, tool_args, call_id=None)` | Async. Advance the DFA, validate, handle escalation; return a `ToolCall` or raise |
| `after_call(action, output)` | Async. Record the call and enforce postconditions; return the output or raise |
| `sync_before_call(tool_name, tool_args)` | Run `before_call` on the dedicated monitor loop |
| `sync_after_call(action, output)` | Run `after_call` on the dedicated monitor loop |
| `approve(request_id, approver_id, justification="")` | Resolve a pending escalation from another thread |
| `reject(request_id, approver_id, reason="")` | Reject a pending escalation from another thread |
| `run_sync(coro)` | Submit any monitor coroutine to the dedicated loop |
| `close()` | Stop and close the dedicated monitor loop |
| `.state` | The current `AgentState` |
| `.monitor`, `.config`, `.approval_queue` | Injected components |

A synchronous guard calls `sync_before_call`, and then `sync_after_call` only after the original body returns. A timeout in either bridge is converted to `ToolExecutionBlocked` with stage `monitor` or `postcondition` respectively. An exception from the monitor other than a timeout propagates unchanged.

## Guard installation

```python
from gate.adapters.enforcement import install_tool_guard

install_tool_guard(tool, enforcement)
```

The function mutates the live tool object:

- It shadows `tool._run` with a guarded function.
- If the tool has an `_arun`, it shadows that too.
- It records `_gate_enforcement` and `_gate_tool_name` on the object.

The original methods are captured in closures. The same object is returned; frameworks that already hold a reference see the guard immediately. Passing the same tool to a second enforcement raises `AdapterError` rather than silently replacing the first guard. Re-guarding with the same enforcement is a no-op.

`native_async` controls whether the async guard awaits the tool's own `_arun` or runs `_run` in a worker thread via `asyncio.to_thread`. The LangChain adapter computes this with `langchain_native_async`, which treats `BaseTool._arun` and `StructuredTool._arun` delegating to `_run` as non-native, so the call is validated once rather than twice.

There is no unwrap API. `terminate()` closes the event loop but leaves the guard installed; the tool object remains bound to that enforcement and its run state. Do not share a guarded tool object between two independently wrapped agents.

## Argument marshalling

`marshal_tool_args(tool, args, kwargs)` produces the name-to-value mapping that privilege, contracts, and the semantic score see. It follows the framework's calling convention:

- Keyword arguments are copied, excluding framework control parameters (`run_manager`, `callbacks`, `config`, `configurable`, `metadata`, `tool_call_id`, and similar) and names starting with `_`.
- A single positional argument that is a mapping, or a Pydantic model with `model_dump()`, is flattened into the mapping.
- A single positional value that is not a mapping becomes `{"input": value}`.
- Multiple positional arguments are bound to the tool's declared schema field names when they can be read from `args_schema`, `args`, `model_fields`, or `__fields__`; otherwise they become `arg0`, `arg1`, and so on.

This is why a built-in contract reads `action.tool_args["query"]`: it only matches when the framework or host calls the tool with a `query` keyword (or a keyword-equivalent model field). A tool that receives the query as an anonymous positional string will present `{"input": "..."}` instead, and the SQL contract will not apply.

Contract preconditions may mutate `action.tool_args`. Those mutations are visible to the monitor, the audit event, and `state.tool_history`, but the original framework call is invoked with its original `args` and `kwargs`. Argument rewriting is not propagated to dispatch.

## Custom adapters

A new framework adapter only needs to discover the live tool objects and guard them. It does not need to reimplement validation.

```python
from typing import Any, List, Optional, Sequence

from gate.adapters.base import BaseFrameworkAdapter
from gate.adapters.enforcement import ToolEnforcement, install_tool_guard
from gate.core.config import gateConfig
from gate.core.interfaces import SecureAgent
from gate.core.models import AgentState, ToolCall


class MySecureAgent(SecureAgent):
    def __init__(self, wrapped, enforcement):
        self.wrapped = wrapped
        self.enforcement = enforcement

    def invoke(self, input, **kwargs):
        self.enforcement.begin_run(str(input))
        try:
            return self.wrapped.run(input, **kwargs)
        finally:
            self.enforcement.finish_run()

    def get_state(self) -> AgentState:
        return self.enforcement.state

    def terminate(self) -> None:
        self.enforcement.close()


class MyAdapter(BaseFrameworkAdapter):
    def __init__(self):
        super().__init__("my-framework")

    def wrap_agent(
        self,
        agent: Any,
        config: gateConfig,
        *,
        tools: Optional[Sequence[Any]] = None,
        approval_queue: Optional[Any] = None,
    ) -> SecureAgent:
        from gate.core.monitor import gateMonitor

        resolved = list(tools or getattr(agent, "tools", []))
        if not resolved:
            raise ValueError("Pass tools=[...] so GATE can guard them")

        monitor = gateMonitor(config)
        enforcement = ToolEnforcement(monitor, config, approval_queue)
        for tool in resolved:
            install_tool_guard(tool, enforcement)
        return MySecureAgent(agent, enforcement)

    # The remaining BaseFrameworkAdapter methods are for inspection only.
    def extract_state(self, agent):
        return agent.enforcement.state

    def inject_monitoring(self, agent, monitor):
        pass

    def get_tool_calls(self, agent):
        return list(agent.enforcement.state.tool_history)

    def get_agent_id(self, agent):
        return f"my-agent-{id(agent) % 10000:04d}"
```

Register it with the global registry if you want string-based wrapping:

```python
from gate import get_registry

get_registry().register_adapter("my-framework", MyAdapter())
secure = get_registry().wrap_agent(agent, "my-framework", config, tools=[...])
```

The hard part is discovering every tool that the framework can reach, including tools on sub-agents, handoff targets, and task-level overrides. If your framework supports dynamic tool creation, a one-time wrap cannot see tools created later; in that case the framework needs a dispatch-level hook rather than an object-level guard.

## Block handling

`ToolExecutionBlocked` carries:

| Attribute | Meaning |
|---|---|
| `tool_name` | Name of the refused tool |
| `result` | The monitor's `ValidationResult`, or `None` for guards raised before the monitor (completed run, DFA hop refusal) |
| `post_execution` | `True` when the block happened after the body ran |
| `details["stage"]` | Stage label for pre-monitor refusals (`dfa`, `monitor`, `hitl`, `semantic`) when available |
| `details["reason"]`, `details["checks_failed"]`, `details["checks_passed"]`, `details["escalated"]` | Copied from `result` when present |

Catch it at the boundary where the framework surfaces tool errors. LangGraph and LangChain propagate it out of `invoke`; the framework does not convert it into a normal tool observation. A host that wants the model to see a refusal should catch the exception and inject a tool error message itself.

## Async bridging details

The dedicated loop is created lazily and only for synchronous guard calls. It is a daemon thread named `gate-monitor-<hex id>`, and it runs `loop.run_forever()`. `close()` stops the loop and joins the thread for up to five seconds.

The approval path records the loop that is currently awaiting a human. `approve()` and `reject()` submit the corresponding coroutine to that loop and wait up to ten seconds. They raise `AdapterError` if no approval is pending. They also refuse to block the monitor loop itself; from inside that loop, await the queue methods directly.

## Related pages

- [Architecture](architecture.md) for the full lifecycle.
- [Adapters](adapters/README.md) for discovery rules per framework.
- [Human-in-the-loop](human-in-the-loop.md) for approval handling.
