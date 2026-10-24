# Framework adapters

GATE wraps the framework you already use. The adapter does not rebuild the graph, re-register the tools, or change how the planner works. It finds the live tool objects and installs a guard on each one.

| Framework | Key | Adapter | Accepted object | Extra |
|---|---|---|---|---|
| LangChain | `langchain` | `LangChainAdapter` | `AgentExecutor` or a compiled LangChain agent graph | `langchain` |
| LangGraph | `langgraph` | `LangGraphAdapter` | Compiled `StateGraph` with a `ToolNode` | `langgraph` |
| OpenAI Agents SDK | `openai-agents` | `OpenAIAgentsAdapter` | `agents.Agent` | `openai-agents` |
| CrewAI | `crewai` | `CrewAIAdapter` | `Crew` | `crewai` |

## Common API

```python
from gate import wrap_agent

secure = wrap_agent(agent, "<key>", config, tools=None, approval_queue=None)
```

| Option | Applies to | Purpose |
|---|---|---|
| `tools=` | LangChain, LangGraph | Explicit list of tools to guard when discovery cannot find them |
| `approval_queue=` | All | `HumanApprovalQueue` used for `ESCALATE` decisions |

The returned `SecureAgent` provides:

| Method | LangChain | LangGraph | OpenAI Agents | CrewAI |
|---|---|---|---|---|
| `invoke(input, **kwargs)` | sync | sync | **async** | sync |
| `ainvoke(input, **kwargs)` | async | async | not defined | async |
| `get_state()` | yes | yes | yes | yes |
| `terminate()` | yes | yes | yes | yes |

For OpenAI Agents, `invoke` is a coroutine: `await secure.invoke(...)`. There is no separate `ainvoke` on that wrapper.

`get_state()` returns the live `AgentState` for the current run. After `invoke` returns, `current_phase` is `ANSWERING` and `tool_history` contains the executed calls.

## What gets mediated

The guard is installed on the tool's own execution method, so the framework's normal dispatch hits it:

| Framework | Interception point |
|---|---|
| LangChain | `BaseTool._run` / `_arun` |
| LangGraph | `BaseTool._run` / `_arun` inside `ToolNode` |
| OpenAI Agents | `FunctionTool.on_invoke_tool` |
| CrewAI | `BaseTool._run` / `_arun`, including the native function-call dispatch table |

Only guarded tools are mediated. A tool the adapter did not discover or was not given runs unguarded. This is the central operational rule: verify the tool list, do not assume it.

## Discovery and refusal rules

| Framework | Discovery | Refuses when |
|---|---|---|
| LangChain | Explicit `tools=`, then `.tools` on the executor, then `ToolNode`s in a compiled graph | Object is neither `AgentExecutor` nor a compiled graph, and no explicit tools were given |
| LangGraph | Explicit `tools=`, then `ToolNode`s in the compiled graph | No `ToolNode` with tools was found; pass `tools=` |
| OpenAI Agents | Every `FunctionTool` on the agent and all reachable handoff targets | MCP servers or non-`FunctionTool` hosted tools are declared |
| CrewAI | `tools` on every agent and every task | A listed tool has no `_run` method |

A LangChain compiled graph with no discoverable `ToolNode` returns an empty tool list and wraps the graph with no guards. This is intentional for graphs that genuinely have no tool surface, but it is also the path by which a nested tool surface can escape mediation. Pass `tools=` explicitly if you are not certain. The LangGraph adapter is stricter and raises instead.

## Guard lifetime and sharing

Guards mutate the tool objects in place. A tool already guarded by a different enforcement instance causes an `AdapterError`; a framework that shares tool instances between agents cannot have two wrapped agents guard the same object. Wrap one agent per tool set, or give each agent distinct tool objects.

`terminate()` closes the monitor's event loop. It does **not** remove the guard from the tool object. The object remains bound to that enforcement instance and its run state. Do not reuse a guarded tool in an unwrapped agent and expect unguarded behavior.

Tools added after wrapping are not guarded. This includes dynamically generated tools, tools attached to a sub-agent after `wrap_agent`, and tools registered on a graph after compilation.

## Failure propagation

The guard raises `ToolExecutionBlocked` inside the framework's tool dispatch. What happens next is framework behavior:

- LangGraph and LangChain propagate the exception out of `invoke`; the tests assert this.
- OpenAI's `FunctionTool.on_invoke_tool` raises; the SDK's runner decides whether that becomes a tool error, a retry, or a run failure.
- CrewAI's dispatch call raises; its executor decides how to surface it.

If you want the model to see a refusal as a tool observation rather than an exception, catch `ToolExecutionBlocked` at the framework boundary and insert the message yourself. Do not catch it and then call the tool directly.

## What the adapters do not do

- They do not attach an `EncryptedAuditLogger`. `gateConfig.audit_log_path` is unused. See [Audit](../audit.md).
- They do not accept a prebuilt monitor, firewall, enforcer, or D-CBF instance. Each `wrap_agent` builds `gateMonitor(config)`.
- They do not guard model calls, prompts, retrievers, or non-tool side effects.
- They do not sandbox the tool process. A guarded tool still runs with the host's permissions.
- They do not retry a blocked call. A refusal is final for that call.
- They do not detect tools created after wrapping.

## Timeouts

Every adapter applies `config.timeout_seconds` to the whole framework invocation. The default is 300 seconds. The CrewAI adapter's constructor default of 600 seconds is used only if the config object has no `timeout_seconds` attribute, which is not the case for `gateConfig`.

On timeout, the run is aborted and later tool calls are refused. Python cannot interrupt an already-running call in a worker thread, so on Windows the framework may continue in the background after `invoke` has raised.

## Framework-specific pages

- [LangChain](langchain.md)
- [LangGraph](langgraph.md)
- [OpenAI Agents SDK](openai-agents.md)
- [CrewAI](crewai.md)
