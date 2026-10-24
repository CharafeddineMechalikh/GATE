# OpenAI Agents SDK adapter

The OpenAI Agents adapter wraps an `agents.Agent`, guards every local `FunctionTool`, and follows handoffs so tools on specialist agents are guarded too.

## Example

```python
from agents import Agent, function_tool

from gate import AgentProfile, gateConfig, wrap_agent


@function_tool
def search(query: str) -> str:
    """Search the knowledge base."""
    return "result"


@function_tool
def delete_records(table: str) -> str:
    """Delete rows."""
    return "deleted"


agent = Agent(name="assistant", tools=[search, delete_records])

config = gateConfig(
    agent_profile=AgentProfile(
        agent_id="openai-agent",
        role="assistant",
        allowed_tools={"search"},
    ),
    enabled_checks={"privilege", "dfa"},
)

secure = wrap_agent(agent, "openai-agents", config)

result = await secure.invoke("Find the retention policy")
secure.terminate()
```

`invoke` is a coroutine. There is no synchronous `invoke` and no `ainvoke` method on this wrapper. It calls `Runner.run(agent, input, **kwargs)` under `config.timeout_seconds`.

## Discovery

The adapter walks the wrapped agent and every reachable handoff target:

```python
agent.handoffs -> handoff.agent (or the handoff object itself) -> ...
```

Every local tool on every reachable agent is guarded with the same enforcement instance, so one approval queue and one run state cover the whole handoff tree.

## Refusals

The adapter refuses to wrap an agent when a tool executes outside the Python process:

- `agent.mcp_servers` is non-empty. MCP tool calls happen on the MCP server, not through a local Python callback.
- Any tool in `agent.tools` lacks `on_invoke_tool`, such as hosted web search, file search, code interpreter, computer use, or image generation tools.

The error tells you to replace the hosted tool with a local function. This is deliberate: wrapping such an agent would silently leave those tools unmediated.

The same rule applies to handoff targets. If any reachable agent declares an MCP server or hosted tool, the wrap fails.

## What the guard sees

The SDK calls `FunctionTool.on_invoke_tool(ctx, args)`. The adapter wraps that callback and parses `args`:

| `args` type | Marshalled form |
|---|---|
| JSON string | Parsed JSON object; if parsing fails, `{"input": raw_string}` |
| `dict` | A shallow copy |
| Anything else | `marshal_tool_args(tool, (args,), {})` |

The parsed mapping is what privilege, contracts, and the semantic stage see. If the SDK passes a JSON string, the keys are the function's parameter names.

The original callback receives the original `ctx` and `args`, unchanged. GATE does not rewrite tool arguments on dispatch.

## State in the test path

The integration tests call the patched `tool.on_invoke_tool` directly, which is the SDK's own callback entry point. The test does not use `Runner.run`, so no model or API key is needed, but the guard path is real. After an allowed call, the wrapper's state shows the call in `tool_history` and phase `OBSERVING`. Running through `Runner.run` adds the SDK's agent loop around the same callback.

## Handoffs and shared tools

If two agents in the handoff tree share the same `FunctionTool` object, the second guard installation raises `AdapterError`, because a tool can belong to only one enforcement. Give each agent its own tool instance when wrapping the tree, or exclude the shared tool from one of the agents.

The enforcement state is shared across the whole tree. A tool call on a specialist agent advances the same DFA phase and step count as a call on the root agent.

## Streaming

`Runner.run_streamed` is not wrapped. The secure agent exposes only `invoke`, which uses `Runner.run`. A streaming application must add its own wrapping or use the monitor plus `ToolEnforcement` directly.

## Errors and timeouts

A refusal raises `ToolExecutionBlocked` from `on_invoke_tool`. The SDK runner decides how to surface that exception; it may fail the run or report a tool error. The guard has already prevented the body from executing.

On timeout, the secure wrapper raises the adapter `TimeoutError` and aborts the run. `asyncio.wait_for` cancels the awaited coroutine; whether the SDK stops its internal work promptly depends on the SDK's cancellation handling.

## Limitations

- Hosted tools and MCP tools cannot be mediated; the wrap fails if they are present.
- Tools added to an agent after wrapping are not guarded.
- Streaming runs are not covered.
- A tool shared across handoff targets cannot be guarded twice.
- The adapter does not mediate guardrails, model calls, or session storage.

## Related pages

- [Adapters overview](README.md)
- [Enforcement plumbing](../enforcement.md)
- [Security model](../security-model.md)
