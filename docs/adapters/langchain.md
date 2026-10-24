# LangChain adapter

The LangChain adapter wraps either a legacy `AgentExecutor` or a compiled LangChain 1.x agent graph, such as the object returned by `langchain.agents.create_agent`.

## Wrap an `AgentExecutor`

```python
from gate import AgentProfile, gateConfig, wrap_agent

config = gateConfig(
    agent_profile=AgentProfile(
        agent_id="lc-agent",
        role="assistant",
        allowed_tools={"search"},
    ),
    enabled_checks={"privilege", "dfa"},
)

executor = AgentExecutor(agent=agent, tools=[search, delete_records])
secure = wrap_agent(executor, "langchain", config)

try:
    result = secure.invoke({"input": "Find the retention policy"})
finally:
    secure.terminate()
```

The adapter reads `.tools` from the executor and installs a guard on every tool in that list. The executor and its agent keep their existing references, so no re-registration is needed.

## Wrap a compiled agent graph

```python
from langchain.agents import create_agent

graph = create_agent(model, tools=[search, delete_records])
secure = wrap_agent(graph, "langchain", config)

# If discovery cannot see the tools, name them explicitly:
secure = wrap_agent(graph, "langchain", config, tools=[search, delete_records])
```

Accepted graph type is `langgraph.graph.state.CompiledStateGraph`. Tools are discovered from `ToolNode` instances in the compiled graph using the same traversal as the LangGraph adapter.

## Tool resolution order

1. The `tools=` argument, if provided.
2. `agent.tools`, if it is a list or tuple.
3. Tools registered on `ToolNode`s in the compiled graph.
4. For a compiled graph with no `ToolNode`: an empty list, and the graph is wrapped with **no guards**.
5. Otherwise: `AdapterError`.

Step 4 is the sharp edge. A compiled graph with tools hidden inside a nested graph that does not expose a `ToolNode` will be wrapped successfully and silently leave those tools unguarded. If you are not certain what discovery finds, pass `tools=` explicitly:

```python
secure = wrap_agent(graph, "langchain", config, tools=[search, delete_records, nested_tool])
```

Check the actual guarded set by inspecting the tool objects after wrapping:

```python
assert getattr(search, "_gate_enforcement", None) is secure.enforcement
```

## State and identifiers

`extract_state()` and `get_state()` return the enforcement's `AgentState`. `get_agent_id()` uses an `agent_id` attribute if the wrapped object has one; otherwise it generates `langchain-agent-<id>`. The generated identifier is not the `agent_id` in your profile. The profile identifier is used for privilege checks because the enforcement state is initialized from `config.agent_profile.agent_id`.

The adapter does not inject identifiers into the LangChain config. If your graph depends on `configurable.agent_id`, pass it yourself.

## Invocation methods

| Method | Behavior |
|---|---|
| `invoke(input, **kwargs)` | Synchronous; runs the executor/graph under `config.timeout_seconds` |
| `ainvoke(input, **kwargs)` | Asynchronous; uses `asyncio.wait_for` |
| `get_state()` | Current `AgentState` |
| `terminate()` | Closes the monitor event loop |

The intent anchor for the semantic stage is `str(input)` when the input is not a string. For a message dictionary, that is a Python repr of the dictionary.

## Async tools

`langchain_native_async(tool)` decides whether an async call should await the tool's own `_arun` or run `_run` in a thread. `StructuredTool._arun` without an explicit coroutine delegates to `_run`; treating that as native would validate the same call twice. Tools with a real coroutine are awaited directly.

## Errors

`ToolExecutionBlocked` is raised from `_run` or `_arun`. Whether `AgentExecutor` catches tool exceptions depends on its `handle_tool_error` setting; the guard's exception reaches whatever handler the executor has. If the executor is configured to convert tool errors into observations, the model may see the refusal text; otherwise the exception propagates out of `invoke`.

Do not confuse this with a normal tool failure. `ToolExecutionBlocked` means no tool body ran. See [Enforcement plumbing](../enforcement.md#block-handling).

## Limitations

- Tools added to the executor after wrapping are not guarded.
- A shared tool object cannot be guarded by two wrapped agents; the second wrap raises `AdapterError`.
- A compiled graph without a discoverable `ToolNode` gets zero guards unless `tools=` is passed.
- The adapter does not mediate retriever calls, model calls, or callbacks.

## Related pages

- [Adapters overview](README.md)
- [LangGraph](langgraph.md)
- [Enforcement plumbing](../enforcement.md)
