# LangGraph adapter

The LangGraph adapter wraps a compiled `StateGraph` whose tools execute in a `ToolNode`. It guards each tool on the node in place, so every node that reaches those tools is mediated.

## Example

```python
from typing import Annotated, TypedDict

from langchain_core.tools import tool
from langgraph.graph import END, START, StateGraph
from langgraph.prebuilt import ToolNode

from gate import AgentProfile, gateConfig, wrap_agent


@tool
def search(query: str) -> str:
    """Search the knowledge base."""
    return "result"


@tool
def delete_records(table: str) -> str:
    """Delete rows."""
    return "deleted"


class State(TypedDict):
    messages: Annotated[list, lambda left, right: left + right]


builder = StateGraph(State)
builder.add_node("tools", ToolNode([search, delete_records]))
builder.add_edge(START, "tools")
builder.add_edge("tools", END)
graph = builder.compile()

config = gateConfig(
    agent_profile=AgentProfile(
        agent_id="graph-agent",
        role="assistant",
        allowed_tools={"search"},
    ),
    enabled_checks={"privilege", "dfa"},
)

secure = wrap_agent(graph, "langgraph", config)
result = secure.invoke(
    {"messages": [ai_message_with_tool_call("search", {"query": "policy"})]}
)
secure.terminate()
```

## Tool discovery

The adapter calls `collect_graph_tools(agent)`, which inspects:

- the builder's node specs (`graph.builder.nodes[*].runnable`), and
- the compiled graph's Pregel nodes (`graph.nodes[*].bound`),

then collects `tools_by_name` from every `ToolNode` it finds. Tools are de-duplicated by identity, so a tool registered on two nodes is guarded once.

If no tools are found and `tools` was not supplied, `wrap_agent` raises:

```text
No ToolNode with registered tools was found in this graph. Pass tools=[...]
explicitly so GATE can install a guard on every executable tool (use tools=[]
only if the graph has no tool surface).
```

Passing `tools=[]` explicitly is accepted for a graph that genuinely has no tool surface. It installs no guards; nothing is mediated.

Passing `tools=[...]` bypasses discovery and guards exactly that list.

## Agent identifier

On both `invoke` and `ainvoke`, the adapter injects the configured agent identifier into the LangGraph config:

```python
config["configurable"]["agent_id"] = config.agent_profile.agent_id
```

Existing `configurable` values are preserved. If your graph reads `configurable.agent_id`, it sees the GATE profile identifier rather than a framework-generated one.

## State

`get_state()` returns the live enforcement `AgentState`, not the graph's channel state. After a successful run it shows:

- `current_phase == "ANSWERING"`
- the executed calls in `tool_history`
- `step_count` equal to the number of executed calls

A blocked call leaves `tool_history` unchanged because `after_call` never runs.

## Invocation

| Method | Behavior |
|---|---|
| `invoke(input, **kwargs)` | Runs `graph.invoke` under `config.timeout_seconds` |
| `ainvoke(input, **kwargs)` | Awaits `graph.ainvoke` with `asyncio.wait_for` |
| `get_state()` | Enforcement state |
| `terminate()` | Closes the monitor event loop |

The semantic intent anchor is taken from `input["input"]` or `input["messages"]` when the input is a dict, stringified. Message lists are long and structured; the anchor is not a concise summary of the user's request.

## Subgraphs

`collect_graph_tools` inspects the top-level builder and compiled nodes. A `ToolNode` inside a nested subgraph is not traversed unless it appears in those top-level structures. If your graph delegates tool execution to a subgraph, pass those tools explicitly:

```python
secure = wrap_agent(graph, "langgraph", config, tools=subgraph_tools)
```

Only guarded tools are mediated. A tool hidden in a subgraph that discovery cannot see runs unguarded.

## Tools shared with other agents

A tool instance can belong to only one `ToolEnforcement`. Wrapping a second graph that shares the same tool object raises `AdapterError`:

```text
Tool 'search' is already guarded by another GATE enforcement instance
```

Create separate tool instances per wrapped agent, or wrap a single agent and route all runs through it.

## Errors and timeouts

A refusal raises `ToolExecutionBlocked` from inside `ToolNode` dispatch. The tests assert that it propagates out of `graph.invoke`.

A timeout raises the adapter `TimeoutError` after calling `enforcement.abort(...)`. On Windows the underlying graph call may continue in a worker thread after the exception. See [Installation](../installation.md#windows-notes).

## Test coverage

The integration suite builds a real `StateGraph` with a real `ToolNode` and asserts:

- an authorized call executes and appears in state,
- an unauthorized call raises with `checks_failed == ["privilege"]` and never executes,
- a failed postcondition withholds the output after execution.

See [Testing](../testing.md).

## Related pages

- [LangChain](langchain.md)
- [Adapters overview](README.md)
- [Enforcement plumbing](../enforcement.md)
