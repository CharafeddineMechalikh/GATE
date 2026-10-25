# The same GATE scenario in LangGraph, LangChain, OpenAI Agents, and CrewAI

This page runs one scenario through all four adapters with the same configuration. It shows the object each adapter expects, how to run a full agent, and a keyless driver that exercises the framework's real tool-dispatch entry point. Use the keyless driver to verify enforcement without a model or API key; use the full-agent path for a real run.

## The scenario

Two tools:

- `search(query)` is allowed and returns a string.
- `delete_records(table)` is not on the allow-list. Its body must never run.

The configuration is identical for every framework:

```python
from gate import AgentProfile, ResourceBudget, gateConfig

config = gateConfig(
    agent_profile=AgentProfile(
        agent_id="scenario-agent",
        role="assistant",
        allowed_tools={"search"},
        resource_budget=ResourceBudget(max_steps=20, max_loops_per_phase=5),
    ),
    enabled_checks={"privilege", "dfa"},
)
```

The checks are deterministic, so no embedding model is downloaded. The expected outcomes are:

- `search` executes, returns its output, and appears in `secure.get_state().tool_history`.
- `delete_records` raises `ToolExecutionBlocked`, `exc.result.checks_failed == ["privilege"]`, and its body is not called.

## What changes per framework

| Framework | Wrapped object | Key | Full-run call | Keyless dispatch entry point |
|---|---|---|---|---|
| LangGraph | Compiled `StateGraph` with a `ToolNode` | `"langgraph"` | `secure.invoke({"messages": [...]})` | `ToolNode` through the compiled graph |
| LangChain | `AgentExecutor` or compiled `create_agent` graph | `"langchain"` | `secure.invoke("...")` or `secure.invoke({"messages": [...]})` | Compiled graph with a `ToolNode` |
| OpenAI Agents SDK | `agents.Agent` | `"openai-agents"` | `await secure.invoke("...")` | `FunctionTool.on_invoke_tool` |
| CrewAI | `crewai.Crew` | `"crewai"` | `secure.invoke({...})` | CrewAI function table or `BaseTool.run` |

Only the LangChain and LangGraph adapters accept `tools=`. OpenAI Agents and CrewAI derive their tool sets from the wrapped object. The same monitor, stages, and `ToolExecutionBlocked` behaviour apply in every row.

## LangGraph

A full graph has a model node and a `ToolNode`. GATE does not change the graph; it guards the tool objects inside the node.

```python
from langchain_core.messages import HumanMessage
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langgraph.graph import END, START, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode, tools_condition

from gate import wrap_agent


@tool
def search(query: str) -> str:
    """Search the internal knowledge base."""
    return f"results for {query}"


@tool
def delete_records(table: str) -> str:
    """Delete every row in a table."""
    return f"deleted {table}"


tools = [search, delete_records]
model = ChatOpenAI(model="gpt-4o-mini")


def agent_node(state: MessagesState):
    return {"messages": [model.bind_tools(tools).invoke(state["messages"])]}


builder = StateGraph(MessagesState)
builder.add_node("agent", agent_node)
builder.add_node("tools", ToolNode(tools))
builder.add_edge(START, "agent")
builder.add_conditional_edges("agent", tools_condition)
builder.add_edge("tools", "agent")
graph = builder.compile()

secure = wrap_agent(graph, "langgraph", config)
result = secure.invoke(
    {"messages": [HumanMessage("Find the retention policy")]}
)
secure.terminate()
```

The model call needs provider credentials. To verify enforcement without a model, drive the same `ToolNode` with a prepared `AIMessage`:

```python
from langchain_core.messages import AIMessage
from langchain_core.tools import tool
from langgraph.graph import END, START, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode

from gate import wrap_agent
from gate.adapters import ToolExecutionBlocked

executed = []


@tool
def search(query: str) -> str:
    """Search the internal knowledge base."""
    executed.append("search")
    return f"results for {query}"


@tool
def delete_records(table: str) -> str:
    """Delete every row in a table."""
    executed.append("delete_records")
    return f"deleted {table}"


builder = StateGraph(MessagesState)
builder.add_node("tools", ToolNode([search, delete_records]))
builder.add_edge(START, "tools")
builder.add_edge("tools", END)
graph = builder.compile()

secure = wrap_agent(graph, "langgraph", config)

permitted = AIMessage(
    content="",
    tool_calls=[
        {"name": "search", "args": {"query": "retention policy"}, "id": "c1", "type": "tool_call"}
    ],
)
output = secure.invoke({"messages": [permitted]})
assert output["messages"][-1].content == "results for retention policy"
assert [call.tool_name for call in secure.get_state().tool_history] == ["search"]

forbidden = AIMessage(
    content="",
    tool_calls=[
        {"name": "delete_records", "args": {"table": "users"}, "id": "c2", "type": "tool_call"}
    ],
)
try:
    secure.invoke({"messages": [forbidden]})
except ToolExecutionBlocked as exc:
    assert exc.result.checks_failed == ["privilege"]
    assert exc.post_execution is False

assert executed == ["search"]
secure.terminate()
```

The allowed output is `results for retention policy`. After `invoke` returns, `finish_run()` has moved the state to `ANSWERING`.

## LangChain

LangChain 1.x builds an agent graph with `create_agent`. Pass the compiled graph to the `"langchain"` adapter:

```python
from langchain.agents import create_agent
from langchain_openai import ChatOpenAI
from langchain_core.tools import tool

from gate import wrap_agent


@tool
def search(query: str) -> str:
    """Search the internal knowledge base."""
    return f"results for {query}"


@tool
def delete_records(table: str) -> str:
    """Delete every row in a table."""
    return f"deleted {table}"


model = ChatOpenAI(model="gpt-4o-mini")
graph = create_agent(model, tools=[search, delete_records])

secure = wrap_agent(graph, "langchain", config)
result = secure.invoke(
    {"messages": [{"role": "user", "content": "Find the retention policy"}]}
)
secure.terminate()
```

For a legacy `AgentExecutor`, the object is the executor instead:

```python
from langchain.agents import AgentExecutor

# agent is your existing LangChain agent runnable.
executor = AgentExecutor(agent=agent, tools=[search, delete_records])
secure = wrap_agent(executor, "langchain", config)
result = secure.invoke({"input": "Find the retention policy"})
secure.terminate()
```

If discovery cannot see the tools, pass `tools=[search, delete_records]` explicitly. A compiled graph with no discoverable `ToolNode` is wrapped with no guards unless you do.

Keyless check: build a compiled graph whose only node is a `ToolNode`, then use the same prepared `AIMessage` driver shown for LangGraph, with `secure = wrap_agent(graph, "langchain", config, tools=[search, delete_records])`. The adapter accepts compiled graphs, so the enforcement path is the same. See [LangChain adapter](adapters/langchain.md#wrap-a-compiled-agent-graph).

## OpenAI Agents SDK

```python
from agents import Agent, function_tool

from gate import wrap_agent

executed = []


@function_tool
def search(query: str) -> str:
    """Search the internal knowledge base."""
    executed.append("search")
    return f"results for {query}"


@function_tool
def delete_records(table: str) -> str:
    """Delete every row in a table."""
    executed.append("delete_records")
    return f"deleted {table}"


agent = Agent(name="scenario-agent", tools=[search, delete_records])
secure = wrap_agent(agent, "openai-agents", config)

result = await secure.invoke("Find the retention policy")
secure.terminate()
```

`invoke` is async because it calls `Runner.run`. This path needs an OpenAI API key.

Keyless check: the SDK dispatches every function tool through `FunctionTool.on_invoke_tool`. Call it directly with the JSON arguments the model would produce:

```python
import asyncio
import json

from gate.adapters import ToolExecutionBlocked

by_name = {tool.name: tool for tool in agent.tools}

allowed = asyncio.run(
    by_name["search"].on_invoke_tool(
        None, json.dumps({"query": "retention policy"})
    )
)
assert allowed == "results for retention policy"

try:
    asyncio.run(
        by_name["delete_records"].on_invoke_tool(
            None, json.dumps({"table": "users"})
        )
    )
except ToolExecutionBlocked as exc:
    assert exc.result.checks_failed == ["privilege"]

assert executed == ["search"]
```

After a direct tool call, the state phase is `OBSERVING`, not `ANSWERING`, because `SecureAgent.invoke` did not run and therefore did not call `finish_run()`. The enforcement decision is the same.

The adapter refuses hosted tools and MCP servers because their execution happens outside the Python process. See [OpenAI Agents adapter](adapters/openai-agents.md#refusals).

## CrewAI

```python
from crewai import Agent, Crew, Task
from crewai.tools import BaseTool
from pydantic import BaseModel, Field

from gate import wrap_agent


class SearchArgs(BaseModel):
    query: str = Field(description="query text")


class DeleteArgs(BaseModel):
    table: str = Field(description="table to delete from")


class SearchTool(BaseTool):
    name: str = "search"
    description: str = "Search the internal knowledge base."
    args_schema: type[BaseModel] = SearchArgs
    calls: list = Field(default_factory=list)

    def _run(self, query: str) -> str:
        self.calls.append("search")
        return f"results for {query}"


class DeleteTool(BaseTool):
    name: str = "delete_records"
    description: str = "Delete every row in a table."
    args_schema: type[BaseModel] = DeleteArgs
    calls: list = Field(default_factory=list)

    def _run(self, table: str) -> str:
        self.calls.append("delete_records")
        return f"deleted {table}"


search = SearchTool()
delete_records = DeleteTool()

agent = Agent(
    role="assistant",
    goal="answer questions",
    backstory="careful assistant",
    tools=[search, delete_records],
    verbose=False,
    allow_delegation=False,
)
task = Task(
    description="Find the retention policy.",
    expected_output="A policy summary.",
    agent=agent,
)
crew = Crew(agents=[agent], tasks=[task], verbose=False)

secure = wrap_agent(crew, "crewai", config)
result = secure.invoke({"topic": "retention"})
secure.terminate()
```

`secure.invoke` calls `crew.kickoff(inputs=...)`. The full run needs a configured CrewAI LLM.

Keyless check: CrewAI builds an OpenAI-style function table for tool dispatch. Calling that table is the same path its executor uses:

```python
from crewai.utilities.agent_utils import convert_tools_to_openai_schema

from gate.adapters import ToolExecutionBlocked

_, functions, _ = convert_tools_to_openai_schema(crew.agents[0].tools)

allowed = functions["search"](query="retention policy")
assert allowed == "results for retention policy"

try:
    functions["delete_records"](table="users")
except ToolExecutionBlocked as exc:
    assert exc.result.checks_failed == ["privilege"]

assert search.calls == ["search"]
assert delete_records.calls == []
```

`convert_tools_to_openai_schema` is a CrewAI internal helper, not a GATE API. It is used here because it is the dispatch table the framework itself builds. A direct `search.run(query="retention policy")` also reaches the guard, because `BaseTool.run` calls the guarded `_run`.

## Shared behaviour

The following are the same for all four frameworks:

- Stage order and decisions: privilege, DFA, contracts, semantic firewall, D-CBF.
- `approval_queue=` on every `wrap_agent` call for handling `ESCALATE`.
- Contract lookup by exact tool name, registered on `secure.monitor.contract_registry`.
- `ToolExecutionBlocked` carries the same `ValidationResult` fields.
- `secure.get_state()` exposes the same `AgentState`.
- `secure.terminate()` closes the monitor event loop.

Differences that matter in a scenario:

- Input shape: messages for LangGraph, a string or messages for LangChain, a string for OpenAI Agents, a dict for CrewAI.
- OpenAI Agents `invoke` is async and has no synchronous form.
- Explicit `tools=` is accepted only by the LangChain and LangGraph adapters.
- Discovery gaps differ by framework; check the adapter page before assuming a tool is guarded.

## Verified output

The keyless drivers above were run on 2026-10-25 against the framework versions in [Installation](installation.md#framework-versions). Each produced the same decision, condensed here:

```text
LangGraph:      allowed='results for retention policy'  blocked=ToolExecutionBlocked  checks=['privilege']  executed=['search']
LangChain:      allowed='results for retention policy'  blocked=ToolExecutionBlocked  checks=['privilege']  executed=['search']
OpenAI Agents:  allowed='results for retention policy'  blocked=ToolExecutionBlocked  checks=['privilege']  executed=['search']
CrewAI:         allowed='results for retention policy'  blocked=ToolExecutionBlocked  checks=['privilege']  executed=['search']
```

`executed=['search']` means only the allowed tool body ran. The forbidden body was never called.

The repository test suite exercises these paths in `tests/test_framework_adapters.py`. The adapter pages document the framework-specific details and limitations.

## Related pages

- [Adapters overview](adapters/README.md)
- [LangGraph](adapters/langgraph.md)
- [LangChain](adapters/langchain.md)
- [OpenAI Agents SDK](adapters/openai-agents.md)
- [CrewAI](adapters/crewai.md)
- [Quick start](quickstart.md)
- [Configuration](configuration.md)
