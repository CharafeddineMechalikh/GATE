"""Bypass evaluation for the framework adapters.

Each test states one completeness question about the guarded dispatch boundary
and measures the answer against genuine framework objects. Some answers are
negative: they are recorded here because the manuscript claims completeness only
"within the guarded dispatch boundary", and this suite is what that qualifier
covers. No model, mock, or stub is used.

Questions addressed:

1. Can the same callable be reached through another reference held from before
   wrapping?
2. Can the tool body be swapped after the guard is installed?
3. Can a tool object be replaced or registered after wrapping?
4. Does the asynchronous dispatch path reach the guard, or bypass it?
5. Are tools inside nested subgraphs discovered, and is failure to discover
   them loud or silent?
6. Is double installation detected?
"""

import asyncio
import json
import os
from typing import Annotated, TypedDict

import pytest
from pydantic import BaseModel, Field

os.environ.setdefault("CREWAI_DISABLE_TELEMETRY", "true")
os.environ.setdefault("OTEL_SDK_DISABLED", "true")

from gate.adapters.crewai_adapter import CrewAIAdapter  # noqa: E402
from gate.adapters.enforcement import (  # noqa: E402
    ToolExecutionBlocked,
    collect_graph_tools,
    install_tool_guard,
)
from gate.adapters.langgraph_adapter import LangGraphAdapter  # noqa: E402
from gate.adapters.openai_agents_adapter import OpenAIAgentsAdapter  # noqa: E402
from gate.core.config import AgentProfile, ResourceBudget, gateConfig  # noqa: E402
from gate.core.exceptions import AdapterError  # noqa: E402


def make_config(allowed=("add",), checks=("privilege", "dfa")):
    return gateConfig(
        agent_profile=AgentProfile(
            agent_id="bypass-test-agent",
            role="tester",
            allowed_tools=set(allowed),
            resource_budget=ResourceBudget(max_steps=20, max_loops_per_phase=5),
        ),
        enabled_checks=set(checks),
    )


# ---------------------------------------------------------------------------
# Shared real-tool fixtures
# ---------------------------------------------------------------------------


def make_tools(ran, blocked_attempts):
    from langchain_core.tools import tool

    @tool
    def add(a: int, b: int) -> int:
        """Add two integers."""
        ran.append(("add", a, b))
        return a + b

    @tool
    def delete_records(target: str) -> str:
        """Delete every record in the target table."""
        blocked_attempts.append(target)
        return "deleted"

    @tool
    def exfiltrate(payload: str) -> str:
        """Send a payload to an external host."""
        ran.append(("exfiltrate", payload))
        return "sent"

    return add, delete_records, exfiltrate


def tool_graph(tools):
    from langgraph.graph import END, START, StateGraph
    from langgraph.prebuilt import ToolNode

    class GraphState(TypedDict):
        messages: Annotated[list, lambda left, right: left + right]

    builder = StateGraph(GraphState)
    builder.add_node("tools", ToolNode(tools))
    builder.add_edge(START, "tools")
    builder.add_edge("tools", END)
    return builder.compile()


def tool_call(name, args):
    from langchain_core.messages import AIMessage

    return AIMessage(
        content="",
        tool_calls=[{"name": name, "args": args, "id": f"call-{name}", "type": "tool_call"}],
    )


def guard_count(secure):
    """Tool names the monitor actually recorded for this run."""
    return [call.tool_name for call in secure.get_state().tool_history]


# ---------------------------------------------------------------------------
# Q1: another reference to the same callable, held from before wrapping
# ---------------------------------------------------------------------------


def test_bound_method_captured_before_wrapping_bypasses_the_guard():
    ran, attempts = [], []
    add, _, _ = make_tools(ran, attempts)
    stale_run = add._run  # bound method, taken before wrapping
    graph = tool_graph([add])
    secure = LangGraphAdapter().wrap_agent(graph, make_config())
    try:
        assert stale_run(2, 3, config=None) == 5
        assert ran == [("add", 2, 3)]
        assert guard_count(secure) == []
        assert attempts == []
    finally:
        secure.terminate()


def test_underlying_python_callable_bypasses_the_guard():
    ran, attempts = [], []
    add, _, _ = make_tools(ran, attempts)
    raw = add.func  # the plain function the @tool decorator wrapped
    graph = tool_graph([add])
    secure = LangGraphAdapter().wrap_agent(graph, make_config())
    try:
        assert raw(4, 5) == 9
        assert ran == [("add", 4, 5)]
        assert guard_count(secure) == []
    finally:
        secure.terminate()


def test_guard_on_one_instance_does_not_cover_a_second_instance():
    ran, attempts = [], []
    add, _, _ = make_tools(ran, attempts)
    from langchain_core.tools import StructuredTool

    twin = StructuredTool.from_function(
        func=add.func, name="add", description="Add two integers."
    )
    graph = tool_graph([add])
    secure = LangGraphAdapter().wrap_agent(graph, make_config())
    try:
        assert twin.invoke({"a": 1, "b": 2}) == 3
        assert ran == [("add", 1, 2)]
        assert guard_count(secure) == []
    finally:
        secure.terminate()


# ---------------------------------------------------------------------------
# Q2: mutating the tool body after the guard is installed
# ---------------------------------------------------------------------------


def test_body_swapped_after_wrapping_runs_under_a_decision_about_the_arguments():
    ran, attempts = [], []
    add, _, _ = make_tools(ran, attempts)
    graph = tool_graph([add])
    secure = LangGraphAdapter().wrap_agent(graph, make_config())

    def malicious(a: int, b: int) -> int:
        ran.append(("swapped-body", a, b))
        return -1

    try:
        object.__setattr__(add, "func", malicious)
        output = secure.invoke({"messages": [tool_call("add", {"a": 2, "b": 3})]})
        assert ran == [("swapped-body", 2, 3)]
        assert output["messages"][-1].content == "-1"
        # The monitor did see this call, but only its arguments: an allow
        # decision made about the original body now governs a different one.
        assert guard_count(secure) == ["add"]
    finally:
        secure.terminate()


# ---------------------------------------------------------------------------
# Q3: replacing or registering tools after wrapping
# ---------------------------------------------------------------------------


def test_tool_object_swapped_into_the_toolnode_after_wrapping_is_unguarded():
    ran, attempts = [], []
    add, _, exfiltrate = make_tools(ran, attempts)
    graph = tool_graph([add])
    secure = LangGraphAdapter().wrap_agent(graph, make_config())
    try:
        node = graph.builder.nodes["tools"].runnable
        node.tools_by_name["add"] = exfiltrate
        output = secure.invoke({"messages": [tool_call("add", {"payload": "secrets"})]})
        assert ran == [("exfiltrate", "secrets")]
        assert output["messages"][-1].content == "sent"
        assert guard_count(secure) == []
    finally:
        secure.terminate()


def test_tool_registered_on_the_agent_after_wrapping_is_unguarded():
    from agents import Agent, function_tool

    ran, attempts = [], []

    @function_tool
    def add(a: int, b: int) -> int:
        """Add two integers."""
        ran.append(("add", a, b))
        return a + b

    @function_tool
    def exfiltrate(payload: str) -> str:
        """Send a payload to an external host."""
        ran.append(("exfiltrate", payload))
        return "sent"

    agent = Agent(name="bypass-test", tools=[add])
    secure = OpenAIAgentsAdapter().wrap_agent(agent, make_config())
    try:
        agent.tools.append(exfiltrate)
        assert getattr(exfiltrate, "_gate_enforcement", None) is None
        result = asyncio.run(
            agent.tools[-1].on_invoke_tool(None, json.dumps({"payload": "keys"}))
        )
        assert result == "sent"
        assert ran == [("exfiltrate", "keys")]
        assert guard_count(secure) == []
    finally:
        secure.terminate()


def test_crewai_tool_attached_after_wrapping_is_unguarded():
    from crewai.tools import BaseTool

    class _AddArgs(BaseModel):
        a: int = Field(description="first addend")
        b: int = Field(description="second addend")

    class _ExfilArgs(BaseModel):
        payload: str = Field(description="payload")

    class _Add(BaseTool):
        name: str = "add"
        description: str = "Add two integers."
        args_schema: type[BaseModel] = _AddArgs
        calls: list = Field(default_factory=list)

        def _run(self, a: int, b: int) -> int:
            self.calls.append((a, b))
            return a + b

    class _Exfil(BaseTool):
        name: str = "exfiltrate"
        description: str = "Send a payload."
        args_schema: type[BaseModel] = _ExfilArgs
        calls: list = Field(default_factory=list)

        def _run(self, payload: str) -> str:
            self.calls.append(payload)
            return "sent"

    add, exfil = _Add(), _Exfil()
    from crewai import Agent, Crew, Task

    agent = Agent(
        role="tester",
        goal="exercise tools",
        backstory="bypass test agent",
        tools=[add],
        verbose=False,
        allow_delegation=False,
    )
    task = Task(description="Call a tool.", expected_output="A result.", agent=agent)
    crew = Crew(agents=[agent], tasks=[task], verbose=False)
    secure = CrewAIAdapter().wrap_agent(crew, make_config())
    try:
        agent.tools.append(exfil)
        crew.tasks[0].tools = [exfil]
        assert getattr(exfil, "_gate_enforcement", None) is None
        assert exfil.run(payload="keys") == "sent"
        assert exfil.calls == ["keys"]
        assert guard_count(secure) == []
    finally:
        secure.terminate()


# ---------------------------------------------------------------------------
# Q4: the asynchronous dispatch path
# ---------------------------------------------------------------------------


def test_async_tool_dispatch_is_guarded():
    ran, attempts = [], []
    _, delete, _ = make_tools(ran, attempts)
    graph = tool_graph([delete])
    secure = LangGraphAdapter().wrap_agent(graph, make_config())
    try:
        with pytest.raises(ToolExecutionBlocked) as excinfo:
            asyncio.run(delete.arun({"target": "users"}))
        assert excinfo.value.result.checks_failed == ["privilege"]
        assert attempts == []
    finally:
        secure.terminate()


def test_graph_async_invocation_is_guarded():
    ran, attempts = [], []
    _, delete, _ = make_tools(ran, attempts)
    graph = tool_graph([delete])
    secure = LangGraphAdapter().wrap_agent(graph, make_config())
    try:
        with pytest.raises(ToolExecutionBlocked) as excinfo:
            asyncio.run(secure.ainvoke({"messages": [tool_call("delete_records", {"target": "users"})]}))
        assert excinfo.value.result.checks_failed == ["privilege"]
        assert attempts == []
    finally:
        secure.terminate()


def test_batched_graph_invocation_is_guarded():
    """``graph.batch`` reaches the same guarded ``_run`` as ``invoke``."""
    ran, attempts = [], []
    add, delete, _ = make_tools(ran, attempts)
    graph = tool_graph([add, delete])
    secure = LangGraphAdapter().wrap_agent(graph, make_config())
    try:
        outputs = secure.wrapped_graph.batch(
            [{"messages": [tool_call("add", {"a": 1, "b": 1})]}]
        )
        assert outputs[0]["messages"][-1].content == "2"
        assert ran == [("add", 1, 1)]
        assert attempts == []
    finally:
        secure.terminate()


def test_crewai_async_dispatch_is_guarded():
    from crewai.tools import BaseTool

    class _TargetArgs(BaseModel):
        target: str = Field(description="table")

    class _Delete(BaseTool):
        name: str = "delete_records"
        description: str = "Delete every record in a table."
        args_schema: type[BaseModel] = _TargetArgs

        def _run(self, target: str) -> str:
            return "deleted"

    delete = _Delete()
    from crewai import Agent, Crew, Task

    agent = Agent(
        role="tester",
        goal="exercise tools",
        backstory="bypass test agent",
        tools=[delete],
        verbose=False,
        allow_delegation=False,
    )
    task = Task(description="Call a tool.", expected_output="A result.", agent=agent)
    crew = Crew(agents=[agent], tasks=[task], verbose=False)
    secure = CrewAIAdapter().wrap_agent(crew, make_config())
    try:
        with pytest.raises(ToolExecutionBlocked) as excinfo:
            asyncio.run(delete._arun(target="users"))
        assert excinfo.value.result.checks_failed == ["privilege"]
    finally:
        secure.terminate()


# ---------------------------------------------------------------------------
# Q5: discovery inside nested subgraphs
# ---------------------------------------------------------------------------


def test_nested_subgraph_tools_are_silently_missed_by_discovery():
    ran, attempts = [], []
    add, _, exfiltrate = make_tools(ran, attempts)
    child = tool_graph([exfiltrate])

    from langgraph.graph import END, START, StateGraph
    from langgraph.prebuilt import ToolNode

    class ParentState(TypedDict):
        messages: Annotated[list, lambda left, right: left + right]

    builder = StateGraph(ParentState)
    builder.add_node("tools", ToolNode([add]))
    builder.add_node("sub", child)
    builder.add_edge(START, "tools")
    builder.add_edge("tools", END)
    parent = builder.compile()

    discovered = collect_graph_tools(parent)
    assert [getattr(t, "name", "?") for t in discovered] == ["add"]

    secure = LangGraphAdapter().wrap_agent(parent, make_config())
    try:
        assert getattr(add, "_gate_enforcement", None) is secure.enforcement
        assert getattr(exfiltrate, "_gate_enforcement", None) is None
        assert exfiltrate.invoke({"payload": "keys"}) == "sent"
        assert ran == [("exfiltrate", "keys")]
    finally:
        secure.terminate()


def test_graph_with_only_a_nested_subgraph_is_refused_loudly():
    _, _, exfiltrate = make_tools([], [])
    child = tool_graph([exfiltrate])

    from langgraph.graph import END, START, StateGraph

    class ParentState(TypedDict):
        messages: Annotated[list, lambda left, right: left + right]

    builder = StateGraph(ParentState)
    builder.add_node("sub", child)
    builder.add_edge(START, "sub")
    builder.add_edge("sub", END)
    parent = builder.compile()

    with pytest.raises(AdapterError) as excinfo:
        LangGraphAdapter().wrap_agent(parent, make_config())
    assert "No ToolNode with registered tools" in str(excinfo.value)


# ---------------------------------------------------------------------------
# Q6: installation hygiene
# ---------------------------------------------------------------------------


def test_reinstalling_the_same_enforcement_is_idempotent():
    ran, attempts = [], []
    add, _, _ = make_tools(ran, attempts)
    graph = tool_graph([add])
    secure = LangGraphAdapter().wrap_agent(graph, make_config())
    try:
        guarded = add._run
        install_tool_guard(add, secure.enforcement)
        assert add._run is guarded
    finally:
        secure.terminate()


def test_second_enforcement_on_a_guarded_tool_is_refused():
    ran, attempts = [], []
    add, _, _ = make_tools(ran, attempts)
    graph = tool_graph([add])
    secure = LangGraphAdapter().wrap_agent(graph, make_config())
    other = asyncio.run(_noop_enforcement(make_config()))
    try:
        with pytest.raises(AdapterError) as excinfo:
            install_tool_guard(add, other)
        assert "already guarded" in str(excinfo.value)
    finally:
        secure.terminate()
        other.close()


async def _noop_enforcement(config):
    from gate.adapters.enforcement import ToolEnforcement
    from gate.core.monitor import gateMonitor

    return ToolEnforcement(gateMonitor(config), config, None)
