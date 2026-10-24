"""Integration tests for the framework adapters.

Every test builds genuine framework objects and drives the same dispatch entry
point the framework uses at runtime:

* LangGraph ``ToolNode`` inside a compiled ``StateGraph``
* LangChain 1.x compiled agent graph (the object ``create_agent`` returns)
* OpenAI Agents SDK ``FunctionTool.on_invoke_tool``
* CrewAI's native function-call dispatch table

A model is never involved, so no API key or network access is required; the
security path under test (GATE's guard around the tool body) is the real one.
"""

import asyncio
import json
import os
from typing import Annotated, TypedDict

import pytest
from pydantic import BaseModel, Field

from gate.adapters.crewai_adapter import CrewAIAdapter
from gate.adapters.enforcement import ToolExecutionBlocked
from gate.adapters.langchain_adapter import LangChainAdapter
from gate.adapters.langgraph_adapter import LangGraphAdapter
from gate.adapters.openai_agents_adapter import OpenAIAgentsAdapter
from gate.core.config import AgentProfile, ResourceBudget, gateConfig
from gate.security.smart_contracts import BaseSmartContract, postcondition

os.environ.setdefault("CREWAI_DISABLE_TELEMETRY", "true")
os.environ.setdefault("OTEL_SDK_DISABLED", "true")


def make_config(allowed=("add",), checks=("privilege", "dfa")):
    return gateConfig(
        agent_profile=AgentProfile(
            agent_id="adapter-test-agent",
            role="tester",
            allowed_tools=set(allowed),
            resource_budget=ResourceBudget(max_steps=20, max_loops_per_phase=5),
        ),
        enabled_checks=set(checks),
    )


# ---------------------------------------------------------------------------
# LangChain / LangGraph
# ---------------------------------------------------------------------------


def _make_langchain_tools(executed, blocked_attempts):
    from langchain_core.tools import tool

    @tool
    def add(a: int, b: int) -> int:
        """Add two integers."""
        executed.append((a, b))
        return a + b

    @tool
    def delete_records(target: str) -> str:
        """Delete every record in the target table."""
        blocked_attempts.append(target)
        return "deleted"

    return add, delete_records


def _tool_graph(tools):
    from langgraph.graph import END, START, StateGraph
    from langgraph.prebuilt import ToolNode

    class GraphState(TypedDict):
        messages: Annotated[list, lambda left, right: left + right]

    builder = StateGraph(GraphState)
    builder.add_node("tools", ToolNode(tools))
    builder.add_edge(START, "tools")
    builder.add_edge("tools", END)
    return builder.compile()


def _tool_call(name, args):
    from langchain_core.messages import AIMessage

    return AIMessage(
        content="",
        tool_calls=[{"name": name, "args": args, "id": f"call-{name}", "type": "tool_call"}],
    )


def test_langgraph_toolnode_executes_authorized_tool():
    executed, blocked = [], []
    add, delete = _make_langchain_tools(executed, blocked)
    graph = _tool_graph([add, delete])
    secure = LangGraphAdapter().wrap_agent(graph, make_config())
    try:
        output = secure.invoke({"messages": [_tool_call("add", {"a": 2, "b": 3})]})
        assert executed == [(2, 3)]
        assert output["messages"][-1].name == "add"
        assert output["messages"][-1].content == "5"
        state = secure.get_state()
        assert [call.tool_name for call in state.tool_history] == ["add"]
        assert state.step_count == 1
        assert state.current_phase == "ANSWERING"
    finally:
        secure.terminate()


def test_langgraph_toolnode_blocks_unauthorized_tool():
    executed, blocked = [], []
    add, delete = _make_langchain_tools(executed, blocked)
    graph = _tool_graph([add, delete])
    secure = LangGraphAdapter().wrap_agent(graph, make_config())
    try:
        with pytest.raises(ToolExecutionBlocked) as excinfo:
            secure.invoke({"messages": [_tool_call("delete_records", {"target": "users"})]})
        assert excinfo.value.result.checks_failed == ["privilege"]
        assert blocked == []
        assert executed == []
        assert secure.get_state().tool_history == []
    finally:
        secure.terminate()


def test_langchain_adapter_guards_explicit_tools_on_compiled_graph():
    executed, blocked = [], []
    add, delete = _make_langchain_tools(executed, blocked)
    graph = _tool_graph([add, delete])
    secure = LangChainAdapter().wrap_agent(
        graph, make_config(), tools=[add, delete]
    )
    try:
        output = secure.invoke({"messages": [_tool_call("add", {"a": 4, "b": 5})]})
        assert executed == [(4, 5)]
        assert output["messages"][-1].content == "9"
        assert [call.tool_name for call in secure.get_state().tool_history] == ["add"]
    finally:
        secure.terminate()


def test_langchain_adapter_discovers_tools_from_graph():
    executed, blocked = [], []
    add, delete = _make_langchain_tools(executed, blocked)
    graph = _tool_graph([add, delete])
    secure = LangChainAdapter().wrap_agent(graph, make_config())
    try:
        with pytest.raises(ToolExecutionBlocked) as excinfo:
            secure.invoke({"messages": [_tool_call("delete_records", {"target": "users"})]})
        assert excinfo.value.result.checks_failed == ["privilege"]
        assert blocked == []
    finally:
        secure.terminate()


class _RejectOutput(BaseSmartContract):
    @postcondition
    def output_must_be_accepted(self, action, result, state):
        return False


def test_langchain_postcondition_withholds_output():
    executed, blocked = [], []
    add, _ = _make_langchain_tools(executed, blocked)
    graph = _tool_graph([add])
    secure = LangChainAdapter().wrap_agent(
        graph, make_config(checks=("privilege", "dfa", "contracts")), tools=[add]
    )
    secure.monitor.contract_registry.register_contract("add", _RejectOutput())
    try:
        with pytest.raises(ToolExecutionBlocked) as excinfo:
            secure.invoke({"messages": [_tool_call("add", {"a": 1, "b": 2})]})
        assert excinfo.value.post_execution is True
        assert "Postcondition failed" in str(excinfo.value)
        assert executed == [(1, 2)]
        assert [call.tool_name for call in secure.get_state().tool_history] == ["add"]
    finally:
        secure.terminate()


# ---------------------------------------------------------------------------
# OpenAI Agents SDK
# ---------------------------------------------------------------------------


def _make_openai_tools(executed, blocked_attempts):
    from agents import function_tool

    @function_tool
    def add(a: int, b: int) -> int:
        """Add two integers."""
        executed.append((a, b))
        return a + b

    @function_tool
    def delete_records(target: str) -> str:
        """Delete every record in the target table."""
        blocked_attempts.append(target)
        return "deleted"

    return add, delete_records


def _invoke_openai_tool(tool, arguments):
    return asyncio.run(tool.on_invoke_tool(None, json.dumps(arguments)))


def test_openai_agents_function_tool_executes_authorized_tool():
    from agents import Agent

    executed, blocked = [], []
    add, delete = _make_openai_tools(executed, blocked)
    agent = Agent(name="adapter-test", tools=[add, delete])
    secure = OpenAIAgentsAdapter().wrap_agent(agent, make_config())
    try:
        assert _invoke_openai_tool(agent.tools[0], {"a": 2, "b": 3}) == 5
        assert executed == [(2, 3)]
        state = secure.get_state()
        assert [call.tool_name for call in state.tool_history] == ["add"]
        assert state.current_phase == "OBSERVING"
    finally:
        secure.terminate()


def test_openai_agents_function_tool_blocks_unauthorized_tool():
    from agents import Agent

    executed, blocked = [], []
    add, delete = _make_openai_tools(executed, blocked)
    agent = Agent(name="adapter-test", tools=[add, delete])
    secure = OpenAIAgentsAdapter().wrap_agent(agent, make_config())
    try:
        with pytest.raises(ToolExecutionBlocked) as excinfo:
            _invoke_openai_tool(agent.tools[1], {"target": "users"})
        assert excinfo.value.result.checks_failed == ["privilege"]
        assert blocked == []
        assert secure.get_state().tool_history == []
    finally:
        secure.terminate()


def test_openai_agents_rejects_hosted_tools():
    from agents import Agent, WebSearchTool

    agent = Agent(name="adapter-test", tools=[WebSearchTool()])
    with pytest.raises(Exception) as excinfo:
        OpenAIAgentsAdapter().wrap_agent(agent, make_config())
    assert "outside the Python process" in str(excinfo.value)


def test_openai_agents_guards_handoff_targets():
    from agents import Agent

    executed, blocked = [], []
    add, delete = _make_openai_tools(executed, blocked)
    specialist = Agent(name="specialist", tools=[delete])
    triage = Agent(name="triage", tools=[add], handoffs=[specialist])
    secure = OpenAIAgentsAdapter().wrap_agent(triage, make_config())
    try:
        with pytest.raises(ToolExecutionBlocked):
            _invoke_openai_tool(specialist.tools[0], {"target": "users"})
        assert blocked == []
    finally:
        secure.terminate()


# ---------------------------------------------------------------------------
# CrewAI
# ---------------------------------------------------------------------------


class _AddArgs(BaseModel):
    a: int = Field(description="first addend")
    b: int = Field(description="second addend")


class _DeleteArgs(BaseModel):
    target: str = Field(description="table to delete from")


from crewai.tools import BaseTool  # noqa: E402  (after env guards above)


class _AddTool(BaseTool):
    name: str = "add"
    description: str = "Add two integers."
    args_schema: type[BaseModel] = _AddArgs
    calls: list = Field(default_factory=list)

    def _run(self, a: int, b: int) -> int:
        self.calls.append((a, b))
        return a + b


class _DeleteTool(BaseTool):
    name: str = "delete_records"
    description: str = "Delete every record in a table."
    args_schema: type[BaseModel] = _DeleteArgs
    calls: list = Field(default_factory=list)

    def _run(self, target: str) -> str:
        self.calls.append(target)
        return "deleted"


def _make_crew(add, delete):
    from crewai import Agent, Crew, Task

    agent = Agent(
        role="tester",
        goal="exercise tools",
        backstory="integration test agent",
        tools=[add, delete],
        verbose=False,
        allow_delegation=False,
    )
    task = Task(
        description="Call a tool.",
        expected_output="A tool result.",
        agent=agent,
    )
    return Crew(agents=[agent], tasks=[task], verbose=False)


def _crew_dispatch_table(crew):
    from crewai.utilities.agent_utils import convert_tools_to_openai_schema

    _, functions, _ = convert_tools_to_openai_schema(crew.agents[0].tools)
    return functions


def test_crewai_native_dispatch_executes_authorized_tool():
    add, delete = _AddTool(), _DeleteTool()
    crew = _make_crew(add, delete)
    secure = CrewAIAdapter().wrap_agent(crew, make_config())
    try:
        assert _crew_dispatch_table(crew)["add"](a=2, b=3) == 5
        assert add.calls == [(2, 3)]
        state = secure.get_state()
        assert [call.tool_name for call in state.tool_history] == ["add"]
        assert state.current_phase == "OBSERVING"
    finally:
        secure.terminate()


def test_crewai_native_dispatch_blocks_unauthorized_tool():
    add, delete = _AddTool(), _DeleteTool()
    crew = _make_crew(add, delete)
    secure = CrewAIAdapter().wrap_agent(crew, make_config())
    try:
        with pytest.raises(ToolExecutionBlocked) as excinfo:
            _crew_dispatch_table(crew)["delete_records"](target="users")
        assert excinfo.value.result.checks_failed == ["privilege"]
        assert delete.calls == []
        assert secure.get_state().tool_history == []
    finally:
        secure.terminate()


def test_crewai_guards_tools_attached_to_tasks():
    add, delete = _AddTool(), _DeleteTool()
    crew = _make_crew(add, delete)
    crew.tasks[0].tools = [delete]
    secure = CrewAIAdapter().wrap_agent(crew, make_config())
    try:
        assert getattr(delete, "_gate_enforcement", None) is secure.enforcement
        with pytest.raises(ToolExecutionBlocked):
            delete.run(target="users")
        assert delete.calls == []
    finally:
        secure.terminate()


# ---------------------------------------------------------------------------
# Registry plumbing
# ---------------------------------------------------------------------------


def test_registry_forwards_adapter_options():
    from gate.adapters.registry import wrap_agent

    executed, blocked = [], []
    add, delete = _make_langchain_tools(executed, blocked)
    graph = _tool_graph([add, delete])
    secure = wrap_agent(
        graph, "langchain", make_config(), tools=[add, delete]
    )
    try:
        output = secure.invoke({"messages": [_tool_call("add", {"a": 1, "b": 1})]})
        assert output["messages"][-1].content == "2"
    finally:
        secure.terminate()
