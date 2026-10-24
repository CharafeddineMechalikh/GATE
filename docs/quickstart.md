# Quick start

This page wraps a compiled LangGraph and shows what happens on each decision. The same pattern applies to the other frameworks; only the object passed to `wrap_agent` and the framework key change.

## A guarded LangGraph

```python
from langchain_core.tools import tool
from langgraph.graph import END, START, StateGraph
from langgraph.prebuilt import ToolNode

from gate import AgentProfile, ResourceBudget, gateConfig, wrap_agent


@tool
def search(query: str) -> str:
    """Search the internal knowledge base."""
    return f"results for {query}"


@tool
def delete_records(table: str) -> str:
    """Delete every row in a table."""
    return f"deleted {table}"


builder = StateGraph(dict)
builder.add_node("tools", ToolNode([search, delete_records]))
builder.add_edge(START, "tools")
builder.add_edge("tools", END)
graph = builder.compile()

config = gateConfig(
    agent_profile=AgentProfile(
        agent_id="research-agent",
        role="analyst",
        allowed_tools={"search"},
        resource_budget=ResourceBudget(max_steps=20, max_loops_per_phase=5),
    ),
    enabled_checks={"privilege", "dfa"},
)

secure = wrap_agent(graph, "langgraph", config)
```

The example enables only the deterministic stages so it runs without downloading an embedding model. `search` is allowed, `delete_records` is not on the allow-list.

## What a blocked call looks like

When the model asks for a forbidden tool, the framework's dispatch reaches the guard, the monitor denies the call, and the tool body never runs:

```python
from gate.adapters import ToolExecutionBlocked

try:
    secure.invoke({"messages": [ai_message_with_tool_call("delete_records", {"table": "users"})]})
except ToolExecutionBlocked as exc:
    print(exc.tool_name)                 # delete_records
    print(exc.result.checks_failed)      # ['privilege']
    print(exc.result.reason)             # Privilege violation: ...
    print(exc.post_execution)            # False
```

`ToolExecutionBlocked` extends `SecurityViolation` and carries the monitor's `ValidationResult` in `.result`. How the surrounding framework reacts depends on the framework: LangGraph and LangChain let the exception propagate through `invoke`, while a host application may catch it and report the refusal to the model.

The tool history stays empty because the call never executed:

```python
assert secure.get_state().tool_history == []
```

## Inspecting an allowed call

```python
result = secure.invoke({"messages": [ai_message_with_tool_call("search", {"query": "retention policy"})]})
state = secure.get_state()

print(state.current_phase)               # ANSWERING after invoke returns
print([call.tool_name for call in state.tool_history])   # ['search']
print(state.step_count)                  # 1
```

After `invoke` finishes, `finish_run()` moves the run to `ANSWERING`. A tool call attempted after that point is refused by the DFA guard even if its privilege check would pass.

## Enabling the semantic stage

The default `gateConfig` enables all five stages. The semantic firewall needs harm prototypes and safe centroids before its score is meaningful; without them, one of its three drift terms is a constant and the score mostly reflects drift from the run's intent anchor.

```python
config = gateConfig(
    agent_profile=profile,
    enabled_checks={"privilege", "dfa", "contracts", "semantic", "dcbf"},
    vector_store_path="gate-vectors",   # directory containing the .npy prototypes
)
```

Populate the vector store before constructing the monitor, or attach prototypes to the firewall after construction. The full procedure and the exact scoring formula are in [Semantic firewall](stages/semantic-firewall.md).

The D-CBF stage has its own defaults. In particular, the default privacy barrier turns negative after the first `send_email` or `http_request` call and then blocks subsequent actions. Read [D-CBF monitor](stages/dcbf.md) before enabling it on a tool set that sends mail or makes outbound requests.

## Adding a contract

Contracts are looked up by exact tool name. A contract applies to any tool with that name, regardless of framework.

```python
from gate.security.smart_contracts import BaseSmartContract, postcondition


class SearchOutputContract(BaseSmartContract):
    @postcondition
    def output_is_text(self, action, result, state):
        return isinstance(result, str)


secure.monitor.contract_registry.register_contract("search", SearchOutputContract())
```

With the `contracts` check enabled, a postcondition runs after the tool body and can withhold the output from the agent. It cannot undo the side effect. See [Smart contracts](stages/contracts.md).

## Routing an escalation to a human

An `ESCALATE` decision is not a refusal yet. The call is withheld until a human resolves it. Pass an approval queue to `wrap_agent`:

```python
from gate.security.hitl_queue import HumanApprovalQueue, SlackNotificationChannel

queue = HumanApprovalQueue(
    notification_channels=[
        SlackNotificationChannel("https://hooks.slack.com/services/...", "#agent-approvals")
    ],
    default_sla_seconds=300,
)

secure = wrap_agent(graph, "langgraph", config, approval_queue=queue)
```

The approval blocks the tool call until someone resolves the request. A separate thread can resolve it:

```python
import threading
import time


def approver():
    while True:
        pending = queue.get_pending_requests()
        if pending:
            secure.enforcement.approve(pending[0].request_id, "alice", "looks fine")
            return
        time.sleep(0.1)


threading.Thread(target=approver, daemon=True).start()
result = secure.invoke({"messages": [...]})
```

If no queue is configured, an escalated call is refused with `ToolExecutionBlocked` and the reason "no human approval queue is configured". If the queue is full, the SLA expires, or the approver rejects the request, the call is denied. See [Human-in-the-loop](human-in-the-loop.md).

## Other frameworks

```python
# LangChain AgentExecutor or compiled agent graph
secure = wrap_agent(agent, "langchain", config)
result = secure.invoke("Summarise the report")

# OpenAI Agents SDK
secure = wrap_agent(agent, "openai-agents", config)
result = await secure.invoke("Summarise the report")   # async only

# CrewAI
secure = wrap_agent(crew, "crewai", config)
result = secure.invoke({"topic": "retention"})
```

If a LangChain or LangGraph graph does not expose its tools through a `ToolNode` or a `.tools` attribute, pass them explicitly:

```python
secure = wrap_agent(graph, "langchain", config, tools=[search, delete_records])
```

An explicit `tools=` list is also the way to guard tools that live in a nested graph the adapter cannot see. Only guarded tools are mediated; a tool the adapter never receives runs unguarded.

## Clean up

`SecureAgent.terminate()` closes the dedicated monitor event loop and releases its thread:

```python
secure.terminate()
```

Call it when the wrapped agent is no longer needed. The event loop thread is a daemon, so process exit does not hang without it, but long-lived processes that create many wrapped agents should terminate them explicitly.

## Next steps

- [Architecture](architecture.md) explains the exact call sequence and failure semantics.
- [Configuration](configuration.md) lists which configuration fields the runtime actually reads.
- [Security model](security-model.md) states what GATE does and does not guarantee.
