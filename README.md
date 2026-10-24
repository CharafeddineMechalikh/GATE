# GATE

GATE (Agent Execution Guard with Invariant Safety) is a runtime security layer for LLM agents. It sits between an agent and its tools, validates every proposed tool call, and returns `ALLOW`, `BLOCK`, or `ESCALATE` before the tool body executes. It wraps existing agent frameworks: the agent loop and the tools stay as they are.

## Enforcement model

GATE installs a guard on the live tool objects the framework already dispatches to. For every call the guard:

1. marshals the framework's native arguments into a `ToolCall`;
2. advances the execution state machine;
3. awaits `monitor.validate_action`, which runs the enabled stages in order and short-circuits on the first failure;
4. dispatches only on `ALLOW`;
5. after execution, calls `monitor.validate_result` and withholds the output if a contract postcondition fails.

A `BLOCK` raises `ToolExecutionBlocked` with the `ValidationResult` attached. An `ESCALATE` is routed to an approval queue; with no queue configured the call is withheld. Stage errors fail closed: an unexpected exception is treated as a violation of that stage, never as a pass.

The five stages are privilege, DFA supervision, smart contracts, semantic firewall, and a discrete control barrier function (D-CBF).

## Supported frameworks

| Framework | Adapter | Framework key | Extra |
|---|---|---|---|
| LangChain | `LangChainAdapter` | `langchain` | `langchain` |
| LangGraph | `LangGraphAdapter` | `langgraph` | `langgraph` |
| OpenAI Agents SDK | `OpenAIAgentsAdapter` | `openai-agents` | `openai-agents` |
| CrewAI | `CrewAIAdapter` | `crewai` | `crewai` |

## Install

Python 3.9 or newer.

```bash
pip install -e ".[all,dev]"
```

Use one extra instead of `all` when you only need one framework. The distribution is named `GATE-security`; the import package is `gate`.

## Quick start

```python
from gate import AgentProfile, ResourceBudget, gateConfig, wrap_agent

config = gateConfig(
    agent_profile=AgentProfile(
        agent_id="research-agent",
        role="analyst",
        allowed_tools={"search"},
        resource_budget=ResourceBudget(max_steps=20, max_loops_per_phase=5),
    ),
    enabled_checks={"privilege", "dfa"},
)

# graph is a compiled LangGraph whose tools run in a ToolNode.
secure = wrap_agent(graph, "langgraph", config)
result = secure.invoke({"messages": [...]})
```

`wrap_agent` accepts a compiled LangGraph, a LangChain agent or graph, an OpenAI Agents `Agent`, or a CrewAI `Crew`. If a LangGraph or LangChain graph does not expose its tools through a `ToolNode` or `.tools`, pass them explicitly with `tools=[...]`.

The example enables only the deterministic stages so it runs without downloading an embedding model. The default configuration enables all five stages.

## Documentation

Full documentation lives in [`docs/`](docs/README.md):

- [Installation](docs/installation.md): requirements, extras, verified framework versions.
- [Quick start](docs/quickstart.md): a guarded agent, block handling, approvals.
- [Architecture](docs/architecture.md) and [Enforcement plumbing](docs/enforcement.md): how a call reaches the monitor and how guards are installed.
- [Security stages](docs/stages/privilege.md): privilege, DFA, contracts, semantic firewall, and D-CBF.
- [Framework adapters](docs/adapters/README.md): what complete mediation means for each framework.
- [Security model](docs/security-model.md): guarantees, known gaps, and deployment guidance.
- [API reference](docs/api-reference.md) and [FAQ](docs/faq.md).

## Tests

```bash
python -m pytest tests/ -q
python -m pytest tests/test_framework_adapters.py -v
```

`tests/test_framework_adapters.py` builds real framework objects and drives each framework's native dispatch path: LangGraph `ToolNode`, LangChain's compiled agent graph, OpenAI's `FunctionTool.on_invoke_tool`, and CrewAI's function-call dispatch table. No model, API key, or network access is needed.

## Layout

```
gate/
  core/       monitor, configuration, models, interfaces
  security/   privilege, DFA, contracts, semantic firewall, D-CBF
  adapters/   framework wrappers and the shared enforcement layer
  audit/      encrypted audit log
docs/         user and developer documentation
tests/        unit and framework integration tests
```

## License

Licensed under the [Apache License 2.0](LICENSE).

## Scope

This repository contains the runtime framework and its tests. The evaluation harness and the manuscript are maintained separately.
