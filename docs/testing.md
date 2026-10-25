# Testing

The repository ships 59 tests. The framework adapter tests build real framework objects and drive each framework's native dispatch path; they do not call a model, so they need no API key and no network access.

## Run the suite

From the repository root, using the interpreter that has the extras installed:

```bash
# Windows
.venv/Scripts/python.exe -m pytest tests/ -q

# Linux / macOS
python -m pytest tests/ -q
```

Use `python -m pytest` rather than a bare `pytest` when multiple Python installations are present, so the test process uses the same environment as the package. Restrict collection to `tests/`: a working tree may contain benchmark or scratch directories that are not part of this repository.

Run only the adapter integration tests:

```bash
python -m pytest tests/test_framework_adapters.py -v
```

## Current result

Verified on 2026-10-25 with Python 3.12.4 and the framework versions listed in [Installation](installation.md#framework-versions):

```text
59 passed, 195 warnings in 36.89s
```

The warnings are deprecations from the frameworks and from dependencies, not GATE failures.

## Coverage

Measured with `pytest --cov=gate` against the same environment:

```text
TOTAL 3267 statements, 1390 missed, 57% coverage
```

```bash
python -m pytest tests/ --cov=gate --cov-report=term-missing
```

The uncovered majority is concentrated in modules the framework path does not reach: the optional encrypted audit logger, the HITL notification transports (Slack and PagerDuty), the embedding and vector-store utilities (the semantic stage is disabled in the adapter tests), and the standalone utilities documented in [Standalone utilities](standalone-utilities.md). The core decision path, the five stages, and all four adapters are the well-covered parts of that figure.

## Test layout

| File | Tests | Covers |
|---|---:|---|
| `tests/test_framework_adapters.py` | 13 | Real LangGraph, LangChain, OpenAI Agents, and CrewAI dispatch |
| `tests/test_smart_contracts.py` | 9 | SQL, HTTP, email, and code contracts |
| `tests/test_enhanced_cbf.py` | 13 | Hand-designed barriers and forward invariance |
| `tests/test_neural_cbf.py` | 5 | Experimental Neural CBF |
| `tests/test_circuit_breaker.py` | 8 | Circuit breaker states and transitions |
| `tests/test_dfa_supervisor.py` | 6 | Phase transitions and budgets |
| `tests/test_integration.py` | 5 | Privilege and data-scope decisions through the monitor |

## What the adapter tests actually exercise

`tests/test_framework_adapters.py` is deliberately not a mock suite. Each test builds the real framework type and calls the entry point the framework uses at runtime.

### LangGraph

A compiled `StateGraph` with a real `ToolNode`:

- an authorized call executes, returns the tool output, and is recorded in state;
- an unauthorized call raises `ToolExecutionBlocked` with `checks_failed == ["privilege"]`, and the tool body never runs;
- a failed postcondition raises with `post_execution=True` after the body ran and withholds the output.

### LangChain

A compiled agent graph, which is the object `create_agent` returns:

- explicit `tools=` guards the listed tools;
- discovery through the graph's `ToolNode` finds the same tools;
- a postcondition failure withholds the output.

### OpenAI Agents SDK

Real `FunctionTool` objects, invoked through the patched `on_invoke_tool` callback:

- an authorized tool executes;
- an unauthorized tool is refused before its body runs;
- a hosted `WebSearchTool` causes the wrap to be rejected;
- a tool on a handoff target is guarded.

### CrewAI

Real `Crew` and `BaseTool` objects, dispatched through `convert_tools_to_openai_schema`:

- an authorized tool executes;
- an unauthorized tool is refused and its body never runs;
- a tool attached only to a task is guarded.

### Registry

`wrap_agent(graph, "langchain", config, tools=[...])` forwards adapter options through the global registry and enforces the call.

## Deterministic configuration in tests

The integration tests use:

```python
gateConfig(
    agent_profile=AgentProfile(...),
    enabled_checks={"privilege", "dfa"},
)
```

or add `"contracts"` when testing postconditions. No test enables the semantic stage or D-CBF for the adapter path. That keeps the suite fast and free of model downloads. It also means the integration tests do **not** cover semantic escalation, HITL, audit logging, or D-CBF barrier behavior; those are covered by unit tests or are not covered end to end.

## Writing a new adapter test

A useful adapter test has three assertions:

1. The allowed call reaches the original tool body and its output is returned.
2. The forbidden call raises `ToolExecutionBlocked` and the original body was **not** called.
3. The wrapper state reflects the expected history (`tool_history` empty for a blocked first call).

For a new framework, drive the framework's own dispatch function, not the guarded method directly. The existing tests use `ToolNode`, the compiled graph's `invoke`, `FunctionTool.on_invoke_tool`, and CrewAI's function table for exactly this reason: calling `tool._run(...)` directly would prove only that the shadow method works, not that the framework reaches it.

Avoid sharing tool objects across tests. Guards mutate the objects and bind them to one enforcement instance; a shared object will fail the second wrap with an `AdapterError`.

## Environment notes

- The adapter tests import `typing.Annotated`, so Python 3.9 or newer is required. The suite was verified on 3.12.4.
- CrewAI telemetry is disabled in the test module with `CREWAI_DISABLE_TELEMETRY=true` and `OTEL_SDK_DISABLED=true` before the CrewAI import.
- `sentence-transformers` is imported only when a semantic firewall is constructed. The adapter suite does not construct one.
- The full suite's CBF tests use NumPy and, for Neural CBF, Torch. They run on CPU.

## Related pages

- [Installation](installation.md)
- [Adapters](adapters/README.md)
- [Security model](security-model.md)
