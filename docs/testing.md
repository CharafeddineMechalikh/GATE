# Testing

The repository ships 441 tests. The framework adapter tests build real framework objects and drive each framework's native dispatch path; they do not call a model, so they need no API key and no network access. The remaining tests are unit tests for the security stages, the enforcement plumbing, the core data models and configuration, and the standalone utilities.

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

Verified on 2026-10-25 with Python 3.12.4 and the framework versions listed in [Installation](installation.md#framework-versions), run offline (`HF_HUB_OFFLINE=1`):

```text
441 passed, 618 warnings in 292.73s
```

The warnings are deprecations from the frameworks and from dependencies, not GATE failures.

## Coverage

Measured with `pytest --cov=gate` against the same environment:

```text
TOTAL 3267 statements, 284 missed, 91% coverage
```

```bash
python -m pytest tests/ --cov=gate --cov-report=term-missing
```

The core is fully covered: the monitor decision path, the five stages, smart contracts, the D-CBF and Neural-CBF barrier math, tenant isolation, privilege enforcement, irreversibility safeguards, the encrypted audit logger, the HITL queue, the configuration and data models, the exception hierarchy, the abstract interfaces, and the standalone policy/semantic/audit utilities. The remaining ~284 uncovered statements are concentrated in the framework adapters' wrap/discovery branches that the real-dispatch tests do not reach (`crewai_adapter`, `langchain_adapter`, `langgraph_adapter`, `openai_agents_adapter`), a few optional transports and key-rotation paths in the encrypted logger, and a handful of `ImportError` guards that only fire when an optional dependency is absent.

## Test layout

| File | Tests | Covers |
|---|---:|---|
| `tests/test_framework_adapters.py` | 13 | Real LangGraph, LangChain, OpenAI Agents, and CrewAI dispatch |
| `tests/test_registry.py` | 10 | Adapter registry lookup and graceful import-skip |
| `tests/test_adapters_base.py` | 14 | Adapter base: abstract methods, timeout helpers and config |
| `tests/test_enforcement_unit.py` | 42 | Tool-enforcement lifecycle, argument marshalling, guards |
| `tests/test_monitor_unit.py` | 26 | Monitor stage orchestration and postcondition validation |
| `tests/test_smart_contracts.py` | 41 | SQL, HTTP, email, and code contracts and injection patterns |
| `tests/test_semantic_firewall_unit.py` | 19 | Semantic scoring, intent-drift, and escalation decisions |
| `tests/test_privilege_enforcer.py` | 21 | Capability tokens, tool/data-scope, and budget checks |
| `tests/test_dfa_supervisor.py` | 17 | Phase transitions, action-phase paths, and budgets |
| `tests/test_enhanced_cbf.py` | 13 | Hand-designed barriers and forward invariance |
| `tests/test_neural_cbf.py` | 20 | Experimental Neural CBF training, verification, and persistence |
| `tests/test_irreversibility.py` | 12 | Irreversible-action classification and dry-run safeguards |
| `tests/test_tenant_isolator.py` | 16 | Tenant context propagation and store/audit isolation |
| `tests/test_hitl_queue.py` | 12 | Approval queue lifecycle and SLA expiry |
| `tests/test_encrypted_logger.py` | 21 | Encrypted audit logger, KMS key handling, and rotation |
| `tests/test_circuit_breaker.py` | 16 | Circuit breaker states, fallbacks, and the decorator |
| `tests/test_retry.py` | 9 | Retry and exponential-backoff behavior |
| `tests/test_embedding.py` | 9 | Embedding model loading and caching |
| `tests/test_vector_store.py` | 11 | Vector-store indexing and cosine search |
| `tests/test_core_config_models.py` | 30 | Configuration validation, data-scope, and core data models |
| `tests/test_core_exceptions.py` | 18 | Exception hierarchy, attributes, and detail formatting |
| `tests/test_interfaces.py` | 9 | Abstract base contracts exercised through concrete subclasses |
| `tests/test_integration.py` | 5 | Privilege and data-scope decisions through the monitor |
| `tests/test_legacy_policy_engines.py` | 25 | Standalone yaml policy engine and step-budget engine |
| `tests/test_legacy_semantic_and_audit.py` | 12 | Standalone semantic firewall wrapper and encrypted logger |

Total: 441 tests.

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
