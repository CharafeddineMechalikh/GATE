# Contributing to GATE

Thanks for your interest. GATE is a runtime security layer for LLM agents, so changes are judged first on whether they preserve the decision boundary: every guarded tool call must still be validated before its body runs, and every failure must still fail closed.

## Reporting a security bypass

Do not open a public issue for a security bypass. Use GitHub's private advisory flow, described in [SECURITY.md](SECURITY.md). Include a minimal reproduction and state whether the tool call reached the GATE guard.

Bugs, feature requests, and documentation fixes are welcome as normal GitHub issues.

## Development setup

GATE targets Python 3.9 or newer.

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux / macOS: source .venv/bin/activate

pip install -e ".[all,dev]"
```

The `all` extra installs LangChain, LangGraph, the OpenAI Agents SDK, and CrewAI. The `dev` extra installs pytest, pytest-asyncio, pytest-cov, black, ruff, and mypy.

The adapter integration tests are verified against a pinned framework stack. To reproduce that exact environment, install the constraints from [.github/requirements-ci.txt](.github/requirements-ci.txt) before the test run. A plain `pip install .[all]` resolves newer framework releases than the ones the adapters hook.

## Running the tests

```bash
python -m pytest tests/ -q
```

Run the suite offline so no embedding model is downloaded during the test:

```bash
HF_HUB_OFFLINE=1 python -m pytest tests/ -q
```

Measure coverage:

```bash
python -m pytest tests/ --cov=gate --cov-report=term-missing
```

The framework adapter tests build real framework objects and drive each framework's native dispatch path (LangGraph `ToolNode`, LangChain's compiled agent graph, OpenAI's `FunctionTool.on_invoke_tool`, CrewAI's function-call table). Do not replace them with mocks: a passing mock proves only that the shadow method works, not that the framework reaches it.

## Code style

- Format with `black` (line length 100).
- Lint with `ruff`.
- Type-check with `mypy` (configured for Python 3.9).

These tools read their settings from [pyproject.toml](pyproject.toml).

## Pull requests

- Keep a pull request focused on one change.
- Describe which security stage or framework dispatch path the change touches, and which checks are affected.
- Make sure `python -m pytest tests/ -q` passes and coverage does not regress.
- Update the relevant page under [docs/](docs/README.md) when behavior changes, and add a line to [CHANGELOG.md](CHANGELOG.md) for functional changes.

## Adapters

GATE supports LangChain, LangGraph, the OpenAI Agents SDK, and CrewAI. Documentation and examples must cover all four, not a single framework. When adding or changing an adapter, add a real-dispatch test for that framework and confirm the other three still pass.

## Roadmap

The checked items ship today. The unchecked ones are directions rather than commitments, ordered by how soon they could land; each closes a gap recorded in the [security model](docs/security-model.md#known-gaps-and-bypasses). If you want to take one on, open an issue first so the design is agreed before code.

### Shipped

- [x] Fail-closed decision path: `validate_action` and `validate_result` return `ALLOW`, `BLOCK`, or `ESCALATE` before the tool body runs.
- [x] Privilege stage with capability tokens, data scopes, and the privilege enforcer.
- [x] DFA stage with phase transitions, step budgets, and loop budgets.
- [x] Contracts with preconditions and postconditions for SQL, HTTP, email, and code execution.
- [x] Semantic firewall based on embedding similarity to a prototype corpus.
- [x] Discrete control barrier function stage, plus the experimental Neural CBF.
- [x] Human-in-the-loop queue with filesystem, Slack, and PagerDuty transports.
- [x] Encrypted local audit logger.
- [x] YAML policy loading, circuit breaker, retry helper, tenant isolator, and irreversibility detector.
- [x] Real per-call enforcement in all four adapters: LangChain, LangGraph, the OpenAI Agents SDK, and CrewAI.
- [x] 441 tests at 91% coverage, run in CI on every push and pull request.

### Short term

- [ ] Warn or raise when an adapter discovers no tools, instead of wrapping the agent with no guards.
- [ ] Ship the semantic prototype corpus and document how to extend it.
- [ ] Apply the SQL row limit to the dispatched query instead of only recording it.
- [ ] Track cost cumulatively across a run rather than estimating a single call.
- [ ] Attach audit logging in the adapters and honour `gateConfig.audit_log_path`.

### Mid term

- [ ] Detect tool calls that reach the implementation outside the guard, and make discovery explicit rather than best effort.
- [ ] Replace heuristic contracts with parameterized SQL checks, structured HTTP and DNS allowlists, and code rules that survive obfuscation.
- [ ] Add an approval hook that carries verifiable approver identity instead of an unauthenticated `approver_id` string.
- [ ] Partition enforcement state, budgets, and audit data per tenant within one process.
- [ ] Promote the `llamaindex` and `gemini` extras to first-class adapters with real-dispatch tests, or remove them.

### Long term

- [ ] Define a declarative policy language with a validated schema and a documented, testable decision procedure.
- [ ] Pair the guard with process or sandbox isolation, including timeouts that actually stop the work.
- [ ] Add real KMS backends and a hash-chained local log to replace the in-memory XOR key.
- [ ] Give postconditions a first-class way to compensate for side effects they cannot roll back.
- [ ] Publish a reproducible cross-framework attack corpus with its results, including negative ones.

## License

By contributing you agree that your contributions are licensed under the [MIT License](LICENSE), the same license as the project.
