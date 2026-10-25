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

## License

By contributing you agree that your contributions are licensed under the [Apache License 2.0](LICENSE), the same license as the project.
