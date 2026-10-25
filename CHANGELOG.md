# Changelog

## [1.0.0] - 2026-10-25

### Added

- Extensive documentation under `docs/`: installation, quick start, architecture, enforcement plumbing, configuration, all five security stages, the four framework adapters, human-in-the-loop, audit, security model, API reference, testing, standalone utilities, and an FAQ.
- Apache-2.0 `LICENSE`.
- `CITATION.cff` with provisional software citation metadata, and a README citation section that will be updated when the final reference is available.
- `SECURITY.md` with the supported-version table, the private advisory link, and the in-scope bypass classes.

### Changed

- Version bumped to 1.0.0 in package metadata, runtime, documentation, and citation metadata. The public API and framework keys are unchanged from 0.3.0.
- Package metadata now carries PyPI keywords, AI and security classifiers, and Changelog and Citation URLs, alongside the existing repository and documentation URLs.
- The `firewall` extra no longer pins `sentence-transformers<3`, which conflicted with the base dependency and would have downgraded a verified 6.1.0 environment.

## [0.3.0] - 2026-10-24

### Added

- Real per-tool enforcement in all four framework adapters (LangChain, LangGraph, OpenAI Agents SDK, CrewAI): every live tool call is validated by `monitor.validate_action` before its body executes, with BLOCK/ESCALATE handling and contract postcondition checks through `monitor.validate_result`.
- Shared `gate/adapters/enforcement.py` providing argument marshalling, synchronous/async bridging, HITL approval routing, and in-place guards on framework tool objects.
- Framework integration suite (`tests/test_framework_adapters.py`) covering allowed and blocked paths through each framework's native dispatch mechanism.

### Changed

- `SecurityMonitor.validate_action` and the new `validate_result` are async; adapters bridge synchronous tool hooks onto a dedicated event loop per wrapped agent.
- The adapter registry forwards adapter-specific options such as `tools=` and `approval_queue=`.
- Package metadata now reports 0.3.0 consistently in `pyproject.toml` and `gate.__version__`.

### Fixed

- Invocation timeouts work on Windows without `SIGALRM`.
- Package discovery matches the lowercase `gate` package on case-sensitive filesystems.
- Verified that LangChain 1.4.7, LangGraph 1.2.17, OpenAI Agents SDK 0.6.0, CrewAI 1.15.30, and sentence-transformers 6.1.0 can coexist in one environment.
