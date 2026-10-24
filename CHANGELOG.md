# Changelog

## [Unreleased]

### Added

- Extensive documentation under `docs/`: installation, quick start, architecture, enforcement plumbing, configuration, all five security stages, the four framework adapters, human-in-the-loop, audit, security model, API reference, testing, standalone utilities, and an FAQ.
- Apache-2.0 `LICENSE`.

### Changed

- `README.md` now links the documentation set and the license, and lists `docs/` in the repository layout.
- Package metadata now points at the actual repository and documentation URLs.
- The `firewall` extra no longer pins `sentence-transformers<3`, which conflicted with the base dependency and would have downgraded a verified 6.1.0 environment.

## [0.3.0] - 2026-10-24

### Added

- Real per-tool enforcement in all four framework adapters (LangChain, LangGraph, OpenAI Agents SDK, CrewAI): every live tool call is validated by `monitor.validate_action` before its body executes, with BLOCK/ESCALATE handling and contract postcondition checks through `monitor.validate_result`.
- Shared `gate/adapters/enforcement.py` providing argument marshalling, synchronous/async bridging, HITL approval routing, and in-place guards on framework tool objects.
- Framework integration suite (`tests/test_framework_adapters.py`) covering allowed and blocked paths through each framework's native dispatch mechanism.

### Changed

- `SecurityMonitor.validate_action` and the new `validate_result` are async; adapters bridge synchronous tool hooks onto a dedicated event loop per wrapped agent.
- The adapter registry forwards adapter-specific options such as `tools=` and `approval_queue=`.
- Paper adapter claims reconciled with the implemented behaviour, and the module-size table updated to 1,438 adapter lines.
- Table 1 corrected after checking each system against its primary source: only GATE is a framework wrapper; NeMo Guardrails is an LLM proxy, CaMeL a replacement interpreter, GuardAgent an external guard agent, IPIGuard an agent-loop redesign, Task Shield an in-loop check, and AGrail an external guard model. AGrail's evaluation set corrected to Mind2Web, EICU-AC, AdvWeb, EIA, and the stateful-constraint entries for Task Shield and AGrail corrected. GATE's row is now set in bold and separated from the other systems by a midrule.
- Package metadata now reports 0.3.0 consistently in `pyproject.toml` and `gate.__version__`.

### Fixed

- Invocation timeouts work on Windows without `SIGALRM`.
- Package discovery matches the lowercase `gate` package on case-sensitive filesystems.
- Verified that LangChain 1.4.7, LangGraph 1.2.17, OpenAI Agents SDK 0.6.0, CrewAI 1.15.30, and sentence-transformers 6.1.0 can coexist in one environment.
