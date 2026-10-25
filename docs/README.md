# GATE documentation

GATE (Guarded Agent Tool Execution) is a runtime security layer for LLM agents. It wraps an existing agent framework, intercepts every guarded tool call before dispatch, and returns one of three decisions:

- **ALLOW**: the call proceeds to the original tool body unchanged.
- **BLOCK**: the call is refused and `ToolExecutionBlocked` is raised instead of the tool output.
- **ESCALATE**: the call is withheld and routed to a human approval queue. With no queue configured, it remains withheld.

GATE does not replace the agent loop, the planner, or the tools. The framework keeps running its own graph or execution loop; only the dispatch boundary of the tools it owns is guarded.

## Suggested reading order

The pages below form a guided path from "what it does" to "how it is built" to "how to deploy it". Read them top to bottom. The [documentation map](#documentation-map) further down is the same set, organised by topic for reference.

1. [Installation](installation.md) — requirements, extras, verified framework versions
2. [Quick start](quickstart.md) — a minimal guarded agent, block handling, HITL, audit
3. [Framework scenarios](framework-scenarios.md) — one policy and scenario across all four frameworks
4. [Architecture](architecture.md) — components, request lifecycle, state machine, failure semantics
5. The security pipeline, in check order:
   1. [Privilege](stages/privilege.md) — tool allow-lists, data scope, budget checks
   2. [DFA supervision](stages/dfa.md) — phases, transitions, step and loop budgets
   3. [Smart contracts](stages/contracts.md) — preconditions and postconditions
   4. [Semantic firewall](stages/semantic-firewall.md) — SSS scoring, intent anchor, thresholds
   5. [D-CBF monitor](stages/dcbf.md) — barrier functions and forward invariance
6. [Enforcement plumbing](enforcement.md) — `ToolEnforcement`, guards, argument marshalling, timeouts
7. [Configuration](configuration.md) — every field and whether the runtime uses it
8. Adapters — what complete mediation means per framework:
   1. [Adapters overview](adapters/README.md)
   2. [LangChain](adapters/langchain.md)
   3. [LangGraph](adapters/langgraph.md)
   4. [OpenAI Agents SDK](adapters/openai-agents.md)
   5. [CrewAI](adapters/crewai.md)
9. [Human-in-the-loop](human-in-the-loop.md) — approval queue, channels, SLA, sync approval
10. [Audit](audit.md) — encrypted log, PII masking, KMS backends, retention
11. [Security model](security-model.md) — threat model, guarantees, known gaps
12. [Standalone utilities](standalone-utilities.md) — tenant isolation, irreversibility, circuit breaker, Neural CBF
13. [Testing](testing.md) — test layout and how to run the real-framework integration tests
14. [FAQ](faq.md) — common questions and pitfalls

## Documentation map

| Page | Contents |
|---|---|
| [Installation](installation.md) | Requirements, extras, verified framework versions, model download |
| [Quick start](quickstart.md) | A minimal guarded agent, block handling, HITL, audit |
| [Framework scenarios](framework-scenarios.md) | The same policy and scenario in all four frameworks, with keyless drivers |
| [Architecture](architecture.md) | Components, request lifecycle, state machine, concurrency, failure semantics |
| [Enforcement plumbing](enforcement.md) | `ToolEnforcement`, guards, argument marshalling, timeouts, custom adapters |
| [Privilege](stages/privilege.md) | Tool allow-lists, data scope, budget checks |
| [DFA supervision](stages/dfa.md) | Phases, transitions, step and loop budgets |
| [Smart contracts](stages/contracts.md) | Preconditions, postconditions, built-in contracts, custom contracts |
| [Semantic firewall](stages/semantic-firewall.md) | SSS scoring, intent anchor, prototypes, thresholds, limitations |
| [D-CBF monitor](stages/dcbf.md) | Barrier functions, forward invariance, defaults, limitations |
| [Configuration](configuration.md) | Every configuration field and whether the runtime uses it |
| [Adapters](adapters/README.md) | What complete mediation means per framework |
| [LangChain](adapters/langchain.md) | `AgentExecutor` and compiled agent graphs |
| [LangGraph](adapters/langgraph.md) | Compiled `StateGraph` with `ToolNode` |
| [OpenAI Agents SDK](adapters/openai-agents.md) | `Agent`, `FunctionTool`, handoffs, hosted tools |
| [CrewAI](adapters/crewai.md) | `Crew`, agent tools, task tools |
| [Human-in-the-loop](human-in-the-loop.md) | Approval queue, Slack/PagerDuty channels, SLA, sync approval |
| [Audit](audit.md) | Encrypted audit log, PII masking, KMS backends, retention |
| [Security model](security-model.md) | Threat model, guarantees, known gaps, deployment guidance |
| [API reference](api-reference.md) | Public classes, methods, models, exceptions |
| [Testing](testing.md) | Test layout, real-framework integration tests, how to run them |
| [Standalone utilities](standalone-utilities.md) | Tenant isolation, irreversibility, circuit breaker, Neural CBF |
| [FAQ](faq.md) | Common questions and pitfalls |

## At a glance

| Item | Value |
|---|---|
| Distribution name | `GATE-security` |
| Import package | `gate` |
| Version | 1.1.1 |
| Python | 3.9 or newer |
| License | [MIT](https://github.com/CharafeddineMechalikh/GATE/blob/main/LICENSE) |
| Runtime dependencies | `pydantic`, `numpy`, `faiss-cpu`, `sentence-transformers`, `tenacity` |
| Supported frameworks | LangChain, LangGraph, OpenAI Agents SDK, CrewAI |
| Decision model | Ternary: ALLOW, BLOCK, ESCALATE |

## Scope of this repository

This repository contains the runtime framework, its adapters, and their tests. The evaluation harness, benchmark data, and manuscript are maintained separately and are not part of this distribution.

## Citation

Citation details are being finalised. The [repository README](https://github.com/CharafeddineMechalikh/GATE#citation) and [`CITATION.cff`](https://github.com/CharafeddineMechalikh/GATE/blob/main/CITATION.cff) carry the current reference.

## Status

GATE is at version 1.1.1. The adapter integration tests drive real framework dispatch paths, but the semantic firewall and D-CBF stages are not a substitute for application-level authorization. Read [Security model](security-model.md) before deploying GATE in a production path. Security reports follow [`SECURITY.md`](https://github.com/CharafeddineMechalikh/GATE/blob/main/SECURITY.md).
