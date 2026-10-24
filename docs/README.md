# GATE documentation

GATE (Agent Execution Guard with Invariant Safety) is a runtime security layer for LLM agents. It wraps an existing agent framework, intercepts every guarded tool call before dispatch, and returns one of three decisions:

- **ALLOW**: the call proceeds to the original tool body unchanged.
- **BLOCK**: the call is refused and `ToolExecutionBlocked` is raised instead of the tool output.
- **ESCALATE**: the call is withheld and routed to a human approval queue. With no queue configured, it remains withheld.

GATE does not replace the agent loop, the planner, or the tools. The framework keeps running its own graph or execution loop; only the dispatch boundary of the tools it owns is guarded.

## Documentation map

| Page | Contents |
|---|---|
| [Installation](installation.md) | Requirements, extras, verified framework versions, model download |
| [Quick start](quickstart.md) | A minimal guarded agent, block handling, HITL, audit |
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
| Version | 0.3.0 |
| Python | 3.9 or newer |
| License | [Apache-2.0](../LICENSE) |
| Runtime dependencies | `pydantic`, `numpy`, `faiss-cpu`, `sentence-transformers`, `tenacity` |
| Supported frameworks | LangChain, LangGraph, OpenAI Agents SDK, CrewAI |
| Decision model | Ternary: ALLOW, BLOCK, ESCALATE |

## Scope of this repository

This repository contains the runtime framework, its adapters, and their tests. The evaluation harness, benchmark data, and manuscript are maintained separately and are not part of this distribution.

## Status

GATE is beta software at version 0.3.0. The adapter integration tests drive real framework dispatch paths, but the semantic firewall and D-CBF stages are not a substitute for application-level authorization. Read [Security model](security-model.md) before deploying GATE in a production path.
