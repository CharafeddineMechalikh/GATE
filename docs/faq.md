# FAQ and common pitfalls

This page collects the questions that come up most often when running GATE against a real agent. Each answer states what the current code does, including the rough edges. For the full picture, follow the links to the relevant page.

## Getting started

### Why did `wrap_agent` guard nothing?

Each adapter guards only the tools it can discover. LangGraph raises `AdapterError` when no `ToolNode` with registered tools is found and you did not pass `tools=`, so that failure is loud. LangChain raises for non-graph agents without a `.tools` list, but a compiled graph with no `ToolNode` returns an empty list and runs unguarded. CrewAI and OpenAI Agents SDK derive tools from their agent objects; neither adapter accepts an explicit `tools=` override.

For LangChain and LangGraph, pass the tools explicitly when discovery cannot see them:

```python
secure = wrap_agent(graph, "langgraph", config, tools=[search, query])
```

Check `secure.enforcement` and the tool objects (`_gate_enforcement`) if you are unsure whether guards were installed. Details: [LangChain adapter](adapters/langchain.md#tool-resolution-order), [LangGraph adapter](adapters/langgraph.md#tool-discovery), [Adapters overview](adapters/README.md#discovery-and-refusal-rules).

### Why does the semantic stage download a model?

The semantic firewall embeds text with `sentence-transformers`. The default model is `all-MiniLM-L6-v2`, loaded on the first semantic check and cached by the library. The quick-start example enables only `privilege` and `dfa` to avoid this download. See [Installation](installation.md#the-embedding-model).

### Can I use GATE without a supported framework?

Yes. Construct `gateMonitor` and `ToolEnforcement`, guard the tool objects, call `begin_run()`, then invoke the tools. The monitor itself is framework-agnostic. What you do not get is protection for arbitrary direct function calls: only guarded tool objects pass through the monitor. See [Enforcement plumbing](enforcement.md#custom-adapters).

## Blocked calls

### How do I find out which stage blocked a call?

Catch `ToolExecutionBlocked`:

```python
from gate.adapters.enforcement import ToolExecutionBlocked

try:
    result = secure.invoke({...})
except ToolExecutionBlocked as exc:
    print(exc.tool_name)
    print(exc.details)                 # reason, checks_failed, checks_passed, stage
    print(exc.result)                  # ValidationResult, or None for early refusals
    print(exc.post_execution)          # True when the tool already ran
```

`exc.result` is `None` for refusals that happen before the monitor runs: a completed run, a DFA hop refusal, or a monitor timeout. Those carry `details["stage"]` instead. A postcondition failure sets `post_execution=True`; it does not set `stage`. See [Architecture](architecture.md#failure-semantics).

### Why is every call blocked after the first email or HTTP request?

The default D-CBF privacy barrier is terminal. Its raw value is `0.5 - 0.2 * count(send_email, http_request)`, and any raw value below `0.5` is outside the safe set. After one such call, every later tool call in the run is denied, including retries and reads.

This is a property of the default barrier, not a GATE bug. If your agent sends email or makes outbound HTTP requests, remove or replace the privacy barrier, or use a custom monitor. See [D-CBF defaults](stages/dcbf.md#what-the-defaults-do-in-practice).

### Why do all my calls escalate when I enable `semantic`?

`DefaultSemanticFirewall` ships with no harm prototypes and no safe centroids. Without them, the score reduces to `SSS = 1 / (1 + drift_to_intent)`. If no intent anchor is set, `drift_to_intent` is `0.5`, so `SSS` is about `0.67`, which sits in the escalate band `[0.5, 0.7]`.

Adapters set the anchor from the run input through `begin_run(intent)`. A manual monitor, an empty input, or a call path that bypasses the adapter can leave it unset. Populate prototypes and safe centroids if you want a risk score rather than an intent-drift check. See [Semantic firewall](stages/semantic-firewall.md#why-prototypes-matter).

### Why is a call allowed even though the tool is dangerous?

Only enabled stages run. The default config enables all five, but an explicit `enabled_checks` set replaces the default. The semantic stage scores the **proposed action text**, not the tool result, and it is not adversarially robust. D-CBF only inspects the state it can see, and the adapters do not populate embeddings or cost. GATE is a runtime guard, not an authorization boundary for every possible effect. See [Security model](security-model.md#known-gaps-and-bypasses).

### Why did the tool run when the postcondition failed?

Preconditions run before dispatch. Postconditions run after the tool body has already executed. A false or raising postcondition withholds the output and raises `ToolExecutionBlocked(post_execution=True)`, but it cannot undo an email, a database write, or a payment. Use the pre-execution stages, HITL, or an idempotency/compensation layer for effects that must be reversible. See [Smart contracts](stages/contracts.md#postconditions).

## Approvals

### What happens to an `ESCALATE` with no queue?

The call is withheld and `ToolExecutionBlocked` is raised with `stage="semantic"` and a message that no approval queue is configured. Nothing executes. To handle escalations, pass `approval_queue=` to `wrap_agent`. See [Human-in-the-loop](human-in-the-loop.md).

### Why does `secure.invoke` hang?

A synchronous invocation blocks while the approval queue waits for a human or the SLA. The default SLA is whatever the queue was constructed with, often several minutes. Approve or reject from another thread through `secure.enforcement.approve(...)` / `.reject(...)`, or asynchronously through the queue. If the call is on the monitor loop, the enforcement bridge refuses to block and raises `AdapterError`. See [Resolving a request](human-in-the-loop.md#resolving-a-request).

### Who can approve a request?

Anyone who can call `queue.approve` or reach the Slack/PagerDuty action. GATE does not authenticate approvers and does not bind a resolution to a particular request beyond its `request_id`. Treat the approval queue as a trusted system and protect access to it. See [Human-in-the-loop](human-in-the-loop.md#trust-model).

## Audit

### Why is my audit log empty?

The adapters do not attach an audit logger, and `gateConfig.audit_log_path` is unused. To record events, build `gateMonitor(config, audit_logger=audit)`, build `ToolEnforcement` yourself, and call `await audit.start()` inside a running event loop. Monitor-level events are then written; HITL decisions stay in the queue's in-memory log. See [Audit logging](audit.md#important-adapters-do-not-enable-audit).

### Why did importing `gate.audit_log` create files in the package directory?

`gate/audit_log.py` is the legacy audit logger. It generates or reads `gate/audit_key.key` at **import time** and appends to `gate/audit.log` when you call `log_execution`. Both files are git-ignored. New code should use `gate.audit.EncryptedAuditLogger` instead. See [Standalone utilities](standalone-utilities.md#legacy-audit-logger).

### Is the local KMS secure?

No. `KMSClient(backend="local")` XORs with an ephemeral in-memory key. It demonstrates the interface; it does not protect data at rest. Use the AWS KMS or Vault backend, and treat the local backend as development-only. See [Audit logging](audit.md#kms-backends).

## Configuration

### How do I disable a stage?

```python
config = gateConfig(
    agent_profile=profile,
    enabled_checks={"privilege", "contracts"},
)
```

The set replaces the default of all five stages. Unknown names are ignored. Add a test that asserts the stages you rely on are active, because a typo silently drops a check. See [Configuration](configuration.md#gateconfig-fields).

One exception: the completed-run refusal lives in `ToolEnforcement`, not in the DFA stage. After `finish_run()`, later tool calls are refused even when `dfa` is disabled. See [Enforcement plumbing](enforcement.md).

### Why is `ResourceBudget.max_cost_usd` not enforced?

The privilege stage reads a per-call cost from `action.metadata["estimated_cost"]` and compares it with `max_cost_usd`. It does not compare cumulative spend, and the adapters never set `estimated_cost`, so the value is always `0.0`. `max_tokens` and `max_execution_time_seconds` are declared but not read by the monitor. `max_steps` and `max_loops_per_phase` are enforced, by the DFA. See [Privilege](stages/privilege.md#resource-budget).

### Why did my precondition change the arguments, but the tool got the originals?

The guard marshals the framework's arguments into a `ToolCall` for validation, then calls the original tool with the original argument objects. Mutating `action.tool_args` inside a precondition or custom stage does not rewrite the call. Enforce limits; do not try to sanitize by mutation. See [Enforcement plumbing](enforcement.md#argument-marshalling).

### Why does `validate()` not run automatically?

`gateConfig.validate()` is a helper you call yourself. The adapters do not call it. It checks that `agent_id` is set, that `sss_safe_threshold > sss_block_threshold`, that `max_steps` is positive, that `timeout_seconds` is positive, and that `retry_config.max_attempts >= 1`. It does not verify that the selected stages can run in your environment. See [Configuration](configuration.md#validation).

## Timeouts and concurrency

### Why did a timed-out call keep running?

On Windows, and in non-main threads, the timeout wrapper stops waiting but cannot kill the worker thread. The secured agent marks the run aborted so no further tool calls are accepted, but the in-flight tool body continues until it returns. On POSIX main threads, `SIGALRM` interrupts the call. Do not rely on a timeout to cancel side effects. See [Enforcement plumbing](adapters/README.md#timeouts).

### Can two threads call the same secured agent?

The enforcement state is protected by an `RLock`, and HITL waits hold that lock. A second thread blocks until the first call finishes or the approval resolves. Share one secured agent across threads only if serialized execution is acceptable. Use one wrapper per concurrent run for parallel agents. See [Architecture](architecture.md#concurrency).

### Can I reuse a guarded tool in two agents?

No. A tool object can belong to only one `ToolEnforcement`. Wrapping the same object with a second enforcement raises `AdapterError`. Build separate tool instances, or share the same secured agent. See [Adapters](adapters/README.md#guard-lifetime-and-sharing).

## Multi-tenancy

### Does GATE isolate tenants automatically?

No. `TenantIsolator` is a standalone utility; the monitor does not call it. `gateConfig.tenant_id` is forwarded to HITL requests and used by the audit logger you construct, but it does not set a tenant context or partition tool access. You must establish the tenant at your request boundary and pass tenant-scoped resources yourself. See [Standalone utilities](standalone-utilities.md#tenant-isolation).

## Compatibility

### Which Python and framework versions are supported?

Python 3.9 or newer. The integration suite is verified with LangChain 1.4.7, LangGraph 1.2.17, OpenAI Agents SDK 0.6.0, CrewAI 1.15.30, and sentence-transformers 6.1.0. Older versions allowed by the extras may work but are not exercised. See [Installation](installation.md#framework-versions).

### Why do the tests emit warnings?

The suite passes with warnings from upstream libraries (deprecations and un-awaited coroutine notices). Warning count is not a failure criterion. Run the tests with the project virtual environment so all framework extras are importable. See [Testing](testing.md).

### Why are the paper, benchmarks, and GUI not in this repository?

This repository distributes the runtime framework, its adapters, and their tests. The evaluation harness, benchmark data, and manuscript are maintained separately. See [Scope](README.md#scope-of-this-repository).

### Is GATE production-ready?

It is beta software at 0.3.0. The adapter dispatch paths are tested against real framework objects, but the semantic stage and D-CBF are best-effort signals, not a substitute for application authorization. Read [Security model](security-model.md) before putting GATE in a production path.

## Licensing

### Can I use GATE in a commercial product?

Yes. GATE is licensed under Apache-2.0, which permits commercial use, modification, and redistribution, provided you retain the license and notices and state significant changes. The license also includes a patent grant. See [LICENSE](../LICENSE). This answer is a summary, not legal advice; read the license text.

### Can I publish a modified version?

Yes, under the terms of Apache-2.0. Keep the `LICENSE` and `NOTICE` files (if present), mark modified files, and do not use the project's trademarks in a way that suggests endorsement.
