# Milestone 1 — Repository Assessment

Status: **complete** (inspection only; no source files modified)
Scope: `gate/` runtime package, `benchmarks/`, `gate-union/`, `gate_union/`, existing datasets, tests.
Date: 2026-11-14

---

## 1. What the repository currently is

A Python runtime reference monitor ("GATE") for tool-calling agents, plus a large offline
evaluation harness that replays authored and harmonised attack corpora through it.

```
gate/                     runtime package (the thing being extended)
  core/                   config, models (ToolCall/AgentState/ValidationResult), monitor loop
  security/               the enforcement stages + supporting services
  audit/                  encrypted audit logger
  adapters/               LangChain / LangGraph / OpenAI Agents / CrewAI adapters
  utils/                  embedding model, vector store, retry
benchmarks/               attack_suite.json (200 cases) + harness.py driver
gate-union/               split corpora (calibration/dev/test), scripts, results (1.9k cases)
gate_union/               second, separate evaluation package (different output tree)
docs/                     per-stage documentation
tests/                    ~40 test modules, incl. adversarial/bypass tests
```

Runtime pipeline as implemented in `gate/core/monitor.py::validate_action`:

```
privilege -> dfa -> contracts -> dcbf -> semantic
```

Each stage is fail-fast: the first `SecurityViolation` returns `is_allowed=False` and the
remaining stages do not run. Post-execution, `validate_result` re-checks contracts against the
actual tool output and propagates taint/provenance into `AgentState`.

---

## 2. Verified capability of each existing mechanism

I read every stage implementation rather than trusting its name. Findings:

### 2.1 Privilege / capability — **partial**

`gate/security/privilege_enforcer.py`

- `CapabilityToken(agent_id, capabilities, expires_at, signature)`; `signature` is
  `f"sig-{hash((agent_id, frozenset(capabilities))) % 1000000:06d}"` — a **non-cryptographic
  identifier, not a verifiable signature**. `is_valid()` checks expiry only.
- `check_tool_permission` is a **tool-name allowlist** over `AgentProfile.allowed_tools` /
  `forbidden_tools`.
- `check_data_scope` delegates to `profile.data_scope.check_access(resource)` and is called only
  for argument values that look like `db.table` (`_looks_like_data_resource`).
- No operation-level grant (read/write/delete/send), no per-argument or per-resource-instance
  binding, no tenant claim on the token, no delegation chain, no revocation-at-use.

**Consequence:** the strongest capability property currently enforced is "this agent may call
this tool name, and may name this `db.table`". A tool that is allowed is allowed for *every*
argument value and every operation, subject only to whatever later stages catch.

### 2.2 DFA supervisor — **partial**

`gate/security/dfa_supervisor.py`

- States are the five lifecycle phases `IDLE, PLANNING, ACTING, OBSERVING, ANSWERING`.
- Enforces allowed phase transitions, `max_steps`, `max_loops_per_phase`, and that the current
  action is legal for the current phase.
- It is a **lifecycle automaton, not a task-workflow automaton**: it has no notion of the user's
  authorized plan, permits most ACTING -> ACTING sequences, and has no nonce/replay state, no
  delegation state, no approval gates, no mandatory intermediate states.

**Consequence:** "goal hijacking", "unauthorized tool-chain execution" and "action replay" as
specified in the task are **not** currently detectable by this layer.

### 2.3 Smart contracts — **partial, largely regex-based**

`gate/security/smart_contracts.py`

- `BaseSmartContract` collects `@precondition` / `@postcondition` / `@invariant` decorated
  methods and evaluates them; `ContractRegistry` maps tool name -> contract.
- Shipped contracts: SQL (destructive-keyword regex, injection-pattern regex, ssrf pattern,
  row limit, table access), HTTP (URL allowlist, private-IP block, method list), email
  (recipient allowlist, PII regex, subject length), code execution (dangerous-pattern regex,
  length), admin tool (read-only).
- Preconditions return `bool`; the caller gets no structured evidence beyond the failed stage.

**Consequence:** real enforcement exists, but the predicates are mostly **keyword/regex**, which
the task explicitly disallows as the principal detection mechanism. There is no declarative
contract language, no amount/recipient binding beyond allowlists, and postcondition verification
is limited to the same regex family.

### 2.4 D-CBF — **real, but narrow**

`gate/security/dcbf_monitor.py`

- Genuine barrier formulation: `ClassKFunction`, `BarrierFunction`, `check_transition` enforcing
  `h(next) - h(state) + kappa * h(state) >= 0`, plus `verify_forward_invariance`.
- Barriers: `_h_privacy` (read-before-egress), `_h_resource`, `_h_scope`, `_h_stability`,
  `_h_safety`.
- `_simulate_next_state` is a heuristic forward model of the agent state, not a plant model.

**Consequence:** this is the most defensible layer in the repository, but the state vector is
small (resource counters, taint flags, step counts) and the "system dynamics" are assumed rather
than identified. It is not currently responsible for frequency/budget/ concurrency limits in the
sense required by Layer 6 of the task.

### 2.5 Semantic firewall — **real, with known deficits**

`gate/security/semantic_firewall.py`

- Embeds the action string (`Call tool(k=v, ...)`) with `all-MiniLM-L6-v2`, computes
  `d_harm` (min cosine distance to 18 harm prototypes), `d_safe` (distance to a per-tool "safe
  centroid"), `d_intent` (drift from the trajectory), and `SSS = (d_harm+eps)/(d_safe+d_intent+eps)`.
- Optional NLI cross-encoder gives `contradiction`; `fused_harm = -log(SSS) + 0.5*contradiction`.
- Fixed thresholds: `sss_block_threshold`, `sss_safe_threshold`, `fused_block_threshold`.
- **Verified defects** (from this project's prior work, re-confirmed in the code):
  - `_compute_drift_to_safe_centroid` returns the literal `1.0` when the tool has no centroid;
    only `web_search` and `data_analysis` ever receive one. In the 414 scored rows of the current
    evaluation, **200 rows have `d_safe` exactly `1.000`**.
  - The harness seeds `covariance_inv = np.eye(d)`, so the "Mahalanobis" distance is unwhitened
    Euclidean; embeddings are unit-normalised, so it is monotone in cosine similarity.
  - The benign "centroids" are 5 and 3 sentences respectively, embedded as prose rather than as
    tool calls.
- Not an LLM classifier, so no prompt-injection reasoning; it is a geometric anomaly score.

**Consequence:** the semantic stage is real but is a weak, scale-dependent heuristic whose
"safe" reference is structurally incomplete.

### 2.6 Human-in-the-loop — **partial**

`gate/security/hitl_queue.py`

- `ApprovalRequest(request_id, agent_id, tenant_id, action, risk_level, dry_run_result, status,
  created_at, resolved_at, approver_id, justification, sla_timeout_seconds)`.
- `request_and_await_approval`, `approve`, `reject`, Slack/PagerDuty notifications,
  `get_pending_requests`, `get_audit_log`.

**Consequence:** approval is now bound to a canonical parameter hash
(`action_hash` over tool name and arguments). The request snapshots the `ToolCall` so the preview
a human sees cannot be altered afterwards, and `request_and_await_approval` withholds the
operation if the caller's arguments change while the request is pending. What is still missing:
approval outcomes remain in an in-process list and are not written to the audit log; a granted
approval is not a single-use token that can be replayed against a later identical call.

### 2.7 Audit, circuit breaking, tenant isolation

- `gate/audit/encrypted_logger.py`: per-tenant JSONL, PII masking, retention rotation, and a
  SHA-256 hash chain over every record (`entry_hash` includes `prev_hash`), with
  `EncryptedAuditLogger.verify_chain()` detecting edited, deleted, or reordered entries. The
  `local` KMS backend still uses `_xor_encrypt` with a locally generated key, and the chain is
  **unkeyed**: an attacker with write access to the log and the `.chain_head` sidecar can rebuild
  a consistent chain. Describe it as tamper-evident against accidental or naive edits, not as
  tamper-proof.
- `gate/security/circuit_breaker.py`: a generic availability breaker (failure threshold,
  half-open retry, fallback). It trips on *errors*, not on security violations, and does not
  suspend an agent or a delegation subtree.
- `gate/security/tenant_isolator.py`: `TenantContext`, region validation, isolated vector-store
  namespace, `prevent_cross_tenant_access(resource_tenant_id)`. Real, but not wired into the
  capability decision (no tenant claim in tokens) and not exercised by the evaluation harness.

### 2.8 Information-flow control — **absent as a layer**

There is provenance/taint *bookkeeping* (`AgentState.add_taint`, `add_segment`) and a
read-before-egress barrier in D-CBF, but **no label lattice, no classification propagation across
derived data, no source->destination authorization, no secret detection, no aggregation policy**.
Reading a confidential document, summarising it, and emailing the summary is not currently
blocked by any dedicated layer.

### 2.9 Declarative postconditions — **partial**

`validate_result` runs contract postconditions against the returned value. It is real, but
per-tool and regex-based; there is no generic state-difference verification, no rollback or
containment on postcondition failure (the output is withheld, state is not compensated), and no
notion of transaction constraints.

---

## 3. Evaluation apparatus — two divergent harnesses

This is important and was discovered during a failed delta check:

| Path | Driver | Output tree | Used by |
|---|---|---|---|
| repo `benchmarks/harness.py` | `gate-union/scripts/run_union.py` | `gate-union/results/*.jsonl` | ad-hoc reruns |
| `gate-union/results/response_inspection_v1/phase14B_environment_closure/frozen_snapshot_candidate/benchmarks/harness.py` | `gate_union/` package | `gate-union/results/response_inspection_v1/.../gate_union/` | the paper's authoritative `final_eval_union_intent_fixed` |

The two harnesses are **not interchangeable**: patching the firewall in the process launched by
`run_union.py` produced `semantic` rejections without ever calling the patched method, and the
resulting stage histogram did not match the frozen run. Any new evaluation must therefore use one
documented driver, and must assert that the intended code path actually executed (counter check),
not merely that a run completed.

Existing corpora:

- `benchmarks/attack_suite.json`: 200 cases, 9 tools, fields `id, category, profile, tool, args,
  should_pass, expected_stage, description`. Flat; no execution level, no sequences, no labels.
- `gate-union/splits/{calibration,dev,test}.jsonl`: 1895 harmonised cases with `case_id`,
  `source_dataset`, `user_intent`, `attacker_objective`, `tool_name`, `tool_arguments`,
  `execution_context{profile_spec, tenant, state}`, `expected_outcome`, `primary_layer`.
  This is the richest existing schema and the right foundation, but it is still **single-action**
  (one proposed tool call per row) and contains no compositional or contextual cases.

---

## 4. Gap analysis against the requested seven layers

| Required layer | Exists? | Actually enforced today | Main gap |
|---|---|---|---|
| 1 Capability-based AC | partial | tool-name allowlist + `db.table` scope | no operation/resource-instance/tenant/delegation binding |
| 2 FSM workflow supervision | partial | lifecycle phases, step/loop caps | no task workflow, no replay nonce, no approval states |
| 3 Semantic intent/policy | partial | embedding anomaly score + NLI contradiction | no instruction-source trust, no injection reasoning, no policy check |
| 4 Information-flow control | **no** | taint bookkeeping only | no labels, no propagation, no egress authorization |
| 5 Pre/postconditions | partial | regex contracts, post-execution check | no declarative language, no state-diff, no containment |
| 6 Runtime monitoring / D-CBF | partial | real CBF on a small state | no frequency/budget/concurrency enforcement, no emergency suspension |
| 7 Human-in-the-loop | partial | queue + approve/reject, args-hash binding | approvals not persisted to the audit log; not single-use |
| Audit | partial | encrypted JSONL + SHA-256 chain + `verify_chain` | chain is unkeyed; local XOR placeholder |
| Circuit breaker | partial | availability breaker | not wired to security violations |
| Tenant isolation | partial | contexts + namespaces | not in the authorization decision |

---

## 5. What can be reused without rewriting

Reusable as-is or with small adapters:

- `ToolCall`, `AgentState`, `ValidationResult`, `SemanticScore` models and the
  `SecurityMonitor` interface — a sound base for a structured decision object.
- `ContractRegistry` + `BaseSmartContract` decorator machinery — the *mechanism* is fine even
  though the shipped predicates are weak; new contracts can be declarative and argument-bound.
- `EnhancedDCBFMonitor` barrier machinery — extend with new barriers rather than replace.
- `TenantIsolator` contexts and region policy.
- `EncryptedAuditLogger` file handling, PII masking and rotation (but not its integrity claim).
- The 1895-case split corpora and `benchmarks/attack_suite.json` as *additional* evaluation
  material for cross-checks (not as the new benchmark, which must cover compositions and
  contexts the existing corpora lack).

## 6. What must be built

1. A dataset with execution levels, sequences, intermediate states, benign hard negatives and
   per-layer ground-truth labels (Phase 1 — this milestone's successor).
2. Argument-bound, operation-level, tenant-aware capabilities with a signed/verifiable token.
3. A task-workflow FSM with nonces (replay), bounded delegation, approval states, and recovery.
4. An information-flow layer: label lattice, propagation, source->destination policy, secrets.
5. Declarative contracts with pre/postconditions and state-difference verification.
6. Runtime budgets/frequency/concurrency limits plus security-triggered suspension.
7. Approval bound to a canonical hash of the exact operation, with enforced expiry.
8. A hash-chained audit record and a deny-dominant decision combiner.
9. One documented driver that proves which code path executed.

## 7. Design constraints adopted from this inspection

- **Deny-dominant combining**: `DENY > REQUIRE_APPROVAL > ALLOW`; approval never overrides DENY.
- **Fail closed**: missing tenant, unresolvable capability, unknown tool, malformed args, or a
  layer raising an exception all map to DENY with a reason code.
- **No name-only authorization**: every capability check consumes the concrete tool arguments.
- **Distinguish blocked vs withheld vs executed-but-failed**: `DENY`, `REQUIRE_APPROVAL`, and
  `POSTCONDITION_FAILED` are separate outcomes in the decision record.
- **Evidence, not assertions**: each layer returns `{decision, layer, policy_id, reason, evidence,
  risk, context, timestamp, correlation_id}`.
- **No reuse of the XOR "encryption" claim**; audit integrity will be a hash chain.

## 8. Open issues recorded at this milestone

- Two harnesses with divergent outputs must be reconciled or one must be deprecated in
  documentation before Phase 2 evaluation; otherwise results are not attributable.
- `gate/security/semantic_firewall.py` currently carries uncommitted working-tree changes from
  earlier analysis; Phase 2 must not silently depend on them.
- The local KMS backend is not a security boundary; this must be stated in the limitations.
