# Milestone 2 — Reference monitor architecture

Status: **implemented and evaluated** (2026-11-14)
Scope: `gzt/` package, `dataset/` generator and validator, `gzt/evaluate.py`
Related: [01_repository_assessment.md](01_repository_assessment.md) for the gap analysis this design answers, [03_evaluation.md](03_evaluation.md) for the measured results.

---

## 1. What this package is

`gzt` is an independent reimplementation of the seven enforcement layers the task specifies. It does not import the `gate/` runtime; it shares only the conceptual pipeline. Every layer returns a structured `LayerResult`, and a deny-dominant combiner produces the final decision.

```mermaid
flowchart TD
    A[Observation + RuntimeState + Action + CapabilityToken] --> B{Circuit breaker<br/>suspended?}
    B -- yes --> Z1[DENY CIRCUIT-SUSPENDED-001]
    B -- no --> C{Tenant isolation}
    C -- foreign owner --> Z2[DENY TENANT-ISOLATION-001]
    C -- ok --> D[1 capability]
    D --> E[2 workflow]
    E --> F[3 semantic]
    F --> G[4 ifc]
    G --> H[5 contracts]
    H --> I[6 dcbf]
    I --> J[7 hitl]
    D --> K{any DENY?}
    E --> K
    F --> K
    G --> K
    H --> K
    I --> K
    J --> K
    K -- yes --> Z3[stop: DENY]
    K -- no --> L{any REQUIRE_APPROVAL?}
    L -- yes --> Z4[withhold: REQUIRE_APPROVAL]
    L -- no --> M[execute action]
    M --> N[postcondition verification]
    N -- failure --> Z5[EXECUTED_POSTCONDITION_FAILED]
    N -- ok --> O[apply effects]
    O --> R[response inspector<br/>validate, label, taint]
    R --> P[hash-chained audit record]
```

Short-circuiting is at DENY only, so an approval requirement does not hide a later denial. Any exception inside a layer is converted to `DENY` with `policy_id = FAIL-CLOSED` and the exception repr as evidence.

## 2. Decision objects

`gzt/decision.py`

- `Decision`: `ALLOW < REQUIRE_APPROVAL < DENY`, combined by `max` rank. Ties go to the earliest layer, so the explanation names the first layer that decided at the winning severity.
- `LayerResult`: `decision, layer, policy_id, reason, evidence, risk, context, timestamp, correlation_id`. Evidence is free-form but always names the concrete values the decision read.
- `Outcome`: `executed`, `blocked`, `withheld`, `executed_postcondition_failed`. Blocked and withheld are separate so an escalation is never counted as an execution.
- `combine([])` returns `DENY / FAIL-CLOSED`: a pipeline that produced no opinion cannot allow.

## 3. Layer 1 — capability-based access control

`gzt/capability.py`

A token is `HMAC-SHA256(secret, canonical(subject, tenant, grants, expires_at, delegation_chain, jti))`, verified with `hmac.compare_digest` and a revocation set keyed by `jti`. A grant is:

```json
{"name": "payment_api",
 "permissions": {"allowed_operations": ["charge"],
                  "resource_scope": ["account:acct-approved"],
                  "tenant_scope": ["tenant-a"]}}
```

Checks, in order: token present, signature valid and not revoked, not expired, subject equals the acting agent, tool granted, operation in `allowed_operations`, target matched by `resource_scope` (`fnmatch` for patterns, prefix match for directory-like entries), administrative surfaces not reachable through a wildcard grant, and tenant agreement between the declared row tenant, the resource owner and the token's `tenant_scope`. Delegation depth is capped at `delegation_depth_ceiling` from the D-CBF envelope.

Nothing here is name-only: the operation and the concrete target are both consumed.

## 4. Layer 2 — workflow FSM supervision

`gzt/workflow.py`

Twelve independent detectors run against the session history; each returns a `LayerResult` or `None`:

| Detector | Policy | Property |
|---|---|---|
| replay | `WF-REPLAY-001` | a nonce already consumed in this session |
| memory directive | `WF-MEMORY-001` | a standing rule written after untrusted content was read |
| tool output follow | `WF-TOOLOUTPUT-001` | an instruction traced to a tool result, not the objective |
| tool chain | `WF-CHAIN-001`, `WF-TOOLCHAIN-001` | a read of restricted material followed by egress of derived content |
| escalation | `WF-ESCALATION-001` | privilege gained mid-session |
| context mutation | `WF-CONTEXT-001` | a control fact changed by retrieved context |
| delegation | `WF-DELEGATION-001`, `WF-DEPUTY-001`, `WF-COLLUSION-001` | delegation outside the granted subtree, depth or requester |
| persistence | `WF-PERSIST-001` | a durable hook installed for a later session |
| plan | `WF-PLAN-001` | a step outside the declared plan |
| deployment | `WF-DEPLOY-001` | a release whose scope exceeds the objective |
| scope | `WF-SCOPE-001` | an action outside the objective's declared scope |
| composition | `WF-COLLUSION-001` | two agents composing into an effect neither may produce alone |

The supervisor keeps the FSM state in `RuntimeState`, not in the layer object, so two monitors cannot share a session by accident.

## 5. Layer 3 — semantic intent and policy

`gzt/semantic.py`

Model: `sentence-transformers/all-MiniLM-L6-v2`, normalised embeddings, loaded lazily once per layer instance. Prototypes are grouped into families (identity claim, instruction source, memory, tool output, evasion, context, deception, goal), and each family's score is the best cosine similarity over its prototypes. Benign anchors give `benign_similarity`, which separates "harmful-looking" from "normal for this tool".

Rules and thresholds (`DEFAULT_THRESHOLDS`): identity claim, instruction source (with an objective-similarity gate), memory write, code from tool output, encoded payload that decodes to data movement, audit suppression, credential change caused by context, goal drift. Each rule names its threshold in the evidence so a reviewer can recompute the verdict.

The layer reads the decoded payload (`base64`, `hex`, `rot13`, `url`) before scoring, so obfuscation is scored on the plaintext as well as on the encoded string.

Shared instance: one `SemanticLayer` is passed to every monitor in an evaluation run, otherwise the encoder and prototype matrices are rebuilt per configuration (twelve model loads instead of one).

## 6. Layer 4 — information-flow control

`gzt/ifc.py`, `gzt/policies.py`

Labels: `public < internal < confidential < restricted < secret`, joined by least upper bound. Destination trust comes from `P.destination_trust`: `internal`, `approved_partner`, `external`, `untrusted`.

The effective label is the join of the session's accumulated read labels, the objective's classification for this target, and the payload's own content (secret-shaped material, HR and salary fields, session traces). Policies: tenant boundary (`IFC-TRUSTBOUNDARY-001`), egress to a partner or external domain (`IFC-EGRESS-001`), broadcast surfaces with a wider readership (`IFC-EGRESS-001`), approved-recipient lists for confidential HR data (`IFC-RECIPIENT-001`), aggregation that reconstructs restricted material (`IFC-AGG-001`), credential material (`IFC-SECRET-001`), bulk export (`IFC-EXPORT-001`), cross-user transfer (`IFC-CROSUSER-001`).

Two explicit exemptions keep benign traffic flowing: an objective that names the recipient, and an agreed audit disclosure to an address in `APPROVED_AUDIT_RECIPIENTS`. Both are narrow (exact address plus an objective regex), not a trust-the-request default.

## 7. Layer 5 — contracts with preconditions and postconditions

`gzt/contracts.py`

Per-tool contracts, dispatched by tool name, each consuming the objective (`obs`) and the session state where the decision needs them:

- filesystem: traversal before grant (`CON-FS-TRAVERSAL-001`), workspace scope (`CON-FS-SCOPE-001`), protected paths, delete and write scope;
- SQL and database: destructive keywords, injection patterns, scope predicate, row and volume limits, append-only and immutable tables;
- HTTP: scheme, host allowlist, SSRF, export endpoints, amplification and bulk;
- email: recipient allowlist and objective grounding, secret material, calendar bulk;
- payments: amount sign and ceiling, treasury, payee, duplicate charge, refund matching against a real prior charge, objective intent (a payment verb must appear in the objective);
- code execution: destructive commands, network, privilege, persistence, audit abuse, fetch-and-execute;
- CI, Kubernetes, cloud, delegation, admin, memory, analysis, web search.

Postconditions run after the tool returns, on the environment delta: the effect is checked against the contract's declared invariant, and a violation converts the outcome to `executed_postcondition_failed` and the case to `DENY` with `POSTCONDITION-001`. This is the only control that runs with every layer disabled, which is why the uncontrolled baseline still blocks four attacks.

## 8. Layer 6 — runtime behavioural monitor (D-CBF)

`gzt/dcbf.py`

For each monitored resource `i`, `h_i(s) = ceiling_i - value_i(s)` and the discrete forward-invariance condition is `h_i(s') + (kappa - 1) * h_i(s) >= 0` with `kappa = 1`, i.e. `h_i(s') >= 0`. `s'` is predicted from the session state and the action's own arguments: recipients per message, gigabytes a `dd` writes, instances a provisioning call starts, agents a spawn creates, delegation depth. Ceilings come from policy tables plus the tenant's session envelope in `initial_state`.

Barriers: authentication attempts, failures and distinct accounts within their windows; outbound request and byte budgets; mail envelope and partner quota; instance and active-agent ceilings; delegation depth; disk, CPU and memory. A barrier fires on the predicted next state, not on the current one, so a single in-envelope action never trips it.

## 9. Layer 7 — human-in-the-loop

`gzt/hitl.py`

Requirements (`REQUIRE_APPROVAL`, never `DENY`): spend above `SPEND_CEILING` on payments and provisioning, provisioning commitments, Kubernetes privileged or host-namespace changes, credential writes through code execution, admin changes.

Approval is bound to the exact parameters: `RuntimeState.matching_approval(action)` matches the stored preview's canonical hash of operation, amount and recipient, and the approval is consumed on use. A preview that matches in kind but not in amount or recipient produces `HITL-PARAM-BINDING-001` rather than a silent pass, which is the "approval of a general task must not authorise unrelated side effects" property from the gap analysis.

## 10. Cross-cutting controls

- **Audit** (`gzt/audit.py`): every step appends a record with `prev_hash` and `record_hash = SHA256(canonical(body including prev_hash))`. `verify()` walks the chain and returns the first broken index. This is tamper-evident, unlike the XOR obfuscation in the existing logger; it is not tamper-proof against an attacker who can rewrite the whole chain and the head, which is stated as a limitation.
- **Circuit breaker** (`gzt/circuit.py`): suspends the session after three consecutive denials, four denials of the same policy, or a postcondition failure. While suspended every call is denied with `CIRCUIT-SUSPENDED-001`. Thresholds are configuration, and the breaker reads only the decision stream.
- **Tenant isolation** (`gzt/monitor.py::_tenant_isolation`): runs before the layer pipeline; a call against a resource owned by another tenant is denied unless a `data_sharing_agreement` names the counterparty or the call narrows itself to the caller's own rows.

## 11. Dataset and validation

`dataset/generator/` builds the authored cases across eleven categories A–K and three execution levels. `dataset/external/` adds cases that already exist in public datasets instead of re-authoring them: `import_union.py` freezes the selected GATE-Union rows (provenance included) into `union_external.jsonl`, and `adapter.py` converts them to the case schema at build time. Imported rows carry category `X`, keep their source label, and record `source_dataset`, `source_case_id`, `source_split`, the union file digest and the licence in `provenance`. The held-out AgentDojo suite is never imported; the importer refuses to run if it finds it.

The adapter is mechanical and documented: the source's `user_intent` becomes the objective (a neutral line when the source recorded none, so the attack description never leaks into the semantic layer), the profile's `allowed_tools` and database/endpoint lists become the capability grants, the recorded session state and barrier envelope become `initial_state`, and `block`/`allow`/`escalate` map to DENY/ALLOW/REQUIRE_APPROVAL. Nothing is derived from monitor behaviour. Of the union's 1,895 rows, 985 are imported (injecagent 745, gate_original 148 after dropping 52 label conflicts, safeclawbench 92), giving 1,957 cases in total: 972 authored and 985 imported. The authored set now meets the per-category floors of 20 atomic, 15 compositional and 15 contextual scenarios for every category A to K; `dataset/out/coverage.md` reports the matrix and `dataset/validate.py` enforces the floors.

`dataset/validate.py` runs eighteen structural, coverage and separation checks (schema, unique ids, sequence/level consistency, label presence, layer validity, state deltas, benign/attack pairing, per-category coverage floors, subcategory spread, record metadata, attack/benign separation, reproducibility and manifest drift); `dataset/out/validation.md` records the result of each and `dataset/out/coverage.*` the matrix. Imported rows are checked against their own family codes rather than the authored A–K subtypes, and the duplicate detector treats distinct source cases as distinct even when they reuse a payload.

The generator is part of the evidence, not a fixture: five templates and three workflow specs were corrected during integration (see D27 in the decision log) because they asserted a delegation authority or a created row that the recorded sequence never established.

## 12. Tool-response inspection

`gzt/responses.py`, enforced through `gzt/monitor.py::execute` and `gzt/workflow.py::_response_following`

The pipeline approves calls; the inspector handles what a tool returns. It is cross-cutting rather than an eighth layer: it runs after an executed call passes postcondition verification, validates the envelope, joins the declared classification with the resource the call touched, quarantines foreign-tenant and malformed bodies, decodes concealed instructions, and taints any content that carries an instruction, an authority or approval claim, or provenance below the tenant. Accepted content is retained as data; nothing in the inspector can add a grant, create an approval, change the objective or advance the workflow state.

Tainted responses are appended to `RuntimeState.untrusted_outputs`. Before a later action is approved, the workflow layer compares its arguments with destinations, commands, URLs and SQL statements found in that output and refuses an action that copies one the trusted objective never named (`WF-RESPONSE-001`). Full design, corpus and measured results are in [05_tool_responses.md](05_tool_responses.md).

## 13. Evaluation harness

`gzt/evaluate.py`

The harness replays each case's recorded sequence through the real pipeline. Ground-truth fields are read only to score, never to decide. The environment advances only when a step executes, using the observation a deployed gateway would see.

- **Containment**: a case is contained when the pipeline stops with DENY or REQUIRE_APPROVAL at or before the violating step. Stopping earlier than the authored layer is an *early block* (reported, not penalised). Only a blocked benign case is a false positive.
- **Configurations**: allow-all, capability only, capability plus contracts, capability plus IFC and contracts, full pipeline.
- **Ablations**: full pipeline with one layer removed, one run per layer.
- **Metrics**: TP/FP/TN/FN, precision, recall, F1, accuracy, exact-decision agreement, hard containment (DENY rather than withheld), layer attribution, early and late blocks, all with Wilson 95% intervals; recall and F1 also get a seeded bootstrap over cases.
- **Latency**: wall clock per case and per decision, plus per-layer `check` timing on the full pass. Layer timing calls `check` a second time, so it measures the layer in isolation rather than the exact share of the pipeline; the harness states this.
- **Memory**: process RSS, resident growth across a 60-case sample, and `tracemalloc` peak.
- **Failures**: every false negative, false positive, early block, late block and escalation-not-denial, with the layer and policy that decided.

Reports are written to `target/evaluation.json` and `target/evaluation.md`.

## 14. Reproducing

```bash
cd gate-zero-trust
python -m dataset.generator.build            # rebuild dataset/out/
python dataset/validate.py                   # eighteen checks
python -m dataset.responses.generate         # response corpus (109 fixtures, 146 scenarios)
python -m gzt.responses_eval                 # response-side experiment
python -m pytest tests/test_gzt_responses.py -q
USE_TF=0 USE_TORCH=1 python -m gzt.evaluate \
    --dataset dataset/out/dataset.jsonl --out target
```

`USE_TF=0` keeps TensorFlow out of the import path so the encoder loads through PyTorch only. The run is CPU-only and single-process; the semantic encoder dominates wall clock.
