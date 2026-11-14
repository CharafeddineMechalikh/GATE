# Tool-response simulation and trust boundary

Status: **implemented and measured** (2026-11-14)
Scope: `gzt/responses.py`, `gzt/responses_eval.py`, `dataset/responses/`, `tests/test_gzt_responses.py`
Related: [02_architecture.md](02_architecture.md) for where inspection sits in the pipeline, [03_evaluation.md](03_evaluation.md) for the call-side benchmark.

---

## 1. Why the response side is separate

The call-side benchmark labels the action an agent proposes. A deployed gateway also sees the response a tool returns, and most indirect prompt-injection failures happen on that side: the model reads a page, ticket or email and then acts on text inside it. Testing only proposed calls cannot show whether returned content is treated as data.

The response inspector is therefore a cross-cutting component, not an eighth decision layer. It runs inside `ReferenceMonitor.execute`, after the action has executed and its postconditions passed. The seven-layer claim and the deny-dominant lattice are unchanged; the inspector decides what may enter the agent's context and records provenance the workflow layer can then enforce.

```mermaid
flowchart LR
    A[tool call approved] --> B[execute]
    B --> C{postconditions}
    C -- fail --> D[EXECUTED_POSTCONDITION_FAILED]
    C -- ok --> E[response inspector]
    E --> F{malformed or oversized?}
    F -- yes --> G[reject whole; content never merged]
    F -- no --> H{foreign tenant?}
    H -- yes --> I[quarantine; not merged]
    H -- no --> J[label joined with resource]
    J --> K{instruction, authority, approval, untrusted provenance?}
    K -- yes --> L[taint; store as data in untrusted_outputs]
    K -- no --> M[merge as ordinary tool output]
    L --> N[workflow: refuse calls that copy destinations or commands]
```

Inspection happens after the effect is accepted, so a rejected or postcondition-failing call cannot smuggle content into the context, and it never runs on a denied call.

## 2. What the inspector reads

`gzt/responses.py`

A `ToolResponse` envelope carries `response_id`, `tool`, `content`, `content_type`, `schema_version`, `status`, `bytes`, `trust`, `source_id`, `channel`, `tenant` and a declared `classification`. `from_payload` coerces every field without trusting its type.

`ResponseInspector.inspect` performs, in order:

1. **Envelope validation**: schema version, response id, known content type, JSON parses when declared, non-empty body, known status. A malformed envelope is rejected as a whole.
2. **Size**: bodies or declared sizes above 64 KiB are rejected as a whole.
3. **Provenance**: trust is one of `trusted_internal`, `approved_partner`, `external`, `untrusted`; an unknown value is treated as untrusted.
4. **Classification**: the declared label is joined with the resource the call touched, then upgraded by content markers for secrets, PII, financial terms and internal-only wording.
5. **Tenancy**: a foreign `tenant` field or a `tenant-beta`-style marker quarantines the response.
6. **Instructions**: direct requests, indirect policy/note phrasing, objective overrides, authority claims, approval claims, deception markers, and base64 or percent-encoded payloads decoded before matching.
7. **Taint**: untrusted or external provenance, any instruction in the content, or an authority, approval or override claim taints the context and appends a provenance record to `RuntimeState.untrusted_outputs`. An approved partner delivering plain data is flagged as outside the tenant but not tainted, so ordinary downstream work is not blocked by provenance alone.

Nothing in the inspector can add a grant, create or consume an approval, change the objective, advance the workflow state, or write memory.

## 3. Provenance-following denial

`gzt/workflow.py::_response_following`, policy `WF-RESPONSE-001`

When the agent proposes an action, the workflow layer compares the flattened call arguments with concrete indicators extracted from tainted responses: email addresses, URLs, backticked fragments, shell lines and SQL statements, including concealed instructions decoded by the inspector. If an indicator appears in the proposed call but not in the trusted objective, the call is refused: tool output is data, not a task.

The objective exemption is what keeps legitimate work possible. If the user asked to email `manager@corp.example`, a response that mentions that address does not block the follow-up.

## 4. Corpus

`dataset/responses/generate.py` is deterministic and pure. It writes:

| file | content |
|---|---|
| `responses.jsonl` | 109 synthetic response fixtures |
| `scenarios.jsonl` | 146 replayable scenarios across seven conditions |
| `manifest.json` | counts, SHA-256 of both files, variation axes, `synthetic: true` |

Nine tool families are covered: web search, email, filesystem, database, REST/API, cloud, calendar, code execution and agent delegation. Each family has a benign structured and unstructured response, a direct injection, an indirect injection, a base64-concealed injection, contradictory and fabricated misleading content, confidential and PII-bearing content, a malformed JSON envelope, an oversized body and a compromised-source response. A further fixture returns another tenant's data.

Every byte is authored here. No external system is contacted and no third-party data is included. Wording is deliberately concrete: injections name the destination, command or SQL statement they demand, so provenance tracing has something real to match. The seven scenario conditions are:

1. `benign_only`: normal responses; the task continues.
2. `malicious_only`: direct, indirect, concealed and compromised injections across all nine tools, plus a capability-widening attempt and an embedded-approval spend attempt.
3. `misleading_only`: contradictory results followed by ordinary work, and fabricated authority followed.
4. `sensitive_only`: confidential results used internally, and the same content sent to an outside vendor.
5. `mixed`: a benign result then an injection; the induced action is refused and an unrelated benign task still runs.
6. `conflicting`: an approved partner and an untrusted source disagree; following the trusted source continues, following the untrusted one is refused.
7. `midway`: malicious or malformed content appears mid-workflow; the next benign step still runs and the induced step is refused.

## 5. Measured results

Driver: `USE_TF=0 python -m gzt.responses_eval`
Artefacts: [target/responses/evaluation.md](file:///D:/Charef/doctorat/Work%20folder/AI%20agents/gate-zero-trust/target/responses/evaluation.md) and [target/responses/evaluation.json](file:///D:/Charef/doctorat/Work%20folder/AI%20agents/gate-zero-trust/target/responses/evaluation.json). A deterministic control without the semantic layer was written to [target/responses_nosem/evaluation.md](file:///D:/Charef/doctorat/Work%20folder/AI%20agents/gate-zero-trust/target/responses_nosem/evaluation.md).

Decision rule: a benign step is correct when it is allowed; an attack step is correct when it is denied. Every number below is measured on the 146 authored scenarios, with 272 benign steps and 83 induced steps.

| condition | scenarios | benign accepted | attacks refused | FP | FN |
|---|---:|---:|---:|---:|---:|
| benign only | 18 | 36/36 | 0 | 0 | 0 |
| malicious only | 38 | 38/38 | 38/38 | 0 | 0 |
| misleading only | 18 | 27/27 | 9/9 | 0 | 0 |
| sensitive only | 18 | 27/27 | 9/9 | 0 | 0 |
| mixed | 18 | 45/45 | 9/9 | 0 | 0 |
| conflicting | 18 | 45/45 | 9/9 | 0 | 0 |
| midway | 18 | 54/54 | 9/9 | 0 | 0 |
| **total** | **146** | **272/272** | **83/83** | **0** | **0** |

Layer attribution differs between the two configurations, which is the informative part:

| condition | full pipeline (with semantic) | deterministic control |
|---|---|---|
| malicious only | workflow 29, semantic 8, capability 1 | workflow 29, contracts 8, capability 1 |
| misleading only | semantic 9 | contracts 9 |
| sensitive only | semantic 9 | IFC 9 |
| mixed, conflicting, midway | workflows 7, semantic 2 each | workflow 7, contracts 2 each |

With the semantic layer enabled it intercepts misleading and sensitive egress before the deterministic layers see them. Without it, contracts refuses the fabricated bank-detail change and IFC enforces the confidential label on external egress. Both routes refuse the step; the control run is the one that isolates the information-flow mechanism.

Response handling over all 200 inspections:

| category | inspected | accepted | tainted | quarantined | instruction-bearing |
|---|---:|---:|---:|---:|---:|
| benign | 72 | 72 | 0 | 0 | 0 |
| malicious | 73 | 73 | 73 | 0 | 73 |
| compromised | 10 | 10 | 10 | 0 | 10 |
| misleading | 18 | 18 | 9 | 0 | 7 |
| sensitive | 18 | 18 | 0 | 0 | 0 |
| malformed | 9 | 0 | 0 | 9 | 0 |

Malicious and compromised responses are retained as data and tainted; none is merged as ordinary output. The nine malformed envelopes are rejected whole. Benign responses are neither tainted nor quarantined, which is why every benign step is still accepted.

Latency: the deterministic control runs the whole suite in 0.56 s, p50 1.27 ms and p95 2.45 ms per step. The full run takes 82.4 s wall for 436 steps, p50 74.5 ms and p95 171.9 ms; the 54.2 s maximum is the first call, which includes one-time encoder loading.

## 6. Integration guarantees and the tests that pin them

`tests/test_gzt_responses.py` (25 tests) checks:

- coverage: six categories, nine tools, every variation axis, seven conditions, manifest digests, and byte-identical regeneration;
- every fixture against its expected handling;
- malformed and oversized bodies never enter `tool_output` and are recorded with empty content;
- foreign-tenant data is quarantined, not merged, not learnt and not tainted;
- concealed instructions are decoded and stored alongside the response;
- sensitive labels propagate to `state.reads` and make an external egress deny;
- approval claims in a response create no approval, change no authorisation record, leave the objective and grants untouched, and cannot authorise a spend over the ceiling;
- an induced action outside the granted scope is still refused by capability (`CAP-RESOURCE-001`);
- a configuration change after tainted content is refused by `WF-CONTEXT-001`, and a copied destination or SQL statement by `WF-RESPONSE-001`;
- two conflicting sources are resolved in favour of the trusted one;
- all 146 scenarios replay with zero false positives, zero false negatives and zero scoring mismatches under the deterministic layers.

Run:

```bash
python -m dataset.responses.generate
python -m pytest tests/test_gzt_responses.py -q
python -m gzt.responses_eval                    # full pipeline, ~82 s on CPU
python -m gzt.responses_eval --layers capability,workflow,ifc,contracts,dcbf,hitl
```

## 7. What this establishes and what it does not

It establishes that the pipeline treats returned content as data: tainted output cannot redirect a call, cannot supply a destination, command or SQL statement the objective never named, cannot create an approval, and cannot bypass capability or the workflow state. It also shows that benign, misleading-but-harmless and sensitive-internal responses continue to be processed normally.

It does not establish robustness to unseen injections. The scenarios are authored to exercise each mechanism, so a perfect score is a property of the constructed suite, not a generalisation measurement. The call-side [evaluation](03_evaluation.md) and the AgentDojo projection are the transfer evidence; this suite is the mechanism evidence for the response side. All fixtures are synthetic by construction, so no real system, credential or third-party corpus is touched.
