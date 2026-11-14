# Milestone 4 — Threat model and limitations

Status: **written** (2026-11-14)
Companion to [02_architecture.md](02_architecture.md) and [03_evaluation.md](03_evaluation.md).

---

## 1. What is being defended

An LLM-driven agent that calls tools on behalf of a tenant: filesystem, SQL and document databases, HTTP APIs, email, payments, code execution, CI, Kubernetes, cloud, memory, delegation, admin surfaces. The agent's plan is untrusted wherever it is influenced by retrieved content; the user's objective is trusted because the gateway receives it from the authenticated user channel, not from the model.

## 2. Adversary capabilities assumed

- The adversary controls tool outputs (web pages, documents, email bodies, search results, API responses) and can plant instructions there.
- The adversary can call tools with arbitrary arguments, including well-formed ones, and can sequence calls across a session.
- The adversary knows the deployed policy set (Kerckhoffs's principle for rules; only the capability signing key is secret).
- The adversary may be a compromised or manipulated agent acting with a legitimate token.
- The adversary may delegate to other agents it controls, and may attempt replay, parameter tampering, encoding and euphemism.
- The adversary may be an insider tenant trying to read or move another tenant's data.

## 3. Out of scope

- An adversary who holds the capability signing key or can mint tokens: the authority is assumed honest.
- An adversary with write access to the audit store: the hash chain is tamper-evident, not tamper-proof against wholesale rewrite plus head replacement.
- Host or hypervisor compromise, side channels, and model-weight attacks.
- Denial of service against the monitor itself, beyond the session suspension the breaker provides.
- A malicious user who is the source of the objective: the objective is the authorisation, so an objective that asks for harm is authorised harm.

## 4. Trust boundaries

| Boundary | Trusted side | Untrusted side |
|---|---|---|
| objective | authenticated user channel | everything the model generates from it |
| tool arguments | nothing until checked | the agent |
| tool outputs | nothing until labelled | the environment |
| capability token | the authority | the agent holding it |
| approvals | the human approver, bound to exact arguments | the agent requesting them |
| session state | the gateway | the agent's claims about its own state |

Every layer reads the concrete action (`tool`, `operation`, `target`, `args`); none authorises on a tool name alone.

## 5. Attack classes and the layer that is supposed to catch them

| Attack class | Primary layer | Backstops |
|---|---|---|
| operation outside the grant | capability | contracts |
| replay of a one-shot authorisation | workflow | capability (nonce in scope) |
| instruction followed from retrieved content | semantic | workflow |
| restricted data leaving to an external destination | IFC | contracts, workflow |
| destructive or out-of-scope effect | contracts | IFC, D-CBF |
| resource exhaustion, fan-out, depth | D-CBF | contracts |
| high-value or parameter-changed side effect | HITL | contracts |
| collusion between agents | workflow | capability (delegation) |

## 6. Failure behaviour

- A layer that raises is converted to DENY with `FAIL-CLOSED` evidence; the exception type and message are recorded.
- A pipeline with no verdict denies.
- An approval requirement never overrides a denial.
- A suspended session denies every call until expiry or operator reset.
- Missing tenant, unresolvable token, unknown tool or malformed arguments deny rather than default.

## 7. Known limitations, stated plainly

1. **Authored corpus, not live agents.** The evaluation replays recorded sequences. It measures the monitor, not an end-to-end agent under attack, and it cannot show what an adaptive adversary would do next.
2. **Two benign false blocks are policy costs.** Private-address HTTP (SSRF rule) and client-set server fields (mass assignment) block a benign internal-cluster read and a benign self-profile update. Relaxing either would open the corresponding attack.
3. **One attack executes.** Reading another customer's invoice at a well-formed path with no owner metadata is indistinguishable from the benign own-invoice read. Closing it needs ownership metadata in the observation, not another rule.
4. **Keyword rules still exist inside contracts.** The path, host, command and SQL predicates combine structural checks with regexes. They are argument-bound and evidence-bearing, but a sufficiently novel phrasing can slip a regex; the semantic and behavioural layers are the backstop, not a guarantee.
5. **Semantic similarity is not reasoning.** The layer is a reference-prototype score over embeddings. It does not parse instructions, and the project's other measurements show it can be moved by homoglyphs, whitespace and self-anchored intents.
6. **D-CBF predicts its own next state.** The forward model is derived from the action's arguments, not identified from a plant. A tool whose real footprint differs from its declared arguments can evade a barrier.
7. **Approvals are only as good as the arguments hash.** A change anywhere in the arguments invalidates the approval, which is intended, but two semantically equivalent calls with different surface forms will both need approval.
8. **Single-process, CPU-only latency.** 102 ms per decision is dominated by the 58 ms encoder on this hardware; the numbers are not a throughput claim for a production gateway.
9. **The audit chain protects against local edits.** An attacker who can rewrite every record and the stored head defeats it; anchoring the head in an external append-only store is the fix and is not implemented.
10. **Tenant isolation trusts the declared tenant only for narrowing.** A call that declares a foreign tenant is denied unless a sharing agreement covers it; a call that declares nothing is judged on the resource owner. A shared table with no owner metadata cannot be isolated by this layer.
