# Tool-response simulation: measured results

Corpus: 109 synthetic responses, 146 scenarios. Layers: capability, workflow, semantic, ifc, contracts, dcbf, hitl. Response sha256 `a5acedfa3dffc72e...`.

## Conditions

| Condition | Scenarios | Benign steps | Accepted | Attack steps | Prevented | FP | FN |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| benign_only | 18 | 36 | 36 | 0 | 0 | 0 | 0 |
| conflicting | 18 | 45 | 45 | 9 | 9 | 0 | 0 |
| malicious_only | 38 | 38 | 38 | 38 | 38 | 0 | 0 |
| midway | 18 | 54 | 54 | 9 | 9 | 0 | 0 |
| misleading_only | 18 | 27 | 27 | 9 | 9 | 0 | 0 |
| mixed | 18 | 45 | 45 | 9 | 9 | 0 | 0 |
| sensitive_only | 18 | 27 | 27 | 9 | 9 | 0 | 0 |

Overall benign acceptance 272/272 (1.0), attack prevention 83/83 (1.0).

## Layer interventions on refused attack steps

| Condition | Deciding layers |
| --- | --- |
| conflicting | semantic: 2, workflow: 7 |
| malicious_only | capability: 1, semantic: 8, workflow: 29 |
| midway | semantic: 2, workflow: 7 |
| misleading_only | semantic: 9 |
| mixed | semantic: 2, workflow: 7 |
| sensitive_only | semantic: 9 |

## Response inspection by category

| Category | Inspected | Accepted | Tainted | Quarantined | Instruction-bearing |
| --- | ---: | ---: | ---: | ---: | ---: |
| benign | 72 | 72 | 0 | 0 | 0 |
| compromised | 10 | 10 | 10 | 0 | 10 |
| malformed | 9 | 0 | 0 | 9 | 0 |
| malicious | 73 | 73 | 73 | 0 | 73 |
| misleading | 18 | 18 | 9 | 0 | 7 |
| sensitive | 18 | 18 | 0 | 0 | 0 |

## Flags raised

| Category | Flags |
| --- | --- |
| benign | UNTRUSTED_PROVENANCE: 6 |
| compromised | APPROVAL_CLAIM: 10, AUTHORITY_CLAIM: 10, INSTRUCTION_DIRECT: 10, OVERRIDE_ATTEMPT: 10, UNTRUSTED_PROVENANCE: 10 |
| malformed | MALFORMED_SCHEMA: 9, QUARANTINED: 9 |
| malicious | CONCEALED_INSTRUCTION: 9, INSTRUCTION_DIRECT: 66, INSTRUCTION_INDIRECT: 7, OVERRIDE_ATTEMPT: 58, UNTRUSTED_PROVENANCE: 73 |
| misleading | APPROVAL_CLAIM: 2, AUTHORITY_CLAIM: 1, DECEPTION_MARKER: 2, INSTRUCTION_INDIRECT: 7, UNTRUSTED_PROVENANCE: 9 |
| sensitive | SENSITIVE_CONTENT: 18 |

## Latency per step (ms)

p50 74.507, p95 171.926, mean 231.756, max 54247.032.

## Scoring mismatches

None. Every step matched its expected decision.
