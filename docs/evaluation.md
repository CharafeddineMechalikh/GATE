# Empirical Evaluation and Benchmark Results

This page details the empirical evaluation of GATE conducted across the **GATE-Union** benchmark suite, comprising 1,803 test cases (1,614 attack traces across 12 distinct attack families and 189 benign traces across 4 workflow types).

The benchmark evaluates the reference monitor across five sequential layers:
1. **Privilege enforcement**
2. **DFA supervision**
3. **Smart contracts**
4. **D-CBF safety barrier**
5. **Semantic firewall**

---

## 1. Multi-Stage Layer Attribution

The reference monitor enforces defense-in-depth: upstream deterministic invariants catch structural violations in microseconds, ensuring that expensive or ambiguous calls are rejected before reaching model-based semantic scoring.

![Layer Attribution Breakdown](images/fig_layer_attribution.png)

### Key Findings:
- **Upstream Filtering:** 86.8% of structural attacks (privilege violations, unauthorized system calls, schema mutations, step exhausting loops) are neutralized by Stages 1 to 4 before invoking the semantic embedding model.
- **Microsecond Latency:** Over 70% of denied attacks terminate at Stage 1 (Privilege) and Stage 2 (DFA) in under 1.5 ms.
- **Attack Neutralization:** Only 13.2% of attacks require semantic firewall or barrier evaluation (e.g., subtle prompt injection, exfiltration disguise, and semantic goal hijacking).

---

## 2. Layer Ablation and Defense-in-Depth

To measure the necessity of each stage, we performed systematic ablation where individual stages or combinations were removed.

![Ablation Study](images/fig_ablation.png)

### Ablation Outcomes:
- **Deterministic Layers are Foundational:** Disabling privilege and contract checking causes the attack pass-through rate to jump from 0.0% to over 64%, because intent-matching alone cannot verify database schemas, argument sanitization, or permission boundaries.
- **Cascading Defeats:** When all non-semantic stages are bypassed, the semantic firewall alone admits subtle prompt injections and off-policy parameter manipulation.
- **Fail-Closed Guarantees:** No single layer is sufficient on its own. Total defense requires pairing deterministic invariants with stateful barrier constraints and intent scoring.

---

## 3. Fused Harm and Human-in-the-Loop Escalation

Calls falling into the semantic uncertainty band ($0.50 \le \text{SSS} \le 0.70$) are subjected to a fused cross-encoder Natural Language Inference (NLI) harm barrier before being routed to a human approver.

![Fused Harm Gate and Escalation](images/fig_fused_harm.png)

### Evaluation Metrics:
- **Measured Review Burden:** On the adversarial stress benchmark, only **2.7%** of requests require human review. On benign workloads, this escalation rate drops to **0.5%**.
- **Automated Rejection in the Ambiguity Band:** The fused harm gate ($h(a) \ge 0.9024$) catches severe risks directly in the uncertainty band without imposing human review overhead.
- **Fail-Closed SLA:** If an escalated request is rejected or the human queue SLA expires, the execution fails closed.

---

## 4. Adversarial Intent-Anchor Perturbation

We stress-tested the semantic stage against self-anchoring attacks (where an attacker crafts the user prompt to align with their malicious tool payload).

![Adversarial Perturbation Analysis](images/fig_adversarial.png)

### Critical Findings:
- **Isolated Semantic Vulnerability:** In isolated semantic evaluation (with Stages 1–4 bypassed), self-anchored attacks achieve a 31.1% defeat rate because $d_{\text{intent}} \approx 0$ when the attacker controls the prompt.
- **Full Pipeline Invariance:** Under the complete 5-stage pipeline, these attacks are caught upstream by deterministic contracts, D-CBF exfiltration barriers, and privilege boundaries.
- **Provable Need for Non-Semantic Defenses:** This empirical result proves that prompt filtering and semantic intent matching alone can never serve as a standalone security boundary; non-semantic invariants are strictly required.

---

## Summary of Empirical Benchmarks

| Metric | GATE Full Pipeline | Semantic-Only Baseline | No Defense |
|---|---|---|---|
| **Attack Neutralization Rate** | **100.0%** (0 / 1,614 pass) | 68.9% (31.1% bypass) | 0.0% (100% pass) |
| **Benign Auto-Allow Rate** | **97.3%** | 89.4% | 100.0% |
| **Human Review Burden (Stress)** | **2.7%** | 10.6% | 0.0% |
| **Average Decision Latency** | **1.2 ms** (deterministic stages) | 18.4 ms (model-only) | 0.0 ms |
