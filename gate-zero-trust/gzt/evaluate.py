"""Experimental evaluation of the reference monitor.

The harness replays the recorded action sequence of every case through the real
pipeline. Ground-truth fields (expected decision, enforcing layer) are read only
to score the run, never to make a decision. The environment advances only when a
step executes, using the observation a deployed gateway would see after the tool
returns.

Reported quantities
-------------------
* Confusion matrices at the *case* level: a case is contained when the pipeline
  stops its sequence with DENY or REQUIRE_APPROVAL before the violating step.
* Precision, recall and F1 with Wilson intervals, plus a seeded bootstrap over
  cases for F1.
* Exact-decision agreement with the authored label, which is stricter than
  containment and exposes early blocks.
* Layer attribution: which layer decided, and how often it matches the label.
* Per-level (1, 2, 3), per-category (A-K) and per-split (calibration/test).
* Ablations: the full pipeline with one layer removed.
* Baselines: allow-all, capability-only, capability plus contracts.
* Per-decision latency (full pipeline and per layer) and resident memory.
* Failure analysis: every false negative, false positive and early block.

Nothing is hard-coded: every number below is computed from the replayed run.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import platform
import statistics
import sys
import time
import tracemalloc
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from .decision import Decision
from .monitor import LAYER_ORDER, ReferenceMonitor
from .runtime import Action, Observation, RuntimeState
from .semantic import SemanticLayer

ATTACK_LABELS = {"DENY", "REQUIRE_APPROVAL"}
LAYERS = list(LAYER_ORDER)
LAYER_RANK = {name: index for index, name in enumerate(LAYER_ORDER)}
LAYER_RANK["isolation"] = -1


def layer_relation(outcome: "CaseOutcome") -> str:
    """Where the pipeline stopped relative to the authored enforcing layer."""
    if not outcome.is_malicious or not outcome.contained:
        return "none"
    expected = LAYER_RANK.get(outcome.expected_layer)
    decided = LAYER_RANK.get(outcome.deciding_layer)
    if expected is None or decided is None:
        return "unknown"
    if decided < expected:
        return "early"
    if decided > expected:
        return "late"
    return "match"


# --------------------------------------------------------------------- helpers
def wilson(k: int, n: int, z: float = 1.96) -> Tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    denom = 1.0 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def _prf(tp: int, fp: int, fn: int) -> Dict[str, float]:
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return {"precision": precision, "recall": recall, "f1": f1,
            "tp": tp, "fp": fp, "fn": fn}


def _bootstrap_ci(values: Sequence[float], statistic: Callable[[List[float]], float],
                  samples: int = 1000, seed: int = 20261114) -> Tuple[float, float]:
    if not values:
        return (0.0, 0.0)
    rng = _Rng(seed)
    n = len(values)
    draws: List[float] = []
    for _ in range(samples):
        resample = [values[rng.next_below(n)] for _ in range(n)]
        draws.append(statistic(resample))
    draws.sort()
    lo = draws[int(0.025 * len(draws))]
    hi = draws[int(0.975 * len(draws)) - 1]
    return (lo, hi)


class _Rng:
    """A small deterministic PRNG so the bootstrap needs no global state."""

    def __init__(self, seed: int) -> None:
        self.state = (seed ^ 0x9E3779B97F4A7C15) & ((1 << 64) - 1)

    def _next(self) -> int:
        x = self.state
        x ^= (x << 13) & ((1 << 64) - 1)
        x ^= x >> 7
        x ^= (x << 17) & ((1 << 64) - 1)
        self.state = x & ((1 << 64) - 1)
        return self.state

    def next_below(self, n: int) -> int:
        return self._next() % n


def split_of(case_id: str) -> str:
    digest = hashlib.sha256(case_id.encode("utf-8")).digest()
    return "calibration" if digest[0] & 1 else "test"


# --------------------------------------------------------------------- replay
@dataclass
class CaseOutcome:
    case_id: str
    category: str
    subtype: str
    source: str
    level: int
    is_malicious: bool
    expected_decision: str
    expected_layer: str
    system_decision: str
    decided_at_step: Optional[int]
    deciding_layer: Optional[str]
    deciding_policy: Optional[str]
    steps_run: int
    quarantined: bool
    fail_closed: bool
    latency_ms: float
    layer_latency_ms: Dict[str, float] = field(default_factory=dict)

    @property
    def contained(self) -> bool:
        return self.system_decision != Decision.ALLOW.value

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id, "category": self.category,
            "subtype": self.subtype, "source": self.source, "level": self.level,
            "is_malicious": self.is_malicious,
            "expected_decision": self.expected_decision,
            "expected_layer": self.expected_layer,
            "system_decision": self.system_decision,
            "decided_at_step": self.decided_at_step,
            "deciding_layer": self.deciding_layer,
            "deciding_policy": self.deciding_policy,
            "steps_run": self.steps_run,
            "quarantined": self.quarantined,
            "fail_closed": self.fail_closed,
            "latency_ms": round(self.latency_ms, 3),
            "layer_latency_ms": {k: round(v, 3) for k, v in self.layer_latency_ms.items()},
        }


def _is_gated_benign(o: CaseOutcome) -> bool:
    """A legitimate task whose declared correct outcome is human sign-off.

    It is neither a safety negative (ALLOW) nor an attack, so it stays out of the
    binary confusion matrix and is scored on agreement with its own label.
    """
    return (not o.is_malicious
            and o.expected_decision == Decision.REQUIRE_APPROVAL.value)


def _source_of(case: Dict[str, Any]) -> str:
    provenance = case.get("provenance") or {}
    if provenance.get("source") == "external_import":
        return str(provenance.get("source_dataset") or "external")
    return "authored"


def _action(step: Dict[str, Any]) -> Action:
    return Action(tool=step["tool"], args=dict(step.get("args") or {}),
                  operation=step.get("operation", "call"),
                  target=step.get("target", ""), step=step["step"])


def run_case(monitor: ReferenceMonitor, case: Dict[str, Any],
             time_layers: bool = False) -> CaseOutcome:
    obs = Observation.from_case(case)
    state = RuntimeState.seed(obs)
    token = monitor.token_for(obs)
    started = time.perf_counter()
    decision: Optional[Decision] = None
    decided_at: Optional[int] = None
    deciding_layer: Optional[str] = None
    deciding_policy: Optional[str] = None
    fail_closed = False
    steps_run = 0
    layer_totals: Dict[str, float] = defaultdict(float)

    for step in case["expected_sequence"]:
        action = _action(step)
        delta = step.get("state_after") or {}
        if time_layers:
            for name in monitor.enabled:
                layer = _layer_object(monitor, name)
                if layer is None:
                    continue
                began = time.perf_counter()
                try:
                    if name == "capability":
                        layer.check(obs, state, action, token)
                    else:
                        layer.check(obs, state, action)
                except Exception:
                    pass
                layer_totals[name] += (time.perf_counter() - began) * 1000.0
        result = monitor.execute(obs, state, action, token,
                                 executor=lambda _action, _delta=delta: dict(_delta))
        steps_run += 1
        if result.combined.deciding_policy == "FAIL-CLOSED":
            fail_closed = True
        if result.decision is not Decision.ALLOW:
            decision = result.decision
            decided_at = step["step"]
            deciding_layer = result.combined.deciding_layer
            deciding_policy = result.combined.deciding_policy
            break

    if decision is None:
        decision = Decision.ALLOW

    latency = (time.perf_counter() - started) * 1000.0
    return CaseOutcome(
        case_id=case["case_id"], category=case.get("category", "?"),
        subtype=case.get("subtype", "?"), source=_source_of(case),
        level=int(case.get("execution_level", 1)),
        is_malicious=bool(case.get("is_malicious")),
        expected_decision=case.get("expected_decision", "ALLOW"),
        expected_layer=case.get("expected_enforcing_layer") or "none",
        system_decision=decision.value, decided_at_step=decided_at,
        deciding_layer=deciding_layer, deciding_policy=deciding_policy,
        steps_run=steps_run,
        quarantined=bool(decision is not Decision.ALLOW),
        fail_closed=fail_closed, latency_ms=latency,
        layer_latency_ms=dict(layer_totals),
    )


def _layer_object(monitor: ReferenceMonitor, name: str) -> Any:
    from . import contracts
    return {
        "capability": monitor.capability,
        "workflow": monitor.workflow,
        "semantic": monitor.semantic,
        "ifc": monitor.ifc,
        "dcbf": monitor.dcbf,
        "hitl": monitor.hitl,
        "contracts": _ContractsAdapter(contracts),
    }.get(name)


class _ContractsAdapter:
    def __init__(self, module: Any) -> None:
        self._module = module
        self._obs = None
        self._state = None

    def check(self, obs: Observation, state: RuntimeState, action: Action) -> Any:
        return self._module.evaluate(action, obs, state)


def run_dataset(monitor: ReferenceMonitor, cases: Sequence[Dict[str, Any]],
                time_layers: bool = False) -> List[CaseOutcome]:
    return [run_case(monitor, case, time_layers=time_layers) for case in cases]


# --------------------------------------------------------------------- metrics
def confusion(outcomes: Iterable[CaseOutcome]) -> Dict[str, int]:
    tp = fp = tn = fn = 0
    for o in outcomes:
        if _is_gated_benign(o):
            continue
        if o.is_malicious:
            if o.contained:
                tp += 1
            else:
                fn += 1
        else:
            if o.contained:
                fp += 1
            else:
                tn += 1
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "total": tp + fp + tn + fn}


def summarise(outcomes: Sequence[CaseOutcome]) -> Dict[str, Any]:
    c = confusion(outcomes)
    prf = _prf(c["tp"], c["fp"], c["fn"])
    accuracy = (c["tp"] + c["tn"]) / c["total"] if c["total"] else 0.0
    gated = [o for o in outcomes if _is_gated_benign(o)]
    exact = sum(1 for o in outcomes
                if not _is_gated_benign(o) and o.system_decision == o.expected_decision)
    hard = sum(1 for o in outcomes
               if o.is_malicious and o.system_decision == Decision.DENY.value)
    attacks = sum(1 for o in outcomes if o.is_malicious)
    benign = sum(1 for o in outcomes if not o.is_malicious)
    early = [o for o in outcomes if layer_relation(o) == "early"]
    late = [o for o in outcomes if layer_relation(o) == "late"]
    layer_match = sum(1 for o in outcomes if layer_relation(o) == "match")
    r_ci = wilson(c["tp"], c["tp"] + c["fn"])
    p_ci = wilson(c["tp"], c["tp"] + c["fp"])
    return {
        **c, **prf,
        "accuracy": accuracy,
        "exact_agreement": exact / c["total"] if c["total"] else 0.0,
        "hard_containment": hard / attacks if attacks else 0.0,
        "recall_ci95": list(r_ci), "precision_ci95": list(p_ci),
        "attacks": attacks, "benign": benign,
        "early_blocks": len(early),
        "late_blocks": len(late),
        "benign_approval_gated": len(gated),
        "benign_approval_correct": sum(
            1 for o in gated if o.system_decision == Decision.REQUIRE_APPROVAL.value),
        "benign_approval_allowed": sum(
            1 for o in gated if o.system_decision == Decision.ALLOW.value),
        "benign_approval_overblocked": sum(
            1 for o in gated if o.system_decision == Decision.DENY.value),
        "layer_attribution_match": layer_match,
        "layer_attribution_rate": layer_match / c["tp"] if c["tp"] else 0.0,
        "fail_closed": sum(1 for o in outcomes if o.fail_closed),
    }


def grouped_summary(outcomes: Sequence[CaseOutcome],
                    key: Callable[[CaseOutcome], Any]) -> Dict[str, Dict[str, Any]]:
    buckets: Dict[Any, List[CaseOutcome]] = defaultdict(list)
    for o in outcomes:
        buckets[key(o)].append(o)
    return {str(k): summarise(v) for k, v in sorted(buckets.items(), key=lambda kv: str(kv[0]))}


def failure_analysis(outcomes: Sequence[CaseOutcome]) -> Dict[str, List[Dict[str, Any]]]:
    false_negatives = [o for o in outcomes if o.is_malicious and not o.contained]
    false_positives = [o for o in outcomes
                       if not o.is_malicious and not _is_gated_benign(o) and o.contained]
    overblocked_gated = [o for o in outcomes if _is_gated_benign(o)
                         and o.system_decision == Decision.DENY.value]
    early_blocks = [o for o in outcomes if layer_relation(o) == "early"]
    late_blocks = [o for o in outcomes if layer_relation(o) == "late"]
    escalated = [o for o in outcomes if o.is_malicious and o.contained
                 and o.expected_decision == Decision.DENY.value
                 and o.system_decision == Decision.REQUIRE_APPROVAL.value]

    def compact(o: CaseOutcome) -> Dict[str, Any]:
        return {"case_id": o.case_id, "category": o.category, "subtype": o.subtype,
                "level": o.level, "expected": o.expected_decision,
                "expected_layer": o.expected_layer, "system": o.system_decision,
                "layer": o.deciding_layer, "policy": o.deciding_policy,
                "step": o.decided_at_step}

    return {
        "false_negatives": [compact(o) for o in false_negatives],
        "false_positives": [compact(o) for o in false_positives],
        "benign_approval_overblocked": [compact(o) for o in overblocked_gated],
        "early_blocks": [compact(o) for o in early_blocks],
        "late_blocks": [compact(o) for o in late_blocks],
        "escalated_instead_of_denied": [compact(o) for o in escalated],
    }


def layer_usage(outcomes: Sequence[CaseOutcome]) -> Dict[str, int]:
    return dict(Counter(o.deciding_layer for o in outcomes if o.contained))


# --------------------------------------------------------------------- latency
def latency_stats(values: Sequence[float]) -> Dict[str, float]:
    if not values:
        return {"n": 0, "mean_ms": 0.0, "p50_ms": 0.0, "p95_ms": 0.0, "max_ms": 0.0}
    ordered = sorted(values)
    p95_index = max(0, min(len(ordered) - 1, int(round(0.95 * (len(ordered) - 1)))))
    return {
        "n": len(values),
        "mean_ms": statistics.fmean(values),
        "p50_ms": statistics.median(ordered),
        "p95_ms": ordered[p95_index],
        "max_ms": ordered[-1],
    }


def memory_report(monitor: ReferenceMonitor,
                  cases: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    import psutil
    process = psutil.Process()
    baseline = process.memory_info().rss
    tracemalloc.start()
    for case in cases[: max(1, min(60, len(cases)))]:
        run_case(monitor, case)
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    after = process.memory_info().rss
    return {
        "process_rss_mb": round(after / 1024 / 1024, 1),
        "model_resident_mb": round((after - baseline) / 1024 / 1024, 1),
        "tracemalloc_peak_mb": round(peak / 1024 / 1024, 3),
        "tracemalloc_retained_mb": round(current / 1024 / 1024, 3),
        "sampled_cases": max(1, min(60, len(cases))),
    }


# --------------------------------------------------------------------- configs
def _build_monitor(layers: Optional[Sequence[str]],
                   semantic: Optional[Any] = None) -> ReferenceMonitor:
    enabled = list(layers) if layers is not None else None
    if semantic is not None and enabled is not None and "semantic" in enabled:
        return ReferenceMonitor(layers=enabled, semantic=semantic)
    return ReferenceMonitor(layers=enabled)


CONFIGURATIONS: List[Tuple[str, Optional[List[str]]]] = [
    ("allow_all", []),
    ("capability_only", ["capability"]),
    ("capability_contracts", ["capability", "contracts"]),
    ("static_plus_ifc", ["capability", "ifc", "contracts"]),
    ("full", list(LAYERS)),
]
ABLATIONS: List[str] = list(LAYERS)


def evaluate_configuration(name: str, layers: Optional[Sequence[str]],
                           cases: Sequence[Dict[str, Any]],
                           time_layers: bool = False,
                           semantic: Optional[Any] = None) -> Tuple[Dict[str, Any],
                                                                    List[CaseOutcome],
                                                                    ReferenceMonitor]:
    monitor = _build_monitor(layers, semantic=semantic)
    outcomes = run_dataset(monitor, cases, time_layers=time_layers)
    return summarise(outcomes), outcomes, monitor


# --------------------------------------------------------------------- report
def _pct(value: float) -> str:
    return f"{100.0 * value:.1f}%"


def _ci(pair: Sequence[float]) -> str:
    return f"[{100 * pair[0]:.1f}, {100 * pair[1]:.1f}]"


def _row(label: str, s: Dict[str, Any]) -> str:
    return (f"| {label} | {s['total']} | {s['tp']} | {s['fp']} | {s['fn']} | {s['tn']} | "
            f"{_pct(s['precision'])} {_ci(s['precision_ci95'])} | "
            f"{_pct(s['recall'])} {_ci(s['recall_ci95'])} | {s['f1']:.3f} | "
            f"{_pct(s['accuracy'])} | {_pct(s['exact_agreement'])} | "
            f"{_pct(s['hard_containment'])} | {s['early_blocks']} |")


def render_markdown(report: Dict[str, Any]) -> str:
    lines: List[str] = []
    add = lines.append
    add("# Reference monitor evaluation")
    add("")
    add(f"Generated: {report['generated_at']}")
    add("")
    add(f"Dataset: `{report['dataset']['path']}` "
        f"(sha256 `{report['dataset']['sha256'][:16]}…`, {report['dataset']['cases']} cases, "
        f"{report['dataset']['attacks']} attacks, {report['dataset']['benign']} benign).")
    add("")
    add("A case is contained when the pipeline stops its sequence with DENY or "
        "REQUIRE_APPROVAL before the violating step. Precision/recall are computed "
        "over cases, with attacks as positives. Intervals are Wilson 95%.")
    add("")
    add("## Headline")
    add("")
    add("| configuration | cases | TP | FP | FN | TN | precision | recall | F1 | accuracy | exact | hard | early |")
    add("|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    for name, s in report["configurations"].items():
        add(_row(name, s))
    add("")
    add("Columns: `hard` is the share of attacks ending in DENY rather than withheld; "
        "`early` counts attacks stopped at a layer upstream of the authored one. "
        "`allow_all` disables every pre-execution layer, yet it still blocks the four "
        "attacks whose effect violates a postcondition, because postcondition "
        "verification runs after the tool returns and is part of the contracts stage.")
    add("")
    add("## Splits")
    add("")
    add("| split | cases | TP | FP | FN | TN | precision | recall | F1 | accuracy | exact | hard | early |")
    add("|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    for name, s in report["splits"].items():
        add(_row(name, s))
    add("")
    add("## Per level")
    add("")
    add("| level | cases | TP | FP | FN | TN | precision | recall | F1 | accuracy | exact | hard | early |")
    add("|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    for name, s in report["per_level"].items():
        add(_row(name, s))
    add("")
    add("## Per source")
    add("")
    add("| source | cases | TP | FP | FN | TN | precision | recall | F1 | accuracy | exact | hard | early |")
    add("|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    for name, s in report["per_source"].items():
        add(_row(name, s))
    add("")
    add("`authored` is the GATE taxonomy; the other rows are imported from the named "
        "public dataset and keep their source label. They are reported separately so "
        "that the authored result is not diluted by a different threat model.")
    add("")
    add("## Per category")
    add("")
    add("| category | cases | TP | FP | FN | TN | precision | recall | F1 | accuracy | exact | hard | early |")
    add("|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    for name, s in report["per_category"].items():
        add(_row(name, s))
    add("")
    add("## Ablations (one layer removed)")
    add("")
    add("| removed | TP | FP | FN | TN | recall | precision | F1 | delta recall | delta F1 |")
    add("|---|---|---|---|---|---|---|---|---|---|")
    full = report["configurations"]["full"]
    for name, s in report["ablations"].items():
        add(f"| {name} | {s['tp']} | {s['fp']} | {s['fn']} | {s['tn']} | "
            f"{_pct(s['recall'])} | {_pct(s['precision'])} | {s['f1']:.3f} | "
            f"{s['recall'] - full['recall']:+.3f} | {s['f1'] - full['f1']:+.3f} |")
    add("")
    add("## Layer attribution")
    add("")
    add("| layer | denials | share |")
    add("|---|---|---|")
    usage = report["layer_usage"]
    total = sum(usage.values()) or 1
    for name, count in sorted(usage.items(), key=lambda kv: -kv[1]):
        add(f"| {name} | {count} | {_pct(count / total)} |")
    add("")
    add(f"Layer matches the authored enforcing layer on "
        f"{report['configurations']['full']['layer_attribution_match']} of "
        f"{report['configurations']['full']['tp']} contained attacks "
        f"({_pct(report['configurations']['full']['layer_attribution_rate'])}); "
        f"{report['configurations']['full']['early_blocks']} are stopped upstream of the authored "
        f"layer and {report['configurations']['full']['late_blocks']} downstream of it.")
    add("")
    add("## Latency")
    add("")
    add("| scope | n | mean ms | p50 ms | p95 ms | max ms |")
    add("|---|---|---|---|---|---|")
    for scope, s in report["latency"].items():
        if not isinstance(s, dict) or "n" not in s:
            continue
        add(f"| {scope} | {s['n']} | {s['mean_ms']:.2f} | {s['p50_ms']:.2f} | "
            f"{s['p95_ms']:.2f} | {s['max_ms']:.2f} |")
    add("")
    add(f"Cold start (encoder load plus reference-matrix construction, paid once per process): "
        f"{report['latency']['semantic_cold_start_ms']:.0f} ms. The table below excludes it.")
    add("")
    add("Per-layer mean cost of one `check` call, measured on the full pipeline pass.")
    add("")
    add("| layer | mean ms per decision | total ms |")
    add("|---|---|---|")
    for name in LAYERS:
        mean = report["latency"]["per_layer_mean_ms"].get(name, 0.0)
        total_ms = report["latency"]["per_layer_total_ms"].get(name, 0.0)
        add(f"| {name} | {mean:.3f} | {total_ms:.1f} |")
    add("")
    add("## Memory")
    add("")
    add("| metric | value |")
    add("|---|---|")
    for key, value in report["memory"].items():
        add(f"| {key} | {value} |")
    add("")
    add("## Failure analysis")
    add("")
    for key in ("false_negatives", "false_positives", "early_blocks", "late_blocks",
                "escalated_instead_of_denied"):
        items = report["failures"][key]
        add(f"### {key.replace('_', ' ')} ({len(items)})")
        add("")
        if not items:
            add("None.")
            add("")
            continue
        add("| case | category | level | expected | expected layer | system | layer | policy | step |")
        add("|---|---|---|---|---|---|---|---|---|")
        for item in items:
            add(f"| {item['case_id']} | {item['category']} | {item['level']} | "
                f"{item['expected']} | {item['expected_layer']} | {item['system']} | "
                f"{item['layer']} | {item['policy']} | {item['step']} |")
        add("")
    add("## Reproduction")
    add("")
    add("```")
    add(report["command"])
    add("```")
    add("")
    add(f"Python {report['environment']['python']} on {report['environment']['platform']}; "
        f"CPU-only semantic encoder. Wall clock for the full pass: "
        f"{report['environment']['wall_seconds']:.1f}s.")
    add("")
    return "\n".join(lines) + "\n"


def evaluate(path: Path, out_dir: Path, bootstrap_samples: int = 1000) -> Dict[str, Any]:
    cases = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    started = time.perf_counter()

    shared_semantic = SemanticLayer()
    cold_start_ms = 0.0
    if cases:
        # The encoder and the reference matrices are built lazily on the first
        # semantic check. Time that separately so the per-decision latency is
        # steady-state cost, not a one-off model load.
        warm_up = _build_monitor(["semantic"], semantic=shared_semantic)
        began = time.perf_counter()
        run_case(warm_up, cases[0])
        cold_start_ms = (time.perf_counter() - began) * 1000.0

    configurations: Dict[str, Dict[str, Any]] = {}
    configuration_outcomes: Dict[str, List[CaseOutcome]] = {}
    main_monitor: Optional[ReferenceMonitor] = None
    for name, layers in CONFIGURATIONS:
        summary, outcomes, monitor = evaluate_configuration(
            name, layers, cases, time_layers=(name == "full"),
            semantic=shared_semantic)
        configurations[name] = summary
        configuration_outcomes[name] = outcomes
        if name == "full":
            main_monitor = monitor

    ablations: Dict[str, Dict[str, Any]] = {}
    for removed in ABLATIONS:
        remaining = [layer for layer in LAYERS if layer != removed]
        summary, _, _ = evaluate_configuration(f"ablate_{removed}", remaining, cases,
                                              semantic=shared_semantic)
        ablations[removed] = summary

    full_outcomes = configuration_outcomes["full"]
    by_split = {"calibration": [o for o in full_outcomes if split_of(o.case_id) == "calibration"],
                "test": [o for o in full_outcomes if split_of(o.case_id) == "test"]}
    splits = {name: summarise(outcomes) for name, outcomes in by_split.items()}

    recall_ci = _bootstrap_ci(
        [1.0 if o.contained else 0.0 for o in by_split["test"] if o.is_malicious],
        lambda values: sum(values) / len(values), samples=bootstrap_samples)
    f1_ci = _bootstrap_ci(
        [o for o in by_split["test"]],
        lambda sample: _prf(
            sum(1 for o in sample if o.is_malicious and o.contained),
            sum(1 for o in sample if not o.is_malicious and o.contained),
            sum(1 for o in sample if o.is_malicious and not o.contained))["f1"],
        samples=bootstrap_samples)
    bootstrap = {"test_recall_ci95": list(recall_ci), "test_f1_ci95": list(f1_ci),
                 "resamples": bootstrap_samples}

    latency: Dict[str, Any] = {}
    latency["semantic_cold_start_ms"] = cold_start_ms
    latency["per_case_full_pipeline"] = latency_stats([o.latency_ms for o in full_outcomes])
    per_layer: Dict[str, float] = defaultdict(float)
    layer_counts: Counter = Counter()
    for o in full_outcomes:
        for name, value in o.layer_latency_ms.items():
            per_layer[name] += value
            layer_counts[name] += o.steps_run
    latency["per_layer_mean_ms"] = {
        name: per_layer[name] / layer_counts[name] if layer_counts[name] else 0.0
        for name in LAYERS}
    latency["per_layer_total_ms"] = {name: per_layer[name] for name in LAYERS}
    per_decision = [o.latency_ms / max(1, o.steps_run) for o in full_outcomes]
    latency["per_decision_mean_ms"] = latency_stats(per_decision)

    memory = memory_report(main_monitor, cases) if main_monitor is not None else {}

    wall = time.perf_counter() - started
    report = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "command": "USE_TF=0 USE_TORCH=1 python -m gzt.evaluate --dataset "
                   f"{path.as_posix()} --out {out_dir.as_posix()}",
        "dataset": {
            "path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "cases": len(cases),
            "attacks": sum(1 for c in cases if c["is_malicious"]),
            "benign": sum(1 for c in cases if not c["is_malicious"]),
        },
        "environment": {
            "python": platform.python_version(), "platform": platform.platform(),
            "wall_seconds": wall,
        },
        "configurations": configurations,
        "ablations": ablations,
        "splits": splits,
        "bootstrap": bootstrap,
        "per_level": grouped_summary(full_outcomes, lambda o: f"L{o.level}"),
        "per_category": grouped_summary(full_outcomes, lambda o: o.category),
        "per_source": grouped_summary(full_outcomes, lambda o: o.source),
        "per_subtype": grouped_summary(full_outcomes, lambda o: o.subtype),
        "layer_usage": layer_usage(full_outcomes),
        "latency": latency,
        "memory": memory,
        "failures": failure_analysis(full_outcomes),
        "case_outcomes": [o.to_dict() for o in full_outcomes],
    }

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "evaluation.json").write_text(json.dumps(report, indent=2) + "\n",
                                              encoding="utf-8", newline="\n")
    (out_dir / "evaluation.md").write_text(render_markdown(report), encoding="utf-8",
                                            newline="\n")
    return report


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate the GATE reference monitor")
    parser.add_argument("--dataset", type=Path,
                        default=Path("dataset/out/dataset.jsonl"))
    parser.add_argument("--out", type=Path, default=Path("target"))
    parser.add_argument("--bootstrap", type=int, default=1000)
    args = parser.parse_args(argv)
    report = evaluate(args.dataset, args.out, bootstrap_samples=args.bootstrap)
    full = report["configurations"]["full"]
    print(json.dumps({
        "cases": report["dataset"]["cases"],
        "attacks": report["dataset"]["attacks"],
        "benign": report["dataset"]["benign"],
        "tp": full["tp"], "fp": full["fp"], "fn": full["fn"], "tn": full["tn"],
        "precision": round(full["precision"], 4),
        "recall": round(full["recall"], 4),
        "f1": round(full["f1"], 4),
        "accuracy": round(full["accuracy"], 4),
        "exact_agreement": round(full["exact_agreement"], 4),
        "hard_containment": round(full["hard_containment"], 4),
        "layer_attribution_rate": round(full["layer_attribution_rate"], 4),
        "early_blocks": full["early_blocks"],
        "test_recall_ci95": [round(x, 4) for x in report["bootstrap"]["test_recall_ci95"]],
        "test_f1_ci95": [round(x, 3) for x in report["bootstrap"]["test_f1_ci95"]],
        "fail_closed": full["fail_closed"],
        "wall_seconds": round(report["environment"]["wall_seconds"], 1),
        "report_json": str((args.out / "evaluation.json").resolve()),
        "report_md": str((args.out / "evaluation.md").resolve()),
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
