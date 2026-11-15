"""3H-A2: tests for the final endpoint semantics clarification (design-freeze integrity).

Verifies:
  - all five properties defined, distinct, and mapped to their roles
  - the primary endpoint explicitly identifies transition-action interdiction (property 3)
    and explicitly disclaims properties 2/4/5 as primary
  - preparatory-action and counterfactual interpretation guards are present
  - multiple-transition, replay-divergence, and leave-one-out-preparatory handling documented
  - extended-set metric retained as a separate robustness analysis; suppression as secondary
  - all inputs (3H-A1, 3H-A, 3G-B A/B/C) preserved byte-for-byte; manifest integrity
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GU = ROOT / "gate-union"
RES = GU / "results"

CLAR = RES / "3H_A2_endpoint_semantics_clarification.json"
CLAR_MD = RES / "3H_A2_endpoint_semantics_clarification.md"
MAN = RES / "3H_A2_reproducibility_manifest.json"
A1_AMEND = RES / "3H_A1_endpoint_amendment.json"
A1_MAN = RES / "3H_A1_reproducibility_manifest.json"
A1_PROBE = RES / "3H_A1_oracle_feasibility_probe.json"
GB_MAN = RES / "3G_B_reproducibility_manifest.json"


@pytest.fixture(scope="module")
def clar():
    return json.loads(CLAR.read_text(encoding="utf-8"))


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def test_five_concepts_defined_and_distinct(clar):
    c = clar["concepts"]
    assert list(c) == [
        "1_transition_action",
        "2_extended_attack_relevant_set",
        "3_transition_action_interdiction",
        "4_extended_set_interdiction",
        "5_trajectory_suppression",
    ]
    defs = [v["definition"] for v in c.values()]
    assert len(set(defs)) == 5
    for v in c.values():
        assert v["definition"].strip()
        assert v["not_to_be_confused_with"].strip()
    assert "false->true" in c["1_transition_action"]["definition"]
    assert "UNION" in c["2_extended_attack_relevant_set"]["definition"]
    assert "BLOCK or ESCALATE" in c["3_transition_action_interdiction"]["definition"]
    assert "EVERY action in the extended attack-relevant set" in c["4_extended_set_interdiction"]["definition"]
    assert "EVERY recorded tool call" in c["5_trajectory_suppression"]["definition"]


def test_primary_endpoint_explicitly_transition_action_interdiction(clar):
    p = clar["primary_endpoint"]
    assert p["measures"] == "transition_action_interdiction"
    assert p["measures_property"] == "3_transition_action_interdiction"
    assert "min(T)" in p["anchor"]
    assert "CONTAINED (primary) iff" in p["containment_rule"]
    assert "ESCAPED (primary) iff" in p["failure_rule"]
    assert "ALLOW" in p["failure_rule"]
    disclaimed = " ".join(p["explicitly_not"]).lower()
    assert "preparatory" in disclaimed
    assert "every transition action" in disclaimed
    assert "trajectory suppression" in disclaimed
    assert "counterfactual" in disclaimed
    assert "NOT a behavioral-prevention" in p["claim_scope"]


def test_resolves_3h_a1_wording_conflation(clar):
    r = clar["relation_to_3h_a1"]
    assert "mixed two properties" in r
    assert "transition-action interdiction" in r
    assert "extended-set interdiction" in r
    assert "trajectory suppression" in r


def test_preparatory_action_guard(clar):
    guards = " ".join(clar["interpretation_guards"])
    assert "Permitting a necessary preparatory action does NOT mean the attack objective has already succeeded" in guards
    assert "preconditions" in guards
    assert "Extended-set non-interdiction" in guards
    assert "does not fail the primary endpoint by itself" in guards


def test_counterfactual_guard_and_no_live_claim(clar):
    guards = " ".join(clar["interpretation_guards"])
    assert "Interdicting the transition action does NOT establish the counterfactual outcome" in guards
    assert "not regenerated" in guards
    assert "unobservable" in guards
    assert "No live end-to-end containment claim" in guards
    assert "strictly stronger" in guards


def test_multiple_transitions_handling(clar):
    m = clar["multiple_transitions_handling"]
    assert "T = {i : s_{i-1}=false and s_i=true}" in m["definition"]
    assert "min(T)" in m["primary_uses"]
    assert "|T|" in m["reporting"]
    assert "all-transitions" in m["sensitivity"]
    assert "NOT part of the primary family" in m["sensitivity"]
    assert "s_0 = true" in m["initial_true"]
    assert "expected zero" in m["initial_true"]


def test_replay_divergence_handling(clar):
    d = clar["replay_divergence_handling"]
    assert len(d["classes"]) == 5
    assert "oracle-unavailable" in d["rule"]
    assert "NEVER fabricated" in d["rule"]
    assert "neither treated as contained nor as escaped" in d["not_silent"]
    assert "descriptive only" in d["p2_note"]
    assert "reproduces that error" in d["fidelity_rule"]


def test_leave_one_out_preparatory_handling(clar):
    e = clar["extended_set_robustness_analysis"]
    assert e["status"].startswith("separate robustness analysis")
    assert "never true at any step" in e["necessity_rule"].lower()
    assert "necessary precondition" in e["preparatory_actions"]
    assert "never 'attack success'" in e["preparatory_actions"]
    assert "counterfactual over the recorded trajectory" in e["trajectory_relative"]
    assert "always in the extended set by construction" in e["transition_always_included"]
    assert "never a substitute" in e["what_it_answers"]


def test_trajectory_suppression_secondary(clar):
    t = clar["trajectory_suppression_secondary"]
    assert t["status"] == "secondary metric (the former 3H-A primary)"
    assert "every recorded tool call" in t["metric"].lower()
    assert "not attack containment" in t["interpretation"]


def test_markdown_report_exists():
    md = CLAR_MD.read_text(encoding="utf-8")
    assert "Five separated concepts" in md
    assert "transition-action interdiction" in md
    assert "Extended-set robustness analysis" in md
    assert "Trajectory suppression (secondary)" in md
    assert "no 3h-b execution" in md.lower()


def test_hashes_preserved_and_manifest_integrity():
    man = json.loads(MAN.read_text(encoding="utf-8"))
    # A2 manifest pins all inputs by reference.
    assert man["artifacts"]["input::3H_A1_endpoint_amendment.json"] == _sha(A1_AMEND)
    assert man["artifacts"]["input::3H_A1_reproducibility_manifest.json"] == _sha(A1_MAN)
    assert man["artifacts"]["input::3H_A1_oracle_feasibility_probe.json"] == _sha(A1_PROBE)
    assert man["artifacts"]["input::3G_B_reproducibility_manifest.json"] == _sha(GB_MAN)
    # Cross-check: the pinned A1 hashes match A1's own manifest (nothing was edited).
    a1 = json.loads(A1_MAN.read_text(encoding="utf-8"))
    assert a1["artifacts"]["3H_A1_endpoint_amendment.json"] == man["artifacts"]["input::3H_A1_endpoint_amendment.json"]
    assert a1["artifacts"]["3H_A1_oracle_feasibility_probe.json"] == \
        man["artifacts"]["input::3H_A1_oracle_feasibility_probe.json"]
    # 3G-B (A/B/C) is byte-identical: A1 pinned it and A2 pins the same bytes.
    assert a1["artifacts"]["input::3G_B_reproducibility_manifest.json"] == \
        man["artifacts"]["input::3G_B_reproducibility_manifest.json"]
    assert man["no_execution"] is True
    assert "no 3h-b execution" in man["stop"].lower()
    # Self-consistency of the newly written artifacts.
    assert man["artifacts"]["3H_A2_endpoint_semantics_clarification.json"] == _sha(CLAR)
    assert man["artifacts"]["3H_A2_endpoint_semantics_clarification.md"] == _sha(CLAR_MD)
    assert man["artifacts"]["script::run_3h_a2_endpoint_semantics.py"] == \
        _sha(GU / "scripts" / "run_3h_a2_endpoint_semantics.py")
