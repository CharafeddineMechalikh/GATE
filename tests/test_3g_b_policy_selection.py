"""3G-B: automated tests for DEV-only policy selection.

Covers:
  - A is the identity over the frozen decisions; first decisions preserved under B/C (integrity §7)
  - policies only transition ALLOW->ESCALATE (no auto-block; §4)
  - triggers read ONLY the permitted mechanism-level features + position (§2); label-blind (§5)
  - C is provenance-blind (position-only control)
  - the declared confound: B and C activation sets coincide on the frozen dataset
  - frozen 3F metric conventions: violations, autonomy, N/A rule on zero denominators (§6)
  - dataset accounting: 302 first + 45 subsequent decisions, 302 cases, manifest hash verified
No policy is implemented in the runtime; no frozen artifact is modified; no holdout access.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GU = ROOT / "gate-union"
RES = GU / "results"
sys.path.insert(0, str(GU / "scripts"))
sys.path.insert(0, str(ROOT))

DS = RES / "3G_A2_DEV_trajectory_dataset.jsonl"
SEL = RES / "3G_B_policy_selection.json"
ACT = RES / "3G_B_activation_report.json"
MAN = RES / "3G_B_reproducibility_manifest.json"


@pytest.fixture(scope="module")
def mod():
    import run_3g_b_policy_selection as m
    return m


@pytest.fixture(scope="module")
def data(mod):
    ts, decs = mod.load_decisions()
    return ts, decs


@pytest.fixture(scope="module")
def selection():
    return json.loads(SEL.read_text(encoding="utf-8"))


def _dec(idx, outcome="ALLOW", *, tr=False, ext=False, n_known=2, unknown=0, label="attack"):
    s = {"has_tool_result": tr, "has_external_document": ext, "has_environment_data": False,
         "n_known_origins": n_known, "unknown_segments_n": unknown, "transformed_unresolved_n": 0}
    return {"case_id": "c", "decision_idx": idx, "outcome": outcome, "is_allowed": outcome == "ALLOW",
            "escalated": outcome == "ESCALATE", "tool": "t", "tool_category": "internal",
            "snapshot": s, "label": label, "retrospective_label_raw": label, "termination_reason": None}


# ---------------------------------------------------------------- integrity §7

def test_frozen_dataset_hash_and_accounting(mod, data):
    ts, decs = data
    man = json.loads((RES / "3G_A2_DEV_trajectory_manifest.json").read_text(encoding="utf-8"))
    assert man["dataset_sha256"] == hashlib.sha256(DS.read_bytes()).hexdigest()
    assert sum(1 for d in decs if d["decision_idx"] == 0) == 302
    assert sum(1 for d in decs if d["decision_idx"] > 0) == 45
    assert sum(1 for t in ts if t["termination_reason"] == "first_decision_not_allowed") == 257
    assert len(decs) == 347 and len({d["case_id"] for d in decs}) == 302


def test_A_is_identity_and_first_decisions_preserved(mod, data):
    _, decs = data
    out_A, act_A = mod.apply_policy(decs, lambda d: False)
    assert act_A == [] and all(o["outcome"] == d["outcome"] for o, d in zip(out_A, decs))
    for trig in (mod.trigger_B, mod.trigger_C):
        out, act = mod.apply_policy(decs, trig)
        assert all(o["outcome"] == d["outcome"] for o, d in zip(out, decs) if d["decision_idx"] == 0)
        assert all(a["decision_idx"] > 0 for a in act)  # first decisions untouched


# ---------------------------------------------------------------- policy behavior §4

def test_only_allow_to_escalate_transitions_never_block(mod):
    decs = [_dec(1, "ALLOW", tr=True), _dec(1, "BLOCK", tr=True), _dec(1, "ESCALATE", tr=True)]
    out, act = mod.apply_policy(decs, mod.trigger_B)
    transitions = [(d["outcome"], o["outcome"]) for d, o in zip(decs, out)]
    assert transitions == [("ALLOW", "ESCALATE"), ("BLOCK", "BLOCK"), ("ESCALATE", "ESCALATE")]
    assert all(a["original"] == "ALLOW" and a["resulting"] == "ESCALATE" for a in act)


def test_unknown_provenance_never_triggers(mod):
    # unknown-only provenance (no known origins): unknown != malicious, must not escalate
    d = _dec(1, "ALLOW", unknown=2, n_known=0)
    assert mod.trigger_B(d) is False


def test_triggers_read_only_permitted_features(mod):
    """Trigger output must be invariant to labels/ids/tools: only position + snapshot features."""
    base = _dec(1, "ALLOW", tr=True, label="attack")
    variant = _dec(1, "ALLOW", tr=True, label="benign")
    variant["case_id"], variant["tool"] = "other", "other_tool"
    for trig in (mod.trigger_B, mod.trigger_C):
        assert trig(base) == trig(variant)


def test_position_only_control_is_provenance_blind(mod):
    yes = _dec(1, "ALLOW", tr=True, ext=True, n_known=3)
    no = _dec(1, "ALLOW", tr=False, ext=False, n_known=0)
    assert mod.trigger_C(yes) is True and mod.trigger_C(no) is True


def test_B_requires_position_and_mechanism_provenance(mod):
    assert mod.trigger_B(_dec(0, "ALLOW", tr=True, ext=True, n_known=3)) is False  # position gate
    assert mod.trigger_B(_dec(1, "ALLOW", tr=False, ext=False, n_known=2)) is False  # no mechanism signal
    assert mod.trigger_B(_dec(1, "ALLOW", tr=True, n_known=1)) is False  # not multi-origin
    assert mod.trigger_B(_dec(1, "ALLOW", tr=True, n_known=2)) is True


# ---------------------------------------------------------------- confound + selection

def test_declared_confound_B_and_C_coincide_on_frozen_data(selection):
    b = selection["activation_reports"]["B"]["total_activations"]
    c = selection["activation_reports"]["C"]["total_activations"]
    assert b == c == 45
    assert selection["explicit_decision_on_mechanism_awareness"].startswith("NO measurable utility")


def test_activation_audit_fields_present(selection):
    a = selection["activation_reports"]["B"]
    for key in ("total_activations", "first_vs_subsequent", "tool_result_vs_external_category",
                "tool_category_breakdown", "tool_category_aggregate", "single_vs_multi_origin",
                "unknown_provenance_activations", "decision_transitions",
                "retrospective_label_composition", "label_use_note"):
        assert key in a
    assert a["first_vs_subsequent"] == {"first": 0, "subsequent": 45}
    assert a["decision_transitions"] == {"ALLOW->ESCALATE": 45}
    assert a["retrospective_label_composition"] == {"benign": 31, "attack": 14}


# ---------------------------------------------------------------- metrics §6 (3F conventions)

def test_metric_conventions_violations_and_autonomy(mod):
    sub = [("attack", "ALLOW"), ("attack", "BLOCK"), ("benign", "BLOCK"), ("benign", "ESCALATE")]
    m = mod.metrics(sub, "decision")
    assert m["violations"] == 1 + 1  # attack escape + benign block
    assert m["autonomy"] == 3 / 4  # (n - escalations)/n, one escalation in the sample
    assert m["attack"]["escape_rate"] == 0.5 and m["benign"]["block_rate"] == 0.5


def test_efficiency_na_rule_on_zero_denominators(mod):
    base = {"attack": {"escape": 5, "escalate": 0}, "benign": {"escalate": 0}, "total_escalations": 0}
    cand = {"attack": {"escape": 5, "escalate": 0}, "benign": {"escalate": 0}, "total_escalations": 0}
    e = mod.efficiency(base, cand)
    assert e["attack_escapes_prevented"] == 0 and e["E_attack"] is None and e["E_benign_cost"] is None


def test_efficiency_matches_3f_formula(mod):
    base = {"attack": {"escape": 14, "escalate": 0}, "benign": {"escalate": 12}, "total_escalations": 22}
    cand = {"attack": {"escape": 0, "escalate": 14}, "benign": {"escalate": 43}, "total_escalations": 67}
    e = mod.efficiency(base, cand)
    assert e["attack_escapes_prevented"] == 14 and e["additional_escalations"] == 45
    assert e["additional_benign_escalations"] == 31
    assert abs(e["E_attack"] - 14 / 45) < 1e-9
    assert abs(e["E_benign_cost"] - 31 / 14) < 1e-9


def test_evaluation_levels_and_hard_rule(selection):
    for cfg in ("A", "B", "C"):
        ev = selection["evaluation"][cfg]
        assert ev["n_decisions"] == 347 and ev["n_cases"] == 302
        for lvl in ("decision_level", "case_level", "first_decisions_only"):
            assert ev[lvl]["benign"]["block"] == 0, f"benign block in {cfg}/{lvl} violates the hard rule"
    # B/C keep the 14 first-decision escapes (honest accounting) while removing case-level final escapes
    for cfg in ("B", "C"):
        assert selection["evaluation"][cfg]["first_decisions_only"]["attack"]["escape"] == 14
        assert selection["evaluation"][cfg]["case_level"]["attack"]["escape"] == 0


def test_label_permutation_changes_only_retrospective_fields(mod, data):
    _, decs = data
    flipped = []
    for d in decs:
        d2 = dict(d)
        d2["label"] = "benign" if d["label"] == "attack" else "attack"
        flipped.append(d2)
    base_out, base_act = mod.apply_policy(decs, mod.trigger_B)
    flip_out, flip_act = mod.apply_policy(flipped, mod.trigger_B)
    assert [(o["case_id"], o["decision_idx"], o["outcome"]) for o in base_out] == \
        [(o["case_id"], o["decision_idx"], o["outcome"]) for o in flip_out]
    ka = [(a["case_id"], a["decision_idx"]) for a in base_act]
    kb = [(a["case_id"], a["decision_idx"]) for a in flip_act]
    assert ka == kb


# ---------------------------------------------------------------- deliverables

def test_deliverables_and_manifest_complete():
    for p in (SEL, ACT, RES / "3G_B_policy_selection.md", RES / "3G_B_activation_report.md", MAN):
        assert p.exists(), p
    man = json.loads(MAN.read_text(encoding="utf-8"))
    assert man["no_sweep"] and "B" in man["policy_config"] and "C" in man["policy_config"]
    sel = json.loads(SEL.read_text(encoding="utf-8"))
    script = GU / "scripts" / "run_3g_b_policy_selection.py"
    assert sel["source_hashes"]["gate-union/scripts/run_3g_b_policy_selection.py"] == \
        hashlib.sha256(script.read_bytes()).hexdigest()
