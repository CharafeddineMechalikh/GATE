"""3G-A2: automated tests for the frozen multi-step DEV trajectory dataset construction.

Validation items (F.1–F.10 from the 3G-A2 authorization), plus label-blindness and the N/A rule:
  F.1  pre-decision snapshot isolation
  F.2  no retroactive provenance
  F.3  correct tool-result propagation
  F.4  unknown-origin preservation
  F.5  transformation lineage preservation (incl. 3B-A constraint A: child never inherits parent origin/known)
  F.6  segment identity stability
  F.7  reproducibility (two-pass byte-identity recorded at build time; artifact hash integrity here)
  F.8  no contamination from non-DEV data
  F.9  execution-modality accounting (uniform, explicit, not silently mixed)
  F.10 baseline decisions unmodified (first decisions == frozen R0)
  +    label-blindness: labels only under `audit_labels_retrospective_only`; continuation is not
       label-driven (block-labeled cases DO continue); accounting invariant under label permutation
  +    N/A rule: zero denominators report ratio None (never 100%)
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

DS = RES / "3G_A2_DEV_trajectory_dataset.jsonl"
MAN = RES / "3G_A2_DEV_trajectory_manifest.json"
COV = RES / "3G_A2_DEV_coverage_report.json"
VAL = RES / "3G_A2_validation.json"
R0 = RES / "freeze3A_R0.A5_full.jsonl"


@pytest.fixture(scope="module")
def trajectories():
    return [json.loads(l) for l in DS.read_text(encoding="utf-8").splitlines() if l.strip()]


@pytest.fixture(scope="module")
def manifest():
    return json.loads(MAN.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def coverage():
    return json.loads(COV.read_text(encoding="utf-8"))["coverage"]


@pytest.fixture(scope="module")
def full_coverage():
    return json.loads(COV.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def validation():
    return json.loads(VAL.read_text(encoding="utf-8"))


# ---------------------------------------------------------------- dataset shape

def test_dataset_has_all_302_dev_cases_no_selection(trajectories):
    assert len(trajectories) == 302
    assert all(set(t) >= {"trajectory_id", "source_case_id", "decisions", "execution_modality",
                          "terminated_after_first_decision", "termination_reason",
                          "audit_labels_retrospective_only"} for t in trajectories)
    assert all(t["trajectory_id"] == f"dev3ga2:{t['source_case_id']}" for t in trajectories)


def test_decision_indices_max_two(trajectories):
    for t in trajectories:
        assert [d["decision_idx"] for d in t["decisions"]] == list(range(len(t["decisions"])))
        assert 1 <= len(t["decisions"]) <= 2


# ---------------------------------------------------------------- F.1/F.2 temporal

def test_f1_pre_decision_snapshots_present_and_marked(trajectories):
    for t in trajectories:
        for d in t["decisions"]:
            snap = d["pre_decision_snapshot"]
            assert snap["available_before_decision"] is True
            assert snap["exposure_evidence"] == "monitor_available_only"
            for key in ("segments", "segment_ids", "parent_segment_ids", "transformations",
                        "newly_ingested_since_previous_decision", "tool_result_propagation",
                        "unknown_segments_n", "transformed_unresolved_n", "n_known_origins"):
                assert key in snap


def test_f2_no_retroactive_provenance(trajectories):
    """Decision 1's snapshot must never contain a segment ingested between the decisions; provenance
    is append-only: decision 2's segments = decision 1's segments + newly ingested."""
    for t in trajectories:
        if len(t["decisions"]) < 2:
            continue
        s1, s2 = t["decisions"][0]["pre_decision_snapshot"], t["decisions"][1]["pre_decision_snapshot"]
        ids1, ids2 = set(s1["segment_ids"]), set(s2["segment_ids"])
        assert s1["newly_ingested_since_previous_decision"] == []  # nothing before decision 1
        newly = set(s2["newly_ingested_since_previous_decision"])
        assert newly, "second decision must record what was ingested between decisions"
        assert not (ids1 & newly), "newly-ingested segments must not retro-inform decision 1"
        assert ids2 == ids1 | newly, "provenance must be append-only across decisions"


# ---------------------------------------------------------------- F.3 propagation

def test_f3_tool_result_propagation_between_decisions(trajectories, coverage):
    """validate_result must deliver a known ingestion segment to decision 2 (runtime 3C-H semantics:
    tool_result or external_document depending on the tool), and never to decision 1."""
    n_multi = 0
    for t in trajectories:
        if len(t["decisions"]) < 2:
            assert t["decisions"][0]["pre_decision_snapshot"]["has_tool_result"] is False
            continue
        n_multi += 1
        s2 = t["decisions"][1]["pre_decision_snapshot"]
        ingested = [s for s in s2["segments"] if s["local_segment_id"] in s2["newly_ingested_since_previous_decision"]]
        assert any(s["origin"] in ("tool_result", "external_document") and s["known"] for s in ingested)
    assert n_multi == coverage["cases_producing_subsequent_decisions"]["numerator"] == 45
    assert coverage["tool_result_known"]["first"]["numerator"] == 0


def test_f3_propagation_counts_match_validation(coverage, validation):
    prop = validation["correct_tool_result_propagation"]
    assert prop["numerator"] + coverage["external_document_known"]["subsequent"]["numerator"] >= \
        coverage["tool_result_known"]["subsequent"]["numerator"]
    assert prop["denominator"] == coverage["cases_producing_subsequent_decisions"]["numerator"]


# ---------------------------------------------------------------- F.4/F.5 unknown & lineage

def test_f4_unknown_origin_preservation_unit_level():
    from gate.core.models import AgentState
    from run_3g_a_dev_audit import snapshot
    st = AgentState(agent_id="t")
    st.add_segment("unknown", "initial_context", known=False)
    s = snapshot(st)
    assert s["unknown_segments_n"] == 1
    assert s["known_origins"] == []  # recorded unknown is NOT a known origin
    seg = st.provenance["segments"][0]
    assert seg["known"] is False and seg["origin"] == "unknown"


def test_f5_transformation_lineage_unit_level_3b_a_constraint_a():
    """Child segment must preserve lineage but NEVER inherit parent origin/known-ness."""
    from gate.core.models import AgentState
    st = AgentState(agent_id="t")
    st.add_segment("external_document", "initial_context", known=True)
    st.add_segment("unknown", "tool_ingestion", known=False,
                   parent_segments=["seg_000"], transformation="summarization")
    parent, child = st.provenance["segments"]
    assert child["parent_segments"] == ["seg_000"] and child["transformation"] == "summarization"
    assert child["origin"] == "unknown" and child["known"] is False  # not inherited from parent
    assert parent["origin"] == "external_document" and parent["known"] is True  # parent preserved


def test_f5_dataset_lineage_consistency(trajectories):
    """Every recorded parent id is a real segment id in the same snapshot; transformations listed."""
    n_lineage = 0
    for t in trajectories:
        for d in t["decisions"]:
            snap = d["pre_decision_snapshot"]
            ids = set(snap["segment_ids"])
            for p in snap["parent_segment_ids"]:
                assert p in ids
            n_lineage += len(snap["transformations"])
    # none arise under this modality (no fabricated transformations); unit tests cover the schema
    assert n_lineage == 0


# ---------------------------------------------------------------- F.6 identity stability

def test_f6_segment_identity_stable_and_append_only(trajectories):
    for t in trajectories:
        for d in t["decisions"]:
            snap = d["pre_decision_snapshot"]
            assert snap["segment_ids"] == [s["local_segment_id"] for s in snap["segments"]]
            for i, s in enumerate(snap["segments"]):
                assert s["local_segment_id"] == f"s{i}:{s.get('origin')}:{s.get('boundary')}"
                assert "ts" not in s, "wall-clock ts stripped for reproducibility"


# ---------------------------------------------------------------- F.7 reproducibility / integrity

def test_f7_dataset_hash_matches_manifest(manifest):
    h = hashlib.sha256(DS.read_bytes()).hexdigest()
    assert manifest["dataset_sha256"] == h
    assert manifest["n_trajectories"] == 302


def test_f7_validation_records_two_pass_identity(validation):
    assert validation["reproducibility_two_pass_identical"] is True
    assert validation["all_pass"] is True


# ---------------------------------------------------------------- F.8 contamination

def test_f8_no_non_dev_contamination(trajectories, validation):
    dev = {json.loads(l)["case_id"] for l in (GU / "splits" / "dev.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()}
    for split in ("calibration", "test"):
        p = GU / "splits" / f"{split}.jsonl"
        if p.exists():
            ids = {json.loads(l)["case_id"] for l in p.read_text(encoding="utf-8").splitlines() if l.strip()}
            assert not {t["source_case_id"] for t in trajectories} & ids
    src = [t["source_case_id"] for t in trajectories]
    assert len(src) == len(set(src)) == 302
    assert set(src) <= dev
    assert validation["no_non_dev_contamination"]["overlap_with_reserved_holdout"] == 0


# ---------------------------------------------------------------- F.9 modality accounting

def test_f9_uniform_execution_modality(trajectories, manifest, validation):
    for t in trajectories:
        m = t["execution_modality"]
        assert m["tool_results"] == "deterministic_simulated"
        assert m["payload"] == "{'status':'ok'}"
        assert m["not_reproduced"], "simulation limits must be documented on every trajectory"
    assert validation["execution_modality_accounting"]["uniform_modality"] is True
    assert manifest["protocol"]["modality"] == "deterministic_simulated"
    assert manifest["protocol"]["selection"] .startswith("ALL 302 frozen DEV cases")


# ---------------------------------------------------------------- F.10 baseline unmodified

def test_f10_first_decisions_equal_frozen_r0(trajectories, validation):
    r0 = {}
    for l in R0.read_text(encoding="utf-8").splitlines():
        if l.strip():
            r = json.loads(l)
            r0[r.get("case_id") or r["id"]] = r
    for t in trajectories:
        o = r0[t["source_case_id"]]
        d0 = t["decisions"][0]
        assert o["outcome"] == d0["outcome"], f"first decision drifted for {t['source_case_id']}"
        if o.get("sss") is not None:
            assert d0["semantic"] is not None
            assert abs(float(o["sss"]) - d0["semantic"]["sss"]) <= 1e-4
    assert validation["baseline_decisions_unmodified"]["pass"] is True
    assert validation["baseline_decisions_unmodified"]["n_compared"] == 302


# ---------------------------------------------------------------- label-blindness

def test_labels_appear_only_under_audit_field(trajectories):
    LABEL_KEYS = {"expected_outcome", "attack_family", "source_dataset"}
    for t in trajectories:
        for key in t:
            if key != "audit_labels_retrospective_only":
                assert key not in LABEL_KEYS, f"label material leaked into `{key}`"
        for d in t["decisions"]:
            assert LABEL_KEYS.isdisjoint(d)
            assert LABEL_KEYS.isdisjoint(d["pre_decision_snapshot"])


def test_continuation_is_not_label_driven(trajectories):
    """If continuation were selected on labels, no block-labeled case would reach a second decision.
    Selection must depend only on the first DECISION (label-blind continue condition)."""
    multi_block = [t for t in trajectories
                   if len(t["decisions"]) > 1
                   and t["audit_labels_retrospective_only"]["expected_outcome"] == "block"]
    assert multi_block, "label-blind continuation requires block-labeled cases among multi-step trajectories"
    # and the continue condition matches the recorded first decision, never the label
    for t in trajectories:
        d0 = t["decisions"][0]
        continued = len(t["decisions"]) > 1
        assert continued == (d0["outcome"] == "ALLOW")


def test_accounting_invariant_under_label_permutation():
    """Permuting expected_outcome across trajectories must not change any decision record or
    coverage number except the retrospective audit field."""
    from run_3g_a2_trajectory_dataset import coverage, flatten_decisions
    trajs = [json.loads(l) for l in DS.read_text(encoding="utf-8").splitlines() if l.strip()]
    n_allow = sum(1 for t in trajs if t["audit_labels_retrospective_only"]["expected_outcome"] == "allow")
    perm = {t["trajectory_id"]: ("block" if t["audit_labels_retrospective_only"]["expected_outcome"] == "allow" else "allow")
            for t in trajs[:n_allow] + trajs[n_allow:]}
    permuted = []
    for t in trajs:
        t2 = json.loads(json.dumps(t))
        t2["audit_labels_retrospective_only"]["expected_outcome"] = perm[t2["trajectory_id"]]
        permuted.append(t2)
    # decision records: identical except the audit field
    a, b = flatten_decisions(trajs), flatten_decisions(permuted)
    assert len(a) == len(b)
    for x, y in zip(a, b):
        assert {k: v for k, v in x.items() if k != "label"} == {k: v for k, v in y.items() if k != "label"}
    # coverage structure: identical except retrospective composition
    ca, cb = coverage(trajs), coverage(permuted)
    ca.pop("trajectories_total"), cb.pop("trajectories_total")
    assert json.dumps(ca, sort_keys=True) == json.dumps(cb, sort_keys=True)


# ---------------------------------------------------------------- N/A rule + selection bias

def test_na_rule_zero_denominator_never_100pct(coverage):
    for key in ("construction_coverage", "exposure_coverage",
                "injected_dependency_level", "injected_content_verified"):
        e = coverage[key]
        assert e["denominator"] == 0 and e["ratio"] is None and e["numerator"] == 0
        assert e["note"], "N/A must be explained, not silently reported"


def test_selection_bias_documented(full_coverage):
    note = full_coverage["composition_retrospective"]["representativeness_note"]
    assert "Selection bias" in note and "over-represents" in note
    comp = full_coverage["composition_retrospective"]
    label_buckets = {k: v for k, v in comp.items() if isinstance(v, dict) and "trajectories" in v}
    # every trajectory accounted exactly once across all observed label values (allow/block/escalate)
    assert sum(c["trajectories"] for c in label_buckets.values()) == 302


def test_coverage_splits_first_vs_subsequent(coverage):
    for key in ("tool_result_known", "external_document_known", "environment_data_known",
                "multi_origin", "no_relevant_signal", "unknown_or_transformed_unresolved"):
        assert set(coverage[key]) >= {"first", "subsequent"}
        for side in ("first", "subsequent"):
            r = coverage[key][side]
            assert {"numerator", "denominator", "ratio"} <= set(r)
            assert r["numerator"] <= r["denominator"]
