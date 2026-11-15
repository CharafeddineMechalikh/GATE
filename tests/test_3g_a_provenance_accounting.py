"""3G-A: tests for provenance accounting and temporal availability of the DEV audit.

Covers:
  - ratio(): explicit numerator/denominator; zero denominator -> None (N/A, never 100%)
  - snapshot(): monitor-available provenance levels from agent state
  - classify(): provenance-condition labels used by the audit
  - temporal availability: a segment added only AFTER a decision is never counted for it
    (simulated by snapshotting state before/after an ingestion event)
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "gate-union" / "scripts"))

from run_3g_a_dev_audit import classify, ratio, snapshot  # noqa: E402
from gate.core.models import AgentState  # noqa: E402


def test_ratio_zero_denominator_is_none_not_100pct():
    r = ratio(0, 0)
    assert r == {"numerator": 0, "denominator": 0, "ratio": None}
    r2 = ratio(3, 4)
    assert r2["ratio"] == 0.75 and r2["numerator"] == 3 and r2["denominator"] == 4


def test_snapshot_empty_state_has_no_known_origins():
    st = AgentState(agent_id="t")
    s = snapshot(st)
    assert s["segments_n"] == 0
    assert s["known_origins"] == []
    assert not s["has_user_instruction"] and not s["has_tool_result"]
    assert classify(s) == "no_known_provenance"


def test_snapshot_user_instruction_only():
    st = AgentState(agent_id="t")
    st.add_segment("user_instruction", "initial_context", known=True)
    s = snapshot(st)
    assert s["has_user_instruction"] and s["n_known_origins"] == 1
    assert s["has_external_document"] is False and s["has_tool_result"] is False
    assert classify(s) == "user_instruction_only"


def test_snapshot_tool_result_and_external_document():
    st = AgentState(agent_id="t")
    st.add_segment("tool_result", "tool_ingestion", known=True)
    assert classify(snapshot(st)) == "tool_result_known"
    st.add_segment("external_document", "initial_context", known=True,
                   parent_segments=["x"], transformation="environment_vector_substitution")
    s = snapshot(st)
    # external_document takes precedence in the condition ordering (policy-relevant exposure)
    assert classify(s) == "external_document_known"
    assert s["n_known_origins"] == 2 and s["unknown_segments_n"] == 0


def test_snapshot_unknown_and_transformed_unresolved():
    st = AgentState(agent_id="t")
    st.add_segment("unknown", "initial_context", known=False)
    s = snapshot(st)
    assert s["unknown_segments_n"] == 1
    assert classify(s) == "no_known_provenance"  # recorded unknown is NOT a known origin
    st.add_segment("unknown", "initial_context", known=False,
                   parent_segments=["p1", "p2"], transformation="summarization")
    s2 = snapshot(st)
    assert s2["transformed_unresolved_n"] == 1  # transformed segment with unresolved origin counted


def test_environment_data_classification_single_and_multi_origin():
    st = AgentState(agent_id="t")
    st.add_segment("environment_data", "initial_context", known=True)
    assert classify(snapshot(st)) == "environment_data_known"
    st.add_segment("user_instruction", "initial_context", known=True)
    s = snapshot(st)
    assert classify(s) == "environment_data_plus_other"
    assert s["n_known_origins"] == 2


def test_temporal_availability_pre_decision_only():
    """A tool_result segment created by an ingestion event AFTER decision 1 must appear in the
    pre-decision-2 snapshot but must NOT retroactively appear in decision 1's snapshot."""
    st = AgentState(agent_id="t")
    st.add_segment("user_instruction", "initial_context", known=True)
    pre1 = snapshot(st)                      # taken BEFORE validate_action #1
    assert pre1["has_tool_result"] is False and classify(pre1) == "user_instruction_only"
    # ingestion event between decisions (genuine runtime semantics: validate_result -> add segment)
    st.add_segment("tool_result", "tool_ingestion", known=True)
    pre2 = snapshot(st)                      # taken BEFORE validate_action #2
    assert pre2["has_tool_result"] is True and classify(pre2) == "tool_result_known"
    # decision 1's snapshot is immutable evidence: it must not change after the ingestion
    assert pre1["has_tool_result"] is False


def test_taint_sources_snapshot_preserved():
    st = AgentState(agent_id="t")
    st.add_segment("user_instruction", "initial_context", known=True)
    st.add_taint("tool_result", tool_name="db")
    s = snapshot(st)
    assert "tool_result" in s["taint_sources"] and "user" in s["taint_sources"]
