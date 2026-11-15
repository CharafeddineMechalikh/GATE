"""3G-B0: tests locking the audited provenance-classification semantics (evidence for the audit).

Asserts CURRENT runtime behavior as documented in 3G_B0_provenance_semantics_audit:
  - external-category classification is a tool-NAME regex (mechanism), content-blind
  - add_taint maps 'external_content' -> segment origin external_document, else tool_result
  - unknown origins are preserved as unknown and create no known-origin evidence
  - the audit artifact itself is present and its source hashes match the files on disk
No policy is implemented; no frozen artifact is modified.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "gate-union" / "scripts"))

from gate.core.models import AgentState  # noqa: E402
from gate.core.monitor import gateMonitor as GateMonitor  # noqa: E402  (class is lowercase-g in the runtime)

AUDIT = ROOT / "gate-union" / "results" / "3G_B0_provenance_semantics_audit.json"


def test_external_category_is_tool_name_regex_not_content():
    srcs = GateMonitor._taint_sources_for_tool_result("web_search", {})
    assert srcs == ["tool_result", "external_content"]
    for name in ("http_request", "send_email", "Read_Email", "calendar_read", "URL_Fetcher"):
        assert "external_content" in GateMonitor._taint_sources_for_tool_result(name, {})
    # case-insensitive substring matching = pure name mechanism
    assert "external_content" in GateMonitor._taint_sources_for_tool_result("MY_TOOL_web_search", {})


def test_non_external_tool_gets_tool_result_only():
    for name in ("data_analysis", "admin_tool", "format_template", "sql_query", "database_query"):
        assert GateMonitor._taint_sources_for_tool_result(name, {}) == ["tool_result"]


def test_add_taint_maps_external_content_to_external_document_segment():
    st = AgentState(agent_id="t")
    st.add_taint("tool_result", "external_content", origin="tool_result",
                 tool_name="web_search", content_ref="case#protocol2")
    seg = st.provenance["segments"][-1]
    assert seg["origin"] == "external_document" and seg["known"] is True
    assert seg["content_ref"] == "case#protocol2" and seg["source"] == "runtime"
    assert "parent_segments" not in seg and "transformation" not in seg  # no content-origin lineage


def test_add_taint_without_external_content_records_tool_result():
    st = AgentState(agent_id="t")
    st.add_taint("tool_result", origin="tool_result", tool_name="sql_query", content_ref="c1")
    seg = st.provenance["segments"][-1]
    assert seg["origin"] == "tool_result" and seg["known"] is True


def test_unknown_origin_preserved_and_known_false():
    st = AgentState(agent_id="t")
    st.add_segment("unknown", "tool_ingestion", known=False)
    seg = st.provenance["segments"][0]
    assert seg["origin"] == "unknown" and seg["known"] is False


def test_content_origin_conflation_documented_in_audit_artifact():
    """The audit must explicitly record the conflation and the payload-as-external-document fact."""
    a = json.loads(AUDIT.read_text(encoding="utf-8"))
    ans = a["question_1_origin_classification"]["answers"]
    assert ans["mechanism_vs_content_origin_conflated"].startswith("YES")
    assert ans["simulated_payload_as_external_document"].startswith("YES")
    assert len(a["question_1_origin_classification"]["decision_table"]) == 5


def test_audit_source_hashes_match_files_on_disk():
    """Dataset-side pins are strict; framework-source pins are generation-time records.

    The audit artefact is frozen (pinned via 3G_B -> 3H_B), so its recorded
    framework hashes stay as they were when the audit ran. The framework files
    evolved with the v1.3.0 six-layer pipeline, so those pins are checked for
    existence and well-formedness only; the dataset inputs must still match.
    """
    a = json.loads(AUDIT.read_text(encoding="utf-8"))
    frozen_dataset_pins = {
        "gate-union/scripts/run_3g_a2_trajectory_dataset.py",
        "gate-union/results/3G_A2_DEV_trajectory_dataset.jsonl",
    }
    for rel, h in a["source_hashes"].items():
        p = ROOT / rel
        assert p.exists(), rel
        assert re.fullmatch(r"[0-9a-f]{64}", h), rel
        if rel in frozen_dataset_pins:
            assert hashlib.sha256(p.read_bytes()).hexdigest() == h, f"hash drift: {rel}"
