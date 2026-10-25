# tests/test_legacy_policy_engines.py
"""Tests for the standalone yaml-driven policy engines.

These modules (``gate.policy_engine`` and ``gate.advanced_policy_engine``) are
documented as lightweight utilities that adapters can adopt independently of the
full :mod:`gate.security` pipeline.  They are exercised here against the real
dispatch code, with no stubbing of the functions under test.
"""

from dataclasses import dataclass, field
from typing import List

import pytest

from gate import policy_engine
from gate import advanced_policy_engine as adv


@dataclass
class _Contract:
    permissions: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# gate.policy_engine
# ---------------------------------------------------------------------------

class TestLoadPolicy:
    def test_missing_file_denies_everything(self, tmp_path):
        assert policy_engine.load_policy(tmp_path / "nope.yaml") == {}

    def test_reads_permissions_key(self, tmp_path):
        p = tmp_path / "pol.yaml"
        p.write_text("permissions:\n  fs:read: [open_file]\n", encoding="utf-8")
        assert policy_engine.load_policy(p) == {"fs:read": ["open_file"]}

    def test_empty_file_yields_empty_dict(self, tmp_path):
        p = tmp_path / "empty.yaml"
        p.write_text("", encoding="utf-8")
        assert policy_engine.load_policy(p) == {}

    def test_file_without_permissions_key(self, tmp_path):
        p = tmp_path / "other.yaml"
        p.write_text("something: else\n", encoding="utf-8")
        assert policy_engine.load_policy(p) == {}

    def test_import_time_cache_matches_bundled_policy(self):
        # The shipped policy.yaml grants network:outbound to any tool.
        assert policy_engine._POLICY_CACHE.get("network:outbound") == ["*"]


class TestIsAllowed:
    def test_wildcard_allows_any_tool(self):
        assert policy_engine.is_allowed("fs:read", "anything", {"fs:read": ["*"]})

    def test_membership_allowed(self):
        assert policy_engine.is_allowed("fs:write", "write_demo_file",
                                        {"fs:write": ["write_demo_file"]})

    def test_membership_denied(self):
        assert not policy_engine.is_allowed("fs:write", "rm_rf",
                                            {"fs:write": ["write_demo_file"]})

    def test_missing_permission_denied(self):
        assert not policy_engine.is_allowed("unknown", "t", {})


class TestCheckPermission:
    def test_all_permissions_allowed(self, monkeypatch):
        monkeypatch.setattr(policy_engine, "_POLICY_CACHE",
                            {"a": ["*"], "b": ["tool_x"]})
        assert policy_engine.check_permission(_Contract(["a", "b"]), "tool_x")

    def test_one_denied_permission_blocks(self, monkeypatch):
        monkeypatch.setattr(policy_engine, "_POLICY_CACHE",
                            {"a": ["*"], "b": ["other"]})
        assert not policy_engine.check_permission(_Contract(["a", "b"]), "tool_x")

    def test_empty_permissions_default_allow(self, monkeypatch):
        monkeypatch.setattr(policy_engine, "_POLICY_CACHE", {})
        assert policy_engine.check_permission(_Contract([]), "tool_x")


# ---------------------------------------------------------------------------
# gate.advanced_policy_engine
# ---------------------------------------------------------------------------

class TestStepBudget:
    def test_reset_and_get(self):
        adv.reset_step_count()
        assert adv.get_step_count() == 0

    def test_set_max_steps(self):
        original = adv.MAX_STEPS
        try:
            adv.set_max_steps(3)
            assert adv.MAX_STEPS == 3
        finally:
            adv.MAX_STEPS = original

    def test_check_permission_increments_counter(self, monkeypatch):
        monkeypatch.setattr(policy_engine, "_POLICY_CACHE", {"a": ["*"]})
        adv.reset_step_count()
        adv.set_max_steps(10)
        assert adv.check_permission(_Contract(["a"]), "t") is True
        assert adv.get_step_count() == 1
        assert adv.check_permission(_Contract(["a"]), "t") is True
        assert adv.get_step_count() == 2

    def test_check_permission_denied_at_budget(self, monkeypatch):
        monkeypatch.setattr(policy_engine, "_POLICY_CACHE", {"a": ["*"]})
        adv.reset_step_count()
        adv.set_max_steps(1)
        assert adv.check_permission(_Contract(["a"]), "t") is True
        assert adv.check_permission(_Contract(["a"]), "t") is False

    def test_permission_denied_does_not_consume_step(self, monkeypatch):
        monkeypatch.setattr(policy_engine, "_POLICY_CACHE", {"a": ["allowed"]})
        adv.reset_step_count()
        adv.set_max_steps(5)
        assert adv.check_permission(_Contract(["a"]), "denied_tool") is False
        assert adv.get_step_count() == 0


class TestConditionHooks:
    def test_precondition_none_is_true(self):
        assert adv.run_precondition(None, {"x": 1}) is True

    def test_precondition_true(self):
        assert adv.run_precondition(lambda args: args["x"] > 0, {"x": 5}) is True

    def test_precondition_false(self):
        assert adv.run_precondition(lambda args: args["x"] > 0, {"x": -1}) is False

    def test_postcondition_none_is_true(self):
        assert adv.run_postcondition(None, "result") is True

    def test_postcondition_true(self):
        assert adv.run_postcondition(lambda r: r == "ok", "ok") is True

    def test_postcondition_false(self):
        assert adv.run_postcondition(lambda r: r == "ok", "bad") is False


class TestSemanticReexport:
    def test_semantic_check_is_exported(self):
        from gate.semantic_check import semantic_check
        assert adv.semantic_check is semantic_check

    def test_module_exports(self):
        for name in ("MAX_STEPS", "check_permission", "semantic_check",
                     "run_precondition", "run_postcondition",
                     "reset_step_count", "get_step_count", "set_max_steps"):
            assert name in adv.__all__


@pytest.fixture(autouse=True)
def _restore_budget():
    yield
    adv.MAX_STEPS = 1000
    adv.reset_step_count()
