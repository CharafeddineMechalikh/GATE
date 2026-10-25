# tests/test_core_config_models.py
"""Tests for :mod:`gate.core.config` and :mod:`gate.core.models`.

Covers the pure data-model helpers (serialisation, usage accounting, semantic
scoring) and the configuration validation branches, including every arm of
``DataScope.check_access`` and each guard in ``gateConfig.validate``.
"""

import numpy as np
import pytest

from gate.core.config import (
    DataScope, ResourceBudget, AgentProfile, SemanticThresholds, gateConfig,
)
from gate.core.models import (
    ToolCall, ResourceMetrics, AgentState, SemanticScore, ValidationResult,
)


# ---------------------------------------------------------------------------
# DataScope.check_access
# ---------------------------------------------------------------------------

class TestCheckAccess:
    def test_forbidden_pattern_blocks(self):
        scope = DataScope()
        assert scope.check_access("http://169.254.169.254/meta") is False

    def test_exact_endpoint_match(self):
        scope = DataScope(allowed_api_endpoints={"https://api.x.com"})
        assert scope.check_access("https://api.x.com") is True

    def test_host_only_match(self):
        scope = DataScope(allowed_api_endpoints={"https://api.x.com"})
        assert scope.check_access("api.x.com") is True

    def test_subdomain_suffix_match(self):
        scope = DataScope(allowed_api_endpoints={"https://api.x.com"})
        assert scope.check_access("https://sub.api.x.com") is True

    def test_trailing_slash_normalised(self):
        # The resource is right-stripped of slashes before comparison.
        scope = DataScope(allowed_api_endpoints={"https://api.x.com"})
        assert scope.check_access("https://api.x.com/") is True

    def test_database_with_open_tables(self):
        scope = DataScope(allowed_databases={"db1"})
        assert scope.check_access("db1.users") is True

    def test_database_with_specific_table(self):
        scope = DataScope(allowed_databases={"db1"},
                          allowed_tables={"db1": {"users"}})
        assert scope.check_access("db1.users") is True

    def test_database_table_not_listed(self):
        scope = DataScope(allowed_databases={"db1"},
                          allowed_tables={"db1": {"users"}})
        assert scope.check_access("db1.secrets") is False

    def test_unknown_database_denied(self):
        scope = DataScope(allowed_databases={"db1"})
        assert scope.check_access("db2.users") is False

    def test_unmatched_resource_denied(self):
        scope = DataScope()
        assert scope.check_access("random_string") is False


# ---------------------------------------------------------------------------
# gateConfig.validate
# ---------------------------------------------------------------------------

def _profile(agent_id="agent-1", max_steps=50):
    return AgentProfile(
        agent_id=agent_id, role="assistant", allowed_tools={"tool"},
        resource_budget=ResourceBudget(max_steps=max_steps),
    )


class TestConfigValidate:
    def test_valid_config_passes(self):
        cfg = gateConfig(agent_profile=_profile())
        cfg.validate()

    def test_missing_agent_id(self):
        cfg = gateConfig(agent_profile=_profile(agent_id=""))
        with pytest.raises(ValueError, match="agent_id"):
            cfg.validate()

    def test_threshold_order_enforced(self):
        cfg = gateConfig(agent_profile=_profile())
        cfg.semantic_thresholds = SemanticThresholds(
            sss_safe_threshold=0.4, sss_block_threshold=0.5)
        with pytest.raises(ValueError, match="sss_safe_threshold"):
            cfg.validate()

    def test_max_steps_positive(self):
        cfg = gateConfig(agent_profile=_profile(max_steps=0))
        with pytest.raises(ValueError, match="max_steps"):
            cfg.validate()

    def test_timeout_positive(self):
        cfg = gateConfig(agent_profile=_profile())
        cfg.timeout_seconds = 0
        with pytest.raises(ValueError, match="timeout_seconds"):
            cfg.validate()

    def test_retry_attempts_at_least_one(self):
        cfg = gateConfig(agent_profile=_profile())
        cfg.retry_config.max_attempts = 0
        with pytest.raises(ValueError, match="max_attempts"):
            cfg.validate()

    def test_is_check_enabled(self):
        cfg = gateConfig(agent_profile=_profile(), enabled_checks={"dfa"})
        assert cfg.is_check_enabled("dfa") is True
        assert cfg.is_check_enabled("semantic") is False


# ---------------------------------------------------------------------------
# Core models
# ---------------------------------------------------------------------------

class TestToolCall:
    def test_to_dict_and_json(self):
        tc = ToolCall(tool_name="read", tool_args={"p": "/x"}, call_id="c1",
                      agent_id="a1", metadata={"k": "v"})
        d = tc.to_dict()
        assert d["tool_name"] == "read"
        assert d["call_id"] == "c1"
        assert "timestamp" in d
        import json
        assert json.loads(tc.to_json())["agent_id"] == "a1"

    def test_from_dict_roundtrip(self):
        original = ToolCall(tool_name="read", tool_args={"p": "/x"}, call_id="c1")
        restored = ToolCall.from_dict(original.to_dict())
        assert restored.tool_name == "read"
        assert restored.call_id == "c1"
        assert restored.tool_args == {"p": "/x"}

    def test_from_dict_defaults(self):
        restored = ToolCall.from_dict(
            {"tool_name": "t", "tool_args": {}, "call_id": "c"})
        assert restored.timestamp is not None
        assert restored.metadata == {}

    def test_action_description(self):
        tc = ToolCall(tool_name="read", tool_args={"a": 1, "b": 2}, call_id="c")
        desc = tc.get_action_description()
        assert desc.startswith("Call read(")
        assert "a=1" in desc and "b=2" in desc


class TestResourceMetrics:
    def test_add_usage_accumulates(self):
        m = ResourceMetrics()
        m.add_usage(tokens=10, api_calls=1, compute_time=2.5, cost=0.3)
        m.add_usage(tokens=5, api_calls=2, compute_time=1.0, cost=0.2)
        assert m.tokens_used == 15
        assert m.api_calls == 3
        assert m.compute_time_seconds == 3.5
        assert m.cost_usd == pytest.approx(0.5)


class TestAgentState:
    def test_add_tool_call_and_history(self):
        st = AgentState(agent_id="a1")
        tc = ToolCall(tool_name="t", tool_args={}, call_id="c")
        st.add_tool_call(tc)
        assert st.step_count == 1
        assert st.tool_history[-1] is tc

    def test_increment_loop(self):
        st = AgentState(agent_id="a1")
        st.increment_loop("ACTING")
        st.increment_loop("ACTING")
        assert st.loop_count["ACTING"] == 2

    def test_get_recent_tool_calls(self):
        st = AgentState(agent_id="a1")
        for i in range(7):
            st.add_tool_call(ToolCall(tool_name="t", tool_args={}, call_id=str(i)))
        recent = st.get_recent_tool_calls(3)
        assert len(recent) == 3
        assert [c.call_id for c in recent] == ["4", "5", "6"]

    def test_update_timestamp(self):
        st = AgentState(agent_id="a1")
        before = st.last_updated
        st.update_timestamp()
        assert st.last_updated >= before

    def test_to_dict(self):
        st = AgentState(agent_id="a1", trust_level=0.5, current_phase="ACTING")
        st.resource_usage.add_usage(tokens=99)
        st.add_tool_call(ToolCall(tool_name="t", tool_args={}, call_id="c"))
        d = st.to_dict()
        assert d["agent_id"] == "a1"
        assert d["resource_usage"]["tokens_used"] == 99
        assert d["step_count"] == 1
        assert len(d["tool_history"]) == 1


class TestSemanticScore:
    def _score(self, decision):
        return SemanticScore(sss_value=0.6, drift_to_intent=0.1,
                             drift_to_harm=0.2, drift_to_safe=0.3,
                             decision=decision, details={})

    def test_is_safe_allow(self):
        assert self._score("ALLOW").is_safe() is True

    def test_is_safe_block(self):
        assert self._score("BLOCK").is_safe() is False


class TestValidationResult:
    def test_defaults(self):
        r = ValidationResult(is_allowed=True)
        assert r.reason is None
        assert r.checks_passed == []
        assert r.escalated is False
