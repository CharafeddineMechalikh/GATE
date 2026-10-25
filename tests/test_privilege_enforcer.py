"""Tests for privilege enforcement and capability tokens."""

import time

import pytest

from gate.security.privilege_enforcer import CapabilityToken, DefaultPrivilegeEnforcer
from gate.core.config import (
    AgentProfile,
    DataScope,
    ResourceBudget,
)


def _profile(agent_id="a1"):
    return AgentProfile(
        agent_id=agent_id,
        role="reader",
        allowed_tools={"search", "read"},
        forbidden_tools={"delete"},
        data_scope=DataScope(
            allowed_databases={"db1"},
            allowed_api_endpoints={"https://api.example.com"},
        ),
        resource_budget=ResourceBudget(max_cost_usd=5.0),
    )


class TestCapabilityToken:
    def test_valid_without_expiry(self):
        assert CapabilityToken(agent_id="a", capabilities={"x"}).is_valid() is True

    def test_expired_is_invalid(self):
        token = CapabilityToken(
            agent_id="a", capabilities={"x"}, expires_at=time.time() - 1
        )
        assert token.is_valid() is False

    def test_revoke_sets_zero_expiry(self):
        token = CapabilityToken(agent_id="a", capabilities={"x"}, expires_at=time.time() + 100)
        token.revoke()
        assert token.is_valid() is False


class TestDefaultPrivilegeEnforcer:
    def setup_method(self):
        self.enforcer = DefaultPrivilegeEnforcer()
        self.enforcer.register_profile(_profile("a1"))

    def test_issue_and_check_permission(self):
        token = self.enforcer.issue_token("a1", {"search"}, ttl_seconds=60)
        assert token.agent_id == "a1"
        assert token.signature.startswith("sig-")
        assert self.enforcer.check_tool_permission("a1", "search") is True

    def test_issue_token_unknown_agent_raises(self):
        with pytest.raises(ValueError):
            self.enforcer.issue_token("ghost", {"search"})

    def test_check_permission_forbidden_tool(self):
        assert self.enforcer.check_tool_permission("a1", "delete") is False

    def test_check_permission_not_allowed_tool(self):
        assert self.enforcer.check_tool_permission("a1", "write") is False

    def test_check_permission_no_profile(self):
        assert self.enforcer.check_tool_permission("ghost", "search") is False

    def test_revoke_token(self):
        self.enforcer.issue_token("a1", {"search"})
        self.enforcer.revoke_token("a1")
        assert self.enforcer._tokens["a1"].is_valid() is False

    def test_revoke_unknown_token_noop(self):
        self.enforcer.revoke_token("ghost")

    def test_check_data_scope_allowed(self):
        assert self.enforcer.check_data_scope("a1", "https://api.example.com") is True

    def test_check_data_scope_denied(self):
        assert self.enforcer.check_data_scope("a1", "https://evil.example") is False

    def test_check_data_scope_no_profile(self):
        assert self.enforcer.check_data_scope("ghost", "db1.users") is False

    def test_check_resource_budget_within(self):
        assert self.enforcer.check_resource_budget("a1", 2.0) is True

    def test_check_resource_budget_exceeded(self):
        assert self.enforcer.check_resource_budget("a1", 100.0) is False

    def test_check_resource_budget_no_profile(self):
        assert self.enforcer.check_resource_budget("ghost", 1.0) is False

    def test_get_profile(self):
        assert self.enforcer.get_profile("a1").agent_id == "a1"
        assert self.enforcer.get_profile("ghost") is None

    def test_unregister_profile(self):
        self.enforcer.unregister_profile("a1")
        assert self.enforcer.get_profile("a1") is None

    def test_unregister_missing_profile_noop(self):
        self.enforcer.unregister_profile("ghost")

    def test_audit_trail_filter(self):
        self.enforcer.check_tool_permission("a1", "search")
        all_events = self.enforcer.get_audit_trail()
        filtered = self.enforcer.get_audit_trail(agent_id="a1")
        assert len(all_events) >= 1
        assert all(e["agent_id"] == "a1" for e in filtered)

    def test_audit_trail_trim_at_cap(self):
        enforcer = DefaultPrivilegeEnforcer()
        enforcer._audit_trail = [{"agent_id": "x", "n": i} for i in range(10001)]
        enforcer._log_audit("E", "a1", {})
        assert len(enforcer._audit_trail) == 5000
