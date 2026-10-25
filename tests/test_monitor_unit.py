"""Unit tests for the gate security monitor orchestration."""

import numpy as np
import pytest

from gate.core.config import AgentProfile, DataScope, ResourceBudget, gateConfig
from gate.core.exceptions import (
    ContractViolation,
    DFAViolation,
    DCBFViolation,
    PrivilegeViolation,
    SemanticSafetyViolation,
)
from gate.core.models import AgentState, SemanticScore, ToolCall, ValidationResult
from gate.core.monitor import gateMonitor, _looks_like_data_resource
from gate.security.dfa_supervisor import DefaultDFASupervisor


def _config(**overrides):
    profile = AgentProfile(
        agent_id="a1",
        role="r",
        allowed_tools={"search", "read"},
        forbidden_tools={"delete"},
        data_scope=DataScope(allowed_databases={"db1"}),
        resource_budget=ResourceBudget(max_cost_usd=5.0, max_steps=20),
    )
    base = dict(
        agent_profile=profile,
        enabled_checks={"privilege", "dfa", "contracts", "semantic", "dcbf"},
    )
    base.update(overrides)
    return gateConfig(**base)


class PrivStub:
    def __init__(self, tool_ok=True, scope_ok=True, budget_ok=True):
        self.tool_ok, self.scope_ok, self.budget_ok = tool_ok, scope_ok, budget_ok

    def check_tool_permission(self, agent_id, tool_name):
        return self.tool_ok

    def check_data_scope(self, agent_id, resource):
        return self.scope_ok

    def check_resource_budget(self, agent_id, cost):
        return self.budget_ok


class DfaStub:
    def __init__(self, allowed=True, reason=""):
        self.allowed, self.reason = allowed, reason

    def validate_action_phase(self, state):
        return self.allowed, self.reason


class SemStub:
    def __init__(self, decision="ALLOW", sss=0.9):
        self.decision, self.sss = decision, sss

    def check_semantic_safety(self, action, tool_name, agent_id):
        return SemanticScore(
            sss_value=self.sss,
            drift_to_intent=0.0,
            drift_to_harm=0.0,
            drift_to_safe=0.0,
            decision=self.decision,
            details={},
        )


class DcbfStub:
    def __init__(self, safe=True, reason="", barrier=1.0):
        self.safe, self.reason, self.barrier = safe, reason, barrier

    def check_transition(self, state, action):
        return self.safe, self.reason

    def evaluate_state(self, state):
        return self.barrier


class ContractObj:
    def __init__(self, pre=True, post=True, raises=False):
        self.pre, self.post, self.raises = pre, post, raises

    def validate_precondition(self, action, state):
        if self.raises:
            raise ContractViolation("pre boom", violation_type="X")
        return self.pre

    def validate_postcondition(self, action, result, state):
        if self.raises:
            raise ContractViolation("post boom", violation_type="X")
        return self.post


class ContractStub:
    def __init__(self, contract=None):
        self.contract = contract

    def get_contract(self, tool_name):
        return self.contract


class AuditStub:
    def __init__(self):
        self.events = []

    async def log_event(self, event):
        self.events.append(event)


def _monitor(priv=None, dfa=None, sem=None, dcbf=None, contracts=None, audit=None):
    return gateMonitor(
        _config(),
        semantic_firewall=sem if sem is not None else SemStub(),
        contract_registry=contracts if contracts is not None else ContractStub(),
        dcbf_monitor=dcbf if dcbf is not None else DcbfStub(),
        dfa_supervisor=dfa if dfa is not None else DfaStub(),
        privilege_enforcer=priv if priv is not None else PrivStub(),
        audit_logger=audit if audit is not None else AuditStub(),
    )


def _action(tool_name="search", args=None, meta=None):
    return ToolCall(
        tool_name=tool_name,
        tool_args=args if args is not None else {"q": "hello"},
        call_id="c1",
        metadata=meta or {},
    )


class TestLooksLikeDataResource:
    def test_email_rejected(self):
        assert _looks_like_data_resource("a@b.com") is False

    def test_spaces_rejected(self):
        assert _looks_like_data_resource("some query") is False

    def test_dotted_accepted(self):
        assert _looks_like_data_resource("db1.users") is True

    def test_plain_rejected(self):
        assert _looks_like_data_resource("plain") is False


class TestValidateActionPass:
    @pytest.mark.asyncio
    async def test_allows_clean_call(self):
        mon = _monitor()
        result = await mon.validate_action(_action(), AgentState(agent_id="a1"))
        assert result.is_allowed is True
        assert set(result.checks_passed) == {"privilege", "dfa", "contracts", "semantic", "dcbf"}

    @pytest.mark.asyncio
    async def test_approved_logged(self):
        audit = AuditStub()
        mon = _monitor(audit=audit)
        await mon.validate_action(_action(), AgentState(agent_id="a1"))
        assert audit.events[-1].event_type == "ACTION_APPROVED"


class TestPrivilegeStage:
    @pytest.mark.asyncio
    async def test_tool_denied(self):
        mon = _monitor(priv=PrivStub(tool_ok=False))
        result = await mon.validate_action(_action(), AgentState(agent_id="a1"))
        assert result.is_allowed is False
        assert "privilege" in result.checks_failed

    @pytest.mark.asyncio
    async def test_data_scope_denied(self):
        mon = _monitor(priv=PrivStub(scope_ok=False))
        result = await mon.validate_action(
            _action(args={"resource": "db1.users"}), AgentState(agent_id="a1")
        )
        assert result.is_allowed is False

    @pytest.mark.asyncio
    async def test_budget_denied(self):
        mon = _monitor(priv=PrivStub(budget_ok=False))
        result = await mon.validate_action(
            _action(meta={"estimated_cost": 100.0}), AgentState(agent_id="a1")
        )
        assert result.is_allowed is False


class TestDfaStage:
    @pytest.mark.asyncio
    async def test_dfa_denied(self):
        mon = _monitor(dfa=DfaStub(allowed=False, reason="nope"))
        result = await mon.validate_action(_action(), AgentState(agent_id="a1"))
        assert result.is_allowed is False
        assert "dfa" in result.checks_failed


class TestContractStage:
    @pytest.mark.asyncio
    async def test_contract_precondition_denied(self):
        mon = _monitor(contracts=ContractStub(ContractObj(pre=False)))
        result = await mon.validate_action(_action(), AgentState(agent_id="a1"))
        assert result.is_allowed is False
        assert "contracts" in result.checks_failed


class TestSemanticStage:
    @pytest.mark.asyncio
    async def test_semantic_block(self):
        mon = _monitor(sem=SemStub(decision="BLOCK", sss=0.1))
        result = await mon.validate_action(_action(), AgentState(agent_id="a1"))
        assert result.is_allowed is False
        assert "semantic" in result.checks_failed

    @pytest.mark.asyncio
    async def test_semantic_escalate(self):
        mon = _monitor(sem=SemStub(decision="ESCALATE", sss=0.6))
        result = await mon.validate_action(_action(), AgentState(agent_id="a1"))
        assert result.escalated is True
        assert result.requires_approval is True


class TestDcbfStage:
    @pytest.mark.asyncio
    async def test_dcbf_denied(self):
        mon = _monitor(dcbf=DcbfStub(safe=False, reason="barrier breached"))
        result = await mon.validate_action(_action(), AgentState(agent_id="a1"))
        assert result.is_allowed is False
        assert "dcbf" in result.checks_failed


class TestValidateResult:
    @pytest.mark.asyncio
    async def test_disabled_returns_allowed(self):
        mon = gateMonitor(
            _config(enabled_checks={"privilege"}),
            semantic_firewall=None,
            contract_registry=None,
            dcbf_monitor=None,
            dfa_supervisor=DfaStub(),
            privilege_enforcer=PrivStub(),
            audit_logger=None,
        )
        result = await mon.validate_result(_action(), {"x": 1}, AgentState(agent_id="a1"))
        assert result.is_allowed is True

    @pytest.mark.asyncio
    async def test_no_contract_allows(self):
        mon = _monitor(contracts=ContractStub(None))
        result = await mon.validate_result(_action(), {"x": 1}, AgentState(agent_id="a1"))
        assert result.is_allowed is True

    @pytest.mark.asyncio
    async def test_postcondition_passes(self):
        mon = _monitor(contracts=ContractStub(ContractObj(post=True)))
        result = await mon.validate_result(_action(), {"x": 1}, AgentState(agent_id="a1"))
        assert result.is_allowed is True

    @pytest.mark.asyncio
    async def test_postcondition_false(self):
        mon = _monitor(contracts=ContractStub(ContractObj(post=False)))
        result = await mon.validate_result(_action(), {"x": 1}, AgentState(agent_id="a1"))
        assert result.is_allowed is False

    @pytest.mark.asyncio
    async def test_postcondition_violation(self):
        mon = _monitor(contracts=ContractStub(ContractObj(raises=True)))
        result = await mon.validate_result(_action(), {"x": 1}, AgentState(agent_id="a1"))
        assert result.is_allowed is False

    @pytest.mark.asyncio
    async def test_postcondition_generic_error(self):
        class Boom:
            def validate_postcondition(self, *a):
                raise RuntimeError("kaboom")

        mon = _monitor(contracts=ContractStub(Boom()))
        result = await mon.validate_result(_action(), {"x": 1}, AgentState(agent_id="a1"))
        assert result.is_allowed is False


class TestHelperMethods:
    @pytest.mark.asyncio
    async def test_check_semantic_safety_public(self):
        mon = _monitor(sem=SemStub(decision="ALLOW", sss=0.95))
        score = await mon.check_semantic_safety("act", "search", "a1")
        assert score.decision == "ALLOW"

    @pytest.mark.asyncio
    async def test_check_semantic_no_firewall(self):
        mon = gateMonitor(
            _config(enabled_checks=set()),
            semantic_firewall=None,
            contract_registry=None,
            dcbf_monitor=None,
            dfa_supervisor=DfaStub(),
            privilege_enforcer=PrivStub(),
            audit_logger=None,
        )
        with pytest.raises(ValueError):
            await mon.check_semantic_safety("act", "search", "a1")

    @pytest.mark.asyncio
    async def test_check_state_invariants_no_monitor(self):
        mon = gateMonitor(
            _config(enabled_checks={"privilege"}),
            semantic_firewall=None,
            contract_registry=None,
            dcbf_monitor=None,
            dfa_supervisor=DfaStub(),
            privilege_enforcer=PrivStub(),
            audit_logger=None,
        )
        assert await mon.check_state_invariants(AgentState(agent_id="a1")) is True

    @pytest.mark.asyncio
    async def test_check_state_invariants_evaluates(self):
        mon = _monitor(dcbf=DcbfStub(barrier=2.0))
        assert await mon.check_state_invariants(AgentState(agent_id="a1")) is True

    @pytest.mark.asyncio
    async def test_log_event_delegates(self):
        audit = AuditStub()
        mon = _monitor(audit=audit)
        from gate.audit.encrypted_logger import SecurityEvent

        await mon.log_event(SecurityEvent(event_type="X", agent_id="a1", tenant_id="t"))
        assert len(audit.events) == 1


class TestLazyInit:
    def test_non_semantic_components_built(self):
        # Provide only a semantic stub so the model download path is skipped;
        # the other stages must self-initialize.
        mon = gateMonitor(
            _config(),
            semantic_firewall=SemStub(),
        )
        assert mon.contract_registry is not None
        assert isinstance(mon.dfa_supervisor, DefaultDFASupervisor)
        assert mon.dcbf_monitor is not None
        assert mon.privilege_enforcer is not None
