"""Tests for the irreversibility handler."""

import pytest

from gate.core.models import AgentState, ToolCall
from gate.core.exceptions import SecurityViolation
from gate.security.irreversibility import (
    ActionClassification,
    DryRunResult,
    ImpactEstimate,
    IrreversibilityHandler,
)


class _Approval:
    def __init__(self, approved):
        self.approved = approved
        self.justification = "no" if not approved else "ok"


class _StubQueue:
    def __init__(self, approved):
        self.approved = approved
        self.calls = []

    async def request_and_await_approval(self, **kwargs):
        self.calls.append(kwargs)
        return _Approval(self.approved)


def _tc(tool_name):
    return ToolCall(tool_name=tool_name, tool_args={"x": 1}, call_id="c1")


def _dry_run(success=True):
    return DryRunResult(
        success=success,
        impact=ImpactEstimate(),
        risks_identified=[] if success else ["risk"],
        warnings=[],
    )


class TestClassifyAction:
    def setup_method(self):
        self.handler = IrreversibilityHandler()

    def test_exact_match(self):
        assert self.handler.classify_action(_tc("delete")) == ActionClassification.IRREVERSIBLE_HIGH_RISK

    def test_substring_match(self):
        assert self.handler.classify_action(_tc("bulk_delete_rows")) == ActionClassification.IRREVERSIBLE_HIGH_RISK

    def test_write_keyword_default(self):
        assert self.handler.classify_action(_tc("foo_write_bar")) == ActionClassification.IRREVERSIBLE_LOW_RISK

    def test_unknown_defaults_reversible(self):
        assert self.handler.classify_action(_tc("frobnicate")) == ActionClassification.REVERSIBLE

    def test_custom_classification(self):
        handler = IrreversibilityHandler(
            custom_classifications={"deploy": ActionClassification.CRITICAL}
        )
        assert handler.classify_action(_tc("deploy")) == ActionClassification.CRITICAL


class TestExecuteWithSafeguards:
    @pytest.mark.asyncio
    async def test_reversible_executes_directly(self):
        executed = []

        async def real(tc):
            executed.append(tc.tool_name)
            return {"ok": True}

        handler = IrreversibilityHandler()
        result = await handler.execute_with_safeguards(_tc("search"), AgentState(agent_id="a"), real)
        assert result["execution_result"] == {"ok": True}
        assert executed == ["search"]

    @pytest.mark.asyncio
    async def test_dry_run_failure_raises(self):
        async def real(tc):
            return {}

        async def dry(tc):
            return _dry_run(success=False)

        handler = IrreversibilityHandler(dry_run_executor=dry)
        with pytest.raises(SecurityViolation):
            await handler.execute_with_safeguards(_tc("update"), AgentState(agent_id="a"), real)

    @pytest.mark.asyncio
    async def test_high_risk_requires_queue(self):
        async def real(tc):
            return {"done": True}

        handler = IrreversibilityHandler()  # no hitl_queue
        with pytest.raises(SecurityViolation):
            await handler.execute_with_safeguards(_tc("delete"), AgentState(agent_id="a"), real)

    @pytest.mark.asyncio
    async def test_approved_high_risk_executes(self):
        async def real(tc):
            return {"done": True}

        queue = _StubQueue(approved=True)
        handler = IrreversibilityHandler(hitl_queue=queue)
        result = await handler.execute_with_safeguards(
            _tc("delete"), AgentState(agent_id="a"), real
        )
        assert result["execution_result"] == {"done": True}
        assert queue.calls[0]["risk_level"] == "IRREVERSIBLE_HIGH_RISK"

    @pytest.mark.asyncio
    async def test_denied_high_risk_raises(self):
        async def real(tc):
            return {"done": True}

        queue = _StubQueue(approved=False)
        handler = IrreversibilityHandler(hitl_queue=queue)
        with pytest.raises(SecurityViolation):
            await handler.execute_with_safeguards(_tc("delete"), AgentState(agent_id="a"), real)

    @pytest.mark.asyncio
    async def test_dry_run_success_then_approve(self):
        async def real(tc):
            return {"done": True}

        async def dry(tc):
            return _dry_run(success=True)

        queue = _StubQueue(approved=True)
        handler = IrreversibilityHandler(dry_run_executor=dry, hitl_queue=queue)
        result = await handler.execute_with_safeguards(
            _tc("drop"), AgentState(agent_id="a"), real
        )
        assert result["dry_run_result"].success is True
        assert result["approval_result"].approved is True


class TestRequiresApproval:
    def test_threshold_logic(self):
        handler = IrreversibilityHandler(
            require_approval_threshold=ActionClassification.IRREVERSIBLE_HIGH_RISK
        )
        assert handler._requires_approval(ActionClassification.REVERSIBLE) is False
        assert handler._requires_approval(ActionClassification.IRREVERSIBLE_LOW_RISK) is False
        assert handler._requires_approval(ActionClassification.IRREVERSIBLE_HIGH_RISK) is True
        assert handler._requires_approval(ActionClassification.CRITICAL) is True
