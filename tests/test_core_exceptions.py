# tests/test_core_exceptions.py
"""Tests for the :mod:`gate.core.exceptions` hierarchy.

Each concrete exception stores its identifying fields and a ``details`` dict, and
the base ``__str__`` has a with-details and a without-details branch.  All
constructors are exercised so the attribute wiring is verified.
"""

import pytest

from gate.core import exceptions as ex


class TestBaseException:
    def test_str_without_details(self):
        e = ex.gateException("boom")
        assert str(e) == "boom"
        assert e.details == {}

    def test_str_with_details(self):
        e = ex.gateException("boom", {"code": 5})
        assert "Details:" in str(e)
        assert "code" in str(e)

    def test_message_attribute(self):
        e = ex.gateException("hello")
        assert e.message == "hello"


class TestSecurityViolations:
    def test_semantic_safety_violation(self):
        e = ex.SemanticSafetyViolation("unsafe", sss_score=0.9, threshold=0.5,
                                       semantic_score="SSS")
        assert e.sss_score == 0.9
        assert e.threshold == 0.5
        assert e.semantic_score == "SSS"
        assert e.details["sss_score"] == 0.9

    def test_semantic_escalation(self):
        e = ex.SemanticEscalation("fuzzy", sss_score=0.55, threshold=0.5)
        assert e.sss_score == 0.55
        assert e.threshold == 0.5
        assert e.details["needs_user_approval"] is True

    def test_contract_violation(self):
        e = ex.ContractViolation("bad", contract_name="c", violation_type="pre")
        assert e.contract_name == "c"
        assert e.violation_type == "pre"

    def test_dcbf_violation(self):
        e = ex.DCBFViolation("barrier", barrier_value=-1.0, barrier_name="b")
        assert e.barrier_value == -1.0
        assert e.barrier_name == "b"

    def test_privilege_violation(self):
        e = ex.PrivilegeViolation("denied", agent_id="a", resource="r")
        assert e.agent_id == "a"
        assert e.resource == "r"

    def test_data_scope_violation(self):
        e = ex.DataScopeViolation("oob", agent_id="a", data_resource="d")
        assert e.agent_id == "a"
        assert e.data_resource == "d"

    def test_resource_budget_exceeded(self):
        e = ex.ResourceBudgetExceeded("over", agent_id="a", resource_type="tok",
                                      limit=100, current=200)
        assert e.resource_type == "tok"
        assert e.limit == 100
        assert e.current == 200

    def test_dfa_violation(self):
        e = ex.DFAViolation("bad transition", current_state="IDLE",
                            proposed_state="ACTING")
        assert e.current_state == "IDLE"
        assert e.proposed_state == "ACTING"

    def test_timeout_violation(self):
        e = ex.TimeoutViolation("slow", timeout_seconds=5.0, operation="call")
        assert e.timeout_seconds == 5.0
        assert e.operation == "call"
        assert e.details["operation"] == "call"


class TestSystemErrors:
    @pytest.mark.parametrize("cls", [
        ex.EmbeddingModelError, ex.VectorStoreError,
        ex.AdapterError, ex.ConfigurationError, ex.NeuralCBFError,
    ])
    def test_are_system_errors(self, cls):
        assert issubclass(cls, ex.gateSystemError)
        e = cls("x")
        assert isinstance(e, ex.gateException)

    def test_violations_are_security(self):
        assert issubclass(ex.SecurityViolation, ex.gateException)
        assert issubclass(ex.SemanticEscalation, ex.SecurityViolation)
