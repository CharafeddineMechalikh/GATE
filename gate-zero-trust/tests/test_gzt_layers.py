"""Unit tests for the seven enforcement layers and the cross-cutting controls.

These exercise the mechanisms directly, one layer at a time, with hand-built
observations. They are deliberately independent of the 680-case corpus: the
corpus measures the whole pipeline, these pin the behaviour of each layer so a
regression is attributable rather than just a moved confusion matrix.
"""
from __future__ import annotations

import json
import time

import pytest

from gzt.audit import AuditLog
from gzt.capability import CapabilityAuthority, CapabilityLayer
from gzt.circuit import CircuitBreaker
from gzt.contracts import evaluate as contracts_evaluate
from gzt.dcbf import DCBFLayer
from gzt.decision import Decision, LayerResult, combine
from gzt.hitl import HITLLayer
from gzt.ifc import InformationFlowLayer
from gzt.runtime import Action, Observation, RuntimeState
from gzt.workflow import WorkflowLayer


def _obs(**overrides):
    base = dict(
        tenant_id="tenant-a", agent_id="agent-a", trust_domain="internal",
        role="agent", objective_text="", objective_source="trusted_user",
        constraints=[], instructions=[], grants=[], resources={},
        initial_state={}, delegate_authorized=True, delegation_depth=0,
        parent_agent=None,
    )
    base.update(overrides)
    return Observation(**base)


def _state(obs, **initial):
    obs.initial_state.update(initial)
    return RuntimeState.seed(obs)


def _token(layer, obs, grants, ttl=3600.0):
    return layer.authority.issue(obs.agent_id, obs.tenant_id, grants, ttl_seconds=ttl)


def _grant(tool, operations, scope, tenants=("tenant-a",)):
    return {"name": tool,
            "permissions": {"allowed_operations": list(operations),
                            "resource_scope": list(scope),
                            "tenant_scope": list(tenants)}}


# --------------------------------------------------------------------- layer 1
class TestCapability:
    def setup_method(self):
        self.layer = CapabilityLayer(CapabilityAuthority())

    def _action(self, target="file:/workspace/report.txt", operation="read",
                tool="file_read"):
        return Action(tool=tool, args={"path": target.split(":", 1)[-1]},
                      operation=operation, target=target, step=1)

    def test_granted_read_is_allowed(self):
        obs = _obs()
        state = _state(obs)
        token = _token(self.layer, obs, [_grant("file_read", ["read"],
                                                ["file:/workspace"])])
        result = self.layer.check(obs, state, self._action(), token)
        assert result.decision is Decision.ALLOW

    def test_tampered_grant_invalidates_signature(self):
        obs = _obs()
        state = _state(obs)
        token = _token(self.layer, obs, [_grant("file_read", ["read"], ["file:/workspace"])])
        token.grants[0]["permissions"]["resource_scope"].append("file:/etc")
        result = self.layer.check(obs, state, self._action(), token)
        assert result.policy_id == "CAP-SIGNATURE-001"

    def test_operation_not_granted(self):
        obs = _obs()
        state = _state(obs)
        token = _token(self.layer, obs, [_grant("file_read", ["read"], ["file:/workspace"])])
        result = self.layer.check(obs, state, self._action(operation="delete"), token)
        assert result.policy_id == "CAP-OPERATION-001"

    def test_target_outside_scope(self):
        obs = _obs()
        state = _state(obs)
        token = _token(self.layer, obs, [_grant("file_read", ["read"], ["file:/workspace"])])
        result = self.layer.check(obs, state, self._action("file:/etc/passwd"), token)
        assert result.policy_id == "CAP-RESOURCE-001"

    def test_foreign_tenant_without_scope_is_denied(self):
        obs = _obs()
        state = _state(obs)
        token = _token(self.layer, obs, [_grant("database_query", ["select"],
                                                ["db:orders"], tenants=["tenant-a"])])
        action = Action(tool="database_query", args={"tenant_id": "tenant-b"},
                        operation="select", target="db:orders", step=1)
        result = self.layer.check(obs, state, action, token)
        assert result.policy_id == "CAP-TENANT-001"

    def test_revoked_token_is_denied(self):
        obs = _obs()
        state = _state(obs)
        token = _token(self.layer, obs, [_grant("file_read", ["read"], ["file:/workspace"])])
        self.layer.authority.revoke(token)
        result = self.layer.check(obs, state, self._action(), token)
        assert result.policy_id == "CAP-SIGNATURE-001"

    def test_expired_token_is_denied(self):
        obs = _obs()
        state = _state(obs)
        token = _token(self.layer, obs, [_grant("file_read", ["read"], ["file:/workspace"])],
                       ttl=-1.0)
        result = self.layer.check(obs, state, self._action(), token)
        assert result.policy_id == "CAP-EXPIRED-001"


# --------------------------------------------------------------------- layer 2
class TestWorkflow:
    def test_consumed_nonce_is_a_replay(self):
        obs = _obs()
        state = _state(obs, consumed_nonces=["n-42"])
        action = Action(tool="payment_api", args={"amount": 10.0, "nonce": "n-42"},
                        operation="charge", target="account:acct-a", step=1)
        result = WorkflowLayer().check(obs, state, action)
        assert result.policy_id == "WF-REPLAY-001"

    def test_fresh_nonce_is_not_a_replay(self):
        obs = _obs(objective_text="Pay the invoice 10.00 to vendor:a.")
        state = _state(obs, consumed_nonces=["n-1"])
        action = Action(tool="payment_api", args={"amount": 10.0, "nonce": "n-2"},
                        operation="charge", target="account:acct-a", step=1)
        result = WorkflowLayer().check(obs, state, action)
        assert result.decision is Decision.ALLOW


# --------------------------------------------------------------------- layer 3
class TestInformationFlow:
    def test_restricted_read_then_external_email_is_denied(self):
        obs = _obs(objective_text="Send the document I prepared to the reviewer.")
        state = _state(obs)
        state.reads.append({"target": "file:/workspace/contract.pdf",
                            "label": "restricted"})
        action = Action(tool="send_email",
                        args={"to": "buyer@supplier.example", "subject": "Summary",
                              "body": "The contract allows early termination."},
                        operation="send", target="email:buyer@supplier.example", step=2)
        result = InformationFlowLayer().check(obs, state, action)
        assert result is not None
        assert result.policy_id in ("IFC-EGRESS-001", "IFC-RECIPIENT-001")

    def test_internal_email_of_restricted_content_is_allowed(self):
        obs = _obs(objective_text="Forward the contract summary to the legal team.")
        state = _state(obs)
        state.reads.append({"target": "file:/workspace/contract.pdf",
                            "label": "restricted"})
        action = Action(tool="send_email",
                        args={"to": "legal@corp.example", "subject": "Summary",
                              "body": "The contract allows early termination."},
                        operation="send", target="email:legal@corp.example", step=2)
        result = InformationFlowLayer().check(obs, state, action)
        assert result is None or result.decision is Decision.ALLOW

    def test_internal_only_marker_crossing_trust_boundary(self):
        obs = _obs(objective_text="Send the partner the delivery schedule.")
        state = _state(obs)
        action = Action(tool="send_email",
                        args={"to": "planner@partner.example", "subject": "Schedule",
                              "body": "INTERNAL ONLY: delivery moves to Friday."},
                        operation="send", target="email:planner@partner.example", step=1)
        result = InformationFlowLayer().check(obs, state, action)
        assert result.policy_id == "IFC-TRUSTBOUNDARY-001"


# --------------------------------------------------------------------- layer 5
class TestContracts:
    def test_workspace_traversal_is_denied_before_any_grant(self):
        obs = _obs(grants=[_grant("file_read", ["read"], ["file:*"])])
        state = _state(obs)
        action = Action(tool="file_read", args={"path": "../../etc/shadow"},
                        operation="read", target="file:/etc/shadow", step=1)
        result = contracts_evaluate(action, obs, state)
        assert result.policy_id == "CON-FS-TRAVERSAL-001"

    def test_payment_without_objective_intent_is_denied(self):
        obs = _obs(objective_text="Summarise last quarter's sales figures.")
        state = _state(obs)
        action = Action(tool="payment_api",
                        args={"amount": 100.0, "recipient": "vendor:acme"},
                        operation="charge", target="account:acct-ops", step=1)
        result = contracts_evaluate(action, obs, state)
        assert result.policy_id == "CON-PAY-NOTASKED-001"

    def test_refund_without_matching_charge_is_denied(self):
        obs = _obs(objective_text="Refund the customer for the duplicate charge.")
        state = _state(obs, matching_charge={"amount": 250.0, "recipient": "vendor:acme",
                                             "customer": "c-17"})
        action = Action(tool="payment_api",
                        args={"amount": 900.0, "recipient": "customer:c-17",
                              "operation": "refund"},
                        operation="refund", target="account:acct-ops", step=1)
        result = contracts_evaluate(action, obs, state)
        assert result.policy_id == "CON-REFUND-MATCH-001"

    def test_refund_matching_the_settled_charge_is_allowed(self):
        obs = _obs(objective_text="Refund the customer for the duplicate charge.")
        state = _state(obs, matching_charge={"amount": 250.0, "recipient": "vendor:acme",
                                             "customer": "c-17"})
        action = Action(tool="payment_api",
                        args={"amount": 250.0, "recipient": "customer:c-17",
                              "operation": "refund"},
                        operation="refund", target="account:acct-ops", step=1)
        assert contracts_evaluate(action, obs, state) is None

    def test_nested_server_field_tampering_is_seen(self):
        obs = _obs(objective_text="Create the order for the two requested items.")
        state = _state(obs)
        action = Action(tool="http_request",
                        args={"url": "https://api.app.example/orders", "method": "POST",
                              "body": json.dumps({"items": [{"sku": "A-1",
                                                             "unit_price": 1.0}]})},
                        operation="post", target="https://api.app.example/orders", step=1)
        result = contracts_evaluate(action, obs, state)
        assert result.policy_id == "CON-PARAM-SERVERFIELD-001"


# --------------------------------------------------------------------- layer 6
class TestDCBF:
    def test_provisioning_over_instance_ceiling_is_denied(self):
        obs = _obs(objective_text="Provision staging capacity.")
        state = _state(obs, instances_provisioned=15)
        action = Action(tool="cloud_api",
                        args={"spec": {"op": "provision", "count": 10}},
                        operation="provision", target="cloud:instances", step=1)
        result = DCBFLayer().check(obs, state, action)
        assert result is not None
        assert result.policy_id == "CBF-CLOUD-QUOTA-001"

    def test_provisioning_inside_ceiling_is_allowed(self):
        obs = _obs(objective_text="Provision staging capacity.")
        state = _state(obs, instances_provisioned=2)
        action = Action(tool="cloud_api",
                        args={"spec": {"op": "provision", "count": 3}},
                        operation="provision", target="cloud:instances", step=1)
        result = DCBFLayer().check(obs, state, action)
        assert result is None or result.decision is Decision.ALLOW

    def test_barrier_reads_the_predicted_next_state(self):
        obs = _obs()
        state = _state(obs, disk_gb_used=60.0)
        action = Action(tool="code_execute",
                        args={"command": "dd if=/dev/zero of=/data/fill bs=1M count=8192"},
                        operation="execute", target="host:local", step=1)
        result = DCBFLayer().check(obs, state, action)
        assert result.policy_id == "CBF-RESOURCE-001"
        assert result.evidence["barriers"]


# --------------------------------------------------------------------- layer 7
class TestHITL:
    def _payment(self, amount=25000.0, recipient="vendor:acme"):
        return Action(tool="payment_api",
                      args={"amount": amount, "recipient": recipient,
                            "account": "acct-ops"},
                      operation="charge", target="account:acct-ops", step=1)

    def test_spend_over_ceiling_requires_approval(self):
        obs = _obs(objective_text="Pay the vendor invoice.")
        state = _state(obs)
        result = HITLLayer().check(obs, state, self._payment())
        assert result.decision is Decision.REQUIRE_APPROVAL
        assert result.policy_id == "HITL-SPEND-001"

    def test_approval_bound_to_other_parameters_does_not_authorise(self):
        obs = _obs(objective_text="Pay the vendor invoice.")
        state = _state(obs)
        other = self._payment(amount=25000.0)
        state.approvals = [{"args_hash": other.args_hash, "tool": "payment_api",
                            "used": False, "expires_at": time.time() + 600}]
        changed = self._payment(amount=95000.0)
        result = HITLLayer().check(obs, state, changed)
        assert result.decision is Decision.REQUIRE_APPROVAL

    def test_exact_approved_call_passes(self):
        obs = _obs(objective_text="Pay the vendor invoice.")
        state = _state(obs)
        action = self._payment()
        state.approvals = [{"args_hash": action.args_hash, "tool": "payment_api",
                            "used": False, "expires_at": time.time() + 600}]
        result = HITLLayer().check(obs, state, action)
        assert result is None

    def test_expired_approval_does_not_authorise(self):
        obs = _obs(objective_text="Pay the vendor invoice.")
        state = _state(obs)
        action = self._payment()
        state.approvals = [{"args_hash": action.args_hash, "tool": "payment_api",
                            "used": False, "expires_at": time.time() - 1}]
        result = HITLLayer().check(obs, state, action)
        assert result.decision is Decision.REQUIRE_APPROVAL

    def test_used_approval_does_not_authorise_a_second_call(self):
        obs = _obs(objective_text="Pay the vendor invoice.")
        state = _state(obs)
        action = self._payment()
        state.approvals = [{"args_hash": action.args_hash, "tool": "payment_api",
                            "used": True}]
        result = HITLLayer().check(obs, state, action)
        assert result.decision is Decision.REQUIRE_APPROVAL


# ------------------------------------------------------------ decision lattice
class TestDecisionLattice:
    def test_deny_dominates_approval_and_allow(self):
        results = [LayerResult.allow("capability"),
                   LayerResult(Decision.REQUIRE_APPROVAL, "hitl", "HITL-SPEND-001", "x"),
                   LayerResult(Decision.DENY, "ifc", "IFC-EGRESS-001", "y")]
        assert combine(results).decision is Decision.DENY

    def test_approval_dominates_allow(self):
        results = [LayerResult.allow("capability"),
                   LayerResult(Decision.REQUIRE_APPROVAL, "hitl", "HITL-SPEND-001", "x")]
        assert combine(results).decision is Decision.REQUIRE_APPROVAL

    def test_empty_pipeline_fails_closed(self):
        combined = combine([])
        assert combined.decision is Decision.DENY
        assert combined.deciding_policy == "FAIL-CLOSED"


# --------------------------------------------------------------- cross-cutting
class TestAuditChain:
    def _append(self, log, step):
        return log.append(tenant_id="tenant-a", agent_id="agent-a", step=step,
                          tool="file_read", operation="read", target="file:/w/a",
                          args_hash="h", decision="ALLOW", deciding_layer="capability",
                          deciding_policy="CAP-ALLOW-001", outcome="executed")

    def test_intact_chain_verifies(self):
        log = AuditLog()
        for step in range(3):
            self._append(log, step)
        ok, index = log.verify()
        assert ok and index is None

    def test_tampering_breaks_verification_and_names_the_record(self):
        log = AuditLog()
        for step in range(3):
            self._append(log, step)
        log.records[1].decision = "DENY"
        ok, index = log.verify()
        assert not ok and index == 1

    def test_chain_links_each_record_to_its_predecessor(self):
        log = AuditLog()
        first = self._append(log, 0)
        second = self._append(log, 1)
        assert second.prev_hash == first.record_hash


class TestCircuitBreaker:
    def test_three_consecutive_denials_suspend_the_session(self):
        obs = _obs()
        state = _state(obs)
        breaker = CircuitBreaker()
        for _ in range(3):
            breaker.record(state, Decision.DENY, "IFC-EGRESS-001", "blocked")
        suspension = breaker.check(state)
        assert suspension is not None
        assert suspension.policy_id == "CIRCUIT-SUSPENDED-001"

    def test_an_allow_resets_the_consecutive_counter(self):
        obs = _obs()
        state = _state(obs)
        breaker = CircuitBreaker()
        breaker.record(state, Decision.DENY, "IFC-EGRESS-001", "blocked")
        breaker.record(state, Decision.DENY, "IFC-EGRESS-001", "blocked")
        breaker.record(state, Decision.ALLOW, "CAP-ALLOW-001", "executed")
        breaker.record(state, Decision.DENY, "IFC-EGRESS-001", "blocked")
        assert breaker.check(state) is None
