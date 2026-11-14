"""The reference monitor: a deny-dominant pipeline over seven independent layers.

Order (each layer sees the action and the session state the monitor owns):

    capability -> workflow -> semantic -> ifc -> contracts -> dcbf -> hitl

The monitor fails closed. If a layer raises, the action is denied with
``FAIL-CLOSED``. A circuit breaker sits in front of the pipeline and suspends a
session whose decision stream shows an attack in progress. Every decision is
appended to a hash-chained audit log. Postconditions are verified against the
environment observation the executor returns, so an execution whose effect
violates the safety envelope is recorded as ``EXECUTED_POSTCONDITION_FAILED``
and trips the breaker.

Nothing here reads a benchmark label: the inputs are the observation a gateway
holds, the action, the session state and a capability token.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from . import contracts
from . import policies as P
from .audit import AuditLog
from .capability import CapabilityAuthority, CapabilityLayer, CapabilityToken
from .circuit import CircuitBreaker
from .dcbf import DCBFLayer
from .decision import (CombinedDecision, Decision, LayerResult, Outcome, combine)
from .hitl import HITLLayer
from .ifc import InformationFlowLayer
from .runtime import Action, Observation, RuntimeState, canonical_hash
from .responses import ResponseAssessment, ResponseInspector, ToolResponse
from .semantic import SemanticLayer
from .workflow import WorkflowLayer

LAYER_ORDER = ("capability", "workflow", "semantic", "ifc", "contracts", "dcbf", "hitl")

READ_TOOLS = {"file_read", "sql_query", "database_query", "web_search", "memory_read"}


def grant_set(obs: Observation) -> List[Dict[str, Any]]:
    """Materialise the token grants a tenant authority would issue for this agent."""
    grants: List[Dict[str, Any]] = []
    for entry in obs.grants:
        permissions = dict(entry.get("permissions") or {})
        permissions.setdefault("allowed_operations", list(entry.get("operations") or []))
        permissions.setdefault("resource_scope", list(entry.get("resource_scope") or []))
        permissions.setdefault("tenant_scope", list(entry.get("tenant_scope") or [obs.tenant_id]))
        grants.append({"name": entry["name"], "permissions": permissions})
    return grants


@dataclass
class StepResult:
    action: Action
    combined: CombinedDecision
    outcome: Outcome
    environment_delta: Dict[str, Any] = field(default_factory=dict)
    postcondition_failures: List[str] = field(default_factory=list)
    breaker_event: Optional[Dict[str, Any]] = None
    response: Optional[ResponseAssessment] = None
    elapsed_ms: float = 0.0
    audit_hash: str = ""

    @property
    def decision(self) -> Decision:
        return self.combined.decision

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step": self.action.step, "tool": self.action.tool,
            "operation": self.action.operation, "target": self.action.target,
            "decision": self.decision.value,
            "deciding_layer": self.combined.deciding_layer,
            "deciding_policy": self.combined.deciding_policy,
            "outcome": self.outcome.value,
            "layers": [r.to_dict() for r in self.combined.results],
            "postcondition_failures": self.postcondition_failures,
            "breaker_event": self.breaker_event,
            "response": self.response.to_dict() if self.response else None,
            "elapsed_ms": round(self.elapsed_ms, 3),
            "audit_hash": self.audit_hash,
        }


class ReferenceMonitor:
    def __init__(self, authority: Optional[CapabilityAuthority] = None,
                 layers: Optional[List[str]] = None,
                 audit: Optional[AuditLog] = None,
                 semantic: Optional[SemanticLayer] = None,
                 breaker: Optional[CircuitBreaker] = None,
                 responses: Optional[ResponseInspector] = None) -> None:
        self.authority = authority or CapabilityAuthority()
        self.capability = CapabilityLayer(self.authority)
        self.workflow = WorkflowLayer()
        self.semantic = semantic or SemanticLayer()
        self.ifc = InformationFlowLayer()
        self.dcbf = DCBFLayer()
        self.hitl = HITLLayer()
        self.breaker = breaker or CircuitBreaker()
        self.audit = audit or AuditLog()
        self.responses = responses or ResponseInspector()
        self.enabled = list(LAYER_ORDER) if layers is None else list(layers)

    # ------------------------------------------------------------ tokens
    def token_for(self, obs: Observation, ttl_seconds: float = 3600.0) -> CapabilityToken:
        return self.authority.issue(obs.agent_id, obs.tenant_id, grant_set(obs),
                                    ttl_seconds=ttl_seconds,
                                    delegation_chain=[])

    # ------------------------------------------------------------ decide
    def decide(self, obs: Observation, state: RuntimeState, action: Action,
               token: Optional[CapabilityToken]) -> CombinedDecision:
        results: List[LayerResult] = []

        if not self.enabled:
            return CombinedDecision(Decision.ALLOW, "uncontrolled", "BASELINE-ALLOW",
                                    [], "no layer enabled")

        suspended = self.breaker.check(state)
        if suspended is not None:
            return combine([suspended])

        isolation = self._tenant_isolation(obs, state, action)
        if isolation is not None:
            results.append(isolation)
            return combine(results)

        pipeline: List[tuple] = [
            ("capability", lambda: self.capability.check(obs, state, action, token)),
            ("workflow", lambda: self.workflow.check(obs, state, action)),
            ("semantic", lambda: self.semantic.check(obs, state, action)),
            ("ifc", lambda: self.ifc.check(obs, state, action)),
            ("contracts", lambda: contracts.evaluate(action, obs, state)),
            ("dcbf", lambda: self.dcbf.check(obs, state, action)),
            ("hitl", lambda: self.hitl.check(obs, state, action)),
        ]
        for name, invoke in pipeline:
            if name not in self.enabled:
                continue
            try:
                result = invoke()
            except Exception as error:  # fail closed on any layer fault
                results.append(LayerResult(
                    decision=Decision.DENY, layer=name, policy_id="FAIL-CLOSED",
                    reason=f"layer raised {type(error).__name__}: {error}", risk="critical",
                    evidence={"exception": repr(error)}))
                return combine(results)
            if result is None:
                continue
            results.append(result)
            if result.decision is Decision.DENY:
                break
        return combine(results)

    # ----------------------------------------------------------- execute
    def execute(self, obs: Observation, state: RuntimeState, action: Action,
                token: Optional[CapabilityToken],
                executor: Optional[Callable[[Action], Dict[str, Any]]] = None) -> StepResult:
        started = time.perf_counter()
        combined = self.decide(obs, state, action, token)
        outcome = Outcome.BLOCKED if combined.decision is Decision.DENY else (
            Outcome.WITHHELD if combined.decision is Decision.REQUIRE_APPROVAL
            else Outcome.EXECUTED)

        delta: Dict[str, Any] = {}
        failures: List[str] = []
        assessment: Optional[ResponseAssessment] = None
        if outcome is Outcome.EXECUTED and executor is not None:
            raw = executor(action) or {}
            envelope = raw.get("response") if isinstance(raw, dict) else None
            delta = {k: v for k, v in raw.items() if k != "response"} if isinstance(raw, dict) else {}
            failures = self._verify_postconditions(obs, state, action, delta)
            if failures:
                outcome = Outcome.EXECUTED_POSTCONDITION_FAILED
                combined.results.append(LayerResult(
                    decision=Decision.DENY, layer="postcondition",
                    policy_id="POSTCONDITION-001",
                    reason="the executed effect leaves the safety envelope: " + "; ".join(failures),
                    risk="critical", evidence={"failures": failures}))
                combined = combine(combined.results)
            else:
                self._apply_effects(obs, state, action, delta)
                self._consume_approval(state, action)
                if envelope is not None:
                    # The response is inspected after the effect is accepted, so
                    # a rejected effect cannot smuggle content into the context.
                    assessment = self.responses.inspect(
                        ToolResponse.from_payload(envelope, action.tool, action.target),
                        obs, state, target=action.target)

        state.note_action(action, combined.decision.value)
        event = self.breaker.record(state, combined.decision, combined.deciding_policy,
                                    outcome.value)
        record = self.audit.append(
            tenant_id=obs.tenant_id, agent_id=obs.agent_id, step=action.step,
            tool=action.tool, operation=action.operation, target=action.target,
            args_hash=action.args_hash, decision=combined.decision.value,
            deciding_layer=combined.deciding_layer, deciding_policy=combined.deciding_policy,
            outcome=outcome.value,
            layers=[r.to_dict() for r in combined.results],
            evidence={"delta": delta, "postcondition_failures": failures,
                      "response": assessment.to_dict() if assessment else None},
        )
        elapsed = (time.perf_counter() - started) * 1000.0
        return StepResult(action=action, combined=combined, outcome=outcome,
                          environment_delta=delta, postcondition_failures=failures,
                          breaker_event=(event.__dict__ if event else None),
                          response=assessment, elapsed_ms=elapsed, audit_hash=record.record_hash)

    # ------------------------------------------------------------- helpers
    def _tenant_isolation(self, obs: Observation, state: RuntimeState,
                          action: Action) -> Optional[LayerResult]:
        owner = state.owner_tenant(obs, action.target)
        declared = CapabilityLayer._declared_tenant(action)
        agreement = obs.initial_state.get("data_sharing_agreement")
        counterparty = obs.initial_state.get("sharing_counterparty")
        # A shared table may be owned by another tenant while the call narrows
        # itself to the caller's own rows. The row predicate is then the effective
        # tenant, and the capability layer already rejects a foreign predicate.
        if declared:
            if declared == obs.tenant_id:
                return None
            if agreement and counterparty == declared:
                return None
            return LayerResult(
                decision=Decision.DENY, layer="isolation",
                policy_id="TENANT-ISOLATION-001",
                reason=f"call declares rows in {declared}, not {obs.tenant_id}",
                risk="critical", evidence={"target": action.target, "declared": declared})
        if owner and owner != obs.tenant_id:
            if not (agreement and counterparty == owner):
                return LayerResult(
                    decision=Decision.DENY, layer="isolation",
                    policy_id="TENANT-ISOLATION-001",
                    reason=f"resource {action.target} belongs to {owner}, not {obs.tenant_id}",
                    risk="critical", evidence={"target": action.target, "owner": owner})
        return None

    def _apply_effects(self, obs: Observation, state: RuntimeState, action: Action,
                       delta: Dict[str, Any]) -> None:
        if action.tool in READ_TOOLS:
            label = state.classify(obs, action.target)
            state.note_read(action.target, label)
            state.reads.append({"target": action.target, "label": label,
                                "tool": action.tool})
        if delta:
            state.apply_environment(delta)

    @staticmethod
    def _consume_approval(state: RuntimeState, action: Action) -> None:
        for record in state.approvals:
            if record.get("args_hash") == action.args_hash and not record.get("used"):
                record["used"] = True
                return

    @staticmethod
    def _verify_postconditions(obs: Observation, state: RuntimeState, action: Action,
                               delta: Dict[str, Any]) -> List[str]:
        failures: List[str] = []
        env = dict(getattr(state, "env", {}) or {})
        env.update(delta)

        def over(value_key: str, ceiling_key: str) -> bool:
            value = env.get(value_key)
            ceiling = env.get(ceiling_key)
            if value is None or ceiling is None:
                return False
            try:
                return float(value) > float(ceiling)
            except (TypeError, ValueError):
                return False

        if over("disk_used_gb", "disk_quota_gb"):
            failures.append("disk use above the tenant quota")
        if over("instances_provisioned", "instance_ceiling"):
            failures.append("provisioned instances above the session ceiling")
        if over("active_agents", "active_agents_ceiling"):
            failures.append("concurrent agents above the session ceiling")
        if over("delegation_depth", "delegation_depth_ceiling"):
            failures.append("delegation depth above the session ceiling")
        if over("auth_attempts_5m", "auth_attempts_5m_ceiling"):
            failures.append("authentication attempts above the envelope")
        role = str(delta.get("role", "")).lower()
        if role in ("admin", "superuser", "root"):
            failures.append("execution escalated the role to an administrative identity")
        return failures
