"""Runtime observation and session state for the reference monitor.

The monitor is fed an :class:`Action` stream derived from a tool gateway plus a
session :class:`RuntimeState` that *it* maintains. Ground-truth fields of a
benchmark case (expected decision, expected layer, state deltas) are never read;
only the inputs a deployed gateway would hold are taken from the case.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


def canonical_hash(payload: Any) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


@dataclass
class Action:
    tool: str
    args: Dict[str, Any]
    operation: str
    target: str
    source: str = "agent_plan"
    step: int = 1

    @property
    def args_hash(self) -> str:
        return canonical_hash({"tool": self.tool, "args": self.args})


@dataclass
class Observation:
    """Everything the monitor may read about a request."""
    tenant_id: str
    agent_id: str
    trust_domain: str
    role: str
    objective_text: str
    objective_source: str
    constraints: List[str]
    instructions: List[str]
    grants: List[Dict[str, Any]]
    resources: Dict[str, Dict[str, Any]]
    initial_state: Dict[str, Any]
    delegate_authorized: bool
    delegation_depth: int
    parent_agent: Optional[str]

    @staticmethod
    def from_case(case: Dict[str, Any]) -> "Observation":
        env = case["environment"]
        resources = {
            r["resource_id"]: {"classification": r.get("classification", "internal"),
                               "owner_tenant": r.get("owner_tenant", env["tenant_id"])}
            for r in env.get("resources", [])
        }
        objective = case["user_objective"]
        constraints = list(objective.get("constraints") or [])
        constraint = case.get("contextual_constraint")
        if constraint:
            constraints.append(constraint["constraint"])
        delegation = case["agent"].get("delegation") or {}
        return Observation(
            tenant_id=env["tenant_id"],
            agent_id=case["agent"]["agent_id"],
            trust_domain=env["trust_domain"],
            role=case["agent"].get("role", "agent"),
            objective_text=objective["text"],
            objective_source=objective.get("source", "trusted_user"),
            constraints=constraints,
            instructions=list(case["agent"].get("instructions") or []),
            grants=list(case["tools"]),
            resources=resources,
            initial_state=dict(env.get("initial_state") or {}),
            delegate_authorized=bool(delegation.get("authorized", True)),
            delegation_depth=int(delegation.get("depth", 0)),
            parent_agent=delegation.get("parent_agent"),
        )


@dataclass
class RuntimeState:
    """Session state the monitor owns. Units are explicit in the field names."""
    tenant_id: str
    agent_id: str
    step: int = 0
    started_at: float = field(default_factory=time.monotonic)
    taint: Set[str] = field(default_factory=set)
    read_labels: Dict[str, str] = field(default_factory=dict)
    rows_read: int = 0
    bytes_egress_mb: float = 0.0
    requests: int = 0
    messages: int = 0
    instances: int = 0
    disk_gb: float = 0.0
    failed_auth: int = 0
    delegation_depth: int = 0
    concurrent_agents: int = 0
    workflow_state: str = "SCOPE"
    history: List[Dict[str, Any]] = field(default_factory=list)
    consumed_nonces: Set[str] = field(default_factory=set)
    issued_nonces: Set[str] = field(default_factory=set)
    approvals: List[Dict[str, Any]] = field(default_factory=list)
    memory_writes: List[Dict[str, Any]] = field(default_factory=list)
    written_paths: Set[str] = field(default_factory=set)
    executed_targets: Set[str] = field(default_factory=set)
    blocked: int = 0
    consecutive_denials: int = 0
    failed_authorizations: int = 0
    delegate_depth_seen: int = 0
    suspended: bool = False
    suspended_until: float = 0.0
    denial_log: List[Dict[str, str]] = field(default_factory=list)
    authorization: Dict[str, Any] = field(default_factory=dict)
    # Observable session evidence used by the workflow layer.
    reads: List[Dict[str, Any]] = field(default_factory=list)
    memory: Dict[str, Any] = field(default_factory=dict)
    tool_output: str = ""
    context_taint: List[str] = field(default_factory=list)
    # Tool-response provenance. The response inspector appends to these; the
    # workflow layer reads `untrusted_outputs` to refuse an action that copies a
    # destination or command out of untrusted content.
    response_log: List[Dict[str, Any]] = field(default_factory=list)
    untrusted_outputs: List[Dict[str, Any]] = field(default_factory=list)
    rejected_outputs: List[Dict[str, Any]] = field(default_factory=list)
    staged: Set[str] = field(default_factory=set)
    coordination: Dict[str, List[str]] = field(default_factory=dict)
    delegations: List[Dict[str, Any]] = field(default_factory=list)
    deputy_requests: int = 0
    acting_user: Optional[str] = None
    # Raw session envelope a deployed gateway would receive from the runtime
    # (budgets, quotas, counters). Barrier functions read it by key.
    env: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def seed(cls, obs: Observation) -> "RuntimeState":
        state = cls(tenant_id=obs.tenant_id, agent_id=obs.agent_id)
        initial = obs.initial_state
        state.delegation_depth = int(initial.get("delegation_depth", obs.delegation_depth))
        state.delegate_depth_seen = state.delegation_depth
        state.concurrent_agents = int(initial.get("concurrent_agents",
                                                  initial.get("active_agents", 0)))
        state.requests = int(initial.get("requests_last_hour", 0))
        state.messages = int(initial.get("messages_last_hour", 0))
        state.instances = int(initial.get("instances_running", 0))
        state.disk_gb = float(initial.get("disk_gb_used", 0.0))
        state.failed_auth = int(initial.get("failed_auth_attempts", 0))
        state.rows_read = int(initial.get("rows_read", 0))
        state.bytes_egress_mb = float(initial.get("bytes_egress_mb", 0.0))
        state.consumed_nonces = set(initial.get("consumed_nonces") or [])
        state.approvals = list(initial.get("approvals") or [])
        state.taint = set(initial.get("taint") or [])
        state.authorization = dict(initial.get("authorization") or {})
        state.memory = dict(initial.get("memory") or {})
        state.tool_output = str(initial.get("tool_output") or "")
        state.context_taint = list(initial.get("context_taint") or [])
        state.response_log = list(initial.get("response_log") or [])
        state.untrusted_outputs = list(initial.get("untrusted_outputs") or [])
        state.rejected_outputs = list(initial.get("rejected_outputs") or [])
        state.staged = set(initial.get("staged") or [])
        state.deputy_requests = int(initial.get("deputy_requests", 0))
        state.acting_user = initial.get("acting_user")
        state.env = dict(initial)
        if initial.get("workflow_state"):
            state.workflow_state = initial["workflow_state"]
        return state

    def apply_environment(self, delta: Dict[str, Any]) -> None:
        """Merge the environment state observed after an executed step.

        A deployed gateway sees counters and side effects after a tool returns;
        this is that observation, not a benchmark label. Expected decision and
        enforcing layer are never consulted.
        """
        if not isinstance(delta, dict):
            return
        if "active_agents" in delta:
            self.concurrent_agents = int(delta["active_agents"])
        if "concurrent_agents" in delta:
            self.concurrent_agents = int(delta["concurrent_agents"])
        if "delegation_depth" in delta:
            self.delegation_depth = int(delta["delegation_depth"])
            self.delegate_depth_seen = max(self.delegate_depth_seen, self.delegation_depth)
        for key in ("requests_last_hour", "messages_last_hour", "instances_running",
                    "failed_auth_attempts", "rows_read"):
            if key in delta:
                attr = {"requests_last_hour": "requests", "messages_last_hour": "messages",
                        "instances_running": "instances", "failed_auth_attempts": "failed_auth",
                        "rows_read": "rows_read"}[key]
                setattr(self, attr, int(delta[key]))
        if "bytes_egress_mb" in delta:
            self.bytes_egress_mb = float(delta["bytes_egress_mb"])
        if "disk_gb_used" in delta:
            self.disk_gb = float(delta["disk_gb_used"])
        if delta.get("consumed_nonces"):
            self.consumed_nonces.update(str(n) for n in delta["consumed_nonces"])
        if isinstance(delta.get("memory"), dict):
            self.memory.update(delta["memory"])
        if delta.get("tool_output"):
            self.tool_output = (self.tool_output + "\n" + str(delta["tool_output"])).strip()
        if delta.get("context_taint"):
            self.context_taint.extend(str(x) for x in delta["context_taint"])
        if delta.get("staged"):
            self.staged.update(str(x) for x in delta["staged"])
        if delta.get("coordination"):
            self._record_coordination(str(delta["coordination"]), None)
        if delta.get("deputy_requests"):
            self.deputy_requests = int(delta["deputy_requests"])
        if delta.get("approvals"):
            self.approvals.extend(delta["approvals"])
        if delta.get("workflow_state"):
            self.workflow_state = str(delta["workflow_state"])
        if delta.get("acting_user"):
            self.acting_user = str(delta["acting_user"])
        for key, value in delta.items():
            if key in ("approvals", "memory", "coordination", "context_taint", "staged"):
                continue
            self.env[key] = value

    def _record_coordination(self, group: str, agent: Optional[str]) -> None:
        members = self.coordination.setdefault(group, [])
        if agent and agent not in members:
            members.append(agent)

    # ---------------------------------------------------------------- helpers
    def classify(self, obs: Observation, target: str) -> str:
        known = obs.resources.get(target)
        if known:
            return known.get("classification", "internal")
        return "internal"

    def owner_tenant(self, obs: Observation, target: str) -> Optional[str]:
        known = obs.resources.get(target)
        if known:
            return known.get("owner_tenant")
        return None

    def note_read(self, target: str, label: str) -> None:
        self.read_labels[target] = label
        self.taint.add(label)

    def note_action(self, action: Action, decision: str) -> None:
        self.history.append({
            "step": action.step, "tool": action.tool, "operation": action.operation,
            "target": action.target, "source": action.source,
            "args_hash": action.args_hash, "decision": decision,
            "at": time.monotonic(),
        })

    def repeated(self, action: Action) -> int:
        return sum(1 for h in self.history if h["args_hash"] == action.args_hash)

    def actions_on(self, target: str) -> List[Dict[str, Any]]:
        return [h for h in self.history if h["target"] == target]

    def elapsed(self) -> float:
        return time.monotonic() - self.started_at

    def matching_approval(self, action: Action) -> Optional[Dict[str, Any]]:
        wanted = action.args_hash
        now = time.time()
        for record in self.approvals:
            if record.get("used"):
                continue
            if record.get("args_hash") != wanted:
                continue
            if record.get("tool") not in (None, action.tool):
                continue
            expiry = record.get("expires_at")
            if expiry is not None and float(expiry) < now:
                continue
            if record.get("revoked"):
                continue
            return record
        return None

    def authorization_record(self) -> Dict[str, Any]:
        """The user authorisation recorded at session start (may be empty)."""
        return self.authorization
