"""Layer 6 - runtime behavioural monitoring with discrete control barrier functions.

Each monitored resource ``i`` has a scalar barrier

    h_i(s) = ceiling_i - value_i(s)

and the layer enforces the discrete-time forward-invariance condition

    h_i(s') + (kappa - 1) * h_i(s) >= 0

for every barrier, with ``kappa = 1`` so the condition reduces to
``h_i(s') >= 0``. ``s'`` is not read from the environment: the layer predicts
the next state from the current session state and the action's own arguments
(how many agents a spawn creates, how many instances a provision starts, how
many gigabytes a ``dd`` writes, how many recipients a message carries, ...).
That prediction is what separates a control barrier from a threshold alarm: the
barrier must hold *after* the action, not only before it.

Barriers never fire on their own baseline: a session that starts inside the
safe set and issues one action whose predicted footprint stays inside every
ceiling is allowed, whatever the action's phrasing. Ceilings are configuration
(policy tables plus the tenant's session envelope from ``initial_state``), never
benchmark labels.
"""
from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from .decision import Decision, LayerResult
from .runtime import Action, Observation, RuntimeState

LAYER = "dcbf"
KAPPA = 1.0

# --------------------------------------------------------------- envelopes
DEFAULT_CEILINGS: Dict[str, float] = {
    "auth_attempts_5m": 50.0,
    "auth_failures_5m": 50.0,
    "auth_failures_15m": 60.0,
    "distinct_accounts_15m": 60.0,
    "outbound_requests_1m": 1000.0,
    "outbound_bytes_1m": 1.0e9,
    "email_envelope_1h": 200.0,
    "partner_quota_1h": 600.0,
    "instance_ceiling": 20.0,
    "active_agents_ceiling": 8.0,
    "delegation_depth_ceiling": 3.0,
    "disk_quota_gb": 64.0,
    "cpu_cores": 8.0,
    "memory_gb": 16.0,
}

_AUTH_URL = re.compile(r"login|/auth\b|oauth|sign[-_]?in|/token\b|/session\b", re.I)
_AUTH_BODY = re.compile(r'"(?:pass(?:word)?|pwd|credential|otp|mfa)"\s*:', re.I)
_FORK_BOMB = re.compile(r":\s*\(\s*\)\s*\{[^}]*:\s*\|\s*:\s*&", re.S)
_DD = re.compile(r"\bdd\b.*\bof=(\S+)", re.S)
_DD_COUNT = re.compile(r"\bcount=(\d+)")
_DD_BS = re.compile(r"\bbs=(\d+)([kKmMgG]?)")
_STRESS_CPU = re.compile(r"--cpu\s+(\d+)")
_STRESS_VM = re.compile(r"--vm\s+(\d+)")
_STRESS_BYTES = re.compile(r"--vm-bytes\s+(\d+)([kKmMgG])")
_SPAWN_COUNT = re.compile(r"max_children\s*[:=]\s*(\d+)|spawn\s+(\d+)|(\d+)\s+workers", re.I)
_PAGE_SIZE = re.compile(r"page_size\s*[:=]\s*(\d+)")


def _env(state: RuntimeState) -> Dict[str, Any]:
    return getattr(state, "env", {}) or {}


CEILING_KEYS = frozenset({
    "instance_ceiling", "active_agents_ceiling", "delegation_depth_ceiling",
    "disk_quota_gb", "email_envelope_1h", "partner_quota_1h",
})


def _ceiling(state: RuntimeState, key: str) -> float:
    env = _env(state)
    if key in CEILING_KEYS and key in env:
        try:
            return float(env[key])
        except (TypeError, ValueError):
            return DEFAULT_CEILINGS[key]
    return DEFAULT_CEILINGS[key]


def _value(state: RuntimeState, key: str) -> float:
    env = _env(state)
    if key in env:
        try:
            return float(env[key])
        except (TypeError, ValueError):
            return 0.0
    aliases = {
        "active_agents_ceiling": "concurrent_agents",
        "delegation_depth_ceiling": "delegation_depth",
        "disk_used_gb": "disk_gb",
    }
    if key in aliases:
        return float(getattr(state, aliases[key], 0.0) or 0.0)
    return 0.0


def _session_count(state: RuntimeState, predicate) -> int:
    return sum(1 for h in state.history if predicate(h))


def _recipients(action: Action) -> int:
    total = 0
    for key in ("to", "cc", "bcc", "recipients"):
        raw = action.args.get(key)
        if raw is None:
            continue
        text = raw if isinstance(raw, str) else json.dumps(raw)
        parts = [p for p in re.split(r"[,;]", text) if "@" in p]
        total += max(1, len(parts)) if parts else 0
    return total or 1


def _auth_action(action: Action) -> bool:
    if action.tool != "http_request":
        return False
    url = str(action.args.get("url", ""))
    body = action.args.get("body")
    body_text = body if isinstance(body, str) else json.dumps(body or "")
    return bool(_AUTH_URL.search(url) or _AUTH_BODY.search(body_text))


def _dd_gb(command: str) -> float:
    if not _DD.search(command):
        return 0.0
    match_count = _DD_COUNT.search(command)
    match_bs = _DD_BS.search(command)
    if not (match_count and match_bs):
        return 0.0
    unit = {"": 1, "k": 1e3, "m": 1e6, "g": 1e9}[match_bs.group(2).lower()]
    return int(match_count.group(1)) * int(match_bs.group(1)) * unit / 1e9


def _stress(command: str) -> Tuple[float, float]:
    cpu = 0.0
    memory = 0.0
    match_cpu = _STRESS_CPU.search(command)
    if match_cpu:
        cpu = float(match_cpu.group(1))
    match_bytes = _STRESS_BYTES.search(command)
    if match_bytes:
        unit = {"k": 1e-6, "m": 1e-3, "g": 1.0}[match_bytes.group(2).lower()]
        per_worker = float(match_bytes.group(1)) * unit
        match_vm = _STRESS_VM.search(command)
        workers = float(match_vm.group(1)) if match_vm else 1.0
        memory = per_worker * workers
    return cpu, memory


def _spawn_fanout(action: Action) -> int:
    scope = str(action.args.get("scope", ""))
    task = str(action.args.get("task", ""))
    for text in (scope, task):
        match = _SPAWN_COUNT.search(text)
        if match:
            for group in match.groups():
                if group:
                    return int(group)
    return 1


@dataclass
class Barrier:
    policy_id: str
    key: str
    ceiling: float
    current: float
    predicted: float
    detail: str

    @property
    def h_now(self) -> float:
        return self.ceiling - self.current

    @property
    def h_next(self) -> float:
        return self.ceiling - self.predicted

    @property
    def breached(self) -> bool:
        return self.h_next + (KAPPA - 1.0) * self.h_now < 0.0


class DCBFLayer:
    """Forward-invariant runtime supervisor over finite session budgets."""

    name = LAYER

    def check(self, obs: Observation, state: RuntimeState,
              action: Action) -> Optional[LayerResult]:
        barriers = self._barriers(obs, state, action)
        breached = [b for b in barriers if b.breached]
        if not breached:
            return None
        worst = min(breached, key=lambda b: b.h_next)
        return LayerResult(
            decision=Decision.DENY,
            layer=LAYER,
            policy_id=worst.policy_id,
            reason=(f"{worst.detail}; the predicted next state leaves the safe set "
                    f"(h={worst.h_next:.2f})"),
            risk="high",
            evidence={
                "barriers": [
                    {"policy_id": b.policy_id, "key": b.key, "ceiling": b.ceiling,
                     "current": round(b.current, 3), "predicted": round(b.predicted, 3),
                     "h_now": round(b.h_now, 3), "h_next": round(b.h_next, 3)}
                    for b in barriers
                ],
                "kappa": KAPPA,
            },
        )

    # ------------------------------------------------------------ barriers
    def _barriers(self, obs: Observation, state: RuntimeState,
                  action: Action) -> List[Barrier]:
        out: List[Barrier] = []
        out.extend(self._auth(state, action))
        out.extend(self._network(state, action))
        out.extend(self._mail(state, action))
        out.extend(self._compute(state, action))
        out.extend(self._delegation(state, action))
        return out

    def _auth(self, state: RuntimeState, action: Action) -> List[Barrier]:
        if not _auth_action(action):
            return []
        attempts = _value(state, "auth_attempts_5m")
        failures = _value(state, "auth_failures_5m")
        failures_15 = _value(state, "auth_failures_15m")
        accounts = _value(state, "distinct_accounts_15m")
        result = []
        spec = (
            ("auth_attempts_5m", attempts, "CBF-AUTH-RATE-001",
             "authentication attempts exceed the allowed rate envelope for this session"),
            ("auth_failures_5m", failures, "CBF-AUTH-RATE-001",
             "failed authentication attempts exceed the session failure envelope"),
            ("auth_failures_15m", failures_15, "CBF-AUTH-RATE-001",
             "failed authentication attempts over 15 minutes exceed the envelope"),
            ("distinct_accounts_15m", accounts, "CBF-AUTH-RATE-001",
             "the action widens the account spread beyond the spray envelope"),
        )
        for key, current, policy, detail in spec:
            if current <= 0 and key != "auth_attempts_5m":
                continue
            result.append(Barrier(policy, key, _ceiling(state, key), current,
                                  current + 1.0, detail))
        return result

    def _network(self, state: RuntimeState, action: Action) -> List[Barrier]:
        if action.tool not in ("http_request", "webhook_post"):
            return []
        result: List[Barrier] = []
        requests = _value(state, "outbound_requests_1m")
        if requests > 0:
            result.append(Barrier(
                "CBF-EGRESS-RATE-001", "outbound_requests_1m",
                _ceiling(state, "outbound_requests_1m"), requests, requests + 1.0,
                "outbound request rate is at or beyond the tenant's envelope"))
        sent = _value(state, "outbound_bytes_1m")
        body = action.args.get("body")
        body_size = len(body.encode("utf-8")) if isinstance(body, str) else 0
        requested = 0
        match = _PAGE_SIZE.search(body if isinstance(body, str) else json.dumps(body or ""))
        if match:
            requested = int(match.group(1))
        range_header = str(action.args.get("range", ""))
        range_match = re.search(r"(\d+)-(\d+)", range_header)
        if range_match:
            requested = max(requested, int(range_match.group(2)) - int(range_match.group(1)))
        payload_bytes = max(body_size, requested)
        if sent > 0 or requested > 0:
            result.append(Barrier(
                "CBF-EGRESS-BYTES-001", "outbound_bytes_1m",
                _ceiling(state, "outbound_bytes_1m"), sent, sent + payload_bytes,
                "the request amplifies outbound byte volume beyond the envelope"))
        quota = _value(state, "partner_quota_1h")
        calls = _value(state, "partner_calls_1h")
        if quota > 0 and calls > 0:
            result.append(Barrier(
                "CBF-QUOTA-001", "partner_calls_1h", quota, calls, calls + 1.0,
                "the negotiated partner quota is already consumed"))
        return result

    def _mail(self, state: RuntimeState, action: Action) -> List[Barrier]:
        if action.tool != "send_email":
            return []
        sent = _value(state, "emails_sent_1h")
        if sent <= 0:
            return []
        recipients = _recipients(action)
        return [Barrier(
            "CBF-MAIL-VOLUME-001", "emails_sent_1h",
            _ceiling(state, "email_envelope_1h"), sent, sent + recipients,
            "the message volume continues past the hourly envelope")]

    def _compute(self, state: RuntimeState, action: Action) -> List[Barrier]:
        result: List[Barrier] = []
        if action.tool == "code_execute":
            command = str(action.args.get("command", ""))
            if _FORK_BOMB.search(command) or re.search(r"\bfork\s*bomb\b", command, re.I):
                result.append(Barrier(
                    "CBF-RESOURCE-001", "processes", 0.0, 0.0, math.inf,
                    "a fork bomb drives the process count past the resource barrier"))
            written = _dd_gb(command)
            if written > 0:
                used = _value(state, "disk_used_gb")
                quota = _ceiling(state, "disk_quota_gb")
                result.append(Barrier(
                    "CBF-RESOURCE-001", "disk_quota_gb", quota, used, used + written,
                    "the write exhausts the shared volume for every co-tenant"))
            cpu, memory = _stress(command)
            if cpu > 0:
                result.append(Barrier(
                    "CBF-RESOURCE-001", "cpu_cores", _ceiling(state, "cpu_cores"),
                    0.0, cpu, "the stress run claims more cores than the envelope allows"))
            if memory > 0:
                result.append(Barrier(
                    "CBF-RESOURCE-001", "memory_gb", _ceiling(state, "memory_gb"),
                    0.0, memory, "the stress run claims more memory than the envelope allows"))
        if action.tool == "cloud_api":
            spec = action.args.get("spec") if isinstance(action.args.get("spec"), dict) else {}
            op = str(spec.get("op") or action.operation or "").lower()
            count = spec.get("count", spec.get("instances", 0))
            try:
                count = float(count or 0)
            except (TypeError, ValueError):
                count = 0.0
            if op in ("provision", "create", "scale", "run") and count > 0:
                current = _value(state, "instances_provisioned")
                result.append(Barrier(
                    "CBF-CLOUD-QUOTA-001", "instances_provisioned",
                    _ceiling(state, "instance_ceiling"), current, current + count,
                    "the provisioned instance count breaches the per-session ceiling"))
        return result

    def _delegation(self, state: RuntimeState, action: Action) -> List[Barrier]:
        if action.tool != "agent_delegate":
            return []
        fanout = _spawn_fanout(action)
        agents = _value(state, "active_agents") or float(state.concurrent_agents or 0)
        depth = _value(state, "delegation_depth") or float(state.delegation_depth or 0)
        return [
            Barrier("CBF-DELEGATION-001", "active_agents",
                    _ceiling(state, "active_agents_ceiling"), agents, agents + fanout,
                    "the requested fan-out exceeds the concurrent-agent ceiling"),
            Barrier("CBF-DELEGATION-001", "delegation_depth",
                    _ceiling(state, "delegation_depth_ceiling"), depth, depth + 1.0,
                    "the spawn deepens the delegation chain past its ceiling"),
        ]
