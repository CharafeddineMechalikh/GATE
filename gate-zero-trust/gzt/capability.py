"""Layer 1 - capability-based access control.

A capability token is an HMAC-signed grant from a tenant authority to one
agent. Authorization consumes the concrete tool arguments: the operation class,
the resource instance, the tenant claim and the delegation position must all be
covered by the grant. A tool name alone is never sufficient, and anything the
token does not positively cover is denied.
"""
from __future__ import annotations

import fnmatch
import hmac
import json
import secrets
import time
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any, Dict, List, Optional

from .decision import Decision, LayerResult
from .policies import ADMIN_PATH_MARKERS
from .runtime import Action, Observation, RuntimeState


def _canonical(payload: Dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass
class CapabilityToken:
    subject: str
    tenant: str
    grants: List[Dict[str, Any]]
    expires_at: float
    delegation_chain: List[str] = field(default_factory=list)
    jti: str = field(default_factory=lambda: secrets.token_hex(8))
    signature: str = ""

    def payload(self) -> Dict[str, Any]:
        return {"subject": self.subject, "tenant": self.tenant, "grants": self.grants,
                "expires_at": self.expires_at, "delegation_chain": self.delegation_chain,
                "jti": self.jti}


class CapabilityAuthority:
    """Issues and verifies tokens. The key never leaves the authority."""

    def __init__(self, secret: Optional[bytes] = None) -> None:
        self._secret = secret or sha256(b"gate-zero-trust-deployment-key").digest()
        self.revoked: set[str] = set()

    def issue(self, subject: str, tenant: str, grants: List[Dict[str, Any]],
              ttl_seconds: float = 3600.0,
              delegation_chain: Optional[List[str]] = None) -> CapabilityToken:
        token = CapabilityToken(
            subject=subject, tenant=tenant, grants=[json.loads(json.dumps(g)) for g in grants],
            expires_at=time.time() + ttl_seconds,
            delegation_chain=list(delegation_chain or []),
        )
        token.signature = hmac.new(self._secret, _canonical(token.payload()),
                                   sha256).hexdigest()
        return token

    def verify(self, token: CapabilityToken) -> bool:
        expected = hmac.new(self._secret, _canonical(token.payload()), sha256).hexdigest()
        return hmac.compare_digest(expected, token.signature) and token.jti not in self.revoked

    def revoke(self, token: CapabilityToken) -> None:
        self.revoked.add(token.jti)


def _scope_matches(entry: str, target: str) -> bool:
    if not entry:
        return False
    if entry == target:
        return True
    if "*" in entry or "?" in entry:
        if fnmatch.fnmatchcase(target, entry):
            return True
        return fnmatch.fnmatchcase(target + "/", entry + "/")
    return target.startswith(entry.rstrip("/") + "/")


class CapabilityLayer:
    name = "capability"

    def __init__(self, authority: CapabilityAuthority) -> None:
        self.authority = authority

    def check(self, obs: Observation, state: RuntimeState, action: Action,
              token: Optional[CapabilityToken]) -> LayerResult:
        if token is None:
            return self._deny(action, "CAP-MISSING-001", "no capability token presented")
        if not self.authority.verify(token):
            return self._deny(action, "CAP-SIGNATURE-001", "capability signature invalid or revoked")
        if token.expires_at < time.time():
            return self._deny(action, "CAP-EXPIRED-001", "capability expired")
        if token.subject != obs.agent_id:
            return self._deny(action, "CAP-SUBJECT-001", "token subject is not the acting agent")

        grant = next((g for g in token.grants if g.get("name") == action.tool), None)
        if grant is None:
            return self._deny(action, "CAP-TOOL-001", f"tool {action.tool} not granted")
        permissions = grant.get("permissions") or {}
        allowed_ops = list(permissions.get("allowed_operations") or [])
        scope = list(permissions.get("resource_scope") or [])
        tenant_scope = list(permissions.get("tenant_scope") or [])

        if action.operation not in allowed_ops:
            return self._deny(action, "CAP-OPERATION-001",
                              f"operation {action.operation} not in grant {allowed_ops}")
        if not any(_scope_matches(entry, action.target) for entry in scope):
            return self._deny(action, "CAP-RESOURCE-001",
                              f"target {action.target} outside granted scope {scope}")

        explicitly_granted = any(entry == action.target for entry in scope)
        if not explicitly_granted and any(marker in action.target for marker in ADMIN_PATH_MARKERS):
            return self._deny(action, "CAP-ADMIN-SURFACE-001",
                              f"administrative surface {action.target} is outside the grant")

        owner = state.owner_tenant(obs, action.target)
        declared_tenant = self._declared_tenant(action)
        if declared_tenant and declared_tenant in tenant_scope:
            # The call narrows itself to the token's own rows; a shared table's
            # owner is not the tenant of the rows this call may return.
            owner = None
        foreign = {t for t in (owner, declared_tenant) if t and t not in tenant_scope}
        if foreign:
            agreement = obs.initial_state.get("data_sharing_agreement")
            counterparty = obs.initial_state.get("sharing_counterparty")
            if not (agreement and counterparty and foreign == {counterparty}):
                return self._deny(action, "CAP-TENANT-001",
                                  f"resource tenant {sorted(foreign)} outside token tenant scope")

        if action.tool == "agent_delegate":
            depth = state.delegation_depth
            if not obs.delegate_authorized:
                return self._deny(action, "CAP-DELEGATION-001",
                                  "this agent holds no delegation authority")
            if token.delegation_chain and depth >= len(token.delegation_chain) + 1:
                return self._deny(action, "CAP-DELEGATION-DEPTH-001",
                                  "delegation chain depth exceeded")

        return LayerResult.allow(self.name, "CAP-ALLOW-001",
                                 "operation, resource and tenant are covered by the token",
                                 evidence={"jti": token.jti, "operation": action.operation,
                                           "target": action.target})

    @staticmethod
    def _declared_tenant(action: Action) -> Optional[str]:
        args = action.args or {}
        for key in ("tenant_id", "tenant", "org_id"):
            value = args.get(key)
            if isinstance(value, str):
                return value
        filt = args.get("filter") if isinstance(args.get("filter"), dict) else {}
        for key in ("tenant_id", "tenant", "org_id"):
            value = filt.get(key)
            if isinstance(value, str):
                return value
        body = args.get("body")
        if isinstance(body, str):
            try:
                parsed = json.loads(body)
            except (ValueError, TypeError):
                return None
            if isinstance(parsed, dict):
                for key in ("tenant_id", "tenant", "org_id"):
                    if isinstance(parsed.get(key), str):
                        return parsed[key]
        return None

    def _deny(self, action: Action, policy: str, reason: str) -> LayerResult:
        return LayerResult(Decision.DENY, self.name, policy, reason, risk="high",
                           evidence={"tool": action.tool, "operation": action.operation,
                                     "target": action.target})
