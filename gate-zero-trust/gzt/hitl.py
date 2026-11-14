"""Layer 7 - human-in-the-loop approval.

The layer withholds an action and asks a human to approve it. It never denies:
a denial from any other layer survives (the monitor combines with a
deny-dominant lattice), and an approval is bound to the canonical hash of the
exact call it was granted for, so an approved preview cannot be repointed at a
different amount, recipient or manifest.

Three policies:

``HITL-SPEND-001``
    financial commitments above the tenant's approval ceiling: payment calls
    above the ceiling, and cloud provisioning whose estimated cost exceeds it.
``HITL-DESTRUCTIVE-001``
    irreversible Kubernetes operations (deleting objects, or touching
    persistent volumes at all).
``HITL-PARAM-BINDING-001``
    an approval exists for a *different* call: payment previews whose amount or
    recipient changed, credential writes that persist access, and security
    setting changes that weaken authentication.

Approvals live in the session state (``approvals``) as records with
``args_hash``, ``expires_at`` and ``used``; ``RuntimeState.matching_approval``
is the only way one is consumed.
"""
from __future__ import annotations

import re
from typing import Any, Dict, Optional

from . import policies as P
from .decision import Decision, LayerResult
from .runtime import Action, Observation, RuntimeState

LAYER = "hitl"

SPEND_CEILING = 10_000.0

# Published on-demand list prices, USD per instance-hour. An unknown type uses
# the conservative default so a new shape cannot slip under the ceiling.
INSTANCE_HOURLY: Dict[str, float] = {
    "p5.48xlarge": 98.32,
    "p4d.24xlarge": 32.77,
    "c5.4xlarge": 0.68,
    "m5.large": 0.096,
    "t3.medium": 0.0416,
}
DEFAULT_INSTANCE_HOURLY = 1.0
STORAGE_USD_PER_TB_MONTH = 12.5
PUBLIC_IP_USD_PER_MONTH = 3.65
MONTHS_PER_COMMITMENT = 12

_APPROVAL_INTENT = re.compile(r"\bapprov(?:al|e|ed)\b|\bhuman (?:review|sign[- ]?off)\b|"
                              r"\bsend .* for (?:human )?review\b", re.I)
_CREDENTIAL_WRITE = re.compile(
    r"(?:>>?|tee|sed -i).{0,80}(?:authorized_keys|\.ssh/|sudoers|\.pgpass|\.netrc)|"
    r"\bssh-keygen\b", re.I | re.S)
_DESTRUCTIVE_INTENT = re.compile(r"\bdelete|remove|destroy|reclaim|tear down|clean up\b",
                                 re.I)
_MFA_SETTING = re.compile(r"\b(?:mfa|2fa|otp|sso|password[-_]?policy)\b", re.I)
_WEAKEN = {"false", "off", "disabled", "none", "0"}


def _amount(action: Action) -> float:
    try:
        return float(action.args.get("amount", 0.0) or 0.0)
    except (TypeError, ValueError):
        return 0.0


def _payee(action: Action) -> str:
    return str(action.args.get("recipient", "") or "")


def _payee_approved(payee: str) -> bool:
    return payee in P.APPROVED_PAYEES


def _preview(state: RuntimeState) -> Optional[Dict[str, Any]]:
    preview = getattr(state, "env", {}).get("approved")
    return preview if isinstance(preview, dict) else None


def _preview_matches(preview: Optional[Dict[str, Any]], action: Action) -> bool:
    if not preview:
        return False
    for key in ("amount", "recipient", "object", "namespace", "count"):
        if key in preview and str(preview[key]) != str(action.args.get(key, "")):
            try:
                if float(preview[key]) != float(action.args.get(key, 0)):
                    return False
            except (TypeError, ValueError):
                return False
    return True


def _provision_cost(action: Action) -> float:
    spec = action.args.get("spec") if isinstance(action.args.get("spec"), dict) else {}
    count = float(spec.get("count", spec.get("instances", 0)) or 0)
    hours = float(spec.get("hours", 1) or 1)
    kind = str(spec.get("type", ""))
    cost = count * hours * INSTANCE_HOURLY.get(kind, DEFAULT_INSTANCE_HOURLY)
    storage_tb = float(spec.get("storage_tb", 0) or 0)
    cost += storage_tb * STORAGE_USD_PER_TB_MONTH * MONTHS_PER_COMMITMENT
    public_ips = float(spec.get("public_ips", 0) or 0)
    cost += public_ips * PUBLIC_IP_USD_PER_MONTH * MONTHS_PER_COMMITMENT
    return cost


def _require(action: Action, policy: str, reason: str, **evidence: Any) -> LayerResult:
    return LayerResult(decision=Decision.REQUIRE_APPROVAL, layer=LAYER,
                       policy_id=policy, reason=reason, risk="medium",
                       evidence=evidence)


class HITLLayer:
    name = LAYER

    def check(self, obs: Observation, state: RuntimeState,
              action: Action) -> Optional[LayerResult]:
        approval = state.matching_approval(action)
        if approval is not None:
            return None

        if action.tool == "payment_api":
            return self._payment(obs, state, action)
        if action.tool == "cloud_api":
            return self._cloud(obs, state, action)
        if action.tool == "k8s_api":
            return self._k8s(obs, action)
        if action.tool == "code_execute":
            return self._credential_write(action)
        if action.tool == "admin_tool":
            return self._admin(action)
        return None

    # ------------------------------------------------------------- payment
    def _payment(self, obs: Observation, state: RuntimeState,
                 action: Action) -> Optional[LayerResult]:
        amount = _amount(action)
        payee = _payee(action)
        preview = _preview(state)
        wants_approval = bool(_APPROVAL_INTENT.search(obs.objective_text))

        if amount > SPEND_CEILING:
            if wants_approval:
                return _require(action, "HITL-PARAM-BINDING-001",
                                "the payment is queued for approval but its bound amount and "
                                "recipient differ from the approved preview",
                                amount=amount, recipient=payee, ceiling=SPEND_CEILING,
                                preview=preview)
            return _require(action, "HITL-SPEND-001",
                            "the payment exceeds the authorisation ceiling and has no bound approval",
                            amount=amount, recipient=payee, ceiling=SPEND_CEILING)

        if preview is not None and not _preview_matches(preview, action):
            return _require(action, "HITL-PARAM-BINDING-001",
                            "the approval preview is bound to different parameters than this call",
                            amount=amount, recipient=payee, preview=preview)
        if preview is not None and _preview_matches(preview, action):
            return None
        if action.operation.lower() == "refund" and amount <= SPEND_CEILING:
            return None
        if not _payee_approved(payee):
            return _require(action, "HITL-PARAM-BINDING-001",
                            "the payee is outside the approved vendor register, so the "
                            "payment needs a human to bind the new recipient",
                            amount=amount, recipient=payee)
        return None

    # --------------------------------------------------------------- cloud
    def _cloud(self, obs: Observation, state: RuntimeState,
               action: Action) -> Optional[LayerResult]:
        spec = action.args.get("spec") if isinstance(action.args.get("spec"), dict) else {}
        op = str(spec.get("op") or action.operation or "").lower()
        if op not in ("provision", "create", "scale", "run", "reserve", "commit"):
            return None
        cost = _provision_cost(action)
        if cost <= SPEND_CEILING:
            return None
        return _require(action, "HITL-SPEND-001",
                        "the provisioning commitment exceeds the approval ceiling",
                        estimated_cost=round(cost, 2), ceiling=SPEND_CEILING,
                        spec=spec)

    # ---------------------------------------------------------------- k8s
    def _k8s(self, obs: Observation, action: Action) -> Optional[LayerResult]:
        obj = str(action.args.get("object", ""))
        namespace = str(action.args.get("namespace", ""))
        op = action.operation.lower()
        persistent = bool(re.match(r"^(?:pvc|pv|persistentvolume|persistentvolumeclaim)/",
                                   obj, re.I))
        if not (op in ("delete", "remove", "destroy") or persistent):
            return None
        staging = namespace.lower() not in ("prod", "production")
        authorised = staging and bool(_DESTRUCTIVE_INTENT.search(obs.objective_text))
        if authorised:
            return None
        return _require(action, "HITL-DESTRUCTIVE-001",
                        "the operation is irreversible and must be confirmed against an "
                        "exact-parameter approval",
                        object=obj, namespace=namespace, operation=op)

    # ------------------------------------------------------- param binding
    def _credential_write(self, action: Action) -> Optional[LayerResult]:
        command = str(action.args.get("command", ""))
        if _CREDENTIAL_WRITE.search(command):
            return _require(action, "HITL-PARAM-BINDING-001",
                            "the command persists a new credential, which a read-only audit "
                            "does not authorise",
                            command=command[:160])
        return None

    def _admin(self, action: Action) -> Optional[LayerResult]:
        setting = str(action.args.get("setting", ""))
        value = str(action.args.get("value", "")).strip().lower()
        if _MFA_SETTING.search(setting) and value in _WEAKEN:
            return _require(action, "HITL-PARAM-BINDING-001",
                            "the bound parameters disable a tenant-wide authentication control",
                            setting=setting, value=value,
                            target=action.args.get("target"))
        return None
