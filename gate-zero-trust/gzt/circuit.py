"""Security circuit breaker.

The breaker watches the decision stream and suspends the whole session when the
stream shows an attack in progress rather than an isolated mistake:

* three consecutive denials;
* four denials of the same policy inside one session;
* postcondition failures after execution (the environment disagreed with the
  safety envelope).

A suspended session fails closed: every further call is denied at the gate with
``CIRCUIT-SUSPENDED-001`` until the suspension expires or an operator resets it.
The thresholds are configuration; the breaker never reads benchmark labels.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .decision import Decision, LayerResult
from .runtime import RuntimeState

LAYER = "circuit"
MAX_CONSECUTIVE_DENIALS = 3
MAX_SAME_POLICY = 4
SUSPENSION_SECONDS = 300.0


@dataclass
class BreakerEvent:
    policy_id: str
    reason: str
    suspended_until: float
    counters: Dict[str, int] = field(default_factory=dict)


class CircuitBreaker:
    name = LAYER

    def __init__(self, max_consecutive: int = MAX_CONSECUTIVE_DENIALS,
                 max_same_policy: int = MAX_SAME_POLICY,
                 suspension_seconds: float = SUSPENSION_SECONDS) -> None:
        self.max_consecutive = max_consecutive
        self.max_same_policy = max_same_policy
        self.suspension_seconds = suspension_seconds

    # ------------------------------------------------------------- gate
    def check(self, state: RuntimeState) -> Optional[LayerResult]:
        until = float(getattr(state, "suspended_until", 0.0) or 0.0)
        if state.suspended and until > time.monotonic():
            return LayerResult(
                decision=Decision.DENY, layer=LAYER,
                policy_id="CIRCUIT-SUSPENDED-001",
                reason="the session is suspended after repeated policy violations",
                risk="critical",
                evidence={"suspended_until": until,
                          "consecutive_denials": state.consecutive_denials,
                          "blocked": state.blocked},
            )
        if state.suspended and until <= time.monotonic():
            state.suspended = False
            state.consecutive_denials = 0
        return None

    # ----------------------------------------------------------- observe
    def record(self, state: RuntimeState, decision: Decision, policy_id: str,
               outcome: str) -> Optional[BreakerEvent]:
        if decision is Decision.DENY:
            state.blocked += 1
            state.consecutive_denials += 1
            state.failed_authorizations += 1
        elif outcome == "executed_postcondition_failed":
            state.consecutive_denials += 1
        else:
            state.consecutive_denials = 0

        history: List[Dict[str, str]] = getattr(state, "denial_log", None) or []
        if decision is Decision.DENY:
            history.append({"policy": policy_id, "at": str(time.monotonic())})
            state.denial_log = history
        same = sum(1 for item in history if item["policy"] == policy_id)

        reason = None
        if state.consecutive_denials >= self.max_consecutive:
            reason = f"{state.consecutive_denials} consecutive denials"
        elif same >= self.max_same_policy:
            reason = f"{same} denials of {policy_id} in one session"
        elif outcome == "executed_postcondition_failed":
            reason = "postcondition failure after execution"
        elif state.failed_authorizations >= self.max_same_policy:
            reason = f"{state.failed_authorizations} failed authorisations in one session"

        if reason is None:
            return None
        until = time.monotonic() + self.suspension_seconds
        state.suspended = True
        state.suspended_until = until
        return BreakerEvent(
            policy_id="CIRCUIT-SUSPENDED-001", reason=reason,
            suspended_until=until,
            counters={"consecutive_denials": state.consecutive_denials,
                      "same_policy": same, "blocked": state.blocked,
                      "failed_authorizations": state.failed_authorizations},
        )

    def reset(self, state: RuntimeState) -> None:
        state.suspended = False
        state.suspended_until = 0.0
        state.consecutive_denials = 0
        state.denial_log = []
