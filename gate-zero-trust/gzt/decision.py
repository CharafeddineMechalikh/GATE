"""Structured security decisions and deny-dominant combination.

Every layer returns a :class:`LayerResult`. The monitor combines them with a
deny-dominant lattice: ``DENY > REQUIRE_APPROVAL > ALLOW``. A layer can never
silently override another layer's denial, and an approval requirement never
turns a denial into an execution.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional


class Decision(str, Enum):
    ALLOW = "ALLOW"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    DENY = "DENY"


RANK = {Decision.ALLOW: 0, Decision.REQUIRE_APPROVAL: 1, Decision.DENY: 2}
RISK_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class Outcome(str, Enum):
    EXECUTED = "executed"
    BLOCKED = "blocked"
    WITHHELD = "withheld"
    EXECUTED_POSTCONDITION_FAILED = "executed_postcondition_failed"


@dataclass
class LayerResult:
    decision: Decision
    layer: str
    policy_id: str
    reason: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    risk: str = "low"
    context: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    correlation_id: str = field(default_factory=lambda: uuid.uuid4().hex)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision": self.decision.value,
            "layer": self.layer,
            "policy_id": self.policy_id,
            "reason": self.reason,
            "evidence": self.evidence,
            "risk": self.risk,
            "context": self.context,
            "timestamp": self.timestamp,
            "correlation_id": self.correlation_id,
        }

    @staticmethod
    def allow(layer: str, policy_id: str = "", reason: str = "no policy violated",
              **kw: Any) -> "LayerResult":
        return LayerResult(Decision.ALLOW, layer, policy_id, reason, **kw)


@dataclass
class CombinedDecision:
    decision: Decision
    deciding_layer: str
    deciding_policy: str
    results: List[LayerResult]
    explain: str = ""

    @property
    def denied(self) -> bool:
        return self.decision is Decision.DENY

    @property
    def withheld(self) -> bool:
        return self.decision is Decision.REQUIRE_APPROVAL

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision": self.decision.value,
            "deciding_layer": self.deciding_layer,
            "deciding_policy": self.deciding_policy,
            "explain": self.explain,
            "layers": [r.to_dict() for r in self.results],
        }


def combine(results: Iterable[LayerResult]) -> CombinedDecision:
    """Deny-dominant combination, earliest layer wins ties of equal severity."""
    materialised = list(results)
    if not materialised:
        return CombinedDecision(Decision.DENY, "monitor", "FAIL-CLOSED",
                                [], "no layer produced a decision")
    worst = max(RANK[r.decision] for r in materialised)
    winners = [r for r in materialised if RANK[r.decision] == worst]
    winner = winners[0]
    explain = "; ".join(f"{r.layer}:{r.decision.value}:{r.policy_id}" for r in winners)
    return CombinedDecision(winner.decision, winner.layer, winner.policy_id,
                            materialised, explain)


def deny_override(decision: Decision, mandatory_denials: Iterable[LayerResult]) -> Decision:
    """A mandatory prohibition survives an approval requirement."""
    if any(r.decision is Decision.DENY for r in mandatory_denials):
        return Decision.DENY
    return decision
