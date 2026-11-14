"""Tamper-evident audit trail.

Every decision the monitor makes is appended to a hash chain:

    record_hash = SHA256(prev_hash || canonical(record_without_hash))

Rewriting, reordering, deleting or inserting a record breaks every later hash,
so a verifier can name the first index that diverges. The chain also carries the
session history needed for after-the-fact attribution: tenant, agent, action,
args hash, deciding layer, policy and the layer results.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

GENESIS = "0" * 64


def _canonical(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


@dataclass
class AuditRecord:
    seq: int
    at: float
    tenant_id: str
    agent_id: str
    step: int
    tool: str
    operation: str
    target: str
    args_hash: str
    decision: str
    deciding_layer: str
    deciding_policy: str
    outcome: str
    layers: List[Dict[str, Any]] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    prev_hash: str = GENESIS
    record_hash: str = ""

    def body(self) -> Dict[str, Any]:
        return {
            "seq": self.seq, "at": self.at, "tenant_id": self.tenant_id,
            "agent_id": self.agent_id, "step": self.step, "tool": self.tool,
            "operation": self.operation, "target": self.target,
            "args_hash": self.args_hash, "decision": self.decision,
            "deciding_layer": self.deciding_layer,
            "deciding_policy": self.deciding_policy, "outcome": self.outcome,
            "layers": self.layers, "evidence": self.evidence,
            "prev_hash": self.prev_hash,
        }

    def to_dict(self) -> Dict[str, Any]:
        body = self.body()
        body["record_hash"] = self.record_hash
        return body


class AuditLog:
    def __init__(self) -> None:
        self.records: List[AuditRecord] = []

    @property
    def head(self) -> str:
        return self.records[-1].record_hash if self.records else GENESIS

    def append(self, tenant_id: str, agent_id: str, step: int, tool: str,
               operation: str, target: str, args_hash: str, decision: str,
               deciding_layer: str, deciding_policy: str, outcome: str,
               layers: Optional[Iterable[Dict[str, Any]]] = None,
               evidence: Optional[Dict[str, Any]] = None) -> AuditRecord:
        record = AuditRecord(
            seq=len(self.records), at=time.time(), tenant_id=tenant_id,
            agent_id=agent_id, step=step, tool=tool, operation=operation,
            target=target, args_hash=args_hash, decision=decision,
            deciding_layer=deciding_layer, deciding_policy=deciding_policy,
            outcome=outcome, layers=list(layers or []),
            evidence=dict(evidence or {}), prev_hash=self.head,
        )
        record.record_hash = hashlib.sha256(
            (_canonical(record.body())).encode("utf-8")).hexdigest()
        self.records.append(record)
        return record

    def verify(self) -> Tuple[bool, Optional[int]]:
        prev = GENESIS
        for index, record in enumerate(self.records):
            if record.prev_hash != prev:
                return False, index
            digest = hashlib.sha256(_canonical(record.body()).encode("utf-8")).hexdigest()
            if digest != record.record_hash:
                return False, index
            prev = record.record_hash
        return True, None

    # ------------------------------------------------------------ persistence
    def write_jsonl(self, path: str) -> None:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            for record in self.records:
                handle.write(json.dumps(record.to_dict(), sort_keys=True) + "\n")

    def digest(self) -> str:
        return self.head
