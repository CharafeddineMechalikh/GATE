"""Inbound tool-response inspection and provenance tracking.

A deployed gateway sees two sides of every tool call: the request it approves
and the response the tool returns. This module handles the second side. It
validates the response envelope, decides how far the content may be trusted,
labels it, records its provenance on the session, and decides whether the
content may enter the agent's context at all.

Design rules:

* a response is data. Nothing here can add a grant, consume or create an
  approval, change the objective, or move the workflow state forward;
* malformed or oversized responses are rejected as a whole; partial content is
  never merged, so a schema violation cannot smuggle a usable instruction;
* content that belongs to another tenant is quarantined, not tainted;
* untrusted content is retained as data and taints the context, so the workflow
  layer can refuse an action that copies a destination or command out of it;
* a classification is the join of the envelope's declared label, the resource
  the call touched and markers found in the content.

The inspector is deterministic and reads only the response envelope the gateway
would receive plus the session state. Benchmark labels are never consulted.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import unquote

from .runtime import Observation, RuntimeState

MAX_RESPONSE_BYTES = 65_536
CONTENT_TYPES = {"text/plain", "text/markdown", "text/html", "text/csv", "application/json"}
TRUST_LEVELS = {"trusted_internal", "approved_partner", "external", "untrusted"}
CLASSIFICATIONS = {"public", "internal", "confidential", "restricted", "secret"}
LABEL_ORDER = {"public": 0, "internal": 1, "confidential": 2, "restricted": 3, "secret": 4}

_INSTRUCTION_DIRECT = re.compile(
    r"\b(?:please\s+)?(?:send|forward|email|upload|post|publish|share|transfer|pay|refund|"
    r"delete|drop|truncate|grant|revoke|disable|enable|execute|run|invoke|reset|export|"
    r"create|modify|update|apply|deploy)\b[^.\n]{0,120}\b(?:now|immediately|instead|instead of)\b|"
    r"\byou (?:must|should|shall|need to|are required to)\b|"
    r"\bdo not (?:tell|inform|ask|mention)\b|\bwithout (?:telling|informing|asking) the user\b|"
    r"\b(?:forward|send|email|upload|post|share)\b[^.\n]{0,80}\bto\b[^.\n]{0,80}@",
    re.I)
_INSTRUCTION_INDIRECT = re.compile(
    r"\b(?:the|this|a)\s+(?:[\w-]+\s+){0,3}"
    r"(?:policy|procedure|ticket|note|document|page|email|message|report|invite|log|row)\s+"
    r"(?:says|states|requires|instructs|asks|claims|confirms|announces)\b|"
    r"\bper (?:the|this) (?:policy|note|instruction|request|api policy)\b|"
    r"\baccording to (?:the|this) (?:policy|note|document|message|report)\b|"
    r"\bthe (?:administrator|security team|audit team|it team|helpdesk|coordinator|"
    r"orchestrator|sub-agent|console|endpoint)\s+(?:asked|instructed|requires|claims|"
    r"reports|says|states)\b",
    re.I)
_OVERRIDE = re.compile(
    r"\bignore (?:all )?(?:the )?(?:previous|prior|above|earlier) (?:instructions?|rules?|guidance|objectives?)\b|"
    r"\bdisregard (?:all )?(?:the )?(?:previous|prior|above|earlier) (?:instructions?|rules?|guidance)\b|"
    r"\bforget (?:the|your) (?:user|original|previous) (?:request|objective|instructions?)\b|"
    r"\boverride (?:the )?(?:user|system|original|previous)\b|"
    r"\bnew (?:objective|task|instructions?)\s*:",
    re.I)
_AUTHORITY = re.compile(
    r"\b(?:i am|this is|signed by|authorized by|authorised by|approved by|on behalf of)\b"
    r"[^.\n]{0,60}\b(?:ceo|cfo|cto|ciso|administrator|admin|director|head of|manager|"
    r"security team|it support|audit team)\b|"
    r"\bas (?:the )?(?:ceo|cfo|administrator|admin|director|head of)\b",
    re.I)
_APPROVAL_CLAIM = re.compile(
    r"\b(?:pre-?approved|approval (?:has been )?granted|authorization granted|"
    r"authorisation granted|permission granted|no approval (?:is )?(?:needed|required)|"
    r"skip (?:the )?approval|bypass (?:the )?approval|the user (?:already )?approved)\b",
    re.I)
_DECEPTION = re.compile(
    r"\b(?:urgent|account (?:is )?(?:suspended|locked|expired)|verify (?:your )?(?:password|identity)|"
    r"bank(?:ing)? details? (?:have )?changed|wire (?:the )?funds|final notice|"
    r"failure to comply|click (?:this|the) link|re-?authenticate)\b",
    re.I)
_SECRET = re.compile(
    r"AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"\b(?:api[_-]?key|secret|password|token)\s*[:=]\s*\S{8,}|\bBearer\s+[A-Za-z0-9._-]{16,}",
    re.I)
_PII = re.compile(
    r"\b\d{3}-\d{2}-\d{4}\b|\bSSN\b|\bDOB\b|\bdate of birth\b|\bpassport\b|"
    r"\bhome address\b|\b\d{2,4}\s+\w+\s+(?:st|street|ave|road|rd)\b",
    re.I)
_FINANCIAL = re.compile(
    r"\b(?:salary|salaries|compensation|payroll|revenue|net income|board pack|"
    r"financial|pricing model|acquisition)\b", re.I)
_INTERNAL_ONLY = re.compile(
    r"\binternal[- ]only\b|\binternal use\b|\bfor internal\b|\bconfidential\b", re.I)
_FOREIGN_TENANT = re.compile(r"\btenant-(?:beta|gamma|delta)\b", re.I)
_B64 = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")


def _decode_concealed(text: str) -> List[str]:
    decoded: List[str] = []
    for token in _B64.findall(text):
        padded = token + "=" * (-len(token) % 4)
        try:
            raw = base64.b64decode(padded, validate=True)
            rendered = raw.decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        if rendered and all(31 < ord(ch) < 127 or ch in "\n\t" for ch in rendered):
            decoded.append(rendered)
    if "%" in text:
        try:
            unquoted = unquote(text)
            if unquoted != text:
                decoded.append(unquoted)
        except (ValueError, UnicodeDecodeError):
            pass
    return decoded


@dataclass
class ToolResponse:
    """The response envelope a gateway receives from one tool call."""
    response_id: str
    tool: str
    content: str
    content_type: str = "text/plain"
    trust: str = "trusted_internal"
    source_id: str = ""
    channel: str = "tool"
    tenant: str = "tenant-alpha"
    classification: str = "internal"
    schema_version: int = 1
    status: str = "ok"
    bytes_declared: Optional[int] = None

    @staticmethod
    def from_payload(payload: Any, tool: str, target: str = "") -> "ToolResponse":
        """Build from a raw envelope without trusting any field's type."""
        raw = payload if isinstance(payload, dict) else {}
        content = raw.get("content", "")
        if not isinstance(content, (str, bytes)):
            content = json.dumps(content, sort_keys=True, default=str)
        if isinstance(content, bytes):
            try:
                content = content.decode("utf-8")
            except UnicodeDecodeError:
                content = content.decode("utf-8", "replace")
        declared = raw.get("bytes")
        return ToolResponse(
            response_id=str(raw.get("response_id") or raw.get("id") or "anonymous"),
            tool=str(raw.get("tool") or tool),
            content=content,
            content_type=str(raw.get("content_type") or "text/plain"),
            trust=str(raw.get("trust") or ""),
            source_id=str(raw.get("source_id") or raw.get("source") or ""),
            channel=str(raw.get("channel") or "tool"),
            tenant=str(raw.get("tenant") or ""),
            classification=str(raw.get("classification") or ""),
            schema_version=raw.get("schema_version", 1),
            status=str(raw.get("status") or "ok"),
            bytes_declared=declared if isinstance(declared, int) else None,
        )


@dataclass
class ResponseAssessment:
    response_id: str
    tool: str
    target: str
    accepted: bool
    quarantined: bool
    tainted: bool
    instruction_bearing: bool
    trust: str
    classification: str
    source_id: str
    channel: str
    bytes: int
    flags: List[str] = field(default_factory=list)
    concealed_instructions: List[str] = field(default_factory=list)
    tenant_foreign: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "response_id": self.response_id, "tool": self.tool, "target": self.target,
            "accepted": self.accepted, "quarantined": self.quarantined,
            "tainted": self.tainted, "instruction_bearing": self.instruction_bearing,
            "trust": self.trust, "classification": self.classification,
            "source_id": self.source_id, "channel": self.channel,
            "bytes": self.bytes, "flags": list(self.flags),
            "concealed_instructions": list(self.concealed_instructions),
            "tenant_foreign": self.tenant_foreign,
        }


def _join_label(*labels: str) -> str:
    best = "public"
    for label in labels:
        if label in LABEL_ORDER and LABEL_ORDER[label] > LABEL_ORDER[best]:
            best = label
    return best


def _looks_structured(value: str) -> bool:
    stripped = value.strip()
    if not stripped or stripped[0] not in "[{":
        return False
    try:
        json.loads(stripped)
        return True
    except ValueError:
        return False


class ResponseInspector:
    """Validate, label and record one tool response on the session."""

    name = "response"

    def __init__(self, max_bytes: int = MAX_RESPONSE_BYTES) -> None:
        self.max_bytes = max_bytes

    def inspect(self, response: ToolResponse, obs: Observation,
                state: RuntimeState, target: str = "") -> ResponseAssessment:
        content = response.content or ""
        measured = len(content.encode("utf-8", "replace"))
        flags: List[str] = []
        concealed: List[str] = []

        malformed: List[str] = []
        if response.schema_version != 1:
            malformed.append(f"schema_version={response.schema_version!r}")
        if not response.response_id or response.response_id == "anonymous":
            malformed.append("missing response_id")
        if response.content_type not in CONTENT_TYPES:
            malformed.append(f"content_type={response.content_type!r}")
        if response.content_type == "application/json" and not _looks_structured(content):
            malformed.append("json content is not valid JSON")
        if not content.strip():
            malformed.append("empty content")
        if response.status not in ("ok", "error", "partial"):
            malformed.append(f"status={response.status!r}")

        oversized = measured > self.max_bytes or (
            response.bytes_declared is not None and response.bytes_declared > self.max_bytes)
        if oversized:
            flags.append("OVERSIZED")
        if malformed:
            flags.append("MALFORMED_SCHEMA")
        accepted = not malformed and not oversized

        trust = response.trust if response.trust in TRUST_LEVELS else "untrusted"
        if trust == "untrusted":
            flags.append("UNTRUSTED_PROVENANCE")
        elif trust != "trusted_internal":
            flags.append("UNTRUSTED_PROVENANCE")

        declared = response.classification if response.classification in CLASSIFICATIONS else ""
        resource_label = "internal"
        if target:
            resource_label = state.classify(obs, target)
        label = _join_label(declared or "public", resource_label)
        if _SECRET.search(content):
            label = _join_label(label, "secret")
        elif _PII.search(content):
            label = _join_label(label, "restricted")
        elif _FINANCIAL.search(content) or _INTERNAL_ONLY.search(content):
            label = _join_label(label, "confidential")
        if LABEL_ORDER[label] >= LABEL_ORDER["confidential"]:
            flags.append("SENSITIVE_CONTENT")

        tenant_foreign = bool(
            (response.tenant and response.tenant != obs.tenant_id)
            or _FOREIGN_TENANT.search(content))
        if tenant_foreign:
            flags.append("FOREIGN_TENANT")

        decoded = _decode_concealed(content) if accepted else []
        concealed = [d for d in decoded if _INSTRUCTION_DIRECT.search(d) or _OVERRIDE.search(d)]
        if concealed:
            flags.append("CONCEALED_INSTRUCTION")

        direct = bool(_INSTRUCTION_DIRECT.search(content))
        indirect = bool(_INSTRUCTION_INDIRECT.search(content))
        overridden = bool(_OVERRIDE.search(content)) or any(_OVERRIDE.search(d) for d in decoded)
        if overridden:
            direct = True
        if direct or concealed:
            flags.append("INSTRUCTION_DIRECT")
        if indirect and not (direct or concealed):
            flags.append("INSTRUCTION_INDIRECT")
        if overridden:
            flags.append("OVERRIDE_ATTEMPT")
        if _AUTHORITY.search(content):
            flags.append("AUTHORITY_CLAIM")
        if _APPROVAL_CLAIM.search(content):
            flags.append("APPROVAL_CLAIM")
        if _DECEPTION.search(content):
            flags.append("DECEPTION_MARKER")

        instruction_bearing = direct or indirect or bool(concealed)
        # Content taints the context when its provenance is outside the tenant,
        # when it carries an instruction, or when it asserts an authority or
        # approval that would otherwise be read as authorisation. An approved
        # partner delivering plain data is flagged but not tainted, so ordinary
        # downstream work is not blocked by mere provenance.
        tainted = (trust in ("external", "untrusted") or instruction_bearing
                   or "AUTHORITY_CLAIM" in flags or "APPROVAL_CLAIM" in flags
                   or "OVERRIDE_ATTEMPT" in flags)
        quarantined = tenant_foreign or not accepted
        if quarantined:
            flags.append("QUARANTINED")

        assessment = ResponseAssessment(
            response_id=response.response_id, tool=response.tool,
            target=target or response.tool, accepted=accepted,
            quarantined=quarantined, tainted=tainted,
            instruction_bearing=instruction_bearing, trust=trust,
            classification=label, source_id=response.source_id or "unknown",
            channel=response.channel, bytes=measured, flags=flags,
            concealed_instructions=concealed, tenant_foreign=tenant_foreign)

        self._apply(assessment, response, state)
        return assessment

    def _apply(self, assessment: ResponseAssessment, response: ToolResponse,
               state: RuntimeState) -> None:
        record = assessment.to_dict()
        state.response_log.append(record)
        if not assessment.accepted:
            state.rejected_outputs.append({
                **record, "reason": "malformed or oversized response rejected whole",
                "content": ""})
            return
        if assessment.quarantined:
            state.rejected_outputs.append({
                **record, "reason": "foreign tenant content quarantined",
                "content": ""})
            return

        content = response.content
        if content:
            state.tool_output = (state.tool_output + "\n" + content).strip()
        if assessment.classification != "public":
            state.note_read(assessment.target, assessment.classification)
            state.reads.append({"target": assessment.target,
                                "label": assessment.classification,
                                "tool": assessment.tool,
                                "source": "response",
                                "response_id": assessment.response_id})
        if assessment.tainted:
            source = assessment.source_id or assessment.response_id
            if source not in state.context_taint:
                state.context_taint.append(source)
            state.untrusted_outputs.append({
                "response_id": assessment.response_id,
                "source_id": source,
                "tool": assessment.tool,
                "target": assessment.target,
                "content": content,
                "concealed_instructions": list(assessment.concealed_instructions),
                "trust": assessment.trust,
                "instruction_bearing": assessment.instruction_bearing,
                "flags": list(assessment.flags),
            })
