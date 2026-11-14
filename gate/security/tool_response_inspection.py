"""
Tool-response inspection: detection of explicit agent-directed instructions in
tool results plus a minimal finding store.

Corrective V1 implementation:
- Deterministic, conservative, pattern-based detection (no unrestricted LLM).
- Explicit per-call inspection status: success / failure / timeout / unavailable.
  Failure/timeout/unavailable are never treated as clean inspection.
- Findings record originating call_id, tool name, instruction span, category,
  confidence, evidence, and structured action-effect attributes for cross-step
  correspondence (instruction category, requested operation/effect, target/
  recipient when present, relevant data/argument constraints).
- Only explicit instruction-like directives are recorded; ordinary factual content,
  recommendations, quoted user content and arbitrary imperative sentences are not
  classified as findings. External origin alone is never a threat.
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from ..core.models import AgentState, ToolCall

# Explicit inspection statuses per call_id.
INSPECTION_STATUS_SUCCESS = "success"
INSPECTION_STATUS_FAILURE = "failure"
INSPECTION_STATUS_TIMEOUT = "timeout"
INSPECTION_STATUS_UNAVAILABLE = "unavailable"

# Backward-compatible aliases used by V1 tests/callers.
RESPONSE_FINDING_STATUS_OK = "ok"
RESPONSE_FINDING_STATUS_FAILED = "failed"

_CLEAN_STATUSES = {INSPECTION_STATUS_SUCCESS, RESPONSE_FINDING_STATUS_OK}
_UNAVAILABLE_STATUSES = {
    INSPECTION_STATUS_FAILURE,
    INSPECTION_STATUS_TIMEOUT,
    INSPECTION_STATUS_UNAVAILABLE,
    RESPONSE_FINDING_STATUS_FAILED,
}

FINDING_CATEGORY_OVERRIDE = "override"
FINDING_CATEGORY_TOOL_EXECUTION = "tool_execution"
FINDING_CATEGORY_TASK_SCOPE_CHANGE = "task_scope_change"
FINDING_CATEGORY_DISCLOSURE = "disclosure"
FINDING_CATEGORIES_DIRECTIVE = (
    FINDING_CATEGORY_OVERRIDE,
    FINDING_CATEGORY_TOOL_EXECUTION,
    FINDING_CATEGORY_TASK_SCOPE_CHANGE,
    FINDING_CATEGORY_DISCLOSURE,
)

DEFAULT_FINDING_TTL_SECONDS = 900.0
DEFAULT_MIN_CONFIDENCE = 0.5

_OVERRIDE_RES = [
    re.compile(r"ignore\s+(?:all|any|previous|the|your|preceding|prior|these|those)\s+(?:instructions?|instruction|system|prompt|directives?|context|rules?)", re.IGNORECASE),
    re.compile(r"disregard\s+(?:all|any|previous|the|your|preceding|prior|these|those)\s+(?:instructions?|instruction|system|prompt|directives?|context|rules?)", re.IGNORECASE),
    re.compile(r"override\s+(?:all|any|previous|the|your|preceding|prior|these|those)\s+(?:instructions?|instruction|system|prompt|directives?|context|rules?)", re.IGNORECASE),
    re.compile(r"forget\s+(?:all|any|your|the|previous|these|those)\s+(?:instructions?|instruction|system|prompt|context)", re.IGNORECASE),
    re.compile(r"replace\s+(?:the\s+)?(?:system|previous|all|your|these|those)\s+(?:instructions?|prompt|directives?|context)", re.IGNORECASE),
    re.compile(r"skip\s+(?:all|any|the|previous|your|these|those)\s+(?:instructions?|instruction|system|prompt|directives?)", re.IGNORECASE),
]

_TOOL_USE_RES = [
    re.compile(
        r"\b(call|invoke|execute|run|use|apply|trigger|fire|dispatch|connect|configure|setup|install|deploy)\s+"
        r"(?:the\s+|this\s+|that\s+|a\s+|an\s+)?(?:tool|function|action|api|service|endpoint|plugin|agent|handler|integration|module|component|skill|workflow)s?\s+([A-Za-z_][\w.-]{0,60})",
        re.IGNORECASE,
    ),
]

_TASK_SCOPE_RES = [
    re.compile(
        r"\b(change|update|revise|modify|adjust|alter|shift|pivot|transition|refine|expand|broaden|extend)\s+"
        r"(?:the\s+|your\s+|this\s+|an?\s+)?(?:task|objective|goal|scope|mission|purpose|plan)s?\b",
        re.IGNORECASE,
    ),
]

_DISCLOSURE_RES = [
    re.compile(
        r"\b(send|share|post|upload|exfiltrat|reveal|disclose|leak|publish|broadcast|distribute|forward|print|log|output|copy|transmit|exfil|email|mail)\b[^.;]{0,120}\b(?:confidential|secret|internal|private|restricted|proprietary|personal|pii|credential|password|key|data|document|file|email|message|conversation|context|information|content|text|body|attachment)s?\b",
        re.IGNORECASE,
    ),
    # Explicit agent-directed communication directive with concrete recipient (email address)
    # or explicit send/email command form; conservative to avoid generic benign imperatives.
    re.compile(
        r"(?:^|[.!?\n]\s*|(?:please|kindly|now|first|then|immediately|urgently)\s+)"
        r"(?:send|email|mail|forward|share|upload|post|transmit|exfiltrat|exfil)\b[^.;\n]{0,160}\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:^|[.!?\n]\s*|(?:please|kindly|now|first|then|immediately|urgently)\s+)"
        r"(?:send|email|mail|forward)\b[^.;\n]{0,120}\b(?:an?\s+)?(?:email|message|mail)\b[^.;\n]{0,120}\b(?:to|for)\b",
        re.IGNORECASE,
    ),
    # Email/send to explicit address as a directive (general form, e.g. "email the summary to X")
    re.compile(
        r"(?:^|[.!?\n]\s*|(?:please|kindly|now|first|then|immediately|urgently)\s+)"
        r"(?:email|mail|send|forward)\b[^.;\n]{0,140}\b(?:to|for)\b\s*['\"]?[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}['\"]?",
        re.IGNORECASE,
    ),
]

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_EXTERNAL_MARKERS = ("external", "outside", "third party", "third-party", "public", "internet")
_CONFIDENTIAL_MARKERS = ("confidential", "secret", "internal", "private", "restricted", "proprietary", "personal", "pii", "credential", "password", "key")
_FILE_MARKERS = ("file", "document", "attachment", "local file", "backup", "archive")
_ADMIN_MARKERS = ("admin", "administrative", "user account", "permission", "role", "setting", "settings", "configuration", "config")
_READONLY_MARKERS = ("read", "list", "view", "show", "get", "fetch", "search", "query")


def _normalize(text: Optional[str]) -> str:
    return re.sub(r"[^a-z0-9]+", "_", (text or "").lower()).strip("_")


def _extract_text(result: Any, _depth: int = 0) -> str:
    """Best-effort textual extraction from an arbitrary tool result (recursive, bounded)."""
    if result is None or _depth > 6:
        return ""
    if isinstance(result, str):
        return result
    if isinstance(result, bytes):
        try:
            return result.decode("utf-8", errors="ignore")
        except Exception:
            return ""
    if isinstance(result, dict):
        parts = []
        # Prefer common text-bearing keys first
        preferred = ("content", "text", "output", "result", "response", "body", "data", "message", "error", "description", "details", "summary", "note")
        seen = set()
        for key in preferred:
            if key in result:
                seen.add(key)
                val = _extract_text(result.get(key), _depth + 1)
                if val:
                    parts.append(val)
        for key, value in result.items():
            if key in seen:
                continue
            val = _extract_text(value, _depth + 1)
            if val:
                parts.append(val)
        # de-duplicate while preserving order
        out = []
        seen_s = set()
        for p in parts:
            if p not in seen_s:
                seen_s.add(p)
                out.append(p)
        return "\n".join(out)
    if isinstance(result, (list, tuple, set)):
        parts = [p for p in (_extract_text(item, _depth + 1) for item in result) if p]
        return "\n".join(parts)
    if isinstance(result, (int, float, bool)):
        return ""
    try:
        # pydantic/dataclass-like objects
        if hasattr(result, "model_dump"):
            return _extract_text(result.model_dump(), _depth + 1)
        if hasattr(result, "__dict__"):
            return _extract_text(vars(result), _depth + 1)
    except Exception:
        pass
    try:
        s = str(result)
        return "" if s in ("None", "") else s
    except Exception:
        return ""


@dataclass
class ResponseFinding:
    """A detected instruction-like response span and its metadata."""

    call_id: str
    tool_name: str
    instruction_span: Optional[str]
    category: str
    confidence: float
    evidence: str
    action_equivalent: Optional[str] = None
    # Structured action-effect attributes (corrective V1)
    requested_operation: Optional[str] = None
    requested_effect: Optional[str] = None
    target: Optional[str] = None
    data_constraints: List[str] = field(default_factory=list)
    arg_constraints: Dict[str, Any] = field(default_factory=dict)


def _derive_structured(span: str, category: str, action_equivalent: Optional[str]) -> Dict[str, Any]:
    text = (span or "").lower()
    requested_operation: Optional[str] = action_equivalent
    requested_effect: Optional[str] = None
    target: Optional[str] = None
    data_constraints: List[str] = []
    arg_constraints: Dict[str, Any] = {}

    if category == FINDING_CATEGORY_TOOL_EXECUTION:
        requested_operation = action_equivalent
        requested_effect = "tool_execution"
    elif category == FINDING_CATEGORY_DISCLOSURE:
        m = re.search(r"\b(send|share|post|upload|exfiltrat|reveal|disclose|leak|publish|broadcast|distribute|forward|transmit|exfil|email|mail)\w*", text)
        verb = m.group(1) if m else "disclose"
        if "upload" in verb or "exfil" in verb:
            requested_operation = requested_operation or "upload"
            requested_effect = "file_transfer_external"
        elif "send" in verb or "forward" in verb or "email" in verb or "mail" in verb or "email" in text or "mail" in text:
            requested_operation = requested_operation or "send_email"
            requested_effect = "external_send"
        else:
            requested_operation = requested_operation or "disclose"
            requested_effect = "disclosure"
        if any(mk in text for mk in _EXTERNAL_MARKERS):
            data_constraints.append("external")
            arg_constraints["external"] = True
        if any(mk in text for mk in _CONFIDENTIAL_MARKERS):
            data_constraints.append("confidential")
        if any(mk in text for mk in _FILE_MARKERS):
            data_constraints.append("file")
        email = _EMAIL_RE.search(span or "")
        if email:
            target = email.group(0)
    elif category == FINDING_CATEGORY_TASK_SCOPE_CHANGE:
        requested_effect = "task_scope_expansion"
        # detect expansion into unrelated administrative domain when explicit
        if any(mk in text for mk in _ADMIN_MARKERS):
            requested_operation = requested_operation or "admin_operation"
            data_constraints.append("administrative")
        else:
            requested_operation = requested_operation or "scope_change"
    elif category == FINDING_CATEGORY_OVERRIDE:
        requested_effect = "instruction_override"
        requested_operation = requested_operation or "override_instructions"

    return {
        "requested_operation": requested_operation,
        "requested_effect": requested_effect,
        "target": target,
        "data_constraints": data_constraints,
        "arg_constraints": arg_constraints,
    }


class ToolResponseInspector:
    """Conservative, pattern-based response inspector (corrective V1)."""

    def __init__(self, min_confidence: float = DEFAULT_MIN_CONFIDENCE) -> None:
        self.min_confidence = min_confidence
        self._rules: List[tuple] = [
            (_OVERRIDE_RES[0], FINDING_CATEGORY_OVERRIDE, 0.9, 0),
            (_OVERRIDE_RES[1], FINDING_CATEGORY_OVERRIDE, 0.9, 0),
            (_OVERRIDE_RES[2], FINDING_CATEGORY_OVERRIDE, 0.9, 0),
            (_OVERRIDE_RES[3], FINDING_CATEGORY_OVERRIDE, 0.85, 0),
            (_OVERRIDE_RES[4], FINDING_CATEGORY_OVERRIDE, 0.85, 0),
            (_OVERRIDE_RES[5], FINDING_CATEGORY_OVERRIDE, 0.85, 0),
            (_TOOL_USE_RES[0], FINDING_CATEGORY_TOOL_EXECUTION, 0.85, 2),
            (_TASK_SCOPE_RES[0], FINDING_CATEGORY_TASK_SCOPE_CHANGE, 0.8, 0),
            (_DISCLOSURE_RES[0], FINDING_CATEGORY_DISCLOSURE, 0.7, 0),
            (_DISCLOSURE_RES[1], FINDING_CATEGORY_DISCLOSURE, 0.8, 0),
            (_DISCLOSURE_RES[2], FINDING_CATEGORY_DISCLOSURE, 0.75, 0),
            (_DISCLOSURE_RES[3], FINDING_CATEGORY_DISCLOSURE, 0.8, 0),
        ]

    def inspect(self, action: ToolCall, result: Any) -> List[ResponseFinding]:
        """Inspect a tool result and return detected directive findings."""
        text = _extract_text(result)
        findings: List[ResponseFinding] = []
        if not text or not text.strip():
            return findings
        for regex, category, confidence, group_index in self._rules:
            for match in regex.finditer(text):
                span = match.group(0)
                action_equivalent: Optional[str] = match.group(group_index) if group_index else None
                structured = _derive_structured(span, category, action_equivalent)
                findings.append(
                    ResponseFinding(
                        call_id=action.call_id,
                        tool_name=action.tool_name,
                        instruction_span=span,
                        category=category,
                        confidence=confidence,
                        evidence=f"pattern:{regex.pattern}",
                        action_equivalent=action_equivalent,
                        requested_operation=structured["requested_operation"],
                        requested_effect=structured["requested_effect"],
                        target=structured["target"],
                        data_constraints=list(structured["data_constraints"]),
                        arg_constraints=dict(structured["arg_constraints"]),
                    )
                )
        return findings


@dataclass
class ResponseFindingRecord:
    findings: List[ResponseFinding] = field(default_factory=list)
    status: str = INSPECTION_STATUS_SUCCESS
    timestamp: Optional[datetime] = None


def _canonical_status(status: str) -> str:
    if status in _CLEAN_STATUSES:
        return INSPECTION_STATUS_SUCCESS
    if status in _UNAVAILABLE_STATUSES:
        # preserve specific unavailable kinds when provided
        if status in (INSPECTION_STATUS_TIMEOUT, INSPECTION_STATUS_UNAVAILABLE, INSPECTION_STATUS_FAILURE):
            return status
        return INSPECTION_STATUS_FAILURE
    return status


class ResponseFindingStore:
    """Per-call finding store keyed by originating call_id with explicit status."""

    def __init__(self, ttl_seconds: float = DEFAULT_FINDING_TTL_SECONDS) -> None:
        self._ttl_seconds = ttl_seconds
        self._lock = threading.RLock()
        self._records: Dict[str, ResponseFindingRecord] = {}

    def clear(self) -> None:
        with self._lock:
            self._records.clear()

    def add(
        self,
        call_id: str,
        findings: List[ResponseFinding],
        *,
        timestamp: Optional[datetime] = None,
        status: str = INSPECTION_STATUS_SUCCESS,
    ) -> None:
        canonical = _canonical_status(status)
        with self._lock:
            self._records[call_id] = ResponseFindingRecord(
                findings=list(findings) if canonical == INSPECTION_STATUS_SUCCESS else list(findings),
                status=canonical,
                timestamp=timestamp or datetime.utcnow(),
            )

    def _is_unexpired(self, record: ResponseFindingRecord, now: datetime) -> bool:
        if record.timestamp is None:
            return True
        return (now - record.timestamp).total_seconds() <= self._ttl_seconds

    def get_record(self, call_id: str, now: Optional[datetime] = None) -> Optional[ResponseFindingRecord]:
        now = now or datetime.utcnow()
        with self._lock:
            rec = self._records.get(call_id)
            if rec is None:
                return None
            return rec if self._is_unexpired(rec, now) else None

    def get_unexpired(self, now: Optional[datetime] = None) -> List[ResponseFinding]:
        """Return unexpired findings from successful inspections only."""
        now = now or datetime.utcnow()
        collected: List[ResponseFinding] = []
        with self._lock:
            for record in self._records.values():
                if record.status != INSPECTION_STATUS_SUCCESS:
                    continue
                if not self._is_unexpired(record, now):
                    continue
                collected.extend(record.findings)
        return collected

    def get_for_state(self, state: AgentState, now: Optional[datetime] = None) -> List[ResponseFinding]:
        """Return unexpired findings from successful inspections for state history."""
        now = now or datetime.utcnow()
        collected: List[ResponseFinding] = []
        with self._lock:
            for tool_call in state.tool_history:
                record = self._records.get(tool_call.call_id)
                if record is None or record.status != INSPECTION_STATUS_SUCCESS:
                    continue
                if not self._is_unexpired(record, now):
                    continue
                collected.extend(record.findings)
        return collected

    def get_statuses_for_state(self, state: AgentState, now: Optional[datetime] = None) -> List[tuple]:
        """Return (call_id, status) for relevant history records.

        Calls present in history without an inspection record are reported as
        unavailable/missing so evidence gaps are never treated as clean.
        """
        now = now or datetime.utcnow()
        out: List[tuple] = []
        with self._lock:
            for tool_call in state.tool_history:
                record = self._records.get(tool_call.call_id)
                if record is None:
                    out.append((tool_call.call_id, INSPECTION_STATUS_UNAVAILABLE))
                    continue
                if not self._is_unexpired(record, now):
                    # expired/missing effective evidence
                    out.append((tool_call.call_id, INSPECTION_STATUS_UNAVAILABLE))
                    continue
                out.append((tool_call.call_id, record.status))
        return out

    def get_unavailable_for_state(self, state: AgentState, now: Optional[datetime] = None) -> List[tuple]:
        """Return (call_id, status) for history records whose inspection evidence is unavailable."""
        statuses = self.get_statuses_for_state(state, now)
        return [(cid, st) for cid, st in statuses if st in _UNAVAILABLE_STATUSES]
