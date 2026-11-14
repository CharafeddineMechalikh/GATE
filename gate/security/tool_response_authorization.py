"""
Tool-response cross-step authorization gate (corrective V1).

- Correspondence is a detection-level relation over structured action-effect
  attributes; it never establishes causal influence.
- External instructions gain no authority by appearing in a tool result.
- Invoked after existing enforcement layers allow an action (existing BLOCK
  precedence preserved) and before tool execution.
- Outcomes: ALLOW / ESCALATE / BLOCK.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from ..core.models import AgentState, ToolCall
from .irreversibility import ActionClassification, IrreversibilityHandler
from .tool_response_inspection import (
    DEFAULT_MIN_CONFIDENCE,
    FINDING_CATEGORIES_DIRECTIVE,
    FINDING_CATEGORY_DISCLOSURE,
    FINDING_CATEGORY_OVERRIDE,
    FINDING_CATEGORY_TASK_SCOPE_CHANGE,
    FINDING_CATEGORY_TOOL_EXECUTION,
    ResponseFinding,
    ResponseFindingStore,
    ToolResponseInspector,
    _normalize,
)

_SEND_OPS = {"send", "email", "forward", "mail", "message", "notify", "post", "broadcast", "transmit", "share"}
_UPLOAD_OPS = {"upload", "transfer", "exfil", "export", "publish", "put", "copy_remote"}
_FILE_TOKENS = {"file", "document", "attachment", "local", "backup", "archive", "path"}
_ADMIN_TOKENS = {"admin", "administrative", "user", "account", "permission", "role", "setting", "settings", "config", "configuration"}
_READONLY_TOKENS = {"read", "list", "view", "show", "get", "fetch", "search", "query", "describe", "inspect"}
_EXTERNAL_TOKENS = {"external", "outside", "third", "public", "internet", "remote"}
_CONFIDENTIAL_TOKENS = {"confidential", "secret", "internal", "private", "restricted", "proprietary", "personal", "pii", "credential", "password", "key"}


@dataclass
class ToolResponseAuthorizationDecision:
    decision: str  # ALLOW | ESCALATE | BLOCK
    reason: str
    findings: List[ResponseFinding] = field(default_factory=list)
    matched: List[ResponseFinding] = field(default_factory=list)
    unavailable_statuses: List[Tuple[str, str]] = field(default_factory=list)


def _action_tokens(action: ToolCall) -> Set[str]:
    toks: Set[str] = set(_normalize(action.tool_name or "").split("_"))
    try:
        for k, v in (action.tool_args or {}).items():
            toks.update(_normalize(str(k)).split("_"))
            if isinstance(v, str):
                toks.update(re.findall(r"[a-z0-9]+", v.lower()))
            elif isinstance(v, (list, tuple)):
                for item in v:
                    if isinstance(item, str):
                        toks.update(re.findall(r"[a-z0-9]+", item.lower()))
    except Exception:
        pass
    return {t for t in toks if t}


def _action_effects(action: ToolCall) -> Dict[str, Any]:
    name_n = _normalize(action.tool_name or "")
    toks = _action_tokens(action)
    name_toks = set(name_n.split("_"))
    effects: Set[str] = set()
    if name_toks & _SEND_OPS or "email" in name_n or "mail" in name_n:
        effects.add("external_send")
    if name_toks & _UPLOAD_OPS or "upload" in name_n or "transfer" in name_n:
        effects.add("file_transfer_external")
    if name_toks & _ADMIN_TOKENS:
        effects.add("administrative")
    readonly = bool(name_toks & _READONLY_TOKENS) and not (name_toks & (_SEND_OPS | _UPLOAD_OPS | _ADMIN_TOKENS | {"delete", "drop", "write", "update", "remove", "modify", "create", "insert"}))
    if readonly:
        effects.add("readonly")
    has_external = bool(toks & _EXTERNAL_TOKENS) or "@" in str(action.tool_args)
    has_confidential = bool(toks & _CONFIDENTIAL_TOKENS)
    has_file = bool(toks & _FILE_TOKENS) or any(k in (action.tool_args or {}) for k in ("path", "file", "filename", "filepath"))
    return {
        "name_norm": name_n,
        "tokens": toks,
        "effects": effects,
        "external": has_external,
        "confidential": has_confidential,
        "file": has_file,
        "readonly": readonly,
    }


def _is_consequential_action(action: ToolCall) -> bool:
    """Reuse existing irreversibility/consequence mechanism (no second system)."""
    try:
        handler = IrreversibilityHandler()
        classification = handler.classify_action(action)
        # Treat actions requiring approval by default threshold as consequential.
        if handler._requires_approval(classification):
            return True
        # Also treat irreversible high-impact ops as consequential.
        return classification in (
            ActionClassification.IRREVERSIBLE_HIGH_RISK,
            ActionClassification.CRITICAL,
        )
    except Exception:
        # Conservative fallback: only clearly high-impact names.
        name = _normalize(action.tool_name or "")
        return any(k in name for k in ("send", "delete", "drop", "transfer", "upload", "publish", "exfil"))


def _instruction_requires_effect(finding: ResponseFinding) -> Set[str]:
    req: Set[str] = set()
    cat = finding.category
    op = _normalize(finding.requested_operation or finding.action_equivalent or "")
    eff = (finding.requested_effect or "").lower()
    data = set(finding.data_constraints or [])
    span = (finding.instruction_span or "").lower()
    if cat == FINDING_CATEGORY_TOOL_EXECUTION:
        if op:
            req.add(f"op:{op}")
    elif cat == FINDING_CATEGORY_DISCLOSURE:
        if "file_transfer" in eff or "upload" in op or "upload" in span or "file" in data:
            req.add("effect:file_transfer_external")
        if "external_send" in eff or "email" in op or "mail" in span or "send_email" in op:
            req.add("effect:external_send")
        if not req:
            req.add("effect:disclosure")
        if "external" in data or any(t in span for t in _EXTERNAL_TOKENS):
            req.add("flag:external")
        if "confidential" in data or any(t in span for t in _CONFIDENTIAL_TOKENS):
            req.add("flag:confidential")
        if "file" in data:
            req.add("flag:file")
    elif cat == FINDING_CATEGORY_TASK_SCOPE_CHANGE:
        req.add("effect:task_scope_expansion")
        if "administrative" in data or op == "admin_operation":
            req.add("effect:administrative")
    elif cat == FINDING_CATEGORY_OVERRIDE:
        req.add("effect:instruction_override")
    return req


def _action_satisfies(action: ToolCall, eff: Dict[str, Any], reqs: Set[str]) -> bool:
    if not reqs:
        return False
    name_n = eff["name_norm"]
    for r in reqs:
        if r.startswith("op:"):
            wanted = r.split(":", 1)[1]
            if not wanted:
                return False
            if wanted == name_n or wanted in name_n.split("_") or name_n == wanted:
                continue
            # allow semantic op family matches
            if wanted in {"send_email", "email", "send"} and "external_send" in eff["effects"]:
                continue
            if wanted in {"upload", "upload_file", "file_transfer", "transfer_file"} and "effect:file_transfer_external" in {f"effect:{e}" for e in eff["effects"]}:
                continue
            return False
        elif r == "effect:external_send":
            if "external_send" not in eff["effects"]:
                return False
        elif r == "effect:file_transfer_external":
            if "file_transfer_external" not in eff["effects"]:
                return False
        elif r == "effect:disclosure":
            if not ({"external_send", "file_transfer_external"} & eff["effects"]):
                return False
        elif r == "effect:task_scope_expansion":
            # scope expansion corresponds to moving into administrative/unrelated privileged domain
            if "administrative" in eff["effects"]:
                continue
            # non-admin proposed actions do not match scope-expansion-to-admin instruction
            return False
        elif r == "effect:administrative":
            if "administrative" not in eff["effects"]:
                return False
        elif r == "effect:instruction_override":
            # override attempts correspond to consequential/sensitive control-changing actions
            # (escalation context), not to ordinary unrelated reads; match when action is consequential.
            if eff["readonly"]:
                return False
            return True
        elif r == "flag:external":
            # if instruction demands external, action must plausibly go external; send/upload ops qualify
            if not (eff["external"] or ({"external_send", "file_transfer_external"} & eff["effects"])):
                return False
        elif r == "flag:confidential":
            # cannot prove arg-level data class from action alone in V1; treat as satisfiable if exfil channel matches
            continue
        elif r == "flag:file":
            if not (eff["file"] or "file_transfer_external" in eff["effects"]):
                return False
        else:
            return False
    # Special-case: scope expansion (non-admin) should not match unrelated readonly ops
    if "effect:task_scope_expansion" in reqs and "effect:administrative" not in reqs and eff["readonly"]:
        return False
    return True


@dataclass
class _ExplicitConstraint:
    verbs: Set[str]
    objects: Set[str]
    external: bool
    raw: str


def _parse_explicit_constraints(user_constraints: Optional[List[str]]) -> List[_ExplicitConstraint]:
    out: List[_ExplicitConstraint] = []
    for c in (user_constraints or []):
        text = str(c or "")
        low = text.lower()
        # require explicit prohibitive framing
        if not re.search(r"\b(do\s+not|don't|never|forbid|prohibit|disallow|must\s+not|mustn't|cannot|can't|may\s+not)\b", low):
            continue
        verbs: Set[str] = set()
        if re.search(r"\b(send(?:ing)?|sent|email\w*|forward\w*|mail\w*|message\w*)\b", low):
            verbs.update({"send", "email"})
        if re.search(r"\b(upload\w*|transfer\w*|exfiltrat\w*|export\w*)\b", low):
            verbs.update({"upload", "transfer"})
        if re.search(r"\b(share\w*|disclos\w*|leak\w*|reveal\w*|publish\w*|post\w*)\b", low):
            verbs.update({"share", "disclose"})
        if re.search(r"\b(delet\w*|drop\w*|remov\w*|destroy\w*|eras\w*)\b", low):
            verbs.update({"delete"})
        if re.search(r"\b(writ\w*|modif\w*|updat\w*|chang\w*|edit\w*)\b", low):
            verbs.update({"write", "modify"})
        objects = {t for t in re.findall(r"[a-z0-9]+", low) if t in _EXTERNAL_TOKENS | _CONFIDENTIAL_TOKENS | _FILE_TOKENS | {"email", "emails", "mail", "message", "messages", "data", "information"}}
        external = any(t in low for t in _EXTERNAL_TOKENS) or "outside" in low
        if verbs or objects:
            out.append(_ExplicitConstraint(verbs=verbs, objects=objects, external=external, raw=text))
    return out


def _demonstrable_user_conflict(action: ToolCall, constraints: List[_ExplicitConstraint]) -> Tuple[bool, bool]:
    """Return (is_conflict, is_ambiguous_consequential).

    Conflict is demonstrable only when an explicit user-authored prohibition maps
    to the proposed action's normalized operation/effects. No inference from tool
    name/sensitivity/isolated keywords alone.
    """
    if not constraints:
        return (False, False)
    eff = _action_effects(action)
    name_n = eff["name_norm"]
    name_toks = set(name_n.split("_"))
    conflict = False
    ambiguous = False
    for c in constraints:
        # match by explicit prohibited operation/effect
        verb_match = False
        if c.verbs & {"send", "email"} and "external_send" in eff["effects"]:
            verb_match = True
        if c.verbs & {"upload", "transfer"} and "file_transfer_external" in eff["effects"]:
            verb_match = True
        if c.verbs & {"share", "disclose"} and ({"external_send", "file_transfer_external"} & eff["effects"]):
            verb_match = True
        if c.verbs & {"delete"} and (name_toks & {"delete", "drop", "remove", "destroy", "erase"}):
            verb_match = True
        if c.verbs & {"write", "modify"} and (name_toks & {"write", "modify", "update", "edit", "put", "patch"}):
            verb_match = True
        if not verb_match:
            continue
        # scope qualifiers: if user explicitly restricted to external/outside,
        # conflict is demonstrable only when action is demonstrably external;
        # if action is an external-capable channel but target/scope is not
        # demonstrably external, treat as ambiguous for consequential actions.
        if c.external:
            if eff["external"]:
                conflict = True
                continue
            if {"external_send", "file_transfer_external"} & eff["effects"]:
                ambiguous = True
                continue
            ambiguous = True
            continue
        conflict = True
    return (conflict, (ambiguous and not conflict))


class ToolResponseAuthorizationGate:
    """Cross-step response-to-action authorization gate (corrective V1)."""

    def __init__(
        self,
        inspector: ToolResponseInspector,
        store: Optional[ResponseFindingStore],
        min_confidence: float = DEFAULT_MIN_CONFIDENCE,
    ) -> None:
        self.inspector = inspector
        self.store = store
        self.min_confidence = min_confidence

    def evaluate(
        self,
        action: ToolCall,
        state: AgentState,
        *,
        user_constraints: Optional[List[str]] = None,
        now: Optional[datetime] = None,
    ) -> ToolResponseAuthorizationDecision:
        unavailable = self.store.get_unavailable_for_state(state, now) if self.store is not None else []
        if unavailable and _is_consequential_action(action):
            return ToolResponseAuthorizationDecision(
                decision="ESCALATE",
                reason="inspection evidence unavailable for consequential action; authorization verification required",
                findings=[],
                matched=[],
                unavailable_statuses=list(unavailable),
            )

        parsed_constraints = _parse_explicit_constraints(user_constraints)
        findings = self.store.get_for_state(state, now) if self.store is not None else []
        if not findings:
            conflict, ambiguous = _demonstrable_user_conflict(action, parsed_constraints)
            if conflict:
                return ToolResponseAuthorizationDecision(
                    decision="BLOCK",
                    reason="proposed action conflicts with explicit user-authored constraint",
                    findings=[],
                    matched=[],
                    unavailable_statuses=list(unavailable),
                )
            if ambiguous and _is_consequential_action(action):
                return ToolResponseAuthorizationDecision(
                    decision="ESCALATE",
                    reason="ambiguous conflict with explicit user-authored constraint for consequential action",
                    findings=[],
                    matched=[],
                    unavailable_statuses=list(unavailable),
                )
            return ToolResponseAuthorizationDecision(
                decision="ALLOW",
                reason="no unexpired tool-response findings available for cross-step analysis",
                findings=[],
                unavailable_statuses=list(unavailable),
            )

        matched = [
            f for f in findings
            if self._corresponds(action, f)
            and f.confidence >= self.min_confidence
            and f.category in FINDING_CATEGORIES_DIRECTIVE
        ]
        if not matched:
            conflict, ambiguous = _demonstrable_user_conflict(action, parsed_constraints)
            if conflict:
                return ToolResponseAuthorizationDecision(
                    decision="BLOCK",
                    reason="proposed action conflicts with explicit user-authored constraint",
                    findings=list(findings),
                    matched=[],
                    unavailable_statuses=list(unavailable),
                )
            if ambiguous and _is_consequential_action(action):
                return ToolResponseAuthorizationDecision(
                    decision="ESCALATE",
                    reason="ambiguous conflict with explicit user-authored constraint for consequential action",
                    findings=list(findings),
                    matched=[],
                    unavailable_statuses=list(unavailable),
                )
            return ToolResponseAuthorizationDecision(
                decision="ALLOW",
                reason="no decisive instruction-action correspondence",
                findings=list(findings),
                matched=[],
                unavailable_statuses=list(unavailable),
            )

        conflict, ambiguous = _demonstrable_user_conflict(action, _parse_explicit_constraints(user_constraints))
        if conflict:
            return ToolResponseAuthorizationDecision(
                decision="BLOCK",
                reason="proposed action conflicts with explicit user-authored constraint",
                findings=list(findings),
                matched=list(matched),
                unavailable_statuses=list(unavailable),
            )
        if ambiguous and _is_consequential_action(action):
            return ToolResponseAuthorizationDecision(
                decision="ESCALATE",
                reason="ambiguous conflict with explicit user-authored constraint for consequential action",
                findings=list(findings),
                matched=list(matched),
                unavailable_statuses=list(unavailable),
            )

        decisive = matched[0]
        if decisive.category in (FINDING_CATEGORY_TASK_SCOPE_CHANGE, FINDING_CATEGORY_DISCLOSURE, FINDING_CATEGORY_OVERRIDE) or _is_consequential_action(action):
            return ToolResponseAuthorizationDecision(
                decision="ESCALATE",
                reason=f"instruction-driven {decisive.category} correspondence with proposed action requires authorization verification",
                findings=list(findings),
                matched=list(matched),
                unavailable_statuses=list(unavailable),
            )

        return ToolResponseAuthorizationDecision(
            decision="ALLOW",
            reason="instruction-driven action evaluated within authorized scope",
            findings=list(findings),
            matched=list(matched),
            unavailable_statuses=list(unavailable),
        )

    def _corresponds(self, action: ToolCall, finding: ResponseFinding) -> bool:
        """Structured action-effect correspondence (detection-level relation only)."""
        if action is None or finding is None:
            return False
        if finding.call_id == action.call_id:
            return False
        reqs = _instruction_requires_effect(finding)
        if not reqs:
            return False
        eff = _action_effects(action)
        # Direct tool-execution match remains supported but is not required when
        # structured operation/effect attributes establish correspondence.
        return _action_satisfies(action, eff, reqs)
