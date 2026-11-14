from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..core.exceptions import ContractViolation, DFAViolation, DCBFViolation, PrivilegeViolation
from ..core.models import AgentState, ToolCall, ValidationResult
from .tool_response_inspection import (
    INSPECTION_STATUS_FAILURE,
    INSPECTION_STATUS_SUCCESS,
    INSPECTION_STATUS_UNAVAILABLE,
    ResponseFinding,
    ResponseFindingStore,
    _extract_text,
    _normalize,
    FINDING_CATEGORY_DISCLOSURE,
    FINDING_CATEGORY_OVERRIDE,
    FINDING_CATEGORY_TASK_SCOPE_CHANGE,
    FINDING_CATEGORY_TOOL_EXECUTION,
)

logger = logging.getLogger(__name__)


@dataclass
class InboundLayerResult:
    layer: str
    decision: str  # ALLOW | ESCALATE | BLOCK
    reason: str
    details: Dict[str, Any] = field(default_factory=dict)
    findings: List[ResponseFinding] = field(default_factory=list)
    status: str = "ok"  # ok | unavailable | error


@dataclass
class InboundValidationResult:
    decision: str  # ALLOW | ESCALATE | BLOCK
    reason: str
    layer_results: List[InboundLayerResult] = field(default_factory=list)
    findings: List[ResponseFinding] = field(default_factory=list)
    blocked_layer: Optional[str] = None
    escalated_layers: List[str] = field(default_factory=list)
    call_id: str = ""
    tool_name: str = ""

    @property
    def is_allowed(self) -> bool:
        return self.decision == "ALLOW"

    @property
    def is_blocked(self) -> bool:
        return self.decision == "BLOCK"

    @property
    def is_escalated(self) -> bool:
        return self.decision == "ESCALATE"


def _make_finding(call_id: str, tool_name: str, span: str, category: str, confidence: float, evidence: str,
                  requested_operation=None, requested_effect=None, target=None, data_constraints=None, arg_constraints=None):
    return ResponseFinding(
        call_id=call_id,
        tool_name=tool_name,
        instruction_span=span,
        category=category,
        confidence=confidence,
        evidence=evidence,
        action_equivalent=requested_operation,
        requested_operation=requested_operation,
        requested_effect=requested_effect,
        target=target,
        data_constraints=list(data_constraints or []),
        arg_constraints=dict(arg_constraints or {}),
    )


def _as_segments(result: Any) -> List[Tuple[str, str]]:
    """Deterministic candidate segments: (segment_id, text). Structured-aware, no silent bypass."""
    segs: List[Tuple[str, str]] = []
    def walk(v: Any, path: str, depth: int = 0):
        if depth > 8:
            segs.append((path or "$", "[MAX_DEPTH_TRUNCATED]"))
            return
        if v is None:
            return
        if isinstance(v, str):
            if v.strip():
                segs.append((path or "$", v))
            return
        if isinstance(v, bytes):
            try:
                s = v.decode("utf-8", errors="replace")
            except Exception:
                s = repr(v)
            segs.append((path or "$", s))
            return
        if isinstance(v, dict):
            if not v:
                return
            for k, val in v.items():
                walk(val, f"{path}.{k}" if path else str(k), depth + 1)
            return
        if isinstance(v, (list, tuple, set)):
            for i, item in enumerate(v):
                walk(item, f"{path}[{i}]" if path else f"[{i}]", depth + 1)
            return
        if isinstance(v, (int, float, bool)):
            return
        try:
            if hasattr(v, "model_dump"):
                walk(v.model_dump(), path, depth + 1)
                return
            if hasattr(v, "__dict__"):
                walk(vars(v), path, depth + 1)
                return
        except Exception:
            pass
        try:
            s = str(v)
            if s and s != "None":
                segs.append((path or "$", s))
        except Exception:
            segs.append((path or "$", "[UNSERIALIZABLE]"))
    walk(result, "", 0)
    # also include whole extracted text as candidate if different
    whole = _extract_text(result)
    if whole and all(whole != s for _, s in segs):
        segs.append(("$_text", whole))
    return segs


class PrivilegeResponseValidator:
    """Layer 1 (inbound): tool-result trust and authority boundaries.
    Returned content must never acquire execution privileges or modify the agent's authorization.
    Reuses agent/profile authorization boundary: responses are untrusted data, not policy/privilege sources.
    """
    AUTHORITY_PATTERNS = [
        re.compile(r"\b(grant|assign|elevate|escalate|add|give|set)\b[^.\n]{0,80}\b(admin|administrator|root|superuser|privilege|permission|role|capabilit|access)\b", re.I),
        re.compile(r"\b(you\s+are\s+now|act\s+as|assume\s+the\s+role\s+of)\b[^.\n]{0,80}\b(admin|administrator|root|system|developer|policy)\b", re.I),
        re.compile(r"\b(disable|bypass|override|ignore|turn\s+off)\b[^.\n]{0,80}\b(gate|policy|authorization|permission|privilege|security|restriction|guard)\b", re.I),
        re.compile(r"\b(update|modify|change|rewrite|replace)\b[^.\n]{0,80}\b(policy|policies|permissions?|authorization|auth|allowlist|denylist|system\s+instruction)\b", re.I),
        re.compile(r"\b(treat|consider|accept)\b[^.\n]{0,80}\b(this\s+response|this\s+result|following)\b[^.\n]{0,80}\b(as\s+authorized|as\s+trusted|as\s+policy|as\s+system)\b", re.I),
    ]

    def validate(self, action: ToolCall, result: Any, state: AgentState, context: Optional[Dict[str, Any]] = None) -> InboundLayerResult:
        segments = _as_segments(result)
        findings: List[ResponseFinding] = []
        for seg_id, text in segments:
            for pat in self.AUTHORITY_PATTERNS:
                for m in pat.finditer(text):
                    span = m.group(0)
                    findings.append(_make_finding(action.call_id, action.tool_name, span, FINDING_CATEGORY_OVERRIDE, 0.95,
                                                  f"privilege_boundary:{seg_id}:{pat.pattern}", requested_operation="privilege_escalation",
                                                  requested_effect="authority_escalation", data_constraints=["authorization_boundary"]))
        if findings:
            return InboundLayerResult(layer="privilege", decision="BLOCK",
                                      reason="response attempts to assert/modify privileges or authorization boundaries",
                                      details={"violations": len(findings), "segments_checked": len(segments)},
                                      findings=findings)
        # malformed/ambiguous structural authority markers (e.g. explicit auth tokens/role claims fields)
        try:
            if isinstance(result, dict):
                for k in result.keys():
                    kn = _normalize(str(k))
                    if kn in {"grant_permission", "set_role", "override_policy", "system_instruction", "trusted_policy", "authorization"}:
                        f = _make_finding(action.call_id, action.tool_name, f"field:{k}", FINDING_CATEGORY_OVERRIDE, 0.9,
                                          "privilege_boundary:structured_field", requested_operation="privilege_escalation",
                                          requested_effect="authority_escalation")
                        return InboundLayerResult(layer="privilege", decision="BLOCK",
                                                  reason="response contains structured authority/privilege field",
                                                  details={"field": str(k)}, findings=[f])
        except Exception:
            return InboundLayerResult(layer="privilege", decision="ESCALATE",
                                      reason="unable to safely evaluate privilege/authority boundaries in response", status="error")
        return InboundLayerResult(layer="privilege", decision="ALLOW", reason="no privilege/authority boundary violation in response",
                                  details={"segments_checked": len(segments)})


class DFAResponseValidator:
    """Layer 2 (inbound): validate response and embedded directives against permitted interaction state,
    task scope, and execution history. Reuses DFA supervisor state/phase semantics and history context.
    """
    SCOPE_EXPANSION_PATTERNS = [
        re.compile(r"\b(now|next|instead|also)\b[^.\n]{0,80}\b(change|switch|expand|broaden|ignore|abandon)\b[^.\n]{0,80}\b(task|goal|objective|scope|plan|mission)\b", re.I),
        re.compile(r"\b(do|perform|start)\b[^.\n]{0,80}\b(different|unrelated|another)\b[^.\n]{0,80}\b(task|objective|operation)\b", re.I),
    ]

    def __init__(self, dfa_supervisor=None):
        self.dfa_supervisor = dfa_supervisor

    def validate(self, action: ToolCall, result: Any, state: AgentState, context: Optional[Dict[str, Any]] = None) -> InboundLayerResult:
        segments = _as_segments(result)
        findings: List[ResponseFinding] = []
        # Use execution history/state context: responses embedding directives inconsistent with current permitted phase/scope
        current_phase = getattr(state, "current_phase", None)
        history_tools = [tc.tool_name for tc in getattr(state, "tool_history", [])[-10:]]
        # If agent is in terminal/restricted phase, directive-bearing response is suspect
        terminal = {"ANSWERING", "REJECTED", "EXHAUSTED"}
        for seg_id, text in segments:
            for pat in self.SCOPE_EXPANSION_PATTERNS:
                if pat.search(text):
                    findings.append(_make_finding(action.call_id, action.tool_name, pat.search(text).group(0),
                                                  FINDING_CATEGORY_TASK_SCOPE_CHANGE, 0.8,
                                                  f"dfa_scope:{seg_id}", requested_operation="scope_change",
                                                  requested_effect="task_scope_expansion"))
            # embedded directive to perform action while in terminal/answering phase is out-of-state
            if current_phase in terminal and re.search(r"\b(call|invoke|execute|run|use|send|upload|delete|modify)\b", text, re.I):
                findings.append(_make_finding(action.call_id, action.tool_name, text[:200], FINDING_CATEGORY_TASK_SCOPE_CHANGE, 0.75,
                                              f"dfa_state:{current_phase}", requested_operation="out_of_state_directive",
                                              requested_effect="state_violation"))
        if findings:
            # scope/state violations in response directives require escalation/block depending on strength
            strong = any(f.confidence >= 0.8 or f.requested_effect == "state_violation" for f in findings)
            return InboundLayerResult(layer="dfa", decision="BLOCK" if strong else "ESCALATE",
                                      reason="response/embedded directives inconsistent with permitted interaction state, task scope, or history",
                                      details={"phase": current_phase, "history_tail": history_tools, "findings": len(findings)},
                                      findings=findings)
        return InboundLayerResult(layer="dfa", decision="ALLOW", reason="response consistent with interaction state/task scope/history",
                                  details={"phase": current_phase, "segments_checked": len(segments)})


class ContractResponseValidator:
    """Layer 3 (inbound): response-specific structural, semantic, and security invariants.
    Reuses contract-style invariant enforcement patterns. No silent bypass on malformed/ambiguous/unsupported formats.
    """
    def __init__(self, contract_registry=None):
        self.contract_registry = contract_registry

    def validate(self, action: ToolCall, result: Any, state: AgentState, context: Optional[Dict[str, Any]] = None) -> InboundLayerResult:
        findings: List[ResponseFinding] = []
        # malformed/incomplete/ambiguous handling: fail-closed (ESCALATE) rather than bypass
        try:
            # detect obviously malformed/unserializable/ambiguous structures
            if result is None:
                # missing content -> unavailable/ambiguous evidence, do not silently bypass
                return InboundLayerResult(layer="contracts", decision="ESCALATE",
                                          reason="malformed/incomplete response (missing result) requires validation",
                                          details={"issue": "missing"}, status="unavailable")
            # cyclic/too-deep already bounded in extraction; flag suspicious binary/control payloads
            if isinstance(result, bytes):
                # unsupported binary without text contract -> do not silently bypass
                return InboundLayerResult(layer="contracts", decision="ESCALATE",
                                          reason="unsupported binary response format requires validation (no silent bypass)",
                                          details={"type": "bytes", "len": len(result)})
            # structural invariant: extremely large/ambiguous payloads
            try:
                text = _extract_text(result)
            except Exception:
                return InboundLayerResult(layer="contracts", decision="ESCALATE",
                                          reason="unparseable/ambiguous response structure (fail-closed)", status="error")
            if len(text) > 200000:
                return InboundLayerResult(layer="contracts", decision="ESCALATE",
                                          reason="response exceeds structural size invariant; validation required",
                                          details={"size": len(text)})
            # security invariant: response must not embed executable script/control blobs claiming authority
            if re.search(r"<\s*(script|iframe|object|embed)\b", text, re.I):
                findings.append(_make_finding(action.call_id, action.tool_name, "<script/active-content>", FINDING_CATEGORY_OVERRIDE, 0.85,
                                              "contract:active_content", requested_operation="execute_embedded_content", requested_effect="authority_escalation"))
            # ambiguous mixed directives marker structures
            if isinstance(result, dict) and "instructions" in {str(k).lower() for k in result.keys()} and "data" in {str(k).lower() for k in result.keys()}:
                # not auto-block but explicit structured directive channel -> escalate for validation
                return InboundLayerResult(layer="contracts", decision="ESCALATE",
                                          reason="ambiguous structured response contains explicit instruction channel requiring validation",
                                          details={"keys": list(result.keys())[:20]})
            if findings:
                return InboundLayerResult(layer="contracts", decision="BLOCK",
                                          reason="response violates structural/security contract invariants",
                                          details={"violations": len(findings)}, findings=findings)
            return InboundLayerResult(layer="contracts", decision="ALLOW", reason="response satisfies structural/security invariants",
                                      details={"text_len": len(text)})
        except Exception as e:
            return InboundLayerResult(layer="contracts", decision="ESCALATE",
                                      reason=f"contract response validation error (fail-closed): {e}", status="error")


class DCBFResponseValidator:
    """Layer 4 (inbound): safety constraints on returned information and its potential downstream effects.
    Adapts D-CBF/state-safety reasoning to response delivery: evaluates whether response content would enable
    or induce unsafe downstream state/effects given current history/intent (no bypass).
    """
    def __init__(self, dcbf_monitor=None):
        self.dcbf_monitor = dcbf_monitor

    def validate(self, action: ToolCall, result: Any, state: AgentState, context: Optional[Dict[str, Any]] = None) -> InboundLayerResult:
        findings: List[ResponseFinding] = []
        text = _extract_text(result)
        history_tools = [tc.tool_name for tc in getattr(state, "tool_history", [])[-8:]]
        # potential downstream exfiltration/disclosure effects: response provides sensitive payload + urges externalization
        lower = text.lower()
        has_sensitive_markers = any(k in lower for k in ("password", "api key", "secret", "token", "credential", "ssn", "private key", "confidential"))
        urges_egress = bool(re.search(r"\b(send|upload|post|forward|email|share|exfil|transmit)\b", lower))
        external_target = bool(re.search(r"https?://|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text))
        # dangerous downstream: prior read/data access + response instructs/frames egress of returned sensitive data
        recent_read = any(t in history_tools or "read" in (t or "") or "query" in (t or "") or "get" in (t or "") for t in history_tools)
        if has_sensitive_markers and (urges_egress or external_target):
            findings.append(_make_finding(action.call_id, action.tool_name, text[:240], FINDING_CATEGORY_DISCLOSURE, 0.85,
                                          "dcbf:downstream_exfil_risk", requested_operation="disclose", requested_effect="file_transfer_external",
                                          data_constraints=["confidential"]))
        # if D-CBF monitor indicates current state already unsafe, delivering directive-bearing response is unsafe
        try:
            if self.dcbf_monitor is not None:
                barrier = float(self.dcbf_monitor.evaluate_state(state))
                if barrier < 0 and re.search(r"\b(call|invoke|execute|run|send|delete|upload)\b", lower):
                    return InboundLayerResult(layer="dcbf", decision="BLOCK",
                                              reason="response delivery unsafe: current state outside safety barriers and response contains actionable directives",
                                              details={"barrier": barrier}, findings=findings)
        except Exception:
            pass
        if findings and (recent_read or urges_egress):
            return InboundLayerResult(layer="dcbf", decision="ESCALATE" if not (has_sensitive_markers and urges_egress and external_target) else "BLOCK",
                                      reason="response presents safety-relevant downstream disclosure/exfiltration risk",
                                      details={"recent_read": recent_read, "urges_egress": urges_egress, "external_target": external_target},
                                      findings=findings)
        return InboundLayerResult(layer="dcbf", decision="ALLOW", reason="no D-CBF downstream safety constraint violation for response",
                                  details={"segments_considered": 1 if text else 0})


class SemanticResponseFirewallLayer:
    """Layer 5 (inbound): contextual instructions, indirect prompt injections, scope modifications,
    disclosure requests, and unauthorized directives. Deterministic candidate generation + contextual semantic analysis.
    Regex is not the sole mechanism (used for candidate generation; semantic model/alignment provides contextual analysis when available).
    """
    DIRECTIVE_PATTERNS = [
        (re.compile(r"\b(ignore|disregard|forget|override)\b[^.\n]{0,120}\b(instruction|system|prompt|policy|rule|previous)\b", re.I), FINDING_CATEGORY_OVERRIDE, "override", "instruction_override"),
        (re.compile(r"\b(call|invoke|execute|run|use|open|fetch|delete|update|create|send|upload)\b[^.\n]{0,120}\b(tool|function|api|endpoint|command|action|script)\b", re.I), FINDING_CATEGORY_TOOL_EXECUTION, "tool_execution", "tool_execution"),
        (re.compile(r"\b(send|email|forward|upload|post|share|exfiltrat|leak|reveal|disclose)\b[^.\n]{0,160}\b(data|file|document|secret|credential|password|key|token|confidential|internal|summary|message|content|information)\b", re.I), FINDING_CATEGORY_DISCLOSURE, "disclose", "disclosure"),
        (re.compile(r"\b(change|switch|modify|expand|broaden|revise)\b[^.\n]{0,120}\b(task|goal|objective|scope|mission|plan)\b", re.I), FINDING_CATEGORY_TASK_SCOPE_CHANGE, "scope_change", "task_scope_expansion"),
        (re.compile(r"(?:please|kindly|now|then|immediately|you\s+must|you\s+should)\s+(?:call|run|execute|send|email|upload|open|delete)\b", re.I), FINDING_CATEGORY_TOOL_EXECUTION, "directive", "tool_execution"),
    ]

    # Reference calibration constants (benign tool-result corpus).  A candidate
    # span very close to routine business wording is discounted; one far from
    # every benign reference is treated as a stronger signal.
    REF_TYPICAL = 0.62
    REF_ATYPICAL = 0.30
    REF_DISCOUNT = 0.55
    REF_BOOST = 0.05
    OVERRIDE_MARKER = re.compile(r"\b(ignore|disregard|forget|override)\b[^.\n]{0,80}\b(instruction|system|prompt|policy|previous)\b", re.I)

    # Semantic candidate generation: a directive-shaped sentence that the fixed
    # patterns miss (e.g. "grant permanent access to my friend") still reaches
    # scoring.  Measured on InjectAgent: 80% of injected sentences match this,
    # 2% of benign ones do, so it is a candidate generator, not a verdict.
    IMPERATIVE_PATTERN = re.compile(
        r"\b(please|kindly|you\s+(must|should|need to|have to)|immediately|make sure|ensure that|be sure to)\b"
        r"|\b(grant|send|email|forward|upload|post|share|delete|remove|update|create|run|execute|invoke|call|"
        r"visit|click|download|transfer|pay|wire|approve|disable|enable|add)\b\s+(the|a|an|your|my|all|this|that|it)\b",
        re.I,
    )

    def __init__(self, semantic_firewall=None, benign_references=None, use_references: bool = True,
                 use_imperative_candidates: bool = True):
        self.semantic_firewall = semantic_firewall
        self.use_imperative_candidates = use_imperative_candidates
        if benign_references is None and use_references:
            from .response_references import BenignResultReferenceIndex

            benign_references = BenignResultReferenceIndex()
        self.benign_references = benign_references

    def _reference_similarity(self, candidate: str, tool: Optional[str]) -> Optional[float]:
        if self.benign_references is None:
            return None
        try:
            return self.benign_references.similarity(tool or "", candidate)
        except Exception as exc:  # reference corpus must never break enforcement
            logger.debug(f"benign reference similarity skipped: {exc}")
            return None

    def _semantic_context_score(self, candidate: str, state: AgentState, tool: Optional[str] = None,
                                ref_sim: Optional[float] = None,
                                harm_proximity: Optional[float] = None) -> Optional[Dict[str, Any]]:
        """Contextual semantic analysis via references, firewall alignment and embeddings.

        Any of the three signals may be present; none is required, so the layer
        degrades to candidate generation plus heuristics when models are absent.
        Pre-computed values (ref_sim, harm_proximity) come from the batch pass in
        :meth:`validate` so a result with many candidates is embedded once.
        """
        out: Dict[str, Any] = {}
        if ref_sim is None:
            ref_sim = self._reference_similarity(candidate, tool)
        if ref_sim is not None:
            out["ref_sim"] = ref_sim
        try:
            fw = self.semantic_firewall
            if fw is not None:
                # reuse alignment/intent context if present
                intent = getattr(fw, "intent_text", None)
                aligner = getattr(fw, "aligner", None)
                if intent and aligner is not None:
                    scores = aligner.score(intent, f"tool response instruction candidate: {candidate}")
                    if scores is not None:
                        contradiction, entailment = scores
                        out.update(contradiction=float(contradiction), entailment=float(entailment), mode="alignment")
                        return out
                # fallback: embedding similarity heuristic to harm/intent via firewall internals if safe
                if harm_proximity is None and hasattr(fw, "embedding_model") and hasattr(fw, "harm_prototypes"):
                    try:
                        import numpy as np
                        emb = fw.embedding_model.embed(candidate[:1000])
                        drift_intent = None
                        if hasattr(fw, "trajectory_tracker") and fw.trajectory_tracker.get_current_anchor() is not None:
                            drift_intent = fw.trajectory_tracker.get_drift_from_trajectory(emb)
                        harm = 1.0
                        for p in (getattr(fw, "harm_prototypes", None) if getattr(fw, "harm_prototypes", None) is not None else []):
                            d = 1.0 - float(np.dot(emb, p) / (np.linalg.norm(emb) * np.linalg.norm(p) + 1e-9))
                            harm = min(harm, d)
                        harm_proximity = harm
                        out["drift_intent"] = drift_intent
                    except Exception:
                        pass
                if harm_proximity is not None:
                    out.update(harm_proximity=harm_proximity, mode="embedding")
        except Exception:
            pass
        if "mode" not in out and "ref_sim" in out:
            out["mode"] = "reference"
        return out or None

    def _batch_signals(self, spans: List[str], tool: Optional[str]) -> Tuple[Dict[str, Optional[float]], Dict[str, Optional[float]]]:
        """One embedding pass per signal for all candidate spans."""
        refs: Dict[str, Optional[float]] = {}
        harms: Dict[str, Optional[float]] = {}
        if not spans:
            return refs, harms
        if self.benign_references is not None:
            try:
                values = self.benign_references.similarity_batch(tool or "", spans)
                refs = dict(zip(spans, values))
            except Exception as exc:
                logger.debug(f"benign reference batch skipped: {exc}")
        fw = self.semantic_firewall
        if fw is not None and hasattr(fw, "embedding_model") and hasattr(fw, "harm_prototypes"):
            try:
                import numpy as np
                emb = fw.embedding_model.embed_batch([s[:1000] for s in spans])
                emb = np.asarray(emb, dtype=np.float64)
                emb /= np.maximum(np.linalg.norm(emb, axis=1, keepdims=True), 1e-9)
                protos = getattr(fw, "harm_prototypes", None)
                if protos is not None and len(protos) and emb.shape[0]:
                    P = np.asarray(protos, dtype=np.float64)
                    P /= np.maximum(np.linalg.norm(P, axis=1, keepdims=True), 1e-9)
                    harms = dict(zip(spans, [float(1.0 - v) for v in np.max(emb @ P.T, axis=1)]))
            except Exception as exc:
                logger.debug(f"harm proximity batch skipped: {exc}")
        return refs, harms

    def validate(self, action: ToolCall, result: Any, state: AgentState, context: Optional[Dict[str, Any]] = None) -> InboundLayerResult:
        segments = _as_segments(result)
        candidates: List[Tuple[str, str, str, str, str]] = []  # seg_id, span, cat, op, eff
        # deterministic candidate generation
        covered: Dict[str, List[str]] = {}
        for seg_id, text in segments:
            covered[seg_id] = []
            for pat, cat, op, eff in self.DIRECTIVE_PATTERNS:
                for m in pat.finditer(text):
                    candidates.append((seg_id, m.group(0), cat, op, eff))
                    covered[seg_id].append(m.group(0).lower())
        weak_spans = set()
        if self.use_imperative_candidates:
            for seg_id, text in segments:
                for sentence in re.split(r"(?<=[.!?])\s+|\n+", text):
                    sentence = sentence.strip()
                    if len(sentence) < 12:
                        continue
                    low = sentence.lower()
                    if any(span in low for span in covered.get(seg_id, [])):
                        continue
                    if self.IMPERATIVE_PATTERN.search(sentence):
                        candidates.append((seg_id, sentence[:300], FINDING_CATEGORY_TOOL_EXECUTION,
                                           "imperative", "tool_execution"))
                        weak_spans.add((seg_id, sentence[:300]))
        findings: List[ResponseFinding] = []
        strong = False
        ref_map, harm_map = self._batch_signals(list(dict.fromkeys(c[1] for c in candidates)), action.tool_name)
        for seg_id, span, cat, op, eff in candidates:
            is_weak = (seg_id, span) in weak_spans
            sem = self._semantic_context_score(span, state, tool=action.tool_name,
                                               ref_sim=ref_map.get(span),
                                               harm_proximity=harm_map.get(span))
            confidence = 0.60 if is_weak else 0.75
            evidence = f"semantic_response:candidate:{seg_id}"
            mode = sem.get("mode") if sem else None
            if mode == "alignment":
                evidence += ":alignment"
                contradiction = sem.get("contradiction", 0.0)
                # directive in tool response conflicting with intent -> higher confidence/risk
                if contradiction is not None and contradiction >= 0.5:
                    confidence = min(0.99, 0.75 + 0.4 * float(contradiction))
                    strong = True
                elif contradiction is not None and contradiction <= 0.15:
                    confidence = 0.55  # may be benign/informational in context
            elif mode == "embedding":
                evidence += ":embedding"
                harm = sem.get("harm_proximity")
                if harm is not None and harm < 0.35:
                    confidence = max(confidence, 0.85)
                    strong = True
            elif mode == "reference":
                evidence += ":reference"
            elif not is_weak:
                # no semantic model available -> still not regex-only "sole" in architecture: deterministic generation + contextual heuristics
                # use contextual heuristics (origin is tool response, imperative directive to agent)
                if re.search(r"\b(you\s+must|you\s+should|immediately|ignore\s+previous)\b", span, re.I):
                    confidence = max(confidence, 0.85)
                    strong = True
            ref_sim = sem.get("ref_sim") if sem else None
            if ref_sim is not None:
                evidence += f":ref{ref_sim:.2f}"
                explicit_override = bool(self.OVERRIDE_MARKER.search(span))
                if ref_sim >= self.REF_TYPICAL and not explicit_override:
                    # routine business wording that happens to contain a directive verb
                    confidence *= self.REF_DISCOUNT
                elif ref_sim <= self.REF_ATYPICAL:
                    confidence = min(0.99, confidence + self.REF_BOOST)
            if confidence >= 0.5:
                findings.append(_make_finding(action.call_id, action.tool_name, span, cat, confidence, evidence,
                                              requested_operation=op, requested_effect=eff))
        # de-duplicate by (span,cat)
        uniq = {}
        for f in findings:
            k = ((f.instruction_span or "").strip().lower(), f.category)
            if k not in uniq or f.confidence > uniq[k].confidence:
                uniq[k] = f
        findings = list(uniq.values())
        if findings:
            # disclosure/scope/override/tool-exec directives in untrusted tool response => block/escalate
            cats = {f.category for f in findings}
            if FINDING_CATEGORY_OVERRIDE in cats or any(f.confidence >= 0.8 for f in findings):
                decision = "BLOCK"
            else:
                decision = "ESCALATE"
            return InboundLayerResult(layer="semantic", decision=decision,
                                      reason="contextual unauthorized directive/indirect instruction detected in tool response",
                                      details={"candidates": len(candidates), "findings": len(findings), "semantic_available": self.semantic_firewall is not None},
                                      findings=findings)
        # if semantic analysis unavailable for all candidates? none found => allow; but no bypass of layer
        return InboundLayerResult(layer="semantic", decision="ALLOW", reason="no unauthorized contextual directives detected in response",
                                  details={"segments_checked": len(segments), "candidates": 0, "semantic_available": self.semantic_firewall is not None})


class InboundResponseValidator:
    """Five-layer inbound response validation orchestrator (response-side adaptation of GATE)."""

    def __init__(self, monitor=None, use_benign_references: bool = True):
        self.monitor = monitor
        dfa = getattr(monitor, "dfa_supervisor", None) if monitor else None
        dcbf = getattr(monitor, "dcbf_monitor", None) if monitor else None
        sem = getattr(monitor, "semantic_firewall", None) if monitor else None
        creg = getattr(monitor, "contract_registry", None) if monitor else None
        self.layers = [
            ("privilege", PrivilegeResponseValidator()),
            ("dfa", DFAResponseValidator(dfa_supervisor=dfa)),
            ("contracts", ContractResponseValidator(contract_registry=creg)),
            ("dcbf", DCBFResponseValidator(dcbf_monitor=dcbf)),
            ("semantic", SemanticResponseFirewallLayer(semantic_firewall=sem,
                                                       use_references=use_benign_references)),
        ]

    def validate(self, action: ToolCall, result: Any, state: AgentState, context: Optional[Dict[str, Any]] = None) -> InboundValidationResult:
        layer_results: List[InboundLayerResult] = []
        all_findings: List[ResponseFinding] = []
        escalated: List[str] = []
        call_id = getattr(action, "call_id", "") or ""
        tool_name = getattr(action, "tool_name", "") or ""
        # Preserve provenance/call context in details (no mutation of auth/policy)
        prov_ctx = {"call_id": call_id, "tool_name": tool_name, "origin": "tool_response"}
        if context:
            prov_ctx.update({k: v for k, v in context.items() if k in ("provenance", "turn", "execution_id")})

        for name, layer in self.layers:
            try:
                lr = layer.validate(action, result, state, context=context)
            except Exception as e:
                # no silent bypass: fail-closed
                lr = InboundLayerResult(layer=name, decision="ESCALATE",
                                        reason=f"inbound layer {name} validation error (fail-closed): {e}", status="error")
            layer_results.append(lr)
            all_findings.extend(lr.findings or [])
            if lr.decision == "ESCALATE":
                escalated.append(name)
            if lr.decision == "BLOCK":
                # BLOCK prevents response delivery as trusted usable content
                return InboundValidationResult(
                    decision="BLOCK",
                    reason=lr.reason,
                    layer_results=layer_results,
                    findings=all_findings,
                    blocked_layer=name,
                    escalated_layers=escalated,
                    call_id=call_id,
                    tool_name=tool_name,
                )
        if escalated:
            return InboundValidationResult(
                decision="ESCALATE",
                reason=f"inbound response requires escalation (fail-closed): {', '.join(escalated)}",
                layer_results=layer_results,
                findings=all_findings,
                blocked_layer=None,
                escalated_layers=escalated,
                call_id=call_id,
                tool_name=tool_name,
            )
        return InboundValidationResult(
            decision="ALLOW",
            reason="inbound response passed all five validation layers",
            layer_results=layer_results,
            findings=all_findings,
            blocked_layer=None,
            escalated_layers=[],
            call_id=call_id,
            tool_name=tool_name,
        )
