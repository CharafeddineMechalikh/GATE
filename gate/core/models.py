"""
gate Core Models
Data models for agent state, tool calls, and validation results.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from datetime import datetime
import numpy as np
import json


@dataclass
class ToolCall:
    """Represents a tool call proposed by the agent."""
    
    tool_name: str
    tool_args: Dict[str, Any]
    call_id: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    agent_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    # Provenance/taint (optional, backward-compatible)
    taint_sources: List[str] = field(default_factory=list)
    provenance: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "tool_name": self.tool_name,
            "tool_args": self.tool_args,
            "call_id": self.call_id,
            "timestamp": self.timestamp.isoformat(),
            "agent_id": self.agent_id,
            "metadata": self.metadata
        }
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)
    
    def get_action_description(self) -> str:
        """Get natural language description of the action."""
        args_str = ", ".join(f"{k}={v}" for k, v in self.tool_args.items())
        return f"Call {self.tool_name}({args_str})"
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ToolCall":
        """Create ToolCall from dictionary."""
        return cls(
            tool_name=data["tool_name"],
            tool_args=data["tool_args"],
            call_id=data["call_id"],
            timestamp=datetime.fromisoformat(data.get("timestamp", datetime.utcnow().isoformat())),
            agent_id=data.get("agent_id"),
            metadata=data.get("metadata", {})
        )


@dataclass
class ResourceMetrics:
    """Tracks resource consumption."""
    
    tokens_used: int = 0
    api_calls: int = 0
    compute_time_seconds: float = 0.0
    cost_usd: float = 0.0
    
    def add_usage(self, tokens: int = 0, api_calls: int = 0, 
                  compute_time: float = 0.0, cost: float = 0.0):
        """Add usage metrics."""
        self.tokens_used += tokens
        self.api_calls += api_calls
        self.compute_time_seconds += compute_time
        self.cost_usd += cost


# 3C-H: segment-level provenance schema (origin metadata only; never used for decisions/blocking).
# origin: user_instruction|system_developer_context|environment_data|external_document|tool_result|unknown
# boundary: initial_context|tool_ingestion|decision
# 3B-A: `environment_data` = benchmark/framework-authored environment content observed at construction
# (e.g. retained YAML defaults). Distinct from `external_document` (externally supplied content recorded
# at its construction/substitution event). Neither is inferred from text or labels; neither affects decisions.
SEGMENT_ORIGINS = {"user_instruction", "system_developer_context", "environment_data", "external_document", "tool_result", "unknown"}
SEGMENT_BOUNDARIES = {"initial_context", "tool_ingestion", "decision"}


@dataclass
class AgentState:
    """Represents the complete state of an agent."""

    agent_id: str
    context_embedding: Optional[np.ndarray] = None
    action_embedding: Optional[np.ndarray] = None
    resource_usage: ResourceMetrics = field(default_factory=ResourceMetrics)
    tool_history: List[ToolCall] = field(default_factory=list)
    memory_state: Optional[Dict[str, Any]] = None
    trust_level: float = 1.0
    current_phase: str = "IDLE"  # IDLE, PLANNING, ACTING, OBSERVING, ANSWERING
    step_count: int = 0
    loop_count: Dict[str, int] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    last_updated: datetime = field(default_factory=datetime.utcnow)
    # Provenance/taint (optional, backward-compatible)
    taint_sources: List[str] = field(default_factory=list)
    provenance: Optional[Dict[str, Any]] = None

    def update_timestamp(self):
        """Update the last_updated timestamp."""
        self.last_updated = datetime.utcnow()

    def _ensure_provenance(self) -> Dict[str, Any]:
        prov = self.provenance if isinstance(self.provenance, dict) else {}
        if 'sources' not in prov:
            prov['sources'] = list(self.taint_sources)
        if 'source_log' not in prov:
            prov['source_log'] = []
        if 'segments' not in prov:
            prov['segments'] = []
        self.provenance = prov
        return prov

    def add_segment(self, origin: str, boundary: str, *, known: bool = None,
                    content_ref: str = None, source: str = None,
                    parent_segments: list = None, transformation: str = None,
                    segment_id: str = None, metadata: dict = None) -> None:
        """Record a provenance segment (3C-H; lineage extended in 3B-A). Metadata only; never affects decisions.
        `known` defaults True for established non-unknown origins, False for unknown.
        `source` is the recording mechanism (e.g. runtime/initial_context) — not case labels.
        3B-A lineage (all optional): `parent_segments` (ids of constructed/earlier segments this one
        derives from), `transformation` (e.g. 'environment_vector_substitution',
        'tool_result_serialization', 'summarization'), `segment_id` (auto-assigned when lineage is
        recorded), `metadata` (construction-event fields, e.g. vector_id/replaced/source_mechanism).
        A transformed segment NEVER inherits a parent's origin or known-ness: lineage is preserved
        while the child's own origin stands alone (3B-A constraint A)."""
        if origin not in SEGMENT_ORIGINS:
            origin = 'unknown'
        if boundary not in SEGMENT_BOUNDARIES:
            boundary = 'decision'
        if known is None:
            known = origin != 'unknown'
        prov = self._ensure_provenance()
        seg = {
            'origin': origin,
            'boundary': boundary,
            'known': bool(known),
        }
        if content_ref is not None:
            seg['content_ref'] = str(content_ref)[:200]
        if source is not None:
            seg['source'] = str(source)[:80]
        has_lineage = parent_segments is not None or transformation is not None or segment_id is not None or metadata is not None
        if has_lineage:
            seg['segment_id'] = str(segment_id) if segment_id is not None else f"seg_{len(prov['segments']):03d}"
            seg['parent_segments'] = [str(p) for p in (parent_segments or [])]
            seg['transformation'] = str(transformation) if transformation is not None else None
            if metadata is not None:
                # construction-event metadata only (never scores/labels); keep bounded
                seg['metadata'] = {str(k): v for k, v in list(dict(metadata).items())[:10]}
        seg['ts'] = self.last_updated.isoformat() if self.last_updated else None
        # dedupe identical (origin,boundary,content_ref,transformation,parent set)
        segs = prov['segments']
        key = (seg['origin'], seg['boundary'], seg.get('content_ref'), seg.get('transformation'), tuple(seg.get('parent_segments') or []))
        if not any((s.get('origin'), s.get('boundary'), s.get('content_ref'), s.get('transformation'), tuple(s.get('parent_segments') or [])) == key for s in segs):
            segs.append(seg)
            if len(segs) > 100:
                prov['segments'] = segs[-100:]
        # known initial/user segments also register as a 'user' source for provenance flags (metadata).
        # 3B-A: environment_data / external_document / tool_result segments must NOT add taint flags here.
        if seg['known'] and origin == 'user_instruction' and 'user' not in self.taint_sources:
            self.taint_sources.append('user')
        prov['sources'] = list(self.taint_sources)
        self.provenance = prov
        self.update_timestamp()

    def add_taint(self, *sources: str, origin: str = None, content_ref: str = None, tool_name: str = None,
                  boundary: str = None):
        """Mark state as influenced by given provenance sources (idempotent).
        Taint = information origin (not maliciousness). Preserves per-source records and segments."""
        for s in sources:
            if s and s not in self.taint_sources:
                self.taint_sources.append(s)
        prov = self._ensure_provenance()
        log = list(prov.get('source_log') or [])
        if origin or tool_name or content_ref or sources:
            entry = {'sources': [s for s in sources if s]}
            if origin:
                entry['origin'] = origin
            if tool_name:
                entry['tool_name'] = tool_name
            if content_ref:
                entry['content_ref'] = str(content_ref)[:200]
            entry['ts'] = self.last_updated.isoformat() if self.last_updated else None
            log.append(entry)
            if len(log) > 50:
                log = log[-50:]
        prov['source_log'] = log
        prov['sources'] = list(self.taint_sources)
        # 3C-H: record a tool-ingestion segment when origin is tool_result (metadata; preserves global taint)
        if origin == 'tool_result' and sources:
            b = boundary or 'tool_ingestion'
            seg_origin = 'external_document' if 'external_content' in sources else 'tool_result'
            self.add_segment(seg_origin, b, known=True, content_ref=content_ref or tool_name, source='runtime')
            prov = self._ensure_provenance()
        self.provenance = prov
        self.update_timestamp()

    def add_tool_call(self, tool_call: ToolCall):
        """Add a tool call to history."""
        self.tool_history.append(tool_call)
        self.step_count += 1
        # propagate taint from tool call (tool results/actions can introduce influence)
        for s in getattr(tool_call, 'taint_sources', []) or []:
            self.add_taint(s)
        self.update_timestamp()
    
    def increment_loop(self, phase: str):
        """Increment loop counter for a phase."""
        self.loop_count[phase] = self.loop_count.get(phase, 0) + 1
        self.update_timestamp()
    
    def get_recent_tool_calls(self, n: int = 5) -> List[ToolCall]:
        """Get the last n tool calls."""
        return self.tool_history[-n:]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "agent_id": self.agent_id,
            "resource_usage": {
                "tokens_used": self.resource_usage.tokens_used,
                "api_calls": self.resource_usage.api_calls,
                "compute_time_seconds": self.resource_usage.compute_time_seconds,
                "cost_usd": self.resource_usage.cost_usd
            },
            "tool_history": [tc.to_dict() for tc in self.tool_history],
            "trust_level": self.trust_level,
            "current_phase": self.current_phase,
            "step_count": self.step_count,
            "loop_count": self.loop_count,
            "created_at": self.created_at.isoformat(),
            "last_updated": self.last_updated.isoformat()
        }


@dataclass
class SemanticScore:
    """Result of semantic safety scoring."""
    
    sss_value: float
    drift_to_intent: float
    drift_to_harm: float
    drift_to_safe: float
    decision: str  # "ALLOW", "BLOCK", "ESCALATE"
    details: Dict[str, float]
    alignment_contradiction: Optional[float] = None
    fused_harm: Optional[float] = None
    # Provenance/taint (optional, backward-compatible): source of influencing context
    provenance: Optional[Dict[str, Any]] = None
    taint_score: Optional[float] = None
    
    def is_safe(self) -> bool:
        """Check if the score indicates safety."""
        return self.decision == "ALLOW"


@dataclass
class ValidationResult:
    """Result of action validation."""
    
    is_allowed: bool
    reason: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    semantic_score: Optional[SemanticScore] = None
    checks_passed: List[str] = field(default_factory=list)
    checks_failed: List[str] = field(default_factory=list)
    escalated: bool = False
    requires_approval: bool = False
