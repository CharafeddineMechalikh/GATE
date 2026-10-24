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
    
    def update_timestamp(self):
        """Update the last_updated timestamp."""
        self.last_updated = datetime.utcnow()
    
    def add_tool_call(self, tool_call: ToolCall):
        """Add a tool call to history."""
        self.tool_history.append(tool_call)
        self.step_count += 1
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
