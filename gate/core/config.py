"""
gate Configuration
Enhanced with timeout, retry, and Neural CBF configuration.
"""

from dataclasses import dataclass, field
from typing import Set, Optional, Dict, Any, List
from enum import Enum


class LogLevel(str, Enum):
    """Log levels."""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"


@dataclass
class SemanticThresholds:
    """Thresholds for semantic safety scoring."""
    sss_safe_threshold: float = 0.7
    sss_block_threshold: float = 0.5
    drift_threshold: float = 0.8
    harm_threshold: float = 0.2


@dataclass
class ResourceBudget:
    """Resource budget limits for an agent."""
    max_steps: int = 50
    max_tokens: int = 100000
    max_cost_usd: float = 10.0
    max_execution_time_seconds: int = 300
    max_loops_per_phase: int = 3


@dataclass
class DataScope:
    """Defines what data an agent can access."""
    allowed_databases: Set[str] = field(default_factory=set)
    allowed_tables: Dict[str, Set[str]] = field(default_factory=dict)
    allowed_api_endpoints: Set[str] = field(default_factory=set)
    forbidden_patterns: Set[str] = field(default_factory=lambda: {"169.254.169.254"})
    
    def check_access(self, resource: str) -> bool:
        """Check if resource access is allowed."""
        for pattern in self.forbidden_patterns:
            if pattern in resource:
                return False

        normalized = resource.rstrip("/")
        for endpoint in self.allowed_api_endpoints:
            host = endpoint.split("://", 1)[-1].rstrip("/")
            if normalized == endpoint or normalized == host or normalized.endswith("." + host):
                return True

        if "." in resource:
            db, table = resource.split(".", 1)
            if db in self.allowed_databases:
                if not self.allowed_tables or table in self.allowed_tables.get(db, set()):
                    return True

        return False


@dataclass
class AgentProfile:
    """Profile defining agent capabilities and restrictions."""
    agent_id: str
    role: str
    allowed_tools: Set[str]
    forbidden_tools: Set[str] = field(default_factory=set)
    data_scope: DataScope = field(default_factory=DataScope)
    resource_budget: ResourceBudget = field(default_factory=ResourceBudget)
    trust_level: int = 1
    can_communicate_with: Set[str] = field(default_factory=set)


@dataclass
class RetryConfig:
    """Configuration for retry behavior."""
    max_attempts: int = 3
    min_wait_seconds: float = 0.5
    max_wait_seconds: float = 10.0
    multiplier: float = 2.0
    retryable_exceptions: Optional[tuple] = None


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breakers."""
    failure_threshold: int = 5
    recovery_timeout: float = 60.0
    half_open_max_calls: int = 1


@dataclass
class NeuralCBFConfig:
    """Configuration for Neural CBF."""
    enabled: bool = False
    state_dim: int = 10
    hidden_dims: List[int] = field(default_factory=lambda: [64, 64])
    alpha_kappa: float = 0.5
    safety_margin: float = 0.1
    model_path: Optional[str] = None
    device: str = "cpu"


@dataclass
class gateConfig:
    """Main configuration for gate security system."""
    agent_profile: AgentProfile
    semantic_thresholds: SemanticThresholds = field(default_factory=SemanticThresholds)
    enabled_checks: Set[str] = field(default_factory=lambda: {
        "semantic", "contracts", "dcbf", "dfa", "privilege"
    })
    log_level: LogLevel = LogLevel.INFO
    embedding_model_name: str = "all-MiniLM-L6-v2"
    vector_store_path: Optional[str] = None
    audit_log_path: Optional[str] = None
    enable_async_batching: bool = True
    batch_window_ms: int = 10
    irreversible_actions: Set[str] = field(default_factory=set)
    tenant_id: str = "default"
    
    timeout_seconds: float = 300.0
    retry_config: RetryConfig = field(default_factory=RetryConfig)
    circuit_breaker_config: CircuitBreakerConfig = field(default_factory=CircuitBreakerConfig)
    neural_cbf_config: NeuralCBFConfig = field(default_factory=NeuralCBFConfig)
    
    trajectory_ema_alpha: float = 0.3
    enable_forward_invariance_verification: bool = True
    
    def is_check_enabled(self, check_name: str) -> bool:
        """Check if a specific security check is enabled."""
        return check_name in self.enabled_checks
    
    def validate(self) -> None:
        """Validate configuration."""
        if not self.agent_profile.agent_id:
            raise ValueError("agent_id is required")
        
        if self.semantic_thresholds.sss_safe_threshold <= self.semantic_thresholds.sss_block_threshold:
            raise ValueError("sss_safe_threshold must be > sss_block_threshold")
        
        if self.agent_profile.resource_budget.max_steps <= 0:
            raise ValueError("max_steps must be > 0")
        
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be > 0")
        
        if self.retry_config.max_attempts < 1:
            raise ValueError("max_attempts must be >= 1")
