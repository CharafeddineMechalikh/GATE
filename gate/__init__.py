"""
gate - Guarded Agent Tool Execution
Zero-trust security wrapper for LLM agent frameworks.
"""

__version__ = "1.0.0"
__author__ = "gate Team"

from .core.config import (
    gateConfig,
    AgentProfile,
    ResourceBudget,
    DataScope,
    SemanticThresholds,
    RetryConfig,
    CircuitBreakerConfig,
    NeuralCBFConfig,
)
from .core.exceptions import (
    gateException,
    SecurityViolation,
    SemanticSafetyViolation,
    ContractViolation,
    PrivilegeViolation,
    ResourceBudgetExceeded,
    DCBFViolation,
    DFAViolation,
    DataScopeViolation,
    EmbeddingModelError,
    VectorStoreError,
    AdapterError,
    ConfigurationError,
)
from .core.models import ToolCall, AgentState, ValidationResult, SemanticScore
from .adapters.registry import wrap_agent, get_registry

__all__ = [
    # Configuration
    "gateConfig",
    "AgentProfile",
    "ResourceBudget",
    "DataScope",
    "SemanticThresholds",
    "RetryConfig",
    "CircuitBreakerConfig",
    "NeuralCBFConfig",
    
    # Exceptions
    "gateException",
    "SecurityViolation",
    "SemanticSafetyViolation",
    "ContractViolation",
    "PrivilegeViolation",
    "ResourceBudgetExceeded",
    "DCBFViolation",
    "DFAViolation",
    "DataScopeViolation",
    "EmbeddingModelError",
    "VectorStoreError",
    "AdapterError",
    "ConfigurationError",
    
    # Models
    "ToolCall",
    "AgentState",
    "ValidationResult",
    "SemanticScore",
    
    # Main API
    "wrap_agent",
    "get_registry",
]
