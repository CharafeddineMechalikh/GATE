"""
gate Security Exceptions
Custom exception hierarchy for security violations and system errors.
"""

from typing import Optional, Any, Dict


class gateException(Exception):
    """Base exception for all gate errors."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}
    
    def __str__(self) -> str:
        if self.details:
            return f"{self.message} | Details: {self.details}"
        return self.message


# Security Violations
class SecurityViolation(gateException):
    """Base class for all security violations."""
    pass


class SemanticSafetyViolation(SecurityViolation):
    """Raised when semantic safety check fails.

    Carries the full :class:`SemanticScore` that triggered the block so the
    caller can report the score that caused the decision instead of losing it.
    """

    def __init__(self, message: str, sss_score: float, threshold: float,
                 semantic_score: Optional[Any] = None, **kwargs):
        super().__init__(message, {"sss_score": sss_score, "threshold": threshold, **kwargs})
        self.sss_score = sss_score
        self.threshold = threshold
        self.semantic_score = semantic_score


class SemanticEscalation(SecurityViolation):
    """Raised when the semantic firewall returns ESCALATE: fuzzy case.

    The action is neither clearly safe nor clearly harmful. It must NOT
    execute silently; it is routed to the HITL approval queue for a user
    decision (approve/reject with SLA). Carries the SSS for audit.
    """

    def __init__(self, message: str, sss_score: float, threshold: float, **kwargs):
        super().__init__(message, {"sss_score": sss_score, "threshold": threshold,
                                   "needs_user_approval": True, **kwargs})
        self.sss_score = sss_score
        self.threshold = threshold


class ContractViolation(SecurityViolation):
    """Raised when smart contract validation fails."""
    
    def __init__(self, message: str, contract_name: str, violation_type: str, **kwargs):
        super().__init__(message, {"contract": contract_name, "type": violation_type, **kwargs})
        self.contract_name = contract_name
        self.violation_type = violation_type


class DCBFViolation(SecurityViolation):
    """Raised when Discrete Control Barrier Function invariant is violated."""
    
    def __init__(self, message: str, barrier_value: float, barrier_name: str, **kwargs):
        super().__init__(message, {"barrier_value": barrier_value, "barrier_name": barrier_name, **kwargs})
        self.barrier_value = barrier_value
        self.barrier_name = barrier_name


class PrivilegeViolation(SecurityViolation):
    """Raised when agent attempts unauthorized action."""
    
    def __init__(self, message: str, agent_id: str, resource: str, **kwargs):
        super().__init__(message, {"agent_id": agent_id, "resource": resource, **kwargs})
        self.agent_id = agent_id
        self.resource = resource


class DataScopeViolation(SecurityViolation):
    """Raised when agent accesses data outside its scope."""
    
    def __init__(self, message: str, agent_id: str, data_resource: str, **kwargs):
        super().__init__(message, {"agent_id": agent_id, "data_resource": data_resource, **kwargs})
        self.agent_id = agent_id
        self.data_resource = data_resource


class ResourceBudgetExceeded(SecurityViolation):
    """Raised when agent exceeds resource budget."""
    
    def __init__(self, message: str, agent_id: str, resource_type: str, limit: float, current: float, **kwargs):
        super().__init__(
            message,
            {"agent_id": agent_id, "resource_type": resource_type, "limit": limit, "current": current, **kwargs}
        )
        self.agent_id = agent_id
        self.resource_type = resource_type
        self.limit = limit
        self.current = current


class DFAViolation(SecurityViolation):
    """Raised when DFA supervisor rejects a state transition."""
    
    def __init__(self, message: str, current_state: str, proposed_state: str, **kwargs):
        super().__init__(message, {"current_state": current_state, "proposed_state": proposed_state, **kwargs})
        self.current_state = current_state
        self.proposed_state = proposed_state


class TimeoutViolation(SecurityViolation):
    """Raised when an operation times out."""
    
    def __init__(self, message: str, timeout_seconds: float, operation: str, **kwargs):
        super().__init__(
            message,
            {"timeout_seconds": timeout_seconds, "operation": operation, **kwargs}
        )
        self.timeout_seconds = timeout_seconds
        self.operation = operation


# System Errors
class gateSystemError(gateException):
    """Base class for system-level errors."""
    pass


class EmbeddingModelError(gateSystemError):
    """Raised when embedding model fails."""
    pass


class VectorStoreError(gateSystemError):
    """Raised when vector store operations fail."""
    pass


class AdapterError(gateSystemError):
    """Raised when framework adapter encounters an error."""
    pass


class ConfigurationError(gateSystemError):
    """Raised when configuration is invalid."""
    pass


class NeuralCBFError(gateSystemError):
    """Raised when Neural CBF encounters an error."""
    pass
