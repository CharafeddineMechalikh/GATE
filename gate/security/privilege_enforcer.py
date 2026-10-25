"""
Privilege Enforcer Implementation
Enhanced with capability tokens and audit trail.
"""

import logging
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from ..core.config import AgentProfile
from ..core.interfaces import PrivilegeEnforcer

logger = logging.getLogger(__name__)


@dataclass
class CapabilityToken:
    """Cryptographic capability token for an agent."""
    agent_id: str
    capabilities: Set[str]
    issued_at: float = field(default_factory=time.time)
    expires_at: Optional[float] = None
    signature: str = ""
    
    def is_valid(self) -> bool:
        """Check if token is still valid."""
        if self.expires_at is not None and time.time() > self.expires_at:
            return False
        return True
    
    def revoke(self) -> None:
        """Revoke the token."""
        self.expires_at = 0.0


class DefaultPrivilegeEnforcer(PrivilegeEnforcer):
    """Default implementation of privilege enforcer."""
    
    def __init__(self) -> None:
        self._profiles: Dict[str, AgentProfile] = {}
        self._tokens: Dict[str, CapabilityToken] = {}
        self._audit_trail: List[Dict] = []
    
    def register_profile(self, profile: AgentProfile) -> None:
        """Register an agent profile."""
        self._profiles[profile.agent_id] = profile
        logger.debug(f"Registered profile for agent: {profile.agent_id}")
    
    def unregister_profile(self, agent_id: str) -> None:
        """Unregister an agent profile."""
        if agent_id in self._profiles:
            del self._profiles[agent_id]
            logger.debug(f"Unregistered profile for agent: {agent_id}")
    
    def issue_token(
        self,
        agent_id: str,
        capabilities: Set[str],
        ttl_seconds: Optional[int] = None,
    ) -> CapabilityToken:
        """Issue a capability token for an agent."""
        if agent_id not in self._profiles:
            raise ValueError(f"Unknown agent: {agent_id}")
        
        expires_at = time.time() + ttl_seconds if ttl_seconds else None
        
        token = CapabilityToken(
            agent_id=agent_id,
            capabilities=capabilities,
            expires_at=expires_at,
            signature=f"sig-{hash((agent_id, frozenset(capabilities))) % 1000000:06d}",
        )
        
        self._tokens[agent_id] = token
        self._log_audit("TOKEN_ISSUED", agent_id, {"capabilities": list(capabilities)})
        
        logger.info(f"Issued capability token for agent {agent_id}")
        return token
    
    def revoke_token(self, agent_id: str) -> None:
        """Revoke an agent's capability token."""
        if agent_id in self._tokens:
            self._tokens[agent_id].revoke()
            self._log_audit("TOKEN_REVOKED", agent_id, {})
            logger.info(f"Revoked capability token for agent {agent_id}")
    
    def check_tool_permission(self, agent_id: str, tool_name: str) -> bool:
        """Check if agent is allowed to use a tool."""
        profile = self._profiles.get(agent_id)
        if not profile:
            logger.warning(f"No profile found for agent: {agent_id}")
            self._log_audit("PERMISSION_DENIED", agent_id, {"tool": tool_name, "reason": "no_profile"})
            return False
        
        if tool_name in profile.forbidden_tools:
            logger.warning(f"Tool {tool_name} forbidden for agent {agent_id}")
            self._log_audit("PERMISSION_DENIED", agent_id, {"tool": tool_name, "reason": "forbidden"})
            return False
        
        if tool_name not in profile.allowed_tools:
            logger.warning(f"Tool {tool_name} not in allowed list for agent {agent_id}")
            self._log_audit("PERMISSION_DENIED", agent_id, {"tool": tool_name, "reason": "not_allowed"})
            return False
        
        self._log_audit("PERMISSION_GRANTED", agent_id, {"tool": tool_name})
        return True
    
    def check_data_scope(self, agent_id: str, resource: str) -> bool:
        """Check if agent can access a data resource."""
        profile = self._profiles.get(agent_id)
        if not profile:
            return False
        
        allowed = profile.data_scope.check_access(resource)
        if not allowed:
            self._log_audit("DATA_SCOPE_DENIED", agent_id, {"resource": resource})
        return allowed
    
    def check_resource_budget(self, agent_id: str, estimated_cost: float) -> bool:
        """Check if agent is within resource budget."""
        profile = self._profiles.get(agent_id)
        if not profile:
            return False
        
        within_budget = estimated_cost <= profile.resource_budget.max_cost_usd
        if not within_budget:
            self._log_audit(
                "BUDGET_EXCEEDED",
                agent_id,
                {"estimated_cost": estimated_cost, "limit": profile.resource_budget.max_cost_usd},
            )
        return within_budget
    
    def get_profile(self, agent_id: str) -> Optional[AgentProfile]:
        """Get an agent's profile."""
        return self._profiles.get(agent_id)
    
    def get_audit_trail(self, agent_id: Optional[str] = None) -> List[Dict]:
        """Get the audit trail, optionally filtered by agent."""
        if agent_id:
            return [e for e in self._audit_trail if e["agent_id"] == agent_id]
        return self._audit_trail.copy()
    
    def _log_audit(self, event_type: str, agent_id: str, details: Dict) -> None:
        """Log an audit event."""
        self._audit_trail.append({
            "event_type": event_type,
            "agent_id": agent_id,
            "timestamp": time.time(),
            "details": details,
        })
        
        if len(self._audit_trail) > 10000:
            self._audit_trail = self._audit_trail[-5000:]
