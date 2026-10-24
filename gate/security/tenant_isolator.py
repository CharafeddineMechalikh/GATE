"""
Tenant Isolator
Ensures strict data isolation between tenants in multi-tenant deployments.
"""

import logging
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Set

from ..core.exceptions import SecurityViolation

logger = logging.getLogger(__name__)


_current_tenant: ContextVar[Optional["TenantContext"]] = ContextVar(
    "current_tenant", default=None
)


@dataclass
class DataResidencyPolicy:
    """Defines where tenant data can be stored and processed."""
    allowed_regions: Set[str] = field(default_factory=lambda: {"us-east-1"})
    forbidden_regions: Set[str] = field(default_factory=set)
    require_encryption_at_rest: bool = True
    require_encryption_in_transit: bool = True


@dataclass
class TenantContext:
    """Complete context for a tenant."""
    tenant_id: str
    encryption_key_id: str
    allowed_regions: Set[str] = field(default_factory=lambda: {"us-east-1"})
    compliance_frameworks: Set[str] = field(default_factory=set)
    data_residency: DataResidencyPolicy = field(default_factory=DataResidencyPolicy)
    custom_policies: Dict[str, Any] = field(default_factory=dict)
    
    def validate_region(self, region: str) -> bool:
        """Check if a region is allowed for this tenant."""
        if region in self.data_residency.forbidden_regions:
            return False
        if self.data_residency.allowed_regions and region not in self.data_residency.allowed_regions:
            return False
        return True


class TenantIsolator:
    """
    Enforces strict tenant isolation across all gate components.
    """
    
    def __init__(self) -> None:
        self._tenants: Dict[str, TenantContext] = {}
        self._tenant_vector_stores: Dict[str, Any] = {}
        self._tenant_audit_partitions: Dict[str, str] = {}
    
    def register_tenant(self, context: TenantContext) -> None:
        """Register a new tenant."""
        self._tenants[context.tenant_id] = context
        logger.info(f"Registered tenant: {context.tenant_id}")
    
    def get_tenant(self, tenant_id: Optional[str] = None) -> TenantContext:
        """Get tenant context. Uses current context if tenant_id not provided."""
        tid = tenant_id or self.get_current_tenant_id()
        if tid not in self._tenants:
            raise SecurityViolation(
                f"Unknown tenant: {tid}",
                details={"tenant_id": tid},
            )
        return self._tenants[tid]
    
    def get_current_tenant_id(self) -> str:
        """Get the current tenant ID from context."""
        ctx = _current_tenant.get()
        if ctx is None:
            raise SecurityViolation(
                "No tenant context set. Use tenant_scope() to set tenant.",
                details={},
            )
        return ctx.tenant_id
    
    def tenant_scope(self, tenant_id: str) -> "TenantScope":
        """Context manager to set tenant for a block of code."""
        return TenantScope(self, tenant_id)
    
    def set_tenant(self, tenant_id: str) -> None:
        """Set the current tenant context."""
        if tenant_id not in self._tenants:
            raise SecurityViolation(f"Unknown tenant: {tenant_id}", details={})
        _current_tenant.set(self._tenants[tenant_id])
    
    def get_isolated_vector_store(self, tenant_id: Optional[str] = None) -> Any:
        """Get a tenant-isolated vector store namespace."""
        tid = tenant_id or self.get_current_tenant_id()
        
        if tid not in self._tenant_vector_stores:
            from ..utils.vector_store import VectorStore
            namespace = f"tenant-{tid}"
            self._tenant_vector_stores[tid] = VectorStore(namespace=namespace)
            logger.debug(f"Created isolated vector store for tenant {tid}")
        
        return self._tenant_vector_stores[tid]
    
    def get_isolated_audit_partition(self, tenant_id: Optional[str] = None) -> str:
        """Get the audit log partition path for a tenant."""
        tid = tenant_id or self.get_current_tenant_id()
        
        if tid not in self._tenant_audit_partitions:
            self._tenant_audit_partitions[tid] = f"tenants/{tid}/audit"
        
        return self._tenant_audit_partitions[tid]
    
    def prevent_cross_tenant_access(self, resource_tenant_id: str) -> bool:
        """
        Verify that the current tenant matches the resource's tenant.
        Returns True if access is allowed, raises if not.
        """
        current = self.get_current_tenant_id()
        if current != resource_tenant_id:
            logger.warning(
                f"Cross-tenant access attempt: {current} -> {resource_tenant_id}"
            )
            raise SecurityViolation(
                f"Cross-tenant access denied: {current} cannot access {resource_tenant_id}",
                details={"current_tenant": current, "target_tenant": resource_tenant_id},
            )
        return True


class TenantScope:
    """Context manager for tenant isolation."""
    
    def __init__(self, isolator: TenantIsolator, tenant_id: str) -> None:
        self.isolator = isolator
        self.tenant_id = tenant_id
        self._token: Any = None
    
    def __enter__(self) -> "TenantScope":
        if self.tenant_id not in self.isolator._tenants:
            raise SecurityViolation(f"Unknown tenant: {self.tenant_id}", details={})
        self._token = _current_tenant.set(self.isolator._tenants[self.tenant_id])
        return self
    
    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> bool:
        if self._token is not None:
            _current_tenant.reset(self._token)
        return False
    
    async def __aenter__(self) -> "TenantScope":
        return self.__enter__()
    
    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> bool:
        return self.__exit__(exc_type, exc_val, exc_tb)
