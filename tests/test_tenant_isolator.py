"""Tests for tenant isolation."""

import pytest

from gate.security.tenant_isolator import (
    DataResidencyPolicy,
    TenantContext,
    TenantIsolator,
    TenantScope,
    _current_tenant,
)
from gate.core.exceptions import SecurityViolation


def _make_isolator(*tenant_ids):
    isolator = TenantIsolator()
    for tid in tenant_ids:
        isolator.register_tenant(
            TenantContext(tenant_id=tid, encryption_key_id=f"key-{tid}")
        )
    return isolator


class TestTenantContext:
    def test_validate_region_allowed(self):
        ctx = TenantContext(
            tenant_id="t1",
            encryption_key_id="k",
            data_residency=DataResidencyPolicy(allowed_regions={"eu-west-1"}),
        )
        assert ctx.validate_region("eu-west-1") is True

    def test_validate_region_forbidden(self):
        ctx = TenantContext(
            tenant_id="t1",
            encryption_key_id="k",
            data_residency=DataResidencyPolicy(
                allowed_regions={"us-east-1", "eu-west-1"},
                forbidden_regions={"eu-west-1"},
            ),
        )
        assert ctx.validate_region("eu-west-1") is False

    def test_validate_region_not_in_allowed(self):
        ctx = TenantContext(
            tenant_id="t1",
            encryption_key_id="k",
            data_residency=DataResidencyPolicy(allowed_regions={"us-east-1"}),
        )
        assert ctx.validate_region("ap-south-1") is False


class TestTenantIsolator:
    def setup_method(self):
        _current_tenant.set(None)
        self.isolator = _make_isolator("alpha", "beta")

    def teardown_method(self):
        _current_tenant.set(None)

    def test_get_tenant_by_id(self):
        assert self.isolator.get_tenant("alpha").tenant_id == "alpha"

    def test_get_tenant_unknown_raises(self):
        with pytest.raises(SecurityViolation):
            self.isolator.get_tenant("ghost")

    def test_get_current_tenant_id_none_raises(self):
        with pytest.raises(SecurityViolation):
            self.isolator.get_current_tenant_id()

    def test_set_and_get_current_tenant(self):
        self.isolator.set_tenant("beta")
        assert self.isolator.get_current_tenant_id() == "beta"

    def test_set_unknown_tenant_raises(self):
        with pytest.raises(SecurityViolation):
            self.isolator.set_tenant("ghost")

    def test_get_tenant_uses_current_context(self):
        self.isolator.set_tenant("alpha")
        assert self.isolator.get_tenant().tenant_id == "alpha"

    def test_isolated_vector_store_cached(self):
        first = self.isolator.get_isolated_vector_store("alpha")
        second = self.isolator.get_isolated_vector_store("alpha")
        assert first is second
        assert first.namespace == "tenant-alpha"

    def test_isolated_audit_partition_cached(self):
        path = self.isolator.get_isolated_audit_partition("beta")
        assert path == "tenants/beta/audit"
        assert self.isolator.get_isolated_audit_partition("beta") == path

    def test_prevent_cross_tenant_allows_same(self):
        self.isolator.set_tenant("alpha")
        assert self.isolator.prevent_cross_tenant_access("alpha") is True

    def test_prevent_cross_tenant_blocks_other(self):
        self.isolator.set_tenant("alpha")
        with pytest.raises(SecurityViolation):
            self.isolator.prevent_cross_tenant_access("beta")

    def test_tenant_scope_sets_and_restores(self):
        with self.isolator.tenant_scope("beta"):
            assert self.isolator.get_current_tenant_id() == "beta"
        # after exit, context returns to the previous value (none)
        assert _current_tenant.get() is None

    def test_tenant_scope_unknown_raises(self):
        with pytest.raises(SecurityViolation):
            with self.isolator.tenant_scope("ghost"):
                pass

    @pytest.mark.asyncio
    async def test_async_tenant_scope(self):
        scope = TenantScope(self.isolator, "alpha")
        async with scope:
            assert self.isolator.get_current_tenant_id() == "alpha"
        assert _current_tenant.get() is None
