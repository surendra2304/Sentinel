"""Multi-Tenant Isolation, Scoped Policy, and Usage Metering Service.

Provides:
1. Tenant Context & Isolation (per-tenant asset registries, policies, scopes).
2. Per-tenant API key management and validation.
3. Tenant usage metering (scans executed per month, storage bytes utilized).
"""

from datetime import UTC, datetime

from pydantic import BaseModel, Field


class TenantUsage(BaseModel):
    scans_this_month: int = 0
    storage_bytes_used: int = 0
    last_scan_at: datetime | None = None


class Tenant(BaseModel):
    tenant_id: str
    name: str
    api_keys: list[str] = Field(default_factory=list)
    allowed_assets: list[str] = Field(default_factory=list)
    custom_policy_ids: list[str] = Field(default_factory=list)
    usage: TenantUsage = Field(default_factory=TenantUsage)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class TenantManager:
    """Manages multi-tenant workspaces, API key resolution, and usage quotas."""

    def __init__(self):
        self._tenants: dict[str, Tenant] = {}
        self._api_key_to_tenant: dict[str, str] = {}

    def create_tenant(self, tenant_id: str, name: str, api_keys: list[str], allowed_assets: list[str]) -> Tenant:
        tenant = Tenant(
            tenant_id=tenant_id,
            name=name,
            api_keys=api_keys,
            allowed_assets=allowed_assets,
        )
        self._tenants[tenant_id] = tenant
        for k in api_keys:
            self._api_key_to_tenant[k] = tenant_id
        return tenant

    def get_tenant_by_api_key(self, api_key: str) -> Tenant | None:
        tid = self._api_key_to_tenant.get(api_key)
        return self._tenants.get(tid) if tid else None

    def record_scan_usage(self, tenant_id: str, storage_bytes: int = 0) -> None:
        tenant = self._tenants.get(tenant_id)
        if tenant:
            tenant.usage.scans_this_month += 1
            tenant.usage.storage_bytes_used += storage_bytes
            tenant.usage.last_scan_at = datetime.now(UTC)


tenant_manager = TenantManager()
