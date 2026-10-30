"""Authoritative Target Scope Specification for the FRIDAY Universe.

Conforming to Safety Invariant 3 (Authorized Scope Enforcement).
Authorized By: Surendra (System Architect)
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from sentinel.core.models import (
    AuthorizationMetadata,
    AuthorizationType,
    EnvironmentLabel,
    ImpactLevel,
    Scope,
    TimeWindow,
)

logger = logging.getLogger("sentinel.scope.authoritative")

FRIDAY_UNIVERSE_ALLOWED_TARGETS: list[str] = [
    # A. Public Perimeter & Ingress
    "friday-universe.duckdns.org",
    "140.245.208.100",
    "140.245.208.100/32",
    "https://friday-universe.duckdns.org",
    "http://friday-universe.duckdns.org",
    "https://friday-universe.duckdns.org:443",
    "http://friday-universe.duckdns.org:80",

    # B. Internal Docker Container Mesh (friday_mesh / 172.16.0.0/12)
    "http://friday:10000",
    "http://inference:8000",
    "http://memora:8000",
    "http://stratex:8000",
    "http://forge:8000",
    "http://cortex:8000",
    "http://sentinel:8000",
    "http://intelx:8000",
    "http://futuris:8000",
    "http://vyralx:8000",
    "dokploy-postgres:5432",
    "172.16.0.0/12",
    "friday",
    "inference",
    "memora",
    "stratex",
    "forge",
    "cortex",
    "sentinel",
    "intelx",
    "futuris",
    "vyralx",
    "dokploy-postgres",

    # C. Local Development Workstation
    "127.0.0.1",
    "127.0.0.1/32",
    "localhost",
    "::1",
    "192.168.0.0/16",
    "10.0.0.0/8",

    # D. Authorized GitHub Codebase Repositories (owner: surendra2304)
    "surendra2304/FRIDAY",
    "surendra2304/Inference",
    "surendra2304/Memora",
    "surendra2304/Stratex",
    "surendra2304/Forge",
    "surendra2304/Cortex",
    "surendra2304/Sentinel",
    "surendra2304/IntelX",
    "surendra2304/Futuris",
    "surendra2304/VyralX",
    "surendra2304/*",
    "https://github.com/surendra2304/*",
]

FRIDAY_UNIVERSE_OUT_OF_SCOPE_DECLARATIONS: list[str] = [
    # External third-party cloud & model APIs strictly prohibited from intrusive scan
    "generativelanguage.googleapis.com",
    "api.groq.com",
    "openrouter.ai",
    "api.binance.com",
    "www.googleapis.com/youtube",
    "api.pexels.com",
]


def create_sovereign_production_scope() -> Scope:
    """Create the canonical FRIDAY Universe Sovereign Infrastructure Scope."""
    now = datetime.now(UTC)
    expiry = now + timedelta(days=3650)  # 10-year sovereign operational scope

    return Scope(
        id="scope_friday_universe_production",
        name="FRIDAY Universe Sovereign Infrastructure & Codebase",
        environment=EnvironmentLabel.PRODUCTION,
        authorization=AuthorizationMetadata(
            authorization_type=AuthorizationType.OWNED,
            reference_ticket_id="ARCHITECT-AUTH-FRIDAY-2026",
            authorized_by="Surendra (System Architect)",
            expiry=expiry,
        ),
        allowed_targets=list(FRIDAY_UNIVERSE_ALLOWED_TARGETS),
        targets=list(FRIDAY_UNIVERSE_ALLOWED_TARGETS),
        in_scope_declarations=list(FRIDAY_UNIVERSE_ALLOWED_TARGETS),
        out_of_scope_declarations=list(FRIDAY_UNIVERSE_OUT_OF_SCOPE_DECLARATIONS),
        excluded_targets=list(FRIDAY_UNIVERSE_OUT_OF_SCOPE_DECLARATIONS),
        max_intensity=5,
        offensive_actions_enabled=False,
        owner="Surendra (System Architect)",
        written_authorization_reference="ARCHITECT-AUTH-FRIDAY-2026",
        allowed_methods=[
            "audit",
            "static_analysis",
            "tls_drift",
            "posture_validation",
            "secret_scan",
            "cve_scan",
            "config_audit",
            "passive_recon",
            "dns_monitor",
        ],
        time_window=TimeWindow(
            start_time=now - timedelta(days=1),
            end_time=expiry,
        ),
        rate_limit=50,
        maximum_impact=ImpactLevel.LOW,
    )


SOVEREIGN_PRODUCTION_SCOPE = create_sovereign_production_scope()


async def seed_sovereign_scope_into_database() -> bool:
    """Persist or upsert the sovereign scope into sentinel_scopes table in sentinel_db."""
    from sentinel.config.settings import get_settings

    settings = get_settings()
    if not settings.uses_database_backend:
        logger.info(
            "Storage backend '%s' is process-local; sovereign scope registered in memory.",
            settings.storage_backend_normalized,
        )
        return True

    try:
        from sentinel.storage.database.models import ScopeModel
        from sentinel.storage.database.session import get_db_session

        scope = SOVEREIGN_PRODUCTION_SCOPE
        async with get_db_session() as session:
            existing: Any = await session.get(ScopeModel, scope.id)
            if existing:
                existing.name = scope.name
                existing.allowed_targets = scope.allowed_targets
                existing.in_scope_declarations = scope.in_scope_declarations
                existing.out_of_scope_declarations = scope.out_of_scope_declarations
                existing.environment = scope.environment.value
                existing.authorization_type = scope.authorization.authorization_type.value
                existing.authorized_by = scope.authorization.authorized_by
                existing.reference_ticket_id = scope.authorization.reference_ticket_id
                existing.expiry = scope.authorization.expiry
                existing.max_intensity = float(scope.max_intensity)
                existing.offensive_actions_enabled = scope.offensive_actions_enabled
                existing.scope_contract = scope.model_dump(mode="json")
                logger.info(f"Updated sovereign scope '{scope.id}' in sentinel_scopes table.")
            else:
                model = ScopeModel(
                    id=scope.id,
                    name=scope.name,
                    allowed_targets=scope.allowed_targets,
                    in_scope_declarations=scope.in_scope_declarations,
                    out_of_scope_declarations=scope.out_of_scope_declarations,
                    environment=scope.environment.value,
                    authorization_type=scope.authorization.authorization_type.value,
                    reference_ticket_id=scope.authorization.reference_ticket_id,
                    authorized_by=scope.authorization.authorized_by,
                    expiry=scope.authorization.expiry,
                    max_intensity=float(scope.max_intensity),
                    offensive_actions_enabled=scope.offensive_actions_enabled,
                    scope_contract=scope.model_dump(mode="json"),
                )
                session.add(model)
                logger.info(f"Inserted sovereign scope '{scope.id}' into sentinel_scopes table.")
            await session.commit()
            return True
    except Exception as exc:
        logger.warning(f"Could not persist sovereign scope into database: {exc}")
        return False
