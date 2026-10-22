"""Container Telemetry & Scope Verification REST API Routes."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from sentinel.core.scope import SOVEREIGN_PRODUCTION_SCOPE, ScopeResolver
from sentinel.monitoring.docker_telemetry import docker_telemetry_collector

telemetry_router = APIRouter(tags=["Telemetry & Mesh Auditing"])
_sovereign_resolver = ScopeResolver(SOVEREIGN_PRODUCTION_SCOPE)


class TargetVerificationRequest(BaseModel):
    target: str = Field(..., min_length=1, description="Domain, IP, URL, or repository slug to check")


@telemetry_router.get("/v1/telemetry/containers")
@telemetry_router.get("/api/v1/telemetry/containers")
async def get_container_telemetry() -> dict[str, Any]:
    """Inspect all containers on friday_mesh via read-only /var/run/docker.sock.

    Enforces:
    1. Non-Root Execution (UID != 0)
    2. Host Port Exposure Verification (0.0.0.0 leaks)
    3. Privilege Escalation Audit (privileged: false, no-new-privileges: true)
    4. Health & OOM Watcher
    """
    report = await docker_telemetry_collector.audit_containers()
    return {"container_audit": report.model_dump()}


@telemetry_router.get("/v1/telemetry/scope")
@telemetry_router.get("/api/v1/telemetry/scope")
async def get_sovereign_scope_declaration() -> dict[str, Any]:
    """Retrieve the authoritative FRIDAY Universe Sovereign Infrastructure Scope declaration."""
    return {"scope": SOVEREIGN_PRODUCTION_SCOPE.model_dump(mode="json")}


@telemetry_router.post("/v1/telemetry/verify-target")
@telemetry_router.post("/api/v1/telemetry/verify-target")
async def verify_target_in_scope(req: TargetVerificationRequest) -> dict[str, Any]:
    """Verify whether a target domain, IP, CIDR, URL, or GitHub repo is within authorized scope."""
    in_scope, verdict, reason = _sovereign_resolver.is_target_in_scope(req.target)
    return {
        "target": req.target,
        "authorized": in_scope,
        "verdict": verdict.value,
        "reason": reason,
    }
