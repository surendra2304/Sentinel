"""Sentinel Task Gateway & API Service."""

from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from sentinel.audit.audit_logger import AuditLogger
from sentinel.config.settings import get_settings
from sentinel.contracts.schemas.core import TaskContract
from sentinel.logging.logger import get_correlation_id, get_logger, setup_logging

settings = get_settings()
setup_logging(settings.log_level.value)
logger = get_logger("sentinel.api")
audit_logger = AuditLogger(log_path=settings.audit.log_file_path, signing_key=settings.audit.signing_key)

app = FastAPI(
    title="SENTINEL — Unified Autonomous Cybersecurity Platform",
    description="API Gateway for Sentinel autonomous security, policy evaluation, and evidence store.",
    version="0.1.0",
    docs_url=f"{settings.api_prefix}/docs",
    openapi_url=f"{settings.api_prefix}/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health", tags=["System"])
async def health_check() -> dict[str, Any]:
    """System health and readiness check."""
    return {
        "status": "HEALTHY",
        "service": "SENTINEL",
        "version": "0.1.0",
        "environment": settings.environment.value,
        "kill_switch_active": settings.kill_switch_active,
        "audit_chain_valid": audit_logger.verify_integrity(),
    }


@app.get(f"{settings.api_prefix}/config", tags=["Configuration"])
async def get_platform_config() -> dict[str, Any]:
    """Return active platform configuration and enabled modules."""
    return {
        "app_name": settings.app_name,
        "environment": settings.environment.value,
        "enabled_modules": settings.modules.model_dump(),
        "kill_switch": settings.kill_switch_active,
        "human_approval_required": settings.require_human_approval_for_offensive,
    }


@app.post(f"{settings.api_prefix}/tasks", tags=["Task Gateway"])
async def submit_task(task: TaskContract) -> dict[str, Any]:
    """Submit a security task into the Sentinel execution engine."""
    cid = get_correlation_id()
    logger.info("Task submitted to Sentinel Gateway", extra={"task_id": task.task_id, "correlation_id": cid})

    audit_logger.log_event(
        entry_id=f"audit-task-{task.task_id}",
        event_type="TASK_CREATION",
        actor="operator",
        action_type="TASK_SUBMIT",
        scope_policy=task.scope.scope_id,
        decision="ACCEPTED",
        details={"title": task.title, "allowed_targets": task.scope.allowed_targets}
    )

    return {
        "message": "Task accepted by Sentinel Gateway",
        "task_id": task.task_id,
        "correlation_id": cid,
        "status": "ACCEPTED",
    }
