"""Sentinel Task Gateway & REST API Service."""

import asyncio
import json
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sse_starlette.sse import EventSourceResponse

from sentinel.apps.api.middleware import APIKeyAuthMiddleware
from sentinel.audit.audit_logger import AuditLogger
from sentinel.config.settings import get_settings
from sentinel.core.events.bus import event_bus
from sentinel.core.models import (
    Event,
    Task,
    TaskMode,
)
from sentinel.core.orchestrator.lifecycle import lifecycle_manager
from sentinel.logging.logger import get_correlation_id, get_logger, setup_logging

settings = get_settings()
setup_logging(settings.log_level.value)
logger = get_logger("sentinel.api")
audit_logger = AuditLogger(log_path=settings.audit.log_file_path, signing_key=settings.audit.signing_key)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: recover non-terminal tasks from unexpected restarts
    recovered = await lifecycle_manager.recover_tasks_on_startup()
    if recovered > 0:
        logger.warning("Recovered pending tasks during startup", extra={"recovered_count": recovered})
    yield
    # Shutdown logic if needed


app = FastAPI(
    title="SENTINEL — Unified Autonomous Cybersecurity Platform",
    description="Single Task Gateway API for autonomous security operations, telemetry, and event streaming.",
    version="1.0.0",
    docs_url=f"{settings.api_prefix}/docs",
    openapi_url=f"{settings.api_prefix}/openapi.json",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(APIKeyAuthMiddleware)


# ---------------------------------------------------------------------------
# Request & Response Schemas
# ---------------------------------------------------------------------------

class TargetInput(BaseModel):
    id: str | None = None
    type: str = "domain"
    value: str
    resolved_ips: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class SubmitTaskRequest(BaseModel):
    objective: str
    targets: list[TargetInput]
    scope: dict[str, Any] | None = None
    policy: dict[str, Any] | None = None
    mode: TaskMode = TaskMode.ASSESSMENT
    requested_output: str = "comprehensive_report"


class TaskResponse(BaseModel):
    task_id: str
    objective: str
    mode: str
    status: str
    progress_percentage: float
    correlation_id: str
    created_at: str
    target_count: int


class CancelTaskResponse(BaseModel):
    task_id: str
    status: str
    message: str


# ---------------------------------------------------------------------------
# Health & Readiness Endpoints
# ---------------------------------------------------------------------------

@app.get("/health", tags=["System"])
async def health_check() -> dict[str, Any]:
    """Liveness probe reporting system status and tamper-evident audit integrity."""
    return {
        "status": "HEALTHY",
        "service": "SENTINEL",
        "version": "1.0.0",
        "environment": settings.environment.value,
        "kill_switch_active": settings.kill_switch_active,
        "audit_chain_valid": audit_logger.verify_integrity(),
    }


@app.get("/ready", tags=["System"])
async def readiness_check() -> dict[str, Any]:
    """Readiness probe ensuring modules and event bus are receptive."""
    return {
        "status": "READY",
        "modules_active": sum(1 for v in settings.modules.model_dump().values() if v),
        "event_bus": "IN_MEMORY_ONLINE",
    }


# ---------------------------------------------------------------------------
# Task Gateway Endpoints
# ---------------------------------------------------------------------------

@app.post(f"{settings.api_prefix}/tasks", response_model=TaskResponse, status_code=201, tags=["Task Gateway"])
async def submit_task(request: SubmitTaskRequest) -> TaskResponse:
    """Submit a security task into the Sentinel execution engine."""
    cid = get_correlation_id()
    raw_targets = [t.model_dump() for t in request.targets]

    try:
        task = await lifecycle_manager.create_and_submit_task(
            objective=request.objective,
            targets=raw_targets,
            scope_data=request.scope,
            policy_data=request.policy,
            mode=request.mode,
            requested_output_type=request.requested_output,
            correlation_id=cid,
        )
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e

    return TaskResponse(
        task_id=task.id,
        objective=task.objective,
        mode=task.mode.value,
        status=task.status.value,
        progress_percentage=task.progress_percentage,
        correlation_id=task.correlation_id,
        created_at=task.created_at.isoformat(),
        target_count=len(task.target_set.targets),
    )


@app.get(f"{settings.api_prefix}/tasks", response_model=list[TaskResponse], tags=["Task Gateway"])
async def list_tasks() -> list[TaskResponse]:
    """List all registered tasks and their live statuses."""
    tasks = await lifecycle_manager.list_tasks()
    return [
        TaskResponse(
            task_id=t.id,
            objective=t.objective,
            mode=t.mode.value,
            status=t.status.value,
            progress_percentage=t.progress_percentage,
            correlation_id=t.correlation_id,
            created_at=t.created_at.isoformat(),
            target_count=len(t.target_set.targets),
        )
        for t in tasks
    ]


@app.get(f"{settings.api_prefix}/tasks/{{task_id}}", response_model=Task, tags=["Task Gateway"])
async def get_task(task_id: str) -> Task:
    """Retrieve full task model by ID."""
    task = await lifecycle_manager.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail=f"Task {task_id} not found.")
    return task


@app.post(f"{settings.api_prefix}/tasks/{{task_id}}/cancel", response_model=CancelTaskResponse, tags=["Task Gateway"])
async def cancel_task(task_id: str, reason: str = Query("Operator Kill Switch")) -> CancelTaskResponse:
    """Kill-switch: Immediately halt execution of a specific task."""
    try:
        task = await lifecycle_manager.cancel_task(task_id, reason=reason)
    except KeyError as err:
        raise HTTPException(status_code=404, detail=f"Task {task_id} not found.") from err

    return CancelTaskResponse(
        task_id=task.id,
        status=task.status.value,
        message=f"Task {task_id} execution halted successfully.",
    )


@app.get(f"{settings.api_prefix}/tasks/{{task_id}}/events", tags=["Telemetry & Events"])
async def stream_task_events(task_id: str, request: Request) -> EventSourceResponse:
    """Stream live Server-Sent Events (SSE) for task state changes, findings, and logs."""
    task = await lifecycle_manager.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail=f"Task {task_id} not found.")

    queue = event_bus.register_queue(task.correlation_id)

    async def event_generator() -> AsyncGenerator[dict[str, str], None]:
        try:
            # Yield initial status
            yield {
                "event": "connected",
                "data": json.dumps({"task_id": task.id, "status": task.status.value}),
            }

            while True:
                if await request.is_disconnected():
                    break
                try:
                    event: Event = await asyncio.wait_for(queue.get(), timeout=1.0)
                    yield {
                        "event": event.topic,
                        "data": event.model_dump_json(),
                    }
                except TimeoutError:
                    # Keep-alive ping
                    yield {"event": "ping", "data": ""}
        finally:
            event_bus.unregister_queue(task.correlation_id, queue)

    return EventSourceResponse(event_generator())


@app.get(f"{settings.api_prefix}/tasks/{{task_id}}/findings", tags=["Findings & Evidence"])
async def get_task_findings(task_id: str) -> dict[str, Any]:
    """Retrieve security findings associated with a task."""
    task = await lifecycle_manager.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail=f"Task {task_id} not found.")
    return {
        "task_id": task_id,
        "findings": [],
        "count": 0,
    }


@app.get(f"{settings.api_prefix}/tasks/{{task_id}}/evidence", tags=["Findings & Evidence"])
async def get_task_evidence(task_id: str) -> dict[str, Any]:
    """Retrieve raw cryptographic evidence artifacts associated with a task."""
    task = await lifecycle_manager.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail=f"Task {task_id} not found.")
    return {
        "task_id": task_id,
        "evidence": [],
        "count": 0,
    }


@app.get(f"{settings.api_prefix}/tasks/{{task_id}}/report", tags=["Reporting"])
async def get_task_report(task_id: str) -> dict[str, Any]:
    """Retrieve synthesized security assessment report for a task."""
    task = await lifecycle_manager.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail=f"Task {task_id} not found.")
    return {
        "task_id": task_id,
        "title": f"Security Assessment Report: {task.objective}",
        "status": task.status.value,
        "executive_summary": "Initial baseline assessment initialized.",
        "findings_summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
    }
