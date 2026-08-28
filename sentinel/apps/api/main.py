"""Sentinel Task Gateway & REST API Service."""

import asyncio
import json
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, PlainTextResponse, Response
from pydantic import BaseModel, Field
from sse_starlette.sse import EventSourceResponse

from sentinel.apps.api.middleware import APIKeyAuthMiddleware
from sentinel.audit.audit_logger import AuditLogger
from sentinel.config.settings import get_settings
from sentinel.core.events.bus import event_bus
from sentinel.core.models import (
    Event,
    Finding,
    FindingStatus,
    SeverityLevel,
    Task,
    TaskMode,
)
from sentinel.core.orchestrator.lifecycle import lifecycle_manager
from sentinel.core.policy.engine import ApprovalRecord, policy_engine
from sentinel.integrations.friday.models import (
    BlockedActionRecord,
    FridayDelegationRequest,
    FridayDelegationResponse,
    FridayResultPayload,
    FridaySummarizer,
)
from sentinel.intelligence.attack_paths.analyzer import attack_path_analyzer
from sentinel.intelligence.recommendations.engine import recommendation_engine
from sentinel.intelligence.reporting.generator import ReportType, report_generator
from sentinel.intelligence.risk.finding_engine import finding_engine
from sentinel.intelligence.risk.risk_engine import TaskRiskSummary, risk_engine
from sentinel.logging.logger import get_correlation_id, get_logger, setup_logging
from sentinel.modules.recon.graph import AttackSurfaceReport, asset_graph_store
from sentinel.storage.evidence.store import evidence_store

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


class DecideApprovalRequest(BaseModel):
    approve: bool
    operator: str
    justification: str


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
async def cancel_task(task_id: str, reason: str = Query("Operator Kill Switch")) -> CancelTaskResponse:  # noqa: B008
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


# ---------------------------------------------------------------------------
# Scope & Policy Approvals Endpoints
# ---------------------------------------------------------------------------

@app.get(f"{settings.api_prefix}/approvals", response_model=list[ApprovalRecord], tags=["Policy & Approvals"])
async def list_pending_approvals(task_id: str | None = Query(None)) -> list[ApprovalRecord]:  # noqa: B008
    """List pending operator approval requests."""
    return policy_engine.get_pending_approvals(task_id=task_id)


@app.post(f"{settings.api_prefix}/approvals/{{approval_id}}/decide", response_model=ApprovalRecord, tags=["Policy & Approvals"])
async def decide_approval(approval_id: str, request: DecideApprovalRequest) -> ApprovalRecord:
    """Approve or deny an action requiring operator authorization."""
    try:
        record = await policy_engine.decide_approval(
            approval_id=approval_id,
            approve=request.approve,
            operator=request.operator,
            justification=request.justification,
        )
        return record
    except KeyError as err:
        raise HTTPException(status_code=404, detail=str(err)) from err
    except ValueError as err:
        raise HTTPException(status_code=400, detail=str(err)) from err


# ---------------------------------------------------------------------------
# Findings & Risk Intelligence Endpoints
# ---------------------------------------------------------------------------

@app.get(f"{settings.api_prefix}/findings", response_model=list[Finding], tags=["Findings & Evidence"])
async def list_findings(
    task_id: str | None = Query(None),  # noqa: B008
    severity: SeverityLevel | None = Query(None),  # noqa: B008
    status: FindingStatus | None = Query(None),  # noqa: B008
) -> list[Finding]:
    """List and filter security findings."""
    return finding_engine.list_findings(task_id=task_id, severity=severity, status=status)


@app.get(f"{settings.api_prefix}/findings/{{finding_id}}", response_model=Finding, tags=["Findings & Evidence"])
async def get_finding_detail(finding_id: str) -> Finding:
    """Get finding details including evidence references."""
    finding = finding_engine.get_finding(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found.")
    return finding


@app.get(f"{settings.api_prefix}/tasks/{{task_id}}/risk-summary", response_model=TaskRiskSummary, tags=["Risk Intelligence"])
async def get_task_risk_summary(task_id: str) -> TaskRiskSummary:
    """Retrieve computed risk summary and breakdown for a task."""
    findings = finding_engine.list_findings(task_id=task_id)
    return risk_engine.get_task_risk_summary(task_id, findings)


@app.get(f"{settings.api_prefix}/tasks/{{task_id}}/attack-surface", response_model=AttackSurfaceReport, tags=["Reconnaissance & Attack Surface"])
async def get_task_attack_surface(task_id: str) -> AttackSurfaceReport:
    """Retrieve full attack surface graph, asset inventory, and exposure map."""
    return asset_graph_store.get_task_attack_surface(task_id)


@app.get(f"{settings.api_prefix}/tasks/{{task_id}}/evidence-bundle", tags=["Findings & Evidence"])
async def export_evidence_bundle(task_id: str) -> dict[str, Any]:
    """Export self-contained, hash-verified evidence bundle."""
    return await evidence_store.export_evidence_bundle(task_id=task_id)


# ---------------------------------------------------------------------------
# Telemetry & Telemetry Streaming Endpoints
# ---------------------------------------------------------------------------

@app.get(f"{settings.api_prefix}/tasks/{{task_id}}/events", tags=["Telemetry & Events"])
async def stream_task_events(task_id: str, request: Request) -> EventSourceResponse:
    """Stream live Server-Sent Events (SSE) for task state changes, findings, and logs."""
    task = await lifecycle_manager.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail=f"Task {task_id} not found.")

    queue = event_bus.register_queue(task.correlation_id)

    async def event_generator() -> AsyncGenerator[dict[str, str], None]:
        try:
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
                    yield {"event": "ping", "data": ""}
        finally:
            event_bus.unregister_queue(task.correlation_id, queue)

    return EventSourceResponse(event_generator())


@app.get(f"{settings.api_prefix}/tasks/{{task_id}}/findings", tags=["Findings & Evidence"])
async def get_task_findings(task_id: str) -> dict[str, Any]:
    findings = finding_engine.list_findings(task_id=task_id)
    return {
        "task_id": task_id,
        "findings": [f.model_dump() for f in findings],
        "count": len(findings),
    }


@app.get(f"{settings.api_prefix}/tasks/{{task_id}}/evidence", tags=["Findings & Evidence"])
async def get_task_evidence(task_id: str) -> dict[str, Any]:
    evidence_list = evidence_store.query_evidence(task_id=task_id)
    return {
        "task_id": task_id,
        "evidence": [e.model_dump() for e in evidence_list],
        "count": len(evidence_list),
    }


@app.get(f"{settings.api_prefix}/tasks/{{task_id}}/report", tags=["Reporting"])
async def get_task_report(
    task_id: str,
    type: ReportType = Query(ReportType.TECHNICAL, description="Report type: executive, technical, soc_ir, json"),  # noqa: B008
    format: str = Query("json", description="Report format: json, md, html, pdf"),  # noqa: B008
) -> Response:
    """Generate and return on-demand, evidence-anchored security assessment reports."""
    task = await lifecycle_manager.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail=f"Task {task_id} not found.")

    findings = finding_engine.list_findings(task_id=task_id)
    attack_paths = attack_path_analyzer.analyze_paths(asset_graph_store, findings)
    recommendations = recommendation_engine.generate_recommendations(findings, attack_paths)

    report = report_generator.generate_report(
        task=task,
        findings=findings,
        attack_paths=attack_paths,
        recommendations=recommendations,
        report_type=type,
    )

    fmt_lower = format.lower()
    if fmt_lower in ("md", "markdown"):
        content = report_generator.render_markdown(report)
        return PlainTextResponse(content=content, media_type="text/markdown")
    elif fmt_lower == "html":
        content = report_generator.render_html(report)
        return HTMLResponse(content=content)
    elif fmt_lower == "pdf":
        # Return structured HTML as printable document format
        content = report_generator.render_html(report)
        return Response(content=content.encode("utf-8"), media_type="application/pdf", headers={"Content-Disposition": f"inline; filename=sentinel-report-{task_id}.html"})
    else:
        return Response(content=report_generator.export_machine_json(report), media_type="application/json")

# FRIDAY Integration & Delegation Endpoints

_delegation_map: dict[str, str] = {}


@app.post(f"{settings.api_prefix}/friday/delegate", response_model=FridayDelegationResponse, tags=["FRIDAY Integration"])
async def friday_delegate(fr: FridayDelegationRequest) -> FridayDelegationResponse:
    task_mode = TaskMode.AUTHORIZED_ASSESSMENT if fr.mode == "authorized_assessment" else TaskMode.PASSIVE_RECON
    scope_data = {
        "id": f"scope-fri-{int(datetime.now(UTC).timestamp())}",
        "name": f"FRIDAY: {fr.objective[:30]}",
        "allowed_targets": [t.value for t in fr.targets],
        "environment": fr.policy_context.environment,
        "authorization": {"reference_ticket_id": fr.policy_context.authorization_reference},
    }
    task = await lifecycle_manager.create_and_submit_task(
        objective=fr.objective,
        targets=[{"type": t.type, "value": t.value} for t in fr.targets],
        scope_data=scope_data,
        mode=task_mode,
        requested_output_type=fr.requested_output.value,
    )
    delegation_id = f"del-{task.id}"
    _delegation_map[delegation_id] = task.id
    return FridayDelegationResponse(
        delegation_id=delegation_id,
        task_id=task.id,
        status=task.status.value,
        stream_url=f"{settings.api_prefix}/tasks/{task.id}/events",
    )


@app.get(f"{settings.api_prefix}/friday/delegations/{{delegation_id}}", response_model=FridayResultPayload, tags=["FRIDAY Integration"])
async def get_friday_delegation_result(delegation_id: str) -> FridayResultPayload:
    task_id = _delegation_map.get(delegation_id, delegation_id.replace("del-", ""))
    task = await lifecycle_manager.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail=f"Delegation {delegation_id!r} not found.")
    findings = finding_engine.list_findings(task_id=task_id)
    evidence_list = evidence_store.query_evidence(task_id=task_id)
    attack_paths = attack_path_analyzer.analyze_paths(asset_graph_store, findings)
    recommendations = recommendation_engine.generate_recommendations(findings, attack_paths)
    blocked = [
        BlockedActionRecord(
            action_type=a.action_type,
            target=", ".join(a.target_refs),
            reason=f"Blocked by Sentinel policy: {a.justification_provided or 'No authorization'}",
        )
        for a in policy_engine.get_pending_approvals(task_id=task_id) if a.status == "rejected"
    ]
    summary = FridaySummarizer.generate_summary(task, findings, blocked)
    return FridayResultPayload(
        delegation_id=delegation_id, task_id=task.id, task_status=task.status.value,
        progress_percentage=task.progress_percentage,
        findings=[f.model_dump() for f in findings],
        evidence_references=[e.id for e in evidence_list],
        blocked_actions=blocked,
        remediation_recommendations=[r.model_dump() for r in recommendations],
        report_artifacts={"json_report_url": f"{settings.api_prefix}/tasks/{task.id}/report?format=json",
                          "evidence_bundle_url": f"{settings.api_prefix}/tasks/{task.id}/evidence-bundle"},
        human_summary=summary,
    )


@app.post(f"{settings.api_prefix}/friday/delegations/{{delegation_id}}/cancel", tags=["FRIDAY Integration"])
async def cancel_friday_delegation(delegation_id: str, reason: str = Query("FRIDAY Kill Switch")) -> dict[str, Any]:  # noqa: B008
    task_id = _delegation_map.get(delegation_id, delegation_id.replace("del-", ""))
    task = await lifecycle_manager.cancel_task(task_id, reason=reason)
    return {"delegation_id": delegation_id, "task_id": task.id, "status": task.status.value}
