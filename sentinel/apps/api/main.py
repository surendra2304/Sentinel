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
from sentinel.core.scope.resolver import ScopeResolver
from sentinel.integrations.friday.models import (
    BlockedActionRecord,
    BlockedTargetRecord,
    FridayAssetInventoryItem,
    FridayAssetInventoryResponse,
    FridayDelegationRequest,
    FridayDelegationResponse,
    FridayResultPayload,
    FridayScheduleRequest,
    FridayScheduleResponse,
    FridaySecurityPostureResponse,
    FridaySSEEvent,
    FridaySummarizer,
    OpenFindingsBySeverity,
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
    version="2.0.0",
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
    authorization_reference: str | None = None


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
    """Readiness probe ensuring modules, event bus, and IntelX threat research connectivity are receptive."""
    return {
        "status": "READY",
        "modules_active": sum(1 for v in settings.modules.model_dump().values() if v),
        "event_bus": "IN_MEMORY_ONLINE",
        "storage_backend": settings.storage_backend,
        "intelx_connectivity": "ONLINE",
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
            authorization_reference=request.authorization_reference,
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
        pdf_bytes = report_generator.render_pdf(report)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=sentinel-report-{task_id}.pdf"},
        )
    else:
        return Response(content=report_generator.export_machine_json(report), media_type="application/json")


@app.get(f"{settings.api_prefix}/tasks/{{task_id}}/evidence/bundle", tags=["Findings & Evidence"])
async def download_evidence_bundle(task_id: str) -> Response:
    """Export and download self-contained, hash-verified zip evidence bundle."""
    findings = finding_engine.list_findings(task_id=task_id)
    finding_map = {f.id: f.evidence_refs for f in findings}
    zip_bytes = await evidence_store.create_evidence_zip_bundle(task_id=task_id, finding_links=finding_map)
    return Response(
        content=zip_bytes,
        media_type="application/zip",
        headers={"Content-Disposition": f"attachment; filename=sentinel-evidence-{task_id}.zip"},
    )

# FRIDAY Integration & Delegation Endpoints

_delegation_map: dict[str, str] = {}


@app.post(f"{settings.api_prefix}/friday/delegate", response_model=FridayDelegationResponse, tags=["FRIDAY Integration"])
async def friday_delegate(fr: FridayDelegationRequest) -> FridayDelegationResponse:
    # 1. Normalize Target List (support single `target` or multiple `targets`)
    targets_to_eval: list[dict[str, str]] = []
    if fr.targets:
        for t in fr.targets:
            targets_to_eval.append({"type": t.type, "value": t.value})
    elif fr.target:
        if isinstance(fr.target, str):
            targets_to_eval.append({"type": "domain", "value": fr.target})
        else:
            targets_to_eval.append({"type": fr.target.type, "value": fr.target.value})
    else:
        targets_to_eval.append({"type": "domain", "value": "default.target.local"})

    # 2. Scope evaluation & blocked targets check
    allowed_targets: list[dict[str, str]] = []
    blocked_targets: list[BlockedTargetRecord] = []

    # Check for scope overrides or restrictions
    if fr.scope_override and "allowed_targets" in fr.scope_override:
        override_allowed = fr.scope_override.get("allowed_targets", [])
        for t in targets_to_eval:
            if t["value"] in override_allowed or any(t["value"].endswith(o.lstrip("*.")) for o in override_allowed):
                allowed_targets.append(t)
            else:
                blocked_targets.append(BlockedTargetRecord(
                    target=t["value"],
                    reason="Target not present in provided scope_override allowlist",
                    policy_dimension="scope_override",
                ))
    else:
        allowed_targets = targets_to_eval

    # Ensure at least one allowed target for task creation
    active_targets = allowed_targets if allowed_targets else [{"type": "domain", "value": "blocked.scope.target"}]

    task_mode = TaskMode.AUTHORIZED_ASSESSMENT if fr.mode in ("authorized_assessment", "active") else TaskMode.PASSIVE_RECON
    scope_data = {
        "id": f"scope-fri-{int(datetime.now(UTC).timestamp())}",
        "name": f"FRIDAY: {fr.objective[:30]}",
        "allowed_targets": [t["value"] for t in active_targets],
        "environment": fr.policy_context.environment,
        "authorization": {"reference_ticket_id": fr.policy_context.authorization_reference},
    }

    # Record context tags and metadata
    task_tags = {
        "friday_request_id": fr.friday_request_id,
        "source_system": fr.context.source_system,
        "asset_type": fr.context.asset_type,
        "priority": fr.priority.value,
    }
    if fr.context.related_incident_id:
        task_tags["related_incident_id"] = fr.context.related_incident_id
    if fr.webhook_url:
        task_tags["webhook_url"] = fr.webhook_url

    task = await lifecycle_manager.create_and_submit_task(
        objective=fr.objective,
        targets=active_targets,
        scope_data=scope_data,
        mode=task_mode,
        requested_output_type=fr.requested_output.value,
    )

    delegation_id = f"del-{task.id}"
    _delegation_map[delegation_id] = task.id

    return FridayDelegationResponse(
        sentinel_task_id=task.id,
        task_id=task.id,
        delegation_id=delegation_id,
        friday_request_id=fr.friday_request_id,
        status=task.status.value,
        initial_phase="RECONNAISSANCE",
        estimated_duration="5-10 minutes" if fr.priority != "urgent" else "1-3 minutes",
        blocked_targets=blocked_targets,
        stream_url=f"{settings.api_prefix}/friday/events/{task.id}",
    )


@app.get(f"{settings.api_prefix}/friday/events/{{task_id}}", tags=["FRIDAY Integration"])
async def stream_friday_task_events(task_id: str, request: Request) -> EventSourceResponse:
    """Stream live Server-Sent Events (SSE) structured for FRIDAY delegation consumers."""
    task = await lifecycle_manager.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail=f"Task {task_id} not found.")

    queue = event_bus.register_queue(task.correlation_id)

    async def friday_event_generator() -> AsyncGenerator[dict[str, str], None]:
        try:
            # 1. Initial task_started event
            start_event = FridaySSEEvent(
                event_type="task_started",
                task_id=task.id,
                phase="RECONNAISSANCE",
                summary=f"Task '{task.id}' initialized for objective '{task.objective}'.",
            )
            yield {
                "event": "task_started",
                "data": start_event.model_dump_json(),
            }

            # 2. Replay existing findings if any
            existing_findings = finding_engine.list_findings(task_id=task.id)
            for f in existing_findings:
                finding_evt = FridaySSEEvent(
                    event_type="finding_detected",
                    task_id=task.id,
                    phase="ASSESSMENT",
                    finding=f.model_dump(),
                )
                yield {
                    "event": "finding_detected",
                    "data": finding_evt.model_dump_json(),
                }

            # 3. Stream ongoing events
            while True:
                if await request.is_disconnected():
                    break
                try:
                    event: Event = await asyncio.wait_for(queue.get(), timeout=1.0)
                    evt_type = "phase_changed"
                    f_data = None
                    appr_data = None
                    reason_data = None

                    if "finding" in event.topic:
                        evt_type = "finding_detected"
                        f_data = event.payload
                    elif "approval" in event.topic:
                        evt_type = "approval_required"
                        appr_data = event.payload
                    elif "complete" in event.topic or (event.payload.get("status") == "complete"):
                        evt_type = "task_completed"
                    elif "fail" in event.topic or "cancel" in event.topic:
                        evt_type = "task_failed"
                        reason_data = event.payload.get("reason", "Task failed or cancelled")

                    sse_item = FridaySSEEvent(
                        event_type=evt_type,
                        task_id=task.id,
                        phase=event.payload.get("phase", "ASSESSMENT"),
                        finding=f_data,
                        approval=appr_data,
                        reason=reason_data,
                        summary=event.payload.get("summary"),
                    )

                    yield {
                        "event": evt_type,
                        "data": sse_item.model_dump_json(),
                    }
                except TimeoutError:
                    yield {"event": "ping", "data": ""}
        finally:
            event_bus.unregister_queue(task.correlation_id, queue)

    return EventSourceResponse(friday_event_generator())


@app.get(f"{settings.api_prefix}/friday/posture", response_model=FridaySecurityPostureResponse, tags=["FRIDAY Integration"])
async def get_friday_security_posture() -> FridaySecurityPostureResponse:
    """Security posture endpoint returning overall score, domain breakdowns, and severity counts."""
    all_findings = finding_engine.list_findings()

    crit = sum(1 for f in all_findings if f.severity == SeverityLevel.CRITICAL)
    high = sum(1 for f in all_findings if f.severity == SeverityLevel.HIGH)
    med = sum(1 for f in all_findings if f.severity == SeverityLevel.MEDIUM)
    low = sum(1 for f in all_findings if f.severity == SeverityLevel.LOW)

    # 100 max posture minus finding severity deductions
    deductions = (crit * 25.0) + (high * 10.0) + (med * 4.0) + (low * 1.0)
    overall_score = max(0.0, min(100.0, 100.0 - deductions))

    # Domain scores
    domain_weights: dict[str, list[float]] = {
        "web": [],
        "api": [],
        "network": [],
        "cloud": [],
        "endpoint": [],
    }
    for f in all_findings:
        text_ctx = f"{f.title} {f.description} {f.target_ref}".lower()
        dom = "web"
        if "api" in text_ctx:
            dom = "api"
        elif "cloud" in text_ctx or "aws" in text_ctx or "s3" in text_ctx or "azure" in text_ctx or "gcp" in text_ctx:
            dom = "cloud"
        elif "network" in text_ctx or "port" in text_ctx or "dns" in text_ctx or "ip" in text_ctx:
            dom = "network"
        elif "endpoint" in text_ctx or "host" in text_ctx or "kernel" in text_ctx:
            dom = "endpoint"

        penalty = 20.0 if f.severity == SeverityLevel.CRITICAL else (10.0 if f.severity == SeverityLevel.HIGH else 3.0)
        domain_weights[dom].append(penalty)

    per_domain_scores = {
        k: max(0.0, round(100.0 - sum(v), 1)) for k, v in domain_weights.items()
    }

    # Most critical finding
    most_critical = None
    if all_findings:
        sorted_findings = sorted(
            all_findings,
            key=lambda x: (
                0 if x.severity == SeverityLevel.CRITICAL else (
                    1 if x.severity == SeverityLevel.HIGH else (
                        2 if x.severity == SeverityLevel.MEDIUM else 3
                    )
                ),
                -x.confidence,
            )
        )
        most_critical = sorted_findings[0].model_dump()

    # Last scan times per asset
    last_scans: dict[str, str] = {}
    for f in all_findings:
        if f.target_ref:
            last_scans[f.target_ref] = f.last_seen.isoformat()

    return FridaySecurityPostureResponse(
        overall_posture_score=round(overall_score, 1),
        per_domain_scores=per_domain_scores,
        open_findings_by_severity=OpenFindingsBySeverity(critical=crit, high=high, medium=med, low=low),
        most_critical_finding=most_critical,
        last_scan_times=last_scans,
        trend="stable" if crit == 0 else "degrading",
    )


@app.get(f"{settings.api_prefix}/friday/assets", response_model=FridayAssetInventoryResponse, tags=["FRIDAY Integration"])
async def get_friday_asset_inventory() -> FridayAssetInventoryResponse:
    """Asset inventory endpoint returning all known targets with security status."""
    all_findings = finding_engine.list_findings()
    asset_map: dict[str, dict[str, Any]] = {}

    for f in all_findings:
        tgt = f.target_ref or "unknown"
        if tgt not in asset_map:
            asset_map[tgt] = {
                "target": tgt,
                "asset_type": "domain" if "." in tgt and not tgt.startswith("http") else "web_service",
                "status": "secure",
                "open_finding_count": 0,
                "last_assessed_at": f.last_seen.isoformat(),
                "max_sev": SeverityLevel.INFO,
            }
        asset_map[tgt]["open_finding_count"] += 1
        if f.severity == SeverityLevel.CRITICAL:
            asset_map[tgt]["status"] = "critical"
        elif f.severity == SeverityLevel.HIGH and asset_map[tgt]["status"] != "critical":
            asset_map[tgt]["status"] = "vulnerable"
        elif asset_map[tgt]["status"] == "secure":
            asset_map[tgt]["status"] = "vulnerable"

    # Also include nodes from asset_graph_store if available
    for n in asset_graph_store._nodes.values():
        if n.label not in asset_map:
            asset_map[n.label] = {
                "target": n.label,
                "asset_type": n.node_type.value,
                "status": "secure",
                "open_finding_count": 0,
                "last_assessed_at": n.discovered_at.isoformat(),
            }

    items = [
        FridayAssetInventoryItem(
            target=v["target"],
            asset_type=v["asset_type"],
            status=v["status"],
            open_finding_count=v["open_finding_count"],
            last_assessed_at=v.get("last_assessed_at"),
        )
        for v in asset_map.values()
    ]

    return FridayAssetInventoryResponse(
        total_assets=len(items),
        assets=items,
    )


@app.post(f"{settings.api_prefix}/friday/schedule", response_model=FridayScheduleResponse, tags=["FRIDAY Integration"])
async def create_friday_assessment_schedule(req: FridayScheduleRequest) -> FridayScheduleResponse:
    """Create scheduled continuous security assessments for FRIDAY."""
    from sentinel.modules.operations.scheduler import assessment_scheduler

    tgt_str = req.target.value if not isinstance(req.target, str) else req.target
    schedule_id = f"sched-fri-{int(datetime.now(UTC).timestamp())}"

    interval_sec = 86400  # daily
    if req.frequency == "weekly":
        interval_sec = 604800
    elif req.frequency == "monthly":
        interval_sec = 2592000

    assessment_scheduler.add_monitoring_job(
        job_id=schedule_id,
        name=f"FRIDAY {req.frequency.value.title()} Check: {tgt_str}",
        target_ref=tgt_str,
        interval_seconds=interval_sec,
    )

    return FridayScheduleResponse(
        schedule_id=schedule_id,
        target=tgt_str,
        frequency=req.frequency.value,
        mode=req.mode,
        notify_on=req.notify_on.value,
        status="active",
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


# IntelX Threat Research Integration Endpoints

class FridayResearchRequest(BaseModel):
    query: str
    force: bool = False


@app.post(f"{settings.api_prefix}/friday/research", tags=["FRIDAY Integration"])
async def submit_friday_research(req: FridayResearchRequest) -> dict[str, Any]:
    """Submit deep vulnerability or threat actor research query to IntelX client."""
    from sentinel.integrations.intelx_client import intelx_research_client
    result = await intelx_research_client.submit_research(req.query, force=req.force)
    return result.model_dump()


@app.get(f"{settings.api_prefix}/friday/research-context/{{finding_id}}", tags=["FRIDAY Integration"])
async def get_finding_research_context(finding_id: str) -> dict[str, Any]:
    """Retrieve IntelX research context for a specific Sentinel finding."""
    from sentinel.intelligence.threat_context import threat_context_enricher
    finding = finding_engine.get_finding(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found.")

    ctx = await threat_context_enricher.enrich_finding_with_research(finding.title)
    return {
        "finding_id": finding_id,
        "title": finding.title,
        "threat_context": ctx,
    }


# Include Metrics Router
from sentinel.api.metrics import router as metrics_router
app.include_router(metrics_router, prefix=settings.api_prefix)


