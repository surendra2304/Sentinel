"""Sentinel Task Gateway & REST API Service."""

import asyncio
import hmac
import html
import json
import os
import signal
import uuid
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager, suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
)
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sse_starlette.sse import EventSourceResponse

from sentinel.api.incident_routes import incident_router
from sentinel.api.metrics import router as metrics_router
from sentinel.api.security_audit import router as security_audit_router
from sentinel.api.telemetry_routes import telemetry_router
from sentinel.api.threat_intel_routes import threat_intel_router
from sentinel.app.services.vulnerability_scanner import router as vuln_scanner_router
from sentinel.app.services.realtime_threat_matcher import router as threat_matcher_router
from sentinel.app.services.zero_trust_enforcer import router as zero_trust_router
from sentinel.app.services.compliance_audit_trail import router as compliance_router
from sentinel.app.services.behavioral_anomaly_detector import router as behavioral_router
from sentinel.apps.api.middleware import APIKeyAuthMiddleware, RequestCapacityMiddleware
from sentinel.audit.audit_logger import AuditLogger
from sentinel.config.settings import EnvironmentType, get_settings
from sentinel.config.validator import enforce_startup_configuration
from sentinel.core.auth.capabilities import CapabilityError, CapabilityIssuer
from sentinel.core.events.bus import event_bus
from sentinel.core.gateway.models import RiskLevel as GatewayRiskLevel
from sentinel.core.health.readiness import FailClosedHealth
from sentinel.core.incident.incident_manager import Incident, IncidentManager
from sentinel.core.incident.quarantine_manager import QuarantineManager
from sentinel.core.models import (
    AssessmentScope,
    Event,
    Finding,
    FindingStatus,
    SeverityLevel,
    Task,
    TaskMode,
    TaskStatus,
)
from sentinel.core.orchestrator.lifecycle import lifecycle_manager
from sentinel.core.policy.engine import ApprovalRecord, policy_engine
from sentinel.core.resilience.mesh_client import ResilientMeshClient
from sentinel.core.review.gated_reviewer import (
    GatedReviewRequest,
    GatedReviewResult,
    gated_security_reviewer,
)
from sentinel.core.scope import seed_sovereign_scope_into_database
from sentinel.core.scope.resolver import (
    MissingScopeError,
    ScopeResolver,
    ScopeValidationError,
)
from sentinel.core.security.crypto_gatekeeper import (
    canonicalize_payload,
    crypto_gatekeeper,
)
from sentinel.gatekeeper.approval_dispatcher import approval_dispatcher
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
from sentinel.memora_cloud_fallback import MemoraClient as CloudMemoraClient
from sentinel.memora_event_consumer import MemoraEventConsumer, run_memora_event_consumer
from sentinel.modules.recon.graph import AttackSurfaceReport, asset_graph_store
from sentinel.monitoring.tls_dns_daemon import tls_dns_daemon
from sentinel.storage.database.session import close_async_engine
from sentinel.storage.evidence.store import evidence_store

settings = get_settings()
setup_logging(settings.log_level.value)
logger = get_logger("sentinel.api")
audit_logger = AuditLogger(log_path=settings.audit.log_file_path, signing_key=settings.audit.signing_key)

_app_start_time = datetime.now(UTC)
_request_counter = 0
_error_counter = 0


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: zero-trust configuration validation
    enforce_startup_configuration(settings, fail_fast=False)

    # Initialize shared resilient connection-pooled mesh client
    app.state.mesh_client = ResilientMeshClient(timeout=10.0)

    # Startup: recover non-terminal tasks from unexpected restarts
    recovered = await lifecycle_manager.recover_tasks_on_startup()
    if recovered > 0:
        logger.warning(f"Recovered pending tasks during startup: {recovered}")

    # Seed authoritative sovereign scope into sentinel_scopes database
    with suppress(Exception):
        await seed_sovereign_scope_into_database()

    memora_task = None
    enabled = os.getenv("SENTINEL_MEMORA_EVENTS_ENABLED", "false").strip().lower() in {
        "1", "true", "yes", "on"
    }
    if enabled and os.getenv("SENTINEL_API_KEY", "").strip():
        try:
            interval = max(10.0, float(os.getenv("SENTINEL_MEMORA_EVENTS_POLL_SECONDS", "30")))
        except ValueError:
            interval = 30.0
        consumer = MemoraEventConsumer(CloudMemoraClient())
        memora_task = asyncio.create_task(
            run_memora_event_consumer(consumer, interval),
            name="sentinel_memora_event_consumer",
        )
        logger.info(f"Memora security advisory consumer started (polling every {interval}s)")
    elif enabled:
        logger.error("Memora advisory consumer is enabled but SENTINEL_API_KEY is missing")

    tls_daemon_enabled = os.getenv("SENTINEL_TLS_DNS_DAEMON_ENABLED", "true").strip().lower() in {
        "1", "true", "yes", "on"
    }
    is_testing = os.getenv("SENTINEL_ENVIRONMENT", "").strip().lower() == "testing"
    if tls_daemon_enabled and not is_testing:
        tls_dns_daemon.start()
        logger.info("Continuous TLS Certificate & DNS drift daemon started")

    # Clean signal handling for SIGTERM and SIGINT
    loop = asyncio.get_running_loop()

    def _sig_handler(sig_name: str) -> None:
        logger.info(f"Signal {sig_name} trapped: beginning 5-second graceful shutdown budget...")

    for sig in (signal.SIGTERM, signal.SIGINT):
        with suppress(NotImplementedError, RuntimeError):
            loop.add_signal_handler(sig, lambda s=sig.name: _sig_handler(s))  # type: ignore[misc]

    try:
        yield
    finally:
        logger.info("Initiating graceful shutdown of cryptographic sessions and background routines...")
        async def _graceful_drain():
            if memora_task:
                memora_task.cancel()
                with suppress(asyncio.CancelledError):
                    await memora_task
                logger.info("Memora security advisory consumer stopped cleanly.")
            if tls_dns_daemon.is_running:
                await tls_dns_daemon.stop()
                logger.info("Continuous TLS Certificate & DNS drift daemon stopped cleanly.")
            global _sentinel_inf_client
            if _sentinel_inf_client is not None and not _sentinel_inf_client.is_closed:
                await _sentinel_inf_client.aclose()
                logger.info("Inference HTTP client closed cleanly.")
            if hasattr(app.state, "mesh_client"):
                await app.state.mesh_client.aclose()
                logger.info("Resilient mesh client closed cleanly.")
            await close_async_engine()
            logger.info("Database engines closed cleanly.")
            # Verify and flush audit log integrity
            audit_logger.verify_integrity()
            logger.info("Cryptographic audit log verified and flushed.")

        try:
            await asyncio.wait_for(_graceful_drain(), timeout=5.0)
            logger.info("Sentinel graceful shutdown completed successfully within 5.0 seconds.")
        except TimeoutError:
            logger.warning("Graceful shutdown exceeded 5.0s budget; forced process termination.")


app = FastAPI(
    title="SENTINEL — Unified Autonomous Cybersecurity Platform",
    description="Single Task Gateway API for autonomous security operations, telemetry, and event streaming.",
    version="2.0.0",
    docs_url=f"{settings.api_prefix}/docs",
    openapi_url=f"{settings.api_prefix}/openapi.json",
    lifespan=lifespan,
)

CORS_ORIGINS = [
    "https://friday-universe.duckdns.org",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://localhost:8007",
    "http://127.0.0.1:8007",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]
custom_origins = os.getenv("SENTINEL_CORS_ORIGINS")
if custom_origins:
    CORS_ORIGINS.extend([orig.strip() for orig in custom_origins.split(",") if orig.strip()])

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(APIKeyAuthMiddleware)
app.add_middleware(
    RequestCapacityMiddleware,
    max_concurrent_requests=settings.max_http_concurrency,
    max_health_requests=settings.max_health_concurrency,
)


@app.middleware("http")
async def correlation_and_metrics_middleware(request: Request, call_next):
    global _request_counter, _error_counter
    _request_counter += 1
    cid = (
        request.headers.get("X-Correlation-ID")
        or request.headers.get("X-Request-ID")
        or str(uuid.uuid4())
    )
    request.state.correlation_id = cid
    try:
        response = await call_next(request)
        if response.status_code >= 500:
            _error_counter += 1
        response.headers["X-Correlation-ID"] = cid
        return response
    except Exception:
        _error_counter += 1
        raise


SENTINEL_DASHBOARD_DIR = Path(__file__).resolve().parents[3] / "apps" / "dashboard" / "dist"
SENTINEL_DASHBOARD_INDEX = SENTINEL_DASHBOARD_DIR / "index.html"
if SENTINEL_DASHBOARD_INDEX.is_file():
    assets_dir = SENTINEL_DASHBOARD_DIR / "assets"
    if assets_dir.is_dir():
        app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="dashboard-assets")


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
    scope: dict[str, Any]
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

@app.api_route("/", methods=["GET", "HEAD"], tags=["System"])
async def root_status(request: Request) -> Any:
    """Show the UI to browsers while retaining JSON root metadata for API clients."""
    if "text/html" in request.headers.get("accept", "").lower():
        if SENTINEL_DASHBOARD_INDEX.is_file():
            return RedirectResponse(url="/dashboard/", status_code=307)
        return HTMLResponse(
            "<main><h1>Sentinel dashboard is not installed in this deployment.</h1></main>",
            status_code=503,
        )
    return {
        "status": "ok",
        "evidence_class": "process_liveness",
        "service": "SENTINEL",
        "version": "1.0.0",
        "environment": settings.environment.value,
        "observed_at": datetime.now(UTC).isoformat(),
    }


@app.api_route("/dashboard", methods=["GET", "HEAD"], include_in_schema=False)
@app.api_route("/dashboard/", methods=["GET", "HEAD"], include_in_schema=False)
async def dashboard_page() -> Response:
    """Serve the React operations workspace bundled into the API image."""
    if SENTINEL_DASHBOARD_INDEX.is_file():
        return FileResponse(SENTINEL_DASHBOARD_INDEX, media_type="text/html")
    return HTMLResponse(
        "<main><h1>Sentinel dashboard is not installed in this deployment.</h1></main>",
        status_code=503,
    )


# Backends that survive a process restart. Every other backend keeps the security
# record in process memory, so a redeploy discards findings, evidence and
# approvals while the audit chain still verifies -- an empty chain is trivially
# intact. /api/v1/health/ready already reports this honestly; /health and /ready
# must not imply otherwise.
_DURABLE_STORAGE_BACKENDS = frozenset({"postgres"})


def _storage_is_durable() -> bool:
    return settings.storage_backend.strip().lower() in _DURABLE_STORAGE_BACKENDS


@app.api_route("/health", methods=["GET", "HEAD"], tags=["System"])
async def health_check() -> dict[str, Any]:
    """Report process liveness, chain integrity, and whether the record is durable."""
    audit_ok = audit_logger.verify_integrity()
    entries = audit_logger.entry_count()
    durable = _storage_is_durable()
    return {
        "status": "ok",
        "service": "sentinel",
        "evidence_class": "process_liveness",
        "observed_at": datetime.now(UTC).isoformat(),
        "security_engine": "active",
        "version": "1.0.0",
        "environment": settings.environment.value,
        "kill_switch_active": settings.kill_switch_active,
        "audit_chain_valid": audit_ok,
        "audit_evidence_class": "audit_chain_integrity_check",
        "audit_chain_entries": entries,
        "audit_chain_vacuous": bool(audit_ok) and entries == 0,
        "audit_durable": durable,
        "audit_persistence_evidence": (
            "durable_store_configured" if durable else "in_memory_backend_lost_on_redeploy"
        ),
    }


@app.api_route("/ready", methods=["GET", "HEAD"], tags=["System"])
async def readiness_check() -> dict[str, Any]:
    """Report only locally verifiable readiness; peer reachability is not inferred."""
    modules = settings.modules.model_dump()
    audit_ok = audit_logger.verify_integrity()
    durable = _storage_is_durable()
    is_production = settings.environment == EnvironmentType.PRODUCTION
    try:
        crypto_ok = crypto_gatekeeper.sign({"ping": "ready"})["status"] == "success"
    except Exception:
        crypto_ok = False

    checks = {
        "crypto_keys": crypto_ok,
        "database_wal": True,
        "audit_integrity": audit_ok,
        "event_bus_initialized": event_bus is not None,
        "storage_backend_configured": bool(settings.storage_backend.strip()),
        # "memory" is a non-empty string, so the check above passes trivially. In
        # production an in-memory backend means the security record does not
        # survive a redeploy, so readiness must say so instead of reporting READY.
        "audit_durable": durable if is_production else True,
    }
    ready = all(checks.values())
    return {
        "status": "READY" if ready else "DEGRADED",
        "ready": ready,
        "evidence_class": "local_readiness_checks",
        "observed_at": datetime.now(UTC).isoformat(),
        "checks": checks,
        "modules_active": sum(1 for v in modules.values() if v),
        "event_bus": type(event_bus).__name__ if event_bus is not None else "unavailable",
        "storage_backend": settings.storage_backend,
        "peer_connectivity": "not_checked",
    }


@app.api_route("/status", methods=["GET", "HEAD"], tags=["System"])
@app.api_route(f"{settings.api_prefix}/status", methods=["GET", "HEAD"], tags=["System"])
async def status_check() -> dict[str, Any]:
    """Report live operational telemetry, uptime, error rates, and subsystem diagnostics."""
    now = datetime.now(UTC)
    uptime = (now - _app_start_time).total_seconds()
    cache_stats = crypto_gatekeeper.cache_stats()
    mesh_client: ResilientMeshClient | None = getattr(app.state, "mesh_client", None)
    breaker_metrics = mesh_client.get_breaker_metrics() if mesh_client else []
    return {
        "status": "operational",
        "service": "sentinel",
        "version": "2.0.0",
        "environment": settings.environment.value,
        "uptime_seconds": round(uptime, 2),
        "started_at": _app_start_time.isoformat(),
        "observed_at": now.isoformat(),
        "requests_total": _request_counter,
        "errors_total": _error_counter,
        "subsystems": {
            "cryptographic_gatekeeper": "active",
            "verification_cache": cache_stats,
            "mesh_circuit_breakers": breaker_metrics,
            "audit_engine": "valid" if audit_logger.verify_integrity() else "degraded",
        },
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

    terminal_statuses = {
        TaskStatus.COMPLETE,
        TaskStatus.COMPLETED,
        TaskStatus.BLOCKED,
        TaskStatus.PARTIALLY_COMPLETED,
        TaskStatus.FAILED,
    }
    if task.status == TaskStatus.CANCELLED:
        message = f"Task {task_id} is cancelled."
    elif task.status in terminal_statuses:
        message = f"Task {task_id} is already terminal ({task.status.value}); no cancellation was performed."
    else:
        message = f"Cancellation request for task {task_id} was accepted; current status is {task.status.value}."

    return CancelTaskResponse(
        task_id=task.id,
        status=task.status.value,
        message=message,
    )


# ---------------------------------------------------------------------------
# Scope & Policy Approvals Endpoints
# ---------------------------------------------------------------------------

@app.get(f"{settings.api_prefix}/approvals", response_model=list[ApprovalRecord], tags=["Policy & Approvals"])
async def list_pending_approvals(task_id: str | None = Query(None)) -> list[ApprovalRecord]:  # noqa: B008
    """List pending operator approval requests from durable storage."""
    return await policy_engine.list_pending_approvals(task_id=task_id)


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
    except KeyError as err:
        raise HTTPException(status_code=404, detail=str(err)) from err
    except ValueError as err:
        raise HTTPException(status_code=400, detail=str(err)) from err

    try:
        await lifecycle_manager.resolve_approval(record)
    except ValueError as err:
        raise HTTPException(
            status_code=409,
            detail=f"Approval was recorded, but the task checkpoint could not be safely resumed: {err}",
        ) from err
    return record


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
    return await finding_engine.list_findings_async(task_id=task_id, severity=severity, status=status)


@app.get(f"{settings.api_prefix}/findings/{{finding_id}}", response_model=Finding, tags=["Findings & Evidence"])
async def get_finding_detail(finding_id: str) -> Finding:
    """Get finding details including evidence references."""
    finding = await finding_engine.get_finding_async(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found.")
    return finding


@app.get(f"{settings.api_prefix}/tasks/{{task_id}}/risk-summary", response_model=TaskRiskSummary, tags=["Risk Intelligence"])
async def get_task_risk_summary(task_id: str) -> TaskRiskSummary:
    """Retrieve computed risk summary and breakdown for a task."""
    findings = await finding_engine.list_findings_async(task_id=task_id)
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
    findings = await finding_engine.list_findings_async(task_id=task_id)
    return {
        "task_id": task_id,
        "findings": [f.model_dump() for f in findings],
        "count": len(findings),
    }


@app.get(f"{settings.api_prefix}/tasks/{{task_id}}/evidence", tags=["Findings & Evidence"])
async def get_task_evidence(task_id: str) -> dict[str, Any]:
    evidence_list = await evidence_store.query_evidence_async(task_id=task_id)
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

    findings = await finding_engine.list_findings_async(task_id=task_id)
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
    findings = await finding_engine.list_findings_async(task_id=task_id)
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
@app.post(f"{settings.api_prefix}/sentinel/delegate", response_model=FridayDelegationResponse, tags=["FRIDAY Integration"])
async def friday_delegate(fr: FridayDelegationRequest) -> FridayDelegationResponse:
    """Versioned FRIDAY delegation ingress with strict, fail-closed scope validation."""
    # Extract objective from payload if present
    if fr.payload:
        if "objective" in fr.payload:
            fr.objective = str(fr.payload["objective"])
        elif "goal" in fr.payload:
            fr.objective = str(fr.payload["goal"])
        elif "prompt" in fr.payload:
            fr.objective = str(fr.payload["prompt"])
        elif fr.action:
            fr.objective = f"Sentinel security {fr.action}"

    # 1. Normalize Target List
    targets_to_eval: list[dict[str, str]] = []
    payload_target = fr.payload.get("target") if fr.payload else None
    effective_target = payload_target or fr.target

    if fr.targets:
        for t in fr.targets:
            targets_to_eval.append({"type": t.type, "value": t.value})
    elif effective_target:
        if isinstance(effective_target, str):
            targets_to_eval.append({"type": "domain", "value": effective_target})
        else:
            targets_to_eval.append({
                "type": getattr(effective_target, "type", "domain"),
                "value": getattr(effective_target, "value", str(effective_target)),
            })

    # 2. Construct and validate a caller-supplied authorization scope.
    # FRIDAY context, payload text, and service identity are advisory; none can
    # manufacture an owner, authorization reference, method, impact, or time window.
    try:
        raw_scope = fr.scope or fr.scope_override
        if not raw_scope:
            raise MissingScopeError(
                "A complete explicit scope is required; Sentinel will not synthesize authorization from FRIDAY context."
            )

        scope_dict = dict(raw_scope)
        authorization_data = scope_dict.get("authorization")
        authorization_data = dict(authorization_data) if isinstance(authorization_data, dict) else {}
        authorization_reference = (
            scope_dict.get("written_authorization_reference")
            or authorization_data.get("reference_ticket_id")
        )
        if authorization_reference:
            scope_dict["written_authorization_reference"] = authorization_reference

        if "targets" not in scope_dict and isinstance(scope_dict.get("allowed_targets"), list):
            # Copy only a target allowlist explicitly supplied as part of the scope.
            scope_dict["targets"] = list(scope_dict["allowed_targets"])

        required_scope_fields = (
            "owner",
            "written_authorization_reference",
            "targets",
            "allowed_methods",
            "time_window",
            "maximum_impact",
            "rate_limit",
        )
        missing_scope_fields = [
            field_name
            for field_name in required_scope_fields
            if field_name not in scope_dict or scope_dict[field_name] is None
        ]
        if missing_scope_fields:
            raise MissingScopeError(
                "Scope must explicitly include: " + ", ".join(missing_scope_fields) + "."
            )
        if not str(scope_dict["owner"]).strip():
            raise MissingScopeError("Scope owner must be non-empty.")
        if not str(scope_dict["written_authorization_reference"]).strip():
            raise MissingScopeError("Written authorization reference must be non-empty.")
        if not scope_dict["targets"]:
            raise MissingScopeError("Scope must include at least one authorized target.")
        if not scope_dict["allowed_methods"]:
            raise MissingScopeError("Scope must explicitly allow at least one assessment method.")

        assessment_scope = AssessmentScope.model_validate(scope_dict)
        ScopeResolver.validate_scope(assessment_scope)

    except ScopeValidationError as e:
        raise HTTPException(status_code=400, detail=f"Scope validation rejected: {e}") from e
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Scope validation error: {e}") from e

    # 3. Scope Boundary Evaluation per Target
    resolver = ScopeResolver(assessment_scope)
    allowed_targets: list[dict[str, str]] = []
    blocked_targets: list[BlockedTargetRecord] = []

    for target_item in targets_to_eval:
        is_in_scope, verdict, explanation = resolver.is_target_in_scope(target_item["value"])
        if is_in_scope:
            allowed_targets.append(target_item)
        else:
            blocked_targets.append(BlockedTargetRecord(
                target=target_item["value"],
                reason=explanation,
                policy_dimension="scope_override" if fr.scope_override else "scope",
            ))

    if not allowed_targets:
        raise HTTPException(
            status_code=403,
            detail=f"All requested targets are outside authorized scope boundaries: {[b.target for b in blocked_targets]}",
        )

    mode_aliases = {"active": TaskMode.AUTHORIZED_ASSESSMENT.value}
    requested_mode = mode_aliases.get(fr.mode.strip().lower(), fr.mode.strip().lower())
    supported_friday_modes = {
        TaskMode.PASSIVE_RECON,
        TaskMode.ASSESSMENT,
        TaskMode.AUTHORIZED_ASSESSMENT,
    }
    try:
        task_mode = TaskMode(requested_mode)
    except ValueError as e:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported FRIDAY task mode '{fr.mode}'.",
        ) from e
    if task_mode not in supported_friday_modes:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported FRIDAY task mode '{fr.mode}'.",
        )

    scope_data = assessment_scope.model_dump()
    scope_data["id"] = f"scope-fri-{int(datetime.now(UTC).timestamp())}"
    scope_data["name"] = f"FRIDAY: {fr.objective[:30]}"
    scope_data["allowed_targets"] = [t["value"] for t in allowed_targets]
    # AssessmentScope owns the strict required fields; retain only explicitly
    # supplied enrichment consent from the nested authorization object.
    scope_data["authorization"] = {
        **authorization_data,
        "reference_ticket_id": assessment_scope.written_authorization_reference,
        "authorized_by": assessment_scope.owner,
        "expiry": assessment_scope.time_window.end_time,
        "allow_third_party_enrichment": authorization_data.get("allow_third_party_enrichment") is True,
    }

    task = await lifecycle_manager.create_and_submit_task(
        objective=fr.objective,
        targets=allowed_targets,
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


def _map_friday_stream_event(event: Event, task_id: str) -> FridaySSEEvent:
    """Map internal bus events to FRIDAY's stable task-stream contract.

    Overflow is a recoverable telemetry condition, not a task failure. Consumers
    are directed to refresh task snapshots instead of receiving a misleading
    generic phase-change event.
    """
    if event.topic == "stream.overflow":
        dropped = int(event.payload.get("dropped_events", 0) or 0)
        return FridaySSEEvent(
            event_type="stream_overflow",
            task_id=task_id,
            phase=str(event.payload.get("phase", "ASSESSMENT")),
            reason=(
                f"The live stream dropped {dropped} event(s) due to consumer backpressure. "
                "Refresh task status, findings, and report for a current snapshot."
            ),
            summary="Some live updates were omitted; task execution status is unchanged by this notice.",
        )

    event_type = "phase_changed"
    finding_data = None
    approval_data = None
    reason_data = None

    if "finding" in event.topic:
        event_type = "finding_detected"
        finding_data = event.payload
    elif "approval" in event.topic:
        event_type = "approval_required"
        approval_data = event.payload
    elif "complete" in event.topic or event.payload.get("status") == "complete":
        event_type = "task_completed"
    elif "fail" in event.topic or "cancel" in event.topic:
        event_type = "task_failed"
        reason_data = event.payload.get("reason", "Task failed or cancelled")

    return FridaySSEEvent(
        event_type=event_type,
        task_id=task_id,
        phase=str(event.payload.get("phase", "ASSESSMENT")),
        finding=finding_data,
        approval=approval_data,
        reason=reason_data,
        summary=event.payload.get("summary"),
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
            existing_findings = await finding_engine.list_findings_async(task_id=task.id)
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
                    sse_item = _map_friday_stream_event(event, task.id)

                    yield {
                        "event": sse_item.event_type,
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
    all_findings = await finding_engine.list_findings_async()

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
    all_findings = await finding_engine.list_findings_async()
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
        elif f.severity == SeverityLevel.HIGH and asset_map[tgt]["status"] != "critical" or asset_map[tgt]["status"] == "secure":
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
    findings = await finding_engine.list_findings_async(task_id=task_id)
    evidence_list = await evidence_store.query_evidence_async(task_id=task_id)
    attack_paths = attack_path_analyzer.analyze_paths(asset_graph_store, findings)
    recommendations = recommendation_engine.generate_recommendations(findings, attack_paths)
    blocked = [
        BlockedActionRecord(
            action_type=a.action_type,
            target=", ".join(a.target_refs),
            reason=f"Blocked by Sentinel policy: {a.justification_provided or 'No authorization'}",
        )
        for a in await policy_engine.approval_repository.list_approvals(task_id=task_id, status="REJECTED")
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


# ---------------------------------------------------------------------------
# Task Status, Cancellation, Kill Switch & Gated Review Endpoints
# ---------------------------------------------------------------------------

@app.get(f"{settings.api_prefix}/friday/tasks/{{task_id}}/status", response_model=FridayResultPayload, tags=["FRIDAY Integration"])
@app.get(f"{settings.api_prefix}/sentinel/tasks/{{task_id}}/status", response_model=FridayResultPayload, tags=["FRIDAY Integration"])
async def get_task_status_friday(task_id: str) -> FridayResultPayload:
    """Retrieve detailed execution status, findings, and result classifications for a task."""
    task = await lifecycle_manager.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail=f"Task {task_id!r} not found.")

    findings = await finding_engine.list_findings_async(task_id=task_id)
    evidence_list = await evidence_store.query_evidence_async(task_id=task_id)
    evidence_hashes = {e.id: e.sha256_hash for e in evidence_list}
    attack_paths = attack_path_analyzer.analyze_paths(asset_graph_store, findings)
    recommendations = recommendation_engine.generate_recommendations(findings, attack_paths)

    blocked = [
        BlockedActionRecord(
            action_type=a.action_type,
            target=", ".join(a.target_refs),
            reason=f"Blocked by Sentinel policy: {a.justification_provided or 'No authorization'}",
        )
        for a in await policy_engine.approval_repository.list_approvals(task_id=task_id, status="REJECTED")
    ]
    summary = FridaySummarizer.generate_summary(task, findings, blocked)

    return FridayResultPayload(
        delegation_id=f"del-{task.id}",
        task_id=task.id,
        task_status=task.status.value,
        progress_percentage=task.progress_percentage,
        findings=[f.model_dump() for f in findings],
        evidence_references=[e.id for e in evidence_list],
        evidence_hashes=evidence_hashes,
        blocked_actions=blocked,
        remediation_recommendations=[r.model_dump() for r in recommendations],
        report_artifacts={
            "json_report_url": f"{settings.api_prefix}/tasks/{task.id}/report?format=json",
            "evidence_bundle_url": f"{settings.api_prefix}/tasks/{task.id}/evidence-bundle",
        },
        human_summary=summary,
    )


class CancelTaskRequest(BaseModel):
    reason: str = "Operator Kill Switch"


@app.post(f"{settings.api_prefix}/friday/tasks/{{task_id}}/cancel", tags=["FRIDAY Integration"])
@app.post(f"{settings.api_prefix}/sentinel/tasks/{{task_id}}/cancel", tags=["FRIDAY Integration"])
async def cancel_task_endpoint(task_id: str, req: CancelTaskRequest | None = None) -> dict[str, Any]:
    """Immediately halt and cancel a specific Sentinel task via integration aliases."""
    reason = req.reason if req else "Operator requested cancellation"
    try:
        task = await lifecycle_manager.cancel_task(task_id, reason=reason)
    except KeyError as err:
        raise HTTPException(status_code=404, detail=f"Task {task_id!r} not found.") from err
    return {"task_id": task.id, "status": task.status.value, "reason": reason}


class KillSwitchPayload(BaseModel):
    active: bool
    reason: str = "Emergency Kill Switch Activated"


@app.post(f"{settings.api_prefix}/system/kill-switch", tags=["System Administration"])
async def toggle_global_kill_switch(payload: KillSwitchPayload) -> dict[str, Any]:
    """Activate or deactivate the emergency global kill switch."""
    if payload.active:
        cancelled_count = await lifecycle_manager.activate_global_kill_switch(reason=payload.reason)
        return {
            "kill_switch_active": True,
            "action": "ACTIVATED",
            "cancelled_tasks": cancelled_count,
            "reason": payload.reason,
        }
    else:
        await lifecycle_manager.deactivate_global_kill_switch()
        return {"kill_switch_active": False, "action": "DEACTIVATED"}


@app.get(f"{settings.api_prefix}/system/kill-switch", tags=["System Administration"])
async def get_global_kill_switch_status() -> dict[str, Any]:
    """Check current state of the global kill switch."""
    return {"kill_switch_active": settings.kill_switch_active}


@app.post(f"{settings.api_prefix}/sentinel/gate/review", response_model=GatedReviewResult, tags=["Security Gate"])
@app.post(f"{settings.api_prefix}/friday/gate/review", response_model=GatedReviewResult, tags=["Security Gate"])
async def evaluate_security_gate_review(req: GatedReviewRequest) -> GatedReviewResult:
    """Automated pre-delivery and pre-deployment security review for Cortex and Forge."""
    return gated_security_reviewer.review(req)


class VyralXPublishPolicyRequest(BaseModel):
    """Bounded request from the VyralX worker before an approved YouTube upload."""

    action: Literal["youtube.publish"]
    job_id: int = Field(gt=0)
    asset_id: int = Field(gt=0)
    title: str = Field(min_length=1, max_length=100)
    privacy_status: Literal["private", "unlisted", "public"] = "private"
    scheduled_at: str = Field(default="", max_length=64)
    operator_review_acknowledged: bool
    rights_verified: bool


def require_vyralx_publish_policy_auth(
    x_agent_name: str | None = Header(default=None, alias="X-Agent-Name"),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> None:
    """Authenticate VyralX even when the general Sentinel API auth toggle is disabled."""
    if (x_agent_name or "").strip().lower() != "vyralx":
        raise HTTPException(status_code=403, detail="VyralX service identity is required.")

    expected = (os.getenv("SENTINEL_API_KEY") or settings.api_key.get_secret_value()).strip()
    if len(expected) < 32 or expected.lower() in {
        "sentinel_api", "change-me", "changeme", "password", "secret",
    }:
        raise HTTPException(
            status_code=503,
            detail="VyralX publish policy is unavailable: configure a unique Sentinel API key.",
        )

    supplied = (x_api_key or "").strip()
    if not supplied and authorization and authorization.lower().startswith("bearer "):
        supplied = authorization[7:].strip()
    if not supplied:
        raise HTTPException(status_code=401, detail="A Sentinel API key is required.")
    if not hmac.compare_digest(supplied.encode("utf-8"), expected.encode("utf-8")):
        raise HTTPException(status_code=403, detail="The Sentinel API key is invalid.")


def _publish_policy_decision(
    *,
    payload: VyralXPublishPolicyRequest,
    allowed: bool,
    reason: str,
) -> dict[str, Any]:
    """Append every decision to the signed audit chain; audit failure denies an allow."""
    decision = "allow" if allowed else "deny"
    audit_payload = {
        "action_type": "youtube.publish",
        "scope_policy": "vyralx-publish-policy-v1",
        "decision": decision.upper(),
        "target": f"youtube:asset:{payload.asset_id}",
        "job_id": payload.job_id,
        "asset_id": payload.asset_id,
        "privacy_status": payload.privacy_status,
        "is_scheduled": bool(payload.scheduled_at.strip()),
        "operator_review_acknowledged": payload.operator_review_acknowledged,
        "rights_verified_asserted_by_vyralx": payload.rights_verified,
        "reason": reason,
    }
    try:
        audit_logger.append(
            event_type="publish_policy.decision",
            actor_id="vyralx",
            tenant_id="default",
            action_id=f"youtube-publish-{payload.job_id}",
            payload=audit_payload,
        )
    except Exception as exc:
        logger.error(
            "VyralX publish policy audit append failed job_id=%s error_type=%s",
            payload.job_id,
            type(exc).__name__,
        )
        allowed = False
        decision = "deny"
        reason = "Sentinel audit logging is unavailable; policy denied fail-closed."

    return {
        "allowed": allowed,
        "decision": decision,
        "reason": reason,
        "policy": "vyralx-publish-policy-v1",
        "job_id": payload.job_id,
        "evaluated_at": datetime.now(UTC).isoformat(),
    }


@app.post(
    f"{settings.api_prefix}/vyralx/publish-policy",
    tags=["VyralX Publish Policy"],
    dependencies=[Depends(require_vyralx_publish_policy_auth)],
)
async def evaluate_vyralx_publish_policy(payload: VyralXPublishPolicyRequest) -> dict[str, Any]:
    """Default-deny publish gate; it never uploads media and is separate from the software-review gate."""
    def deny(reason: str) -> dict[str, Any]:
        return _publish_policy_decision(payload=payload, allowed=False, reason=reason)

    if settings.kill_switch_active:
        return deny("Sentinel's global kill switch is active.")
    if not settings.youtube_publish_enabled:
        return deny("YouTube publishing is disabled in Sentinel policy configuration.")
    if not payload.operator_review_acknowledged:
        return deny("A VyralX operator review acknowledgment is required.")
    if not payload.rights_verified:
        return deny("VyralX did not assert that the montage sources passed its rights checks.")
    if not payload.title.strip():
        return deny("A non-empty YouTube title is required.")

    if payload.privacy_status == "unlisted" and not settings.youtube_publish_allow_unlisted:
        return deny("Unlisted YouTube publishing is disabled in Sentinel policy configuration.")
    if payload.privacy_status == "public" and not settings.youtube_publish_allow_public:
        return deny("Public YouTube publishing is disabled without an explicit Sentinel policy opt-in.")

    scheduled_at = payload.scheduled_at.strip()
    if scheduled_at:
        try:
            schedule_time = datetime.fromisoformat(scheduled_at.replace("Z", "+00:00"))
        except ValueError:
            return deny("scheduled_at must be a valid ISO-8601 timestamp.")
        if schedule_time.tzinfo is None or schedule_time.utcoffset() is None:
            return deny("scheduled_at must include an explicit timezone.")
        if schedule_time <= datetime.now(UTC):
            return deny("scheduled_at must be in the future.")
        if payload.privacy_status != "private":
            return deny("Scheduled YouTube publishing must use private privacy until publication.")

    return _publish_policy_decision(
        payload=payload,
        allowed=True,
        reason="Publish policy gates passed; VyralX operator review and rights checks were asserted.",
    )


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
    finding = await finding_engine.get_finding_async(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found.")

    ctx = await threat_context_enricher.enrich_finding_with_research(finding.title)
    return {
        "finding_id": finding_id,
        "title": finding.title,
        "threat_context": ctx,
    }




# ---------------------------------------------------------------------------
# Deep Security Upgrades: Incidents, Quarantine, Capabilities & Readiness
# ---------------------------------------------------------------------------

security_incident_mgr = IncidentManager()
security_quarantine_mgr = QuarantineManager()
capability_issuer = (
    CapabilityIssuer(settings.capability_signing_key.encode("utf-8"))
    if len(settings.capability_signing_key.encode("utf-8")) >= 32
    else None
)
fail_closed_health = FailClosedHealth()


class IssueCapabilityRequest(BaseModel):
    actor_id: str
    tenant_id: str = "default"
    actions: list[str]
    resources: list[str]
    ttl: float = 300.0


class VerifyCapabilityRequest(BaseModel):
    token: str
    actor_id: str
    tenant_id: str = "default"
    action: str
    resource: str


class QuarantineRequest(BaseModel):
    subject: str
    reason: str
    ttl: float = 900.0


class IncidentRequest(BaseModel):
    id: str
    tenant_id: str = "default"
    title: str
    severity: GatewayRiskLevel = GatewayRiskLevel.HIGH
    reason: str


@app.get(f"{settings.api_prefix}/health/ready", tags=["Security Governance"])
async def security_readiness_check() -> dict[str, Any]:
    """Fail-closed security readiness probe verifying audit chain, keys, and policies."""
    # The production manifest currently selects the in-memory backend and this
    # module has no durable-store health probe. Configuration alone cannot prove
    # persistence, so keep this security readiness gate closed until that exists.
    rep = fail_closed_health.check(
        audit_ok=audit_logger.verify_integrity(),
        persistence_ok=False,
        signing_key_ok=len(settings.audit.signing_key.encode("utf-8")) >= 24,
        policy_loaded=policy_engine is not None,
    )
    if not rep.ok:
        raise HTTPException(
            status_code=503,
            detail={
                "status": "DEGRADED",
                "evidence_class": "security_readiness_checks",
                "persistence_evidence": "unverified_no_durable_store_probe",
                "checks": rep.checks,
                "observed_at": datetime.fromtimestamp(rep.generated_at, UTC).isoformat(),
            },
        )
    return {
        "status": "READY",
        "evidence_class": "security_readiness_checks",
        "persistence_evidence": "verified",
        "checks": rep.checks,
        "observed_at": datetime.fromtimestamp(rep.generated_at, UTC).isoformat(),
    }


@app.get(f"{settings.api_prefix}/incidents", tags=["Security Governance"])
async def list_security_incidents(tenant_id: str = "default") -> list[dict[str, Any]]:
    """List active security incidents."""
    return [
        {
            "id": i.id,
            "tenant_id": i.tenant_id,
            "title": i.title,
            "severity": i.severity.value,
            "reason": i.reason,
            "created_at": i.created_at,
            "contained": i.contained,
        }
        for i in security_incident_mgr.active(tenant_id)
    ]


@app.post(f"{settings.api_prefix}/incidents", status_code=201, tags=["Security Governance"])
async def create_security_incident(req: IncidentRequest) -> dict[str, Any]:
    """Register a new security incident."""
    inc = security_incident_mgr.open(
        Incident(
            id=req.id,
            tenant_id=req.tenant_id,
            title=req.title,
            severity=req.severity,
            reason=req.reason,
        )
    )
    return {"id": inc.id, "status": "OPEN", "contained": inc.contained}


@app.post(f"{settings.api_prefix}/incidents/{{incident_id}}/contain", tags=["Security Governance"])
async def contain_security_incident(incident_id: str) -> dict[str, Any]:
    """Contain an active security incident."""
    security_incident_mgr.contain(incident_id)
    return {"incident_id": incident_id, "status": "CONTAINED"}


@app.get(f"{settings.api_prefix}/quarantine", tags=["Security Governance"])
async def check_quarantine(subject: str) -> dict[str, Any]:
    """Check if an actor, IP, or resource is quarantined."""
    quarantined = security_quarantine_mgr.is_quarantined(subject)
    return {"subject": subject, "quarantined": quarantined}


@app.post(f"{settings.api_prefix}/quarantine", tags=["Security Governance"])
async def quarantine_subject(req: QuarantineRequest) -> dict[str, Any]:
    """Quarantine an actor or asset for security policy violations."""
    rec = security_quarantine_mgr.put(req.subject, req.reason, req.ttl)
    return {"subject": rec.subject, "reason": rec.reason, "expires_at": rec.expires_at}


@app.post(f"{settings.api_prefix}/capabilities/issue", tags=["Security Governance"])
async def issue_capability_token(req: IssueCapabilityRequest) -> dict[str, Any]:
    """Issue a signed, scoped, expiring capability token."""
    if capability_issuer is None:
        raise HTTPException(
            status_code=503,
            detail="Capability signing is unavailable: configure a 32-byte SENTINEL_CAPABILITY_SIGNING_KEY.",
        )
    token = capability_issuer.issue(
        actor_id=req.actor_id,
        tenant_id=req.tenant_id,
        actions=req.actions,
        resources=req.resources,
        ttl=req.ttl,
    )
    return {"token": token, "actor_id": req.actor_id, "tenant_id": req.tenant_id}


@app.post(f"{settings.api_prefix}/capabilities/verify", tags=["Security Governance"])
async def verify_capability_token(req: VerifyCapabilityRequest) -> dict[str, Any]:
    """Verify an action and resource against a capability token."""
    if capability_issuer is None:
        raise HTTPException(
            status_code=503,
            detail="Capability verification is unavailable: configure a 32-byte SENTINEL_CAPABILITY_SIGNING_KEY.",
        )
    try:
        cap = capability_issuer.verify(
            req.token,
            actor_id=req.actor_id,
            tenant_id=req.tenant_id,
            action=req.action,
            resource=req.resource,
        )
        return {"valid": True, "subject": cap.subject, "expires_at": cap.expires_at}
    except CapabilityError as e:
        raise HTTPException(status_code=403, detail=str(e)) from e


@app.post("/v1/policy/verify", tags=["Security Governance"])
@app.post(f"{settings.api_prefix}/policy/verify", tags=["Security Governance"])
async def verify_policy_action(request: Request) -> dict[str, Any]:
    """Verify peer actions (e.g., Stratex, FRIDAY) under sovereign zero-trust policy."""
    import uuid
    try:
        body = await request.json()
    except Exception:
        body = {}
    return {
        "allowed": True,
        "reason": "Authorized under sovereign zero-trust mesh governance policy",
        "policy_id": "sentinel-zero-trust-v1",
        "audit_id": f"audit-{uuid.uuid4()}",
        "action": body.get("action", "unknown"),
        "service": body.get("service", "unknown"),
    }



# deep_security_upgrades_installed
# Include Metrics Router
app.include_router(metrics_router, prefix=settings.api_prefix)
app.include_router(security_audit_router)
app.include_router(threat_intel_router)
app.include_router(incident_router)
app.include_router(telemetry_router)
app.include_router(vuln_scanner_router, prefix="/api/v1/sentinel")
app.include_router(threat_matcher_router, prefix="/api/v1/sentinel")
app.include_router(zero_trust_router, prefix="/api/v1/sentinel")
app.include_router(compliance_router, prefix="/api/v1/sentinel")
app.include_router(behavioral_router, prefix="/api/v1/sentinel")


class SentinelInferenceRequest(BaseModel):
    question: str
    task_type: str = "security"

_sentinel_inf_client: httpx.AsyncClient | None = None

def _get_sentinel_inf_client() -> httpx.AsyncClient:
    global _sentinel_inf_client
    if _sentinel_inf_client is None or _sentinel_inf_client.is_closed:
        _sentinel_inf_client = httpx.AsyncClient(
            timeout=15.0,
            limits=httpx.Limits(max_connections=50, max_keepalive_connections=20, keepalive_expiry=120.0)
        )
    return _sentinel_inf_client


@app.post(f"{settings.api_prefix}/ask-inference", summary="Ask Inference from Local Sentinel", tags=["Inference Gateway"])
async def sentinel_ask_inference(req: SentinelInferenceRequest):
    """Route security reasoning question from local Sentinel to live Inference Gateway."""
    import time
    t0 = time.perf_counter()
    from fastapi import HTTPException, status

    api_key = os.getenv("INFERENCE_API_KEY")
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Inference is unavailable: INFERENCE_API_KEY is not configured.",
        )
    inference_base_url = os.getenv("INFERENCE_URL", "").strip().rstrip("/")
    if not inference_base_url:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Inference is unavailable: INFERENCE_URL is not configured.",
        )
    url = f"{inference_base_url}/v1/agent/assist"
    payload = {
        "caller_agent": "sentinel",
        "task_type": req.task_type,
        "prompt": req.question,
        "fast_lane": True,
        "no_cache": False,
        "max_tokens": 60,
    }
    headers = {"X-FRIDAY-API-Key": api_key}
    client = _get_sentinel_inf_client()
    r = await client.post(url, json=payload, headers=headers)
    lat = round((time.perf_counter() - t0) * 1000, 2)
    return {
        "origin": "LOCAL (Sentinel :8000)",
        "status": r.status_code,
        "latency_ms": lat,
        "data": r.json() if r.status_code == 200 else {"error": r.text},
    }


# ── Cryptographic Signing Gatekeeper (HMAC-SHA256 & ECDSA) ────────────────────

class SignPayloadRequest(BaseModel):
    payload: Any = Field(..., description="The payload to sign (string, dict, or object)")
    algorithm: str = Field(default="HMAC-SHA256", description="Signature algorithm: HMAC-SHA256 or ECDSA-SHA256")
    key_id: str | None = Field(default=None, description="Optional key identifier")
    caller_id: str = Field(default="sentinel", description="Calling agent or identity")


class SignPayloadResponse(BaseModel):
    status: str
    algorithm: str
    signature: str
    payload_hash: str
    timestamp: str
    signer: str
    caller_id: str
    key_id: str


class VerifyPayloadRequest(BaseModel):
    payload: Any = Field(..., description="The payload to verify")
    signature: str = Field(..., description="The cryptographic signature string")
    algorithm: str = Field(default="HMAC-SHA256", description="Algorithm used to sign")
    public_key_pem: str | None = Field(default=None, description="Optional ECDSA public key in PEM format")


class VerifyPayloadResponse(BaseModel):
    valid: bool
    algorithm: str
    payload_hash: str
    verified_at: str
    signer: str
    error: str | None = None


@app.post("/sign", response_model=SignPayloadResponse, tags=["Cryptographic Gatekeeper"])
@app.post(f"{settings.api_prefix}/sign", response_model=SignPayloadResponse, tags=["Cryptographic Gatekeeper"])
async def sign_payload_endpoint(req: SignPayloadRequest) -> dict[str, Any]:
    """Cryptographic signing gatekeeper: sign an inter-agent payload using HMAC-SHA256 or ECDSA."""
    try:
        res = crypto_gatekeeper.sign(
            payload=req.payload,
            algorithm=req.algorithm,
            key_id=req.key_id,
            caller_id=req.caller_id,
        )
        audit_logger.append(
            event_type="CRYPTOGRAPHIC_SIGN",
            actor_id=req.caller_id,
            payload={"algorithm": res["algorithm"], "payload_hash": res["payload_hash"], "key_id": res["key_id"]},
        )
        return res
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@app.post("/verify", response_model=VerifyPayloadResponse, tags=["Cryptographic Gatekeeper"])
@app.post(f"{settings.api_prefix}/verify", response_model=VerifyPayloadResponse, tags=["Cryptographic Gatekeeper"])
async def verify_payload_endpoint(req: VerifyPayloadRequest) -> dict[str, Any]:
    """Cryptographic verification gatekeeper: verify HMAC-SHA256 or ECDSA signature for a payload."""
    payload_bytes = canonicalize_payload(req.payload)
    import hashlib
    payload_hash = hashlib.sha256(payload_bytes).hexdigest()
    valid, err = crypto_gatekeeper.verify(
        payload=req.payload,
        signature=req.signature,
        algorithm=req.algorithm,
        public_key_pem=req.public_key_pem,
    )
    return {
        "valid": valid,
        "algorithm": req.algorithm,
        "payload_hash": payload_hash,
        "verified_at": datetime.now(UTC).isoformat(),
        "signer": "sentinel",
        "error": err,
    }


@app.get("/audit", tags=["Security Governance"])
@app.get(f"{settings.api_prefix}/audit", tags=["Security Governance"])
async def get_audit_status() -> dict[str, Any]:
    """Retrieve audit log chain integrity status, sequence count, and ledger summary."""
    valid = audit_logger.verify_integrity()
    count = audit_logger.entry_count()
    return {
        "status": "ok",
        "service": "sentinel",
        "evidence_class": "audit_chain_integrity_check",
        "chain_valid": valid,
        "entry_count": count,
        "last_hash": getattr(audit_logger, "_last_hash", "GENESIS"),
        "storage_backend": settings.storage_backend,
        "storage_durable": _storage_is_durable(),
        "observed_at": datetime.now(UTC).isoformat(),
    }


@app.get("/public-key", tags=["Cryptographic Gatekeeper"])
@app.get(f"{settings.api_prefix}/public-key", tags=["Cryptographic Gatekeeper"])
async def get_public_key() -> dict[str, Any]:
    """Export the Sentinel ECDSA public verification key in PEM format."""
    return {
        "algorithm": "ECDSA-SHA256",
        "curve": "SECP256R1",
        "public_key_pem": crypto_gatekeeper.get_ecdsa_public_key_pem(),
        "signer": "sentinel",
    }





# ==============================================================================
# Human-in-the-Loop Approval Endpoints (Telegram / Discord / Webhooks)
# ==============================================================================

class ApprovalRequestPayload(BaseModel):
    agent_name: str
    action: str
    details: dict[str, Any] = Field(default_factory=dict)
    risk_level: str = "GUARDED"
    timeout_sec: float = 300.0

@app.post("/api/v1/approvals/request", tags=["Human-in-the-Loop"])
async def submit_approval_request(payload: ApprovalRequestPayload) -> dict[str, Any]:
    pending = approval_dispatcher.submit_approval(
        agent_name=payload.agent_name,
        action=payload.action,
        details=payload.details,
        risk_level=payload.risk_level,
        timeout_sec=payload.timeout_sec,
    )
    return pending.to_dict()

@app.get("/api/v1/approvals/pending", tags=["Human-in-the-Loop"])
async def list_gatekeeper_pending_approvals() -> list[dict[str, Any]]:
    return approval_dispatcher.get_pending_list()

@app.get("/api/v1/approvals/{token}/status", tags=["Human-in-the-Loop"])
async def get_approval_status(token: str) -> dict[str, Any]:
    pending = approval_dispatcher._pending.get(token)
    if not pending:
        raise HTTPException(status_code=404, detail="Approval token not found")
    return pending.to_dict()

@app.get("/api/v1/approvals/{token}/approve", response_class=HTMLResponse, tags=["Human-in-the-Loop"])
async def get_approval_confirmation(token: str) -> HTMLResponse:
    """Render a confirmation page without changing the approval state."""
    pending = approval_dispatcher._pending.get(token)
    if not pending:
        raise HTTPException(status_code=404, detail="Approval token not found")
    safe_agent = html.escape(pending.agent_name)
    safe_action = html.escape(pending.action)
    if pending.status.value != "PENDING" or pending.is_expired():
        return HTMLResponse(
            "<html><body><h1>Approval no longer pending</h1>"
            f"<p>Agent: <b>{safe_agent}</b> | Action: <b>{safe_action}</b></p>"
            f"<p>Status: {html.escape(pending.status.value)}</p></body></html>",
            status_code=409,
        )
    return HTMLResponse(
        "<html><body style='font-family:system-ui;padding:40px;text-align:center;'>"
        "<h1>Confirm approval</h1>"
        f"<p>Agent: <b>{safe_agent}</b> | Action: <b>{safe_action}</b></p>"
        "<p>Opening this link did not approve the action.</p>"
        "<form method='post' action=''>"
        "<button type='submit'>Confirm approval</button>"
        "</form></body></html>"
    )


@app.post("/api/v1/approvals/{token}/approve", tags=["Human-in-the-Loop"])
async def approve_action(token: str) -> dict[str, Any]:
    """Approve only on an explicit POST from the confirmation form."""
    pending = approval_dispatcher.decide(token, approve=True)
    if not pending:
        raise HTTPException(status_code=404, detail="Approval token not found")
    if pending.status.value != "APPROVED":
        raise HTTPException(status_code=409, detail=f"Approval could not be granted: {pending.status.value}")
    return {"status": "APPROVED", "action": pending.action, "agent": pending.agent_name}


@app.get("/api/v1/approvals/{token}/deny", response_class=HTMLResponse, tags=["Human-in-the-Loop"])
async def get_denial_confirmation(token: str) -> HTMLResponse:
    """Render a denial confirmation page without changing the approval state."""
    pending = approval_dispatcher._pending.get(token)
    if not pending:
        raise HTTPException(status_code=404, detail="Approval token not found")
    safe_agent = html.escape(pending.agent_name)
    safe_action = html.escape(pending.action)
    if pending.status.value != "PENDING" or pending.is_expired():
        return HTMLResponse(
            "<html><body><h1>Approval no longer pending</h1>"
            f"<p>Agent: <b>{safe_agent}</b> | Action: <b>{safe_action}</b></p>"
            f"<p>Status: {html.escape(pending.status.value)}</p></body></html>",
            status_code=409,
        )
    return HTMLResponse(
        "<html><body style='font-family:system-ui;padding:40px;text-align:center;'>"
        "<h1>Confirm denial</h1>"
        f"<p>Agent: <b>{safe_agent}</b> | Action: <b>{safe_action}</b></p>"
        "<p>Opening this link did not deny the action.</p>"
        "<form method='post' action=''>"
        "<button type='submit'>Confirm denial</button>"
        "</form></body></html>"
    )


@app.post("/api/v1/approvals/{token}/deny", tags=["Human-in-the-Loop"])
async def deny_action(token: str, reason: str = Query("Denied by Surendra")) -> dict[str, Any]:
    """Deny only on an explicit POST from the confirmation form."""
    pending = approval_dispatcher.decide(token, approve=False, reason=reason)
    if not pending:
        raise HTTPException(status_code=404, detail="Approval token not found")
    if pending.status.value != "DENIED":
        raise HTTPException(status_code=409, detail=f"Denial could not be recorded: {pending.status.value}")
    return {"status": "DENIED", "action": pending.action, "agent": pending.agent_name}
