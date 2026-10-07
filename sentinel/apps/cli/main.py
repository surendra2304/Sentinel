"""Sentinel Command Line Interface.

Provides uniform operator control matching the Task Gateway REST API.
"""

import asyncio
import os
from datetime import UTC, datetime, timedelta
from urllib.parse import quote, urlparse

import httpx
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from sentinel.audit.audit_logger import AuditLogger
from sentinel.config.settings import get_settings
from sentinel.core.models import ImpactLevel, TaskMode
from sentinel.core.orchestrator.lifecycle import lifecycle_manager
from sentinel.core.policy.engine import ApprovalRecord, policy_engine
from sentinel.intelligence.attack_paths.analyzer import attack_path_analyzer
from sentinel.intelligence.recommendations.engine import recommendation_engine
from sentinel.intelligence.reporting.generator import ReportType, report_generator
from sentinel.intelligence.risk.finding_engine import finding_engine
from sentinel.intelligence.risk.risk_engine import risk_engine
from sentinel.modules.recon.graph import asset_graph_store
from sentinel.storage.evidence.store import evidence_store

app = typer.Typer(
    name="sentinel",
    help="SENTINEL — Unified Autonomous Cybersecurity Platform CLI",
    add_completion=False,
)
task_app = typer.Typer(help="Task lifecycle management commands")
app.add_typer(task_app, name="task")

approval_app = typer.Typer(help="Policy approvals and governance gates")
app.add_typer(approval_app, name="approval")

findings_app = typer.Typer(help="Findings and Vulnerability intelligence")
app.add_typer(findings_app, name="findings")

evidence_app = typer.Typer(help="Evidence artifacts and chain of custody")
app.add_typer(evidence_app, name="evidence")

recon_app = typer.Typer(help="Reconnaissance and Attack Surface intelligence")
app.add_typer(recon_app, name="recon")

console = Console(legacy_windows=False)


def _configured_remote_api_request(
    method: str,
    path: str,
    *,
    params: dict[str, str] | None = None,
    timeout: float = 10.0,
) -> httpx.Response | None:
    """Call the operator-configured API; return None when remote mode is disabled."""
    settings = get_settings()
    api_url = (os.getenv("SENTINEL_API_URL") or settings.api_url).strip().rstrip("/")
    api_key = (os.getenv("SENTINEL_API_KEY") or settings.api_key.get_secret_value()).strip()
    if not api_url and not api_key:
        return None
    if not api_url or not api_key:
        console.print("[bold red]Set both SENTINEL_API_URL and SENTINEL_API_KEY for remote API access.[/bold red]")
        raise typer.Exit(code=1)

    parsed_url = urlparse(api_url)
    if parsed_url.scheme not in {"http", "https"} or not parsed_url.hostname:
        console.print("[bold red]SENTINEL_API_URL must be an absolute HTTP(S) URL.[/bold red]")
        raise typer.Exit(code=1)
    if parsed_url.scheme != "https" and parsed_url.hostname not in {"localhost", "127.0.0.1", "::1"}:
        console.print("[bold red]Remote API URLs must use HTTPS (HTTP is allowed only for loopback).[/bold red]")
        raise typer.Exit(code=1)

    try:
        with httpx.Client(
            base_url=api_url,
            headers={"X-API-Key": api_key},
            timeout=timeout,
        ) as client:
            return client.request(method, path, params=params)
    except (httpx.HTTPError, ValueError) as err:
        console.print(f"[bold red]Configured remote API request failed: {err}[/bold red]")
        raise typer.Exit(code=1) from err


def _remote_api_error(response: httpx.Response) -> None:
    console.print(f"[bold red]Configured remote API rejected the request (HTTP {response.status_code}).[/bold red]")
    raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# Core Platform Commands
# ---------------------------------------------------------------------------

@app.command()
def status():
    """Display Sentinel platform status and module availability matrix."""
    settings = get_settings()
    audit_logger = AuditLogger(log_path=settings.audit.log_file_path, signing_key=settings.audit.signing_key)

    console.print("\n[bold cyan][SENTINEL] CYBERSECURITY PLATFORM[/bold cyan]\n")
    console.print(f"[bold]Environment:[/bold] {settings.environment.value}")
    console.print(f"[bold]Kill Switch Active:[/bold] {'[red]YES[/red]' if settings.kill_switch_active else '[green]NO[/green]'}")
    console.print(f"[bold]Audit Hash Chain:[/bold] {'[green]VALID[/green]' if audit_logger.verify_integrity() else '[red]CORRUPTED[/red]'}")

    table = Table(title="Module Availability Matrix")
    table.add_column("Module", style="cyan")
    table.add_column("Status", style="green")

    for mod, enabled in settings.modules.model_dump().items():
        table.add_row(mod.replace("_", " ").upper(), "[green]ENABLED[/green]" if enabled else "[red]DISABLED[/red]")

    console.print(table)


@app.command()
def verify_audit():
    """Verify cryptographic integrity of the append-only audit trail."""
    settings = get_settings()
    audit = AuditLogger(log_path=settings.audit.log_file_path, signing_key=settings.audit.signing_key)
    is_valid = audit.verify_integrity()
    if is_valid:
        console.print("[bold green][OK] Audit log integrity verified: Hash chain and HMAC signatures are valid.[/bold green]")
    else:
        console.print("[bold red][FAIL] Audit log integrity check failed: Tampering or discontinuity detected![/bold red]")
        raise typer.Exit(code=1)


@app.command()
def report(task_id: str):
    """View generated security assessment report for a task."""
    task = asyncio.run(lifecycle_manager.get_task(task_id))
    if not task:
        console.print(f"[bold red]Task {task_id} not found.[/bold red]")
        raise typer.Exit(code=1)

    findings = asyncio.run(finding_engine.list_findings_async(task_id=task_id))
    risk_summary = risk_engine.get_task_risk_summary(task_id, findings)
    attack_surface = asset_graph_store.get_task_attack_surface(task_id)

    panel = Panel(
        f"[bold]Task Objective:[/bold] {task.objective}\n"
        f"[bold]Status:[/bold] {task.status.value.upper()}\n"
        f"[bold]Mode:[/bold] {task.mode.value}\n"
        f"[bold]Targets Assessed:[/bold] {len(task.target_set.targets)}\n"
        f"[bold]Attack Surface Assets:[/bold] {attack_surface.total_nodes} nodes, {attack_surface.total_edges} edges\n"
        f"[bold]Total Findings:[/bold] {len(findings)}\n"
        f"[bold]Overall Risk Score:[/bold] {risk_summary.overall_risk_score} ([bold yellow]{risk_summary.highest_risk_tier.value.upper()}[/bold yellow])\n\n"
        f"[bold cyan]Findings Summary:[/bold cyan]\n"
        f"Critical: {risk_summary.severity_counts.get('critical',0)} | "
        f"High: {risk_summary.severity_counts.get('high',0)} | "
        f"Medium: {risk_summary.severity_counts.get('medium',0)} | "
        f"Low: {risk_summary.severity_counts.get('low',0)}",
        title=f"Security Assessment Report — {task.id}",
        border_style="cyan",
    )
    console.print(panel)


# ---------------------------------------------------------------------------
# Task Sub-commands
# ---------------------------------------------------------------------------

def _detect_target_type(val: str) -> str:
    s = val.strip()
    if s.lower().startswith(("http://", "https://")):
        return "url"
    if "/" in s:
        return "cidr"
    import ipaddress
    try:
        ipaddress.ip_address(s)
        return "ip"
    except ValueError:
        return "domain"


@task_app.command("submit")
def task_submit(
    objective: str = typer.Option(..., "--objective", "-o", help="Security objective/goal"),  # noqa: B008
    target: list[str] = typer.Option(..., "--target", "-t", help="Target value (e.g. domain, IP, CIDR, URL)"),  # noqa: B008
    mode: str = typer.Option("assessment", "--mode", "-m", help="Task mode"),  # noqa: B008
    output_type: str = typer.Option("comprehensive_report", "--output", help="Requested output type"),  # noqa: B008
    authorization_reference: str = typer.Option(..., "--authorization-reference", help="Written authorization or change-ticket reference"),  # noqa: B008
    authorized_by: str = typer.Option(..., "--authorized-by", help="Owner/operator who authorized this assessment"),  # noqa: B008
    window_hours: int = typer.Option(8, "--window-hours", min=1, max=168, help="Authorization window duration in hours"),  # noqa: B008
    maximum_impact: str = typer.Option("low", "--maximum-impact", help="Maximum authorized impact: low, medium, high, critical"),  # noqa: B008
    allow_third_party_enrichment: bool = typer.Option(
        False,
        "--allow-third-party-enrichment",
        help="Allow target metadata to be sent to third-party OSINT enrichment services.",
    ),  # noqa: B008
):
    """Submit a task with explicit written authorization and bounded scope."""
    targets_payload = [{"type": _detect_target_type(t), "value": t.strip()} for t in target]

    try:
        task_mode = TaskMode(mode)
    except ValueError as err:
        console.print(f"[bold red]Invalid mode: {mode}. Must be one of {[m.value for m in TaskMode]}[/bold red]")
        raise typer.Exit(code=1) from err

    try:
        impact_ceiling = ImpactLevel(maximum_impact.strip().lower())
    except ValueError as err:
        choices = ", ".join(level.value for level in ImpactLevel)
        console.print(f"[bold red]Invalid maximum impact: {maximum_impact}. Choose one of {choices}.[/bold red]")
        raise typer.Exit(code=1) from err

    now = datetime.now(UTC)
    scope_data = {
        "owner": authorized_by.strip(),
        "written_authorization_reference": authorization_reference.strip(),
        "allowed_targets": [item["value"] for item in targets_payload],
        "allowed_methods": ["passive_recon", "discovery", "validation"],
        "time_window": {
            "start_time": now.isoformat(),
            "end_time": (now + timedelta(hours=window_hours)).isoformat(),
        },
        "rate_limit": 50,
        "maximum_impact": impact_ceiling.value,
        "offensive_actions_enabled": False,
        "authorization": {
            "allow_third_party_enrichment": allow_third_party_enrichment,
        },
    }
    if not scope_data["owner"] or not scope_data["written_authorization_reference"]:
        console.print("[bold red]Owner and written authorization reference must not be empty.[/bold red]")
        raise typer.Exit(code=1)

    request_payload = {
        "objective": objective,
        "targets": targets_payload,
        "scope": scope_data,
        "mode": task_mode.value,
        "requested_output": output_type,
    }

    # Remote submission is opt-in and uses only an operator-configured endpoint/key.
    settings = get_settings()
    api_url = (os.getenv("SENTINEL_API_URL") or settings.api_url).strip().rstrip("/")
    api_key = (os.getenv("SENTINEL_API_KEY") or settings.api_key.get_secret_value()).strip()
    if bool(api_url) != bool(api_key):
        console.print("[bold red]Set both SENTINEL_API_URL and SENTINEL_API_KEY for remote submission.[/bold red]")
        raise typer.Exit(code=1)

    if api_url and api_key:
        parsed_url = urlparse(api_url)
        if parsed_url.scheme != "https" and parsed_url.hostname not in {"localhost", "127.0.0.1", "::1"}:
            console.print("[bold red]Remote API URLs must use HTTPS (HTTP is allowed only for loopback).[/bold red]")
            raise typer.Exit(code=1)
        try:
            with httpx.Client(
                base_url=api_url,
                headers={"X-API-Key": api_key},
                timeout=10.0,
            ) as client:
                response = client.post(f"{settings.api_prefix.rstrip('/')}/tasks", json=request_payload)
        except (httpx.HTTPError, ValueError) as err:
            console.print(f"[bold red]Remote task submission failed: {err}[/bold red]")
            raise typer.Exit(code=1) from err

        if response.status_code not in (200, 201):
            console.print(f"[bold red]Remote task submission rejected (HTTP {response.status_code}).[/bold red]")
            raise typer.Exit(code=1)
        data = response.json()
        console.print("[bold green][OK] Task submitted to configured Sentinel API.[/bold green]")
        console.print(f"[bold]Task ID:[/bold] {data.get('task_id')}")
        console.print(f"[bold]Status:[/bold] {data.get('status', 'submitted')}")
        console.print(f"[bold]Correlation ID:[/bold] {data.get('correlation_id', 'N/A')}")
        return

    task = asyncio.run(
        lifecycle_manager.create_and_submit_task(
            objective=objective,
            targets=targets_payload,
            scope_data=scope_data,
            mode=task_mode,
            requested_output_type=output_type,
        )
    )

    console.print("[bold green][OK] Task submitted successfully![/bold green]")
    console.print(f"[bold]Task ID:[/bold] {task.id}")
    console.print(f"[bold]Status:[/bold] {task.status.value}")
    console.print(f"[bold]Correlation ID:[/bold] {task.correlation_id}")


@task_app.command("list")
def task_list():
    """List locally or durably stored assessment tasks."""
    tasks = asyncio.run(lifecycle_manager.list_tasks())
    if not tasks:
        console.print("No tasks found.")
        return

    table = Table(title="Sentinel Tasks")
    table.add_column("Task ID", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Mode")
    table.add_column("Progress", justify="right")
    table.add_column("Objective")
    for task in tasks:
        table.add_row(
            task.id,
            task.status.value,
            task.mode.value,
            f"{task.progress_percentage:.1f}%",
            task.objective,
        )
    console.print(table)


@task_app.command("status")
def task_status(task_id: str):
    """Check status and progress from the configured API or local store."""
    api_prefix = get_settings().api_prefix.rstrip("/")
    response = _configured_remote_api_request("GET", f"{api_prefix}/tasks/{quote(task_id, safe='')}")
    if response is not None:
        if response.status_code != 200:
            _remote_api_error(response)
        try:
            task_data = response.json()
        except ValueError as err:
            console.print("[bold red]Configured remote API returned invalid JSON.[/bold red]")
            raise typer.Exit(code=1) from err
        table = Table(title=f"Remote Task Status: {task_data.get('id', task_id)}")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")
        table.add_row("Objective", task_data.get("objective", ""))
        table.add_row("Status", str(task_data.get("status", "")).upper())
        table.add_row("Progress", f"{task_data.get('progress_percentage', 0)}%")
        table.add_row("Mode", str(task_data.get("mode", "")))
        table.add_row("Targets", str(len(task_data.get("target_set", {}).get("targets", []))))
        table.add_row("Correlation ID", task_data.get("correlation_id", ""))
        table.add_row("Created At", str(task_data.get("created_at", "")))
        console.print(table)
        return

    task = asyncio.run(lifecycle_manager.get_task(task_id))
    if not task:
        console.print(f"[bold red]Task {task_id} not found.[/bold red]")
        raise typer.Exit(code=1)

    table = Table(title=f"Task Status: {task.id}")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Objective", task.objective)
    table.add_row("Status", task.status.value.upper())
    table.add_row("Progress", f"{task.progress_percentage}%")
    table.add_row("Mode", task.mode.value)
    table.add_row("Targets", str(len(task.target_set.targets)))
    table.add_row("Correlation ID", task.correlation_id)
    table.add_row("Created At", task.created_at.isoformat())

    console.print(table)


@task_app.command("cancel")
def task_cancel(
    task_id: str,
    reason: str = typer.Option("Operator Kill Switch", "--reason", "-r", help="Cancellation rationale"),  # noqa: B008
):
    """Immediately halt a running task through the configured API or local store."""
    api_prefix = get_settings().api_prefix.rstrip("/")
    response = _configured_remote_api_request(
        "POST",
        f"{api_prefix}/tasks/{quote(task_id, safe='')}/cancel",
        params={"reason": reason},
    )
    if response is not None:
        if response.status_code != 200:
            _remote_api_error(response)
        try:
            task_data = response.json()
        except ValueError as err:
            console.print("[bold red]Configured remote API returned invalid JSON.[/bold red]")
            raise typer.Exit(code=1) from err
        remote_task_id = task_data.get("task_id", task_data.get("id", task_id))
        console.print(f"[bold yellow][HALTED] Task {remote_task_id} execution halted on configured server.[/bold yellow]")
        console.print(f"[bold]Final Status:[/bold] {task_data.get('status')}")
        return

    try:
        task = asyncio.run(lifecycle_manager.cancel_task(task_id, reason=reason))
        console.print(f"[bold yellow][HALTED] Task {task.id} execution halted.[/bold yellow]")
        console.print(f"[bold]Final Status:[/bold] {task.status.value}")
    except KeyError as err:
        console.print(f"[bold red]Task {task_id} not found.[/bold red]")
        raise typer.Exit(code=1) from err


@task_app.command("findings")
def task_findings(task_id: str):
    """View task findings from the configured API or local store."""
    api_prefix = get_settings().api_prefix.rstrip("/")
    response = _configured_remote_api_request(
        "GET",
        f"{api_prefix}/tasks/{quote(task_id, safe='')}/findings",
    )
    if response is not None:
        if response.status_code != 200:
            _remote_api_error(response)
        try:
            response_data = response.json()
            findings = response_data.get("findings", [])
        except (AttributeError, ValueError) as err:
            console.print("[bold red]Configured remote API returned an invalid findings response.[/bold red]")
            raise typer.Exit(code=1) from err
        if not findings:
            console.print(f"[bold green]No open vulnerabilities identified for task {task_id}.[/bold green]")
            return
        table = Table(title=f"Findings for Task {task_id}")
        table.add_column("Finding ID", style="cyan")
        table.add_column("Severity", style="red")
        table.add_column("Title", style="yellow")
        table.add_column("Target", style="magenta")
        for finding in findings:
            table.add_row(
                str(finding.get("id", "")),
                str(finding.get("severity", "")).upper(),
                str(finding.get("title", "")),
                str(finding.get("target_ref", "")),
            )
        console.print(table)
        return

    findings = asyncio.run(finding_engine.list_findings_async(task_id=task_id))
    if not findings:
        console.print(f"[bold green]No open vulnerabilities identified for task {task_id}.[/bold green]")
        return

    table = Table(title=f"Findings for Task {task_id}")
    table.add_column("Finding ID", style="cyan")
    table.add_column("Severity", style="red")
    table.add_column("Title", style="yellow")
    table.add_column("Target", style="magenta")

    for f in findings:
        table.add_row(f.id, f.severity.value.upper(), f.title, f.target_ref)

    console.print(table)


# ---------------------------------------------------------------------------
# Findings Commands
# ---------------------------------------------------------------------------

@findings_app.command("list")
def findings_list(task_id: str | None = typer.Option(None, "--task", "-t", help="Filter by Task ID")):  # noqa: B008
    """List security findings."""
    findings = asyncio.run(finding_engine.list_findings_async(task_id=task_id))
    if not findings:
        console.print("[bold green]No findings recorded for this query.[/bold green]")
        return

    table = Table(title="Security Findings")
    table.add_column("Finding ID", style="cyan")
    table.add_column("Severity", style="red")
    table.add_column("Title", style="yellow")
    table.add_column("Target", style="magenta")
    table.add_column("Evidence Refs", style="blue")

    for f in findings:
        table.add_row(f.id, f.severity.value.upper(), f.title, f.target_ref, str(len(f.evidence_refs)))

    console.print(table)


# ---------------------------------------------------------------------------
# Reconnaissance & Attack Surface Commands
# ---------------------------------------------------------------------------

@recon_app.command("surface")
def recon_surface(task_id: str = typer.Argument(..., help="Task ID")):
    """View discovered attack surface graph and asset inventory."""
    report = asset_graph_store.get_task_attack_surface(task_id)
    if report.total_nodes == 0:
        console.print(f"[bold yellow]No attack surface graph nodes recorded for task {task_id}.[/bold yellow]")
        return

    table = Table(title=f"Attack Surface Map: {task_id}")
    table.add_column("Node Type", style="cyan")
    table.add_column("Asset / Label", style="green")
    table.add_column("Internet-Facing", style="magenta")

    for n in report.nodes:
        table.add_row(n.node_type.value.upper(), n.label, "YES" if n.is_internet_facing else "NO")

    console.print(table)
    console.print(f"\n[bold]Total Nodes:[/bold] {report.total_nodes} | [bold]Total Edges:[/bold] {report.total_edges}")
    console.print(f"[bold]Technologies:[/bold] {', '.join(report.technologies) if report.technologies else 'None'}")


# ---------------------------------------------------------------------------
# Evidence Commands
# ---------------------------------------------------------------------------

@evidence_app.command("export")
def evidence_export(
    task_id: str = typer.Argument(..., help="Task ID"),
    output_file: str | None = typer.Option(None, "--output", "-o", help="Optional output zip file path"),
):
    """Export self-contained, hash-verified evidence zip bundle."""
    findings = asyncio.run(finding_engine.list_findings_async(task_id=task_id))
    finding_map = {f.id: f.evidence_refs for f in findings}
    zip_bytes = asyncio.run(evidence_store.create_evidence_zip_bundle(task_id=task_id, finding_links=finding_map))
    out_path = output_file or f"evidence-bundle-{task_id}.zip"
    with open(out_path, "wb") as f:
        f.write(zip_bytes)
    console.print(f"[bold green][OK] Exported evidence bundle for task {task_id} to {out_path}[/bold green]")
    console.print(f"[bold]Total Size:[/bold] {len(zip_bytes)} bytes")


@evidence_app.command("verify")
def evidence_verify(
    bundle_path: str = typer.Argument(..., help="Path to evidence bundle zip file"),
):
    """Verify cryptographic integrity of an evidence bundle zip archive."""
    try:
        res = evidence_store.verify_evidence_zip_bundle(bundle_path)
        console.print(f"[bold green][PASS] Evidence bundle '{bundle_path}' verified successfully.[/bold green]")
        console.print(f"[bold]Task ID:[/bold] {res['task_id']}")
        console.print(f"[bold]Verified Artifacts:[/bold] {res['verified_records']}")
        console.print(f"[bold]Manifest Hash:[/bold] {res['manifest_hash']}")
    except Exception as exc:
        console.print(f"[bold red][FAIL] Tamper or corruption detected: {exc}[/bold red]")
        raise typer.Exit(code=1) from exc


# ---------------------------------------------------------------------------
# Approval Commands
# ---------------------------------------------------------------------------

@approval_app.command("list")
def approval_list(task_id: str | None = typer.Option(None, "--task", "-t", help="Filter by Task ID")):  # noqa: B008
    """List pending approvals requiring operator intervention."""
    pending = asyncio.run(policy_engine.list_pending_approvals(task_id=task_id))
    if not pending:
        console.print("[bold green]No pending approvals requiring authorization.[/bold green]")
        return

    table = Table(title="Pending Human Approval Requests")
    table.add_column("Approval ID", style="cyan")
    table.add_column("Task ID", style="magenta")
    table.add_column("Action Type", style="yellow")
    table.add_column("Requested By", style="blue")
    table.add_column("Expires At", style="red")

    for p in pending:
        table.add_row(p.approval_id, p.task_id, p.action_type, p.requested_by, p.expires_at.isoformat())

    console.print(table)


@approval_app.command("decide")
def approval_decide(
    approval_id: str = typer.Argument(..., help="Approval ID"),
    approve: bool = typer.Option(..., "--approve/--deny", help="Approve or Deny the action"),  # noqa: B008
    operator: str = typer.Option("operator", "--operator", "-u", help="Operator username/identity"),  # noqa: B008
    justification: str = typer.Option(..., "--justification", "-j", help="Operator justification / reason"),  # noqa: B008
):
    """Approve or deny an action approval request."""
    try:
        async def decide_and_resume() -> ApprovalRecord:
            decided = await policy_engine.decide_approval(
                approval_id=approval_id,
                approve=approve,
                operator=operator,
                justification=justification,
            )
            await lifecycle_manager.resolve_approval(decided)
            return decided

        record = asyncio.run(decide_and_resume())
        status_label = "[bold green]APPROVED[/bold green]" if approve else "[bold red]DENIED[/bold red]"
        console.print(f"\nApproval {record.approval_id} has been {status_label}.")
        console.print(f"[bold]Operator:[/bold] {record.approved_by}")
        console.print(f"[bold]Justification:[/bold] {record.justification_provided}")
    except Exception as e:
        console.print(f"[bold red]Failed to decide approval:[/bold red] {e}")
        raise typer.Exit(code=1) from e


# ---------------------------------------------------------------------------
# Report Commands
# ---------------------------------------------------------------------------

@app.command("report")
def generate_report(
    task_id: str = typer.Argument(..., help="Task ID"),
    report_type: str = typer.Option("technical", "--type", "-t", help="Report type: executive, technical, soc_ir, json"),  # noqa: B008
    format: str = typer.Option("md", "--format", "-f", help="Output format: md, html, json"),  # noqa: B008
):
    """Generate and display or export security assessment reports."""
    task = asyncio.run(lifecycle_manager.get_task(task_id))
    if not task:
        console.print(f"[bold red]Task {task_id} not found.[/bold red]")
        raise typer.Exit(code=1)

    findings = asyncio.run(finding_engine.list_findings_async(task_id=task_id))
    attack_paths = attack_path_analyzer.analyze_paths(asset_graph_store, findings)
    recommendations = recommendation_engine.generate_recommendations(findings, attack_paths)

    try:
        rep_enum = ReportType(report_type.lower())
    except ValueError:
        rep_enum = ReportType.TECHNICAL

    report = report_generator.generate_report(
        task=task,
        findings=findings,
        attack_paths=attack_paths,
        recommendations=recommendations,
        report_type=rep_enum,
    )

    fmt_lower = format.lower()
    if fmt_lower in ("md", "markdown"):
        content = report_generator.render_markdown(report)
        console.print(content)
    elif fmt_lower == "html":
        content = report_generator.render_html(report)
        console.print(content)
    elif fmt_lower == "pdf":
        pdf_bytes = report_generator.render_pdf(report)
        pdf_out = f"sentinel-report-{task_id}.pdf"
        with open(pdf_out, "wb") as f:
            f.write(pdf_bytes)
        console.print(f"[bold green][OK] Rendered and saved PDF report to {pdf_out} ({len(pdf_bytes)} bytes)[/bold green]")
    else:
        content = report_generator.export_machine_json(report)
        console.print(content)


if __name__ == "__main__":
    app()
