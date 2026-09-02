"""Sentinel Command Line Interface.

Provides uniform operator control matching the Task Gateway REST API.
"""

import asyncio

import httpx
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from sentinel.audit.audit_logger import AuditLogger
from sentinel.config.settings import get_settings
from sentinel.core.models import TaskMode
from sentinel.core.orchestrator.lifecycle import lifecycle_manager
from sentinel.core.policy.engine import policy_engine
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

    findings = finding_engine.list_findings(task_id=task_id)
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

@task_app.command("submit")
def task_submit(
    objective: str = typer.Option(..., "--objective", "-o", help="Security objective/goal"),  # noqa: B008
    target: list[str] = typer.Option(..., "--target", "-t", help="Target value (e.g. domain, IP, CIDR)"),  # noqa: B008
    mode: str = typer.Option("assessment", "--mode", "-m", help="Task mode"),  # noqa: B008
    output_type: str = typer.Option("comprehensive_report", "--output", help="Requested output type"),  # noqa: B008
):
    """Submit a security task into the Sentinel execution engine."""
    targets_payload = [{"type": "ip" if any(c.isdigit() for c in t) and "." in t and not t.endswith(".com") else "domain", "value": t} for t in target]

    try:
        task_mode = TaskMode(mode)
    except ValueError as err:
        console.print(f"[bold red]Invalid mode: {mode}. Must be one of {[m.value for m in TaskMode]}[/bold red]")
        raise typer.Exit(code=1) from err

    # Check if live Sentinel API server is running on port 8003
    try:
        with httpx.Client(base_url="http://127.0.0.1:8003", timeout=1.5) as client:
            resp = client.post("/api/v1/tasks", json={
                "objective": objective,
                "targets": targets_payload,
                "mode": task_mode.value,
                "requested_output": output_type,
            })
            if resp.status_code in (200, 201):
                data = resp.json()
                console.print("[bold green][OK] Task submitted to live Sentinel server![/bold green]")
                console.print(f"[bold]Task ID:[/bold] {data.get('task_id')}")
                console.print(f"[bold]Status:[/bold] {data.get('status', 'submitted')}")
                console.print(f"[bold]Correlation ID:[/bold] {data.get('correlation_id', 'N/A')}")
                return
    except Exception:
        pass

    task = asyncio.run(
        lifecycle_manager.create_and_submit_task(
            objective=objective,
            targets=targets_payload,
            mode=task_mode,
            requested_output_type=output_type,
        )
    )

    console.print("[bold green][OK] Task submitted successfully![/bold green]")
    console.print(f"[bold]Task ID:[/bold] {task.id}")
    console.print(f"[bold]Status:[/bold] {task.status.value}")
    console.print(f"[bold]Correlation ID:[/bold] {task.correlation_id}")


@task_app.command("status")
def task_status(task_id: str):
    """Check live status and progress of a task."""
    try:
        with httpx.Client(base_url="http://127.0.0.1:8003", timeout=1.5) as client:
            resp = client.get(f"/api/v1/tasks/{task_id}")
            if resp.status_code == 200:
                t = resp.json()
                table = Table(title=f"Live Task Status: {t.get('id')}")
                table.add_column("Property", style="cyan")
                table.add_column("Value", style="green")
                table.add_row("Objective", t.get("objective", ""))
                table.add_row("Status", str(t.get("status", "")).upper())
                table.add_row("Progress", f"{t.get('progress_percentage', 0)}%")
                table.add_row("Mode", str(t.get("mode", "")))
                table.add_row("Targets", str(len(t.get("target_set", {}).get("targets", []))))
                table.add_row("Correlation ID", t.get("correlation_id", ""))
                table.add_row("Created At", str(t.get("created_at", "")))
                console.print(table)
                return
    except Exception:
        pass

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
    """Immediately halt/kill a running security task."""
    try:
        with httpx.Client(base_url="http://127.0.0.1:8003", timeout=1.5) as client:
            resp = client.post(f"/api/v1/tasks/{task_id}/cancel?reason={reason}")
            if resp.status_code == 200:
                t = resp.json()
                console.print(f"[bold yellow][HALTED] Task {t.get('id')} execution halted on live server.[/bold yellow]")
                console.print(f"[bold]Final Status:[/bold] {t.get('status')}")
                return
    except Exception:
        pass

    try:
        task = asyncio.run(lifecycle_manager.cancel_task(task_id, reason=reason))
        console.print(f"[bold yellow][HALTED] Task {task.id} execution halted.[/bold yellow]")
        console.print(f"[bold]Final Status:[/bold] {task.status.value}")
    except KeyError as err:
        console.print(f"[bold red]Task {task_id} not found.[/bold red]")
        raise typer.Exit(code=1) from err


@task_app.command("findings")
def task_findings(task_id: str):
    """View findings registered for a task."""
    try:
        with httpx.Client(base_url="http://127.0.0.1:8003", timeout=1.5) as client:
            resp = client.get(f"/api/v1/tasks/{task_id}/findings")
            if resp.status_code == 200:
                findings = resp.json().get("findings", [])
                if not findings:
                    console.print(f"[bold green]No open vulnerabilities identified for task {task_id}.[/bold green]")
                    return
                table = Table(title=f"Findings for Task {task_id}")
                table.add_column("Finding ID", style="cyan")
                table.add_column("Severity", style="red")
                table.add_column("Title", style="yellow")
                table.add_column("Target", style="magenta")
                for f in findings:
                    table.add_row(f.get("id"), str(f.get("severity", "")).upper(), f.get("title", ""), f.get("target_ref", ""))
                console.print(table)
                return
    except Exception:
        pass

    findings = finding_engine.list_findings(task_id=task_id)
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
    findings = finding_engine.list_findings(task_id=task_id)
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
    findings = finding_engine.list_findings(task_id=task_id)
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
    pending = policy_engine.get_pending_approvals(task_id=task_id)
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
        record = asyncio.run(
            policy_engine.decide_approval(
                approval_id=approval_id,
                approve=approve,
                operator=operator,
                justification=justification,
            )
        )
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

    findings = finding_engine.list_findings(task_id=task_id)
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
