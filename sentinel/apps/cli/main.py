"""Sentinel Command Line Interface."""

import typer
from rich.console import Console
from rich.table import Table

from sentinel.audit.audit_logger import AuditLogger
from sentinel.config.settings import get_settings

app = typer.Typer(
    name="sentinel",
    help="SENTINEL — Unified Autonomous Cybersecurity Platform CLI",
    add_completion=False
)
console = Console(legacy_windows=False)


@app.command()
def status():
    """Display Sentinel platform status and module matrix."""
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


if __name__ == "__main__":
    app()
