"""Unit tests for Sentinel CLI application and commands."""

from typer.testing import CliRunner

from sentinel.apps.cli.main import app

runner = CliRunner()


def test_cli_status():
    result = runner.invoke(app, ["status"])
    assert result.exit_code == 0
    assert "SENTINEL" in result.output
    assert "Audit Hash Chain" in result.output


def test_cli_verify_audit():
    result = runner.invoke(app, ["verify-audit"])
    assert result.exit_code == 0
    assert "Audit log integrity verified" in result.output


def test_cli_report_not_found():
    result = runner.invoke(app, ["report", "nonexistent-task-99"])
    assert result.exit_code == 1
    assert "not found" in result.output.lower()


def test_cli_task_commands():
    # task list
    res_list = runner.invoke(app, ["task", "list"])
    assert res_list.exit_code == 0

    # task status not found
    res_status = runner.invoke(app, ["task", "status", "nonexistent-task-99"])
    assert res_status.exit_code == 1

    # task submit invalid mode
    res_sub_inv = runner.invoke(
        app,
        [
            "task",
            "submit",
            "-o",
            "Scan internal",
            "-t",
            "example.com",
            "-m",
            "invalid_mode",
            "--authorization-reference",
            "AUTH-1",
            "--authorized-by",
            "admin",
        ],
    )
    assert res_sub_inv.exit_code == 1


def test_cli_approval_and_findings():
    # approval list
    res_appr = runner.invoke(app, ["approval", "list"])
    assert res_appr.exit_code == 0

    # findings list
    res_find = runner.invoke(app, ["findings", "list"])
    assert res_find.exit_code == 0


def test_cli_recon_and_evidence():
    # recon surface
    res_recon = runner.invoke(app, ["recon", "surface", "task-dummy-cli"])
    assert res_recon.exit_code == 0

    # evidence export
    res_ev = runner.invoke(app, ["evidence", "export", "task-dummy-cli"])
    assert res_ev.exit_code == 0
