"""Container startup must not serve traffic after database migration failure."""

import os
import subprocess
from pathlib import Path

ENTRYPOINT = Path(__file__).resolve().parents[2] / "docker" / "entrypoint.sh"


def _write_command(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


def _run_entrypoint(
    tmp_path: Path,
    *,
    migration_status: int,
    port: str = "8000",
    max_http_concurrency: str = "256",
) -> tuple[subprocess.CompletedProcess[str], list[str]]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    events_path = tmp_path / "commands.log"
    _write_command(
        bin_dir / "alembic",
        "#!/bin/sh\nprintf 'alembic:%s\\n' \"$*\" >> \"$SENTINEL_TEST_EVENTS\"\n"
        "exit \"$MOCK_MIGRATION_STATUS\"\n",
    )
    _write_command(
        bin_dir / "uvicorn",
        "#!/bin/sh\nprintf 'uvicorn:%s\\n' \"$*\" >> \"$SENTINEL_TEST_EVENTS\"\n",
    )
    env = {
        **os.environ,
        "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
        "SENTINEL_STORAGE_BACKEND": "postgres",
        "SENTINEL_TEST_EVENTS": str(events_path),
        "MOCK_MIGRATION_STATUS": str(migration_status),
        "PORT": port,
        "SENTINEL_MAX_HTTP_CONCURRENCY": max_http_concurrency,
    }
    result = subprocess.run(
        ["bash", str(ENTRYPOINT)],
        capture_output=True,
        check=False,
        env=env,
        text=True,
        timeout=10,
    )
    events = events_path.read_text(encoding="utf-8").splitlines() if events_path.exists() else []
    return result, events


def test_migration_failure_prevents_api_startup(tmp_path):
    result, events = _run_entrypoint(tmp_path, migration_status=7)

    assert result.returncode == 7
    assert "Running database migrations" in result.stdout
    assert "migration warning" not in result.stdout.lower()
    assert events == ["alembic:upgrade head"]


def test_successful_migration_starts_api_afterward(tmp_path):
    result, events = _run_entrypoint(tmp_path, migration_status=0, port="8123")

    assert result.returncode == 0
    assert events == [
        "alembic:upgrade head",
        "uvicorn:sentinel.apps.api.main:app --host 0.0.0.0 --port 8123 --workers 1 --limit-concurrency 256",
    ]


def test_entrypoint_uses_configured_http_capacity_limit(tmp_path):
    result, events = _run_entrypoint(
        tmp_path,
        migration_status=0,
        max_http_concurrency="512",
    )

    assert result.returncode == 0
    assert events[-1].endswith("--limit-concurrency 512")
