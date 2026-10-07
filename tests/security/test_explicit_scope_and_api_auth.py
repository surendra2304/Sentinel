"""Regression coverage for deployed API authentication and explicit authorization scope."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import httpx
import pytest
import yaml
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from sentinel.apps.api import main as api_main
from sentinel.apps.api.main import app
from sentinel.apps.cli import main as cli_main
from sentinel.audit.audit_logger import AuditLogger
from sentinel.config.settings import ObjectStorageSettings, Settings
from sentinel.core.models import SeverityLevel
from sentinel.intelligence.risk.finding_engine import FindingEngine, Observation
from sentinel.storage.artifacts.storage import LocalFileSystemStorage
from sentinel.storage.evidence.store import EvidenceStore


def test_api_authentication_can_be_required_without_render_platform(monkeypatch):
    monkeypatch.delenv("RENDER", raising=False)
    monkeypatch.setenv("SENTINEL_API_AUTH_REQUIRED", "true")
    monkeypatch.delenv("SENTINEL_API_KEY", raising=False)
    client = TestClient(app)

    unconfigured = client.get("/api/v1/tasks")
    assert unconfigured.status_code == 503
    assert unconfigured.json()["error"] == "service_auth_unconfigured"

    api_key = "deployment-specific-api-key-with-more-than-32-characters"
    monkeypatch.setenv("SENTINEL_API_KEY", api_key)
    assert client.get("/api/v1/tasks").status_code == 401
    assert client.get("/api/v1/tasks", headers={"X-API-Key": "incorrect"}).status_code == 403
    assert client.get("/api/v1/tasks", headers={"X-API-Key": api_key}).status_code == 200


def test_inference_proxy_requires_explicit_remote_url(monkeypatch):
    monkeypatch.setenv("SENTINEL_API_AUTH_REQUIRED", "false")
    monkeypatch.setenv("INFERENCE_API_KEY", "test-only-inference-key")
    monkeypatch.delenv("INFERENCE_URL", raising=False)

    def reject_unconfigured_client():
        raise AssertionError("unconfigured inference URL must not create a client")

    monkeypatch.setattr(api_main, "_get_sentinel_inf_client", reject_unconfigured_client)
    response = TestClient(app).post("/api/v1/ask-inference", json={"question": "test question"})

    assert response.status_code == 503
    assert "INFERENCE_URL is not configured" in response.json()["detail"]


def test_production_compose_requires_api_authentication_and_key():
    compose_path = Path(__file__).resolve().parents[2] / "docker-compose.production.yml"
    production = yaml.safe_load(compose_path.read_text(encoding="utf-8"))
    environment = production["services"]["api"]["environment"]

    assert environment["SENTINEL_ENVIRONMENT"] == "production"
    assert environment["SENTINEL_API_AUTH_REQUIRED"] == "true"
    assert environment["SENTINEL_API_KEY"].startswith("${SENTINEL_API_KEY:?")
    assert environment["SENTINEL_CAPABILITY_SIGNING_KEY"].startswith("${SENTINEL_CAPABILITY_SIGNING_KEY:?")
    assert environment["SENTINEL_MAX_HTTP_CONCURRENCY"] == "${SENTINEL_MAX_HTTP_CONCURRENCY:-256}"
    assert environment["SENTINEL_MAX_HEALTH_CONCURRENCY"] == "${SENTINEL_MAX_HEALTH_CONCURRENCY:-16}"
    assert production["services"]["api"]["ports"] == ["127.0.0.1:8000:8000"]
    assert {"postgres_data", "minio_data", "audit_logs"} <= set(production["volumes"])
    assert not {"worker", "redis", "nginx"} & set(production["services"])

    development_path = Path(__file__).resolve().parents[2] / "docker-compose.yml"
    development = yaml.safe_load(development_path.read_text(encoding="utf-8"))
    minio_healthcheck = " ".join(development["services"]["sentinel-minio"]["healthcheck"]["test"])
    assert "http://localhost:9000/minio/health/live" in minio_healthcheck
    assert "onrender.com" not in minio_healthcheck
    api_environment = development["services"]["sentinel-api"]["environment"]
    assert api_environment["SENTINEL_STORAGE_BACKEND"] == "postgres"
    assert api_environment["SENTINEL_S3_BACKEND"] == "s3"
    assert api_environment["SENTINEL_MAX_HTTP_CONCURRENCY"] == "${SENTINEL_MAX_HTTP_CONCURRENCY:-256}"
    assert api_environment["SENTINEL_MAX_HEALTH_CONCURRENCY"] == "${SENTINEL_MAX_HEALTH_CONCURRENCY:-16}"

    dashboard_proxy = Path(__file__).resolve().parents[2] / "apps" / "dashboard" / "nginx.conf"
    proxy_config = dashboard_proxy.read_text(encoding="utf-8")
    assert "proxy_pass http://sentinel-api:8000" in proxy_config
    assert "proxy_buffering off" in proxy_config


def test_unconfigured_s3_endpoint_defaults_to_local(monkeypatch):
    monkeypatch.delenv("SENTINEL_S3_ENDPOINT", raising=False)
    assert ObjectStorageSettings(_env_file=None).endpoint == "localhost:9000"


def test_request_capacity_limits_are_configurable(monkeypatch):
    monkeypatch.setenv("SENTINEL_MAX_HTTP_CONCURRENCY", "32")
    monkeypatch.setenv("SENTINEL_MAX_HEALTH_CONCURRENCY", "4")

    settings = Settings(_env_file=None)

    assert settings.max_http_concurrency == 32
    assert settings.max_health_concurrency == 4


def test_task_submission_rejects_missing_or_synthetic_scope(monkeypatch):
    monkeypatch.delenv("RENDER", raising=False)
    monkeypatch.setenv("SENTINEL_API_AUTH_REQUIRED", "false")
    monkeypatch.delenv("SENTINEL_API_KEY", raising=False)
    client = TestClient(app)
    base_payload = {
        "objective": "explicit scope regression",
        "targets": [{"type": "domain", "value": "authorized.invalid"}],
        "mode": "assessment",
    }

    missing_scope = client.post("/api/v1/tasks", json=base_payload)
    assert missing_scope.status_code == 422

    synthetic_scope = {
        **base_payload,
        "scope": {
            "id": "scope-missing-auth",
            "name": "scope missing authorization",
            "allowed_targets": ["authorized.invalid"],
        },
    }
    rejected_scope = client.post("/api/v1/tasks", json=synthetic_scope)
    assert rejected_scope.status_code == 422
    assert "actual authorizing owner" in rejected_scope.json()["detail"]


def test_task_submission_rejects_targets_outside_explicit_scope(monkeypatch):
    monkeypatch.delenv("RENDER", raising=False)
    monkeypatch.setenv("SENTINEL_API_AUTH_REQUIRED", "false")
    monkeypatch.delenv("SENTINEL_API_KEY", raising=False)
    client = TestClient(app)
    now = datetime.now(UTC)
    payload = {
        "objective": "target-binding regression",
        "targets": [{"type": "domain", "value": "outside.invalid"}],
        "mode": "assessment",
        "scope": {
            "id": "scope-target-binding",
            "name": "scope binds another domain",
            "owner": "operator@example.invalid",
            "written_authorization_reference": "CHG-SEC-2026-42",
            "allowed_targets": ["authorized.invalid"],
            "allowed_methods": ["passive_recon", "discovery"],
            "time_window": {
                "start_time": (now - timedelta(minutes=1)).isoformat(),
                "end_time": (now + timedelta(hours=1)).isoformat(),
            },
            "rate_limit": 25,
            "maximum_impact": "low",
        },
    }

    response = client.post("/api/v1/tasks", json=payload)
    assert response.status_code == 422
    assert "outside the explicit scope" in response.json()["detail"]


@pytest.mark.asyncio
async def test_finding_rejects_missing_or_cross_task_evidence_references(tmp_path):
    audit = AuditLogger(str(tmp_path / "evidence-first-audit.jsonl"), signing_key="evidence-first-test-key")
    engine = FindingEngine(audit_logger=audit)
    evidence_store_for_test = EvidenceStore(
        storage=LocalFileSystemStorage(str(tmp_path / "evidence-first-artifacts")),
        audit_logger=audit,
    )
    evidence = await evidence_store_for_test.record_evidence(
        task_id="evidence-owner-task",
        target_ref="authorized.invalid",
        source_agent="test-agent",
        source_module="test",
        source_tool="fixture",
        raw_data=b"valid test evidence",
        content_type="text/plain",
    )

    base_observation = {
        "target_ref": "authorized.invalid",
        "source_module": "test",
        "title": "Evidence reference validation",
        "description": "The referenced evidence must exist and belong to this task.",
        "severity": SeverityLevel.HIGH,
    }
    with pytest.raises(ValueError, match="does not exist"):
        await engine.ingest_observation(
            Observation(task_id="evidence-owner-task", evidence_refs=["evi-does-not-exist"], **base_observation)
        )

    with pytest.raises(ValueError, match="belongs to another task"):
        await engine.ingest_observation(
            Observation(task_id="different-task", evidence_refs=[evidence.id], **base_observation)
        )


def test_cli_exposes_task_list_command(monkeypatch):
    async def fake_list_tasks():
        return []

    monkeypatch.setattr(cli_main.lifecycle_manager, "list_tasks", fake_list_tasks)
    result = CliRunner().invoke(cli_main.app, ["task", "list"])
    assert result.exit_code == 0, result.output
    assert "No tasks found" in result.output


def test_cli_uses_local_execution_when_remote_is_not_configured(monkeypatch):
    monkeypatch.delenv("SENTINEL_API_URL", raising=False)
    monkeypatch.delenv("SENTINEL_API_KEY", raising=False)
    remote_client = MagicMock(side_effect=AssertionError("unexpected remote request"))
    monkeypatch.setattr(cli_main.httpx, "Client", remote_client)

    async def fake_create_task(**kwargs):
        assert kwargs["scope_data"]["written_authorization_reference"] == "CHG-CLI-1001"
        assert kwargs["scope_data"]["authorization"]["allow_third_party_enrichment"] is False
        return SimpleNamespace(
            id="task-cli-local",
            status=SimpleNamespace(value="submitted"),
            correlation_id="corr-cli-local",
        )

    monkeypatch.setattr(cli_main.lifecycle_manager, "create_and_submit_task", fake_create_task)
    result = CliRunner().invoke(
        cli_main.app,
        [
            "task", "submit",
            "--objective", "CLI local route regression",
            "--target", "authorized.invalid",
            "--authorization-reference", "CHG-CLI-1001",
            "--authorized-by", "cli-operator@example.invalid",
        ],
    )

    assert result.exit_code == 0, result.output
    remote_client.assert_not_called()


def test_cli_remote_submission_uses_only_configured_endpoint_and_key(monkeypatch):
    api_url = "https://sentinel.example.invalid"
    api_key = "test-only-remote-api-key-that-is-long-enough-for-auth"
    monkeypatch.setenv("SENTINEL_API_URL", api_url)
    monkeypatch.setenv("SENTINEL_API_KEY", api_key)
    captured = {}

    class FakeResponse:
        status_code = 201

        @staticmethod
        def json():
            return {
                "task_id": "task-cli-remote",
                "status": "submitted",
                "correlation_id": "corr-cli-remote",
            }

    class FakeClient:
        def __init__(self, *, base_url, headers, timeout):
            captured["base_url"] = base_url
            captured["headers"] = headers
            captured["timeout"] = timeout

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def post(self, path, *, json):
            captured["path"] = path
            captured["payload"] = json
            return FakeResponse()

    monkeypatch.setattr(cli_main.httpx, "Client", FakeClient)
    result = CliRunner().invoke(
        cli_main.app,
        [
            "task", "submit",
            "--objective", "CLI remote route regression",
            "--target", "authorized.invalid",
            "--authorization-reference", "CHG-CLI-2001",
            "--authorized-by", "cli-operator@example.invalid",
            "--allow-third-party-enrichment",
        ],
    )

    assert result.exit_code == 0, result.output
    assert captured["base_url"] == api_url
    assert captured["headers"] == {"X-API-Key": api_key}
    assert captured["path"] == "/api/v1/tasks"
    assert captured["payload"]["scope"]["written_authorization_reference"] == "CHG-CLI-2001"
    assert captured["payload"]["scope"]["owner"] == "cli-operator@example.invalid"
    assert captured["payload"]["scope"]["authorization"]["allow_third_party_enrichment"] is True


def test_cli_task_controls_use_configured_remote_api(monkeypatch):
    api_key = "test-only-remote-control-key-that-is-long-enough"
    monkeypatch.setenv("SENTINEL_API_URL", "https://sentinel.example.invalid")
    monkeypatch.setenv("SENTINEL_API_KEY", api_key)
    requests = []
    transport = httpx.MockTransport(
        lambda request: _remote_cli_response(request, requests)
    )
    real_client = httpx.Client

    def client_factory(*, base_url, headers, timeout):
        return real_client(base_url=base_url, headers=headers, timeout=timeout, transport=transport)

    monkeypatch.setattr(cli_main.httpx, "Client", client_factory)
    runner = CliRunner()

    status_result = runner.invoke(cli_main.app, ["task", "status", "task-remote-01"])
    cancel_result = runner.invoke(
        cli_main.app,
        ["task", "cancel", "task-remote-01", "--reason", "incident response & containment"],
    )
    findings_result = runner.invoke(cli_main.app, ["task", "findings", "task-remote-01"])

    assert status_result.exit_code == 0, status_result.output
    assert "Remote Task Status" in status_result.output
    assert cancel_result.exit_code == 0, cancel_result.output
    assert "configured server" in cancel_result.output
    assert findings_result.exit_code == 0, findings_result.output
    assert "find-remote-01" in findings_result.output
    assert [request.url.path for request in requests] == [
        "/api/v1/tasks/task-remote-01",
        "/api/v1/tasks/task-remote-01/cancel",
        "/api/v1/tasks/task-remote-01/findings",
    ]
    assert requests[1].url.params["reason"] == "incident response & containment"
    assert all(request.headers["X-API-Key"] == api_key for request in requests)


def _remote_cli_response(request: httpx.Request, captured: list[httpx.Request]) -> httpx.Response:
    captured.append(request)
    if request.url.path.endswith("/cancel"):
        return httpx.Response(200, json={"task_id": "task-remote-01", "status": "cancelled"})
    if request.url.path.endswith("/findings"):
        return httpx.Response(
            200,
            json={"findings": [{"id": "find-remote-01", "severity": "high", "title": "Remote finding", "target_ref": "authorized.invalid"}]},
        )
    return httpx.Response(
        200,
        json={
            "id": "task-remote-01",
            "objective": "Remote status fixture",
            "status": "executing",
            "progress_percentage": 25,
            "mode": "passive_recon",
            "target_set": {"targets": []},
            "correlation_id": "corr-remote-01",
            "created_at": "2026-10-05T00:00:00+00:00",
        },
    )


def test_cli_does_not_fall_back_to_local_store_after_remote_error(monkeypatch):
    monkeypatch.setenv("SENTINEL_API_URL", "https://sentinel.example.invalid")
    monkeypatch.setenv("SENTINEL_API_KEY", "test-only-remote-control-key-that-is-long-enough")
    real_client = httpx.Client
    transport = httpx.MockTransport(lambda _request: httpx.Response(503))

    def client_factory(*, base_url, headers, timeout):
        return real_client(base_url=base_url, headers=headers, timeout=timeout, transport=transport)

    async def local_store_must_not_be_used(_task_id):
        raise AssertionError("configured remote failure must not select a different local store")

    monkeypatch.setattr(cli_main.httpx, "Client", client_factory)
    monkeypatch.setattr(cli_main.lifecycle_manager, "get_task", local_store_must_not_be_used)
    result = CliRunner().invoke(cli_main.app, ["task", "status", "task-remote-02"])

    assert result.exit_code == 1
    assert "HTTP 503" in result.output
