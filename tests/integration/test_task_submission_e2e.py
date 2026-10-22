"""API-to-report and task lifecycle acceptance tests using loopback-only fixtures.

These tests deliberately avoid public targets and optional external enrichers.
They cover API validation, task lifecycle scheduling, policy, adapter execution,
evidence-backed findings, reporting, cancellation, and authorization edge cases.
"""

from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Event, Thread
from uuid import uuid4

from fastapi.testclient import TestClient

from sentinel.apps.api import main as api_main
from sentinel.core.orchestrator.orchestrator import orchestrator


class _LocalAssessmentHandler(BaseHTTPRequestHandler):
    requests_seen: list[str] = []

    def do_GET(self) -> None:
        type(self).requests_seen.append(self.path)
        if self.path in {"/.well-known/security.txt", "/security.txt"}:
            body = b"Contact: mailto:security@localhost\n"
            content_type = "text/plain"
        elif self.path == "/robots.txt":
            body = b"User-agent: *\nDisallow: /admin\n"
            content_type = "text/plain"
        elif self.path == "/favicon.ico":
            body = b"sentinel-local-fixture"
            content_type = "image/x-icon"
        else:
            body = b"<html><title>Local fixture</title><h1>Sentinel test service</h1></html>"
            content_type = "text/html"

        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Server", "Sentinel-Local-Fixture/1.0")
        self.send_header("X-Powered-By", "Fixture")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        return


def _scoped_task_payload(
    target: str = "127.0.0.1",
    *,
    allowed_targets: list[str] | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
) -> dict:
    now = datetime.now(UTC)
    return {
        "objective": "Loopback-only task lifecycle regression",
        "targets": [{"type": "ip", "value": target}],
        "mode": "passive_recon",
        "scope": {
            "owner": "local-test-operator",
            "written_authorization_reference": f"LOCAL-ONLY-{uuid4().hex}",
            "allowed_targets": allowed_targets or [target],
            "allowed_methods": ["passive_recon"],
            "time_window": {
                "start_time": (start_time or now - timedelta(minutes=1)).isoformat(),
                "end_time": (end_time or now + timedelta(minutes=5)).isoformat(),
            },
            "maximum_impact": "low",
            "rate_limit": 5,
            "authorization": {"allow_third_party_enrichment": False},
        },
    }


def test_explicitly_scoped_task_runs_through_api_to_report(monkeypatch, tmp_path):
    """An explicit local assessment should produce and report evidence-backed findings."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "logs").mkdir()
    monkeypatch.setenv("SENTINEL_API_AUTH_REQUIRED", "false")
    monkeypatch.delenv("RENDER", raising=False)
    _LocalAssessmentHandler.requests_seen = []

    server = ThreadingHTTPServer(("127.0.0.1", 0), _LocalAssessmentHandler)
    worker = Thread(target=server.serve_forever, daemon=True)
    worker.start()
    target_url = f"http://127.0.0.1:{server.server_address[1]}"

    try:
        with TestClient(api_main.app) as client:
            now = datetime.now(UTC)
            payload = {
                "objective": "Loopback-only authorized functional smoke assessment",
                "targets": [{"type": "url", "value": target_url}],
                "mode": "assessment",
                "scope": {
                    "owner": "local-test-operator",
                    "written_authorization_reference": f"LOCAL-ONLY-{uuid4().hex}",
                    "allowed_targets": [target_url, "127.0.0.1"],
                    "allowed_methods": ["discovery", "validation"],
                    "time_window": {
                        "start_time": (now - timedelta(minutes=1)).isoformat(),
                        "end_time": (now + timedelta(minutes=5)).isoformat(),
                    },
                    "maximum_impact": "low",
                    "rate_limit": 25,
                    "authorization": {"allow_third_party_enrichment": False},
                },
            }

            response = client.post("/api/v1/tasks", json=payload)
            assert response.status_code == 201, response.text
            task_id = response.json()["task_id"]

            deadline = time.monotonic() + 20
            task = None
            while time.monotonic() < deadline:
                task_response = client.get(f"/api/v1/tasks/{task_id}")
                assert task_response.status_code == 200, task_response.text
                task = task_response.json()
                if task["status"] in {
                    "complete", "completed", "failed", "blocked", "partially_completed", "cancelled"
                }:
                    break
                time.sleep(0.05)

            assert task is not None
            assert task["status"] == "completed", task
            assert task["progress_percentage"] == 100.0

            memory = client.portal.call(orchestrator.memory_store.load_memory, task_id)
            action_outcomes = list(memory.action_outcomes.values())
            assert action_outcomes
            assert all(outcome["status"] == "success" for outcome in action_outcomes), action_outcomes
            assert any(outcome["action_type"] == "http.observe" for outcome in action_outcomes)

            evidence = client.get(f"/api/v1/tasks/{task_id}/evidence")
            findings = client.get(f"/api/v1/tasks/{task_id}/findings")
            report = client.get(f"/api/v1/tasks/{task_id}/report")
            assert evidence.status_code == 200, evidence.text
            assert findings.status_code == 200, findings.text
            assert report.status_code == 200, report.text
            assert evidence.json(), "The real action path should persist evidence."
            finding_payload = findings.json()
            assert finding_payload["count"] > 0, "Observed missing headers should produce a finding."
            header_finding = next(
                (
                    finding
                    for finding in finding_payload["findings"]
                    if "security headers" in finding["title"].lower()
                ),
                None,
            )
            assert header_finding is not None, finding_payload
            evidence_ids = {item["id"] for item in evidence.json()["evidence"]}
            assert header_finding["task_id"] == task_id
            assert header_finding["severity"] == "low"
            assert header_finding["remediation"]
            assert header_finding["evidence_refs"]
            assert set(header_finding["evidence_refs"]) <= evidence_ids

            report_data = report.json()
            assert report_data["task_id"] == task_id
            assert report_data["report_id"]
            assert any(
                finding["id"] == header_finding["id"]
                for finding in report_data["findings"]
            ), "The generated report should include the verified evidence-backed finding."

            # Cancellation after successful completion must not claim the task was halted.
            cancel = client.post(f"/api/v1/tasks/{task_id}/cancel?reason=post-completion-check")
            assert cancel.status_code == 200, cancel.text
            assert cancel.json()["status"] == "completed"
            assert "already terminal" in cancel.json()["message"].lower()

        assert _LocalAssessmentHandler.requests_seen
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)


def test_task_api_rejects_expired_future_and_out_of_scope_before_scheduling(monkeypatch, tmp_path):
    """The real API must reject authorization boundary failures before starting work."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "logs").mkdir()
    monkeypatch.setenv("SENTINEL_API_AUTH_REQUIRED", "false")
    monkeypatch.delenv("RENDER", raising=False)
    scheduled: list[str] = []
    monkeypatch.setattr(api_main.lifecycle_manager, "_start_task_job", scheduled.append)

    now = datetime.now(UTC)
    cases = [
        (
            "expired",
            _scoped_task_payload(
                start_time=now - timedelta(minutes=2),
                end_time=now - timedelta(seconds=1),
            ),
            "authorization expired",
        ),
        (
            "not-yet-active",
            _scoped_task_payload(
                start_time=now + timedelta(hours=1),
                end_time=now + timedelta(hours=2),
            ),
            "not yet active",
        ),
        (
            "outside-allowlist",
            _scoped_task_payload(allowed_targets=["127.0.0.2"]),
            "outside the explicit scope",
        ),
    ]

    with TestClient(api_main.app) as client:
        for case_name, payload, expected_detail in cases:
            response = client.post("/api/v1/tasks", json=payload)
            assert response.status_code == 422, f"{case_name}: {response.text}"
            assert expected_detail in response.json()["detail"].lower(), response.json()

        missing_task_cancel = client.post("/api/v1/tasks/not-a-real-task/cancel")
        assert missing_task_cancel.status_code == 404

    assert scheduled == [], "Rejected requests must never schedule task execution."


def test_task_api_cancels_in_flight_worker_and_persists_terminal_state(monkeypatch, tmp_path):
    """Cancellation through the API must stop the scheduled lifecycle worker."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "logs").mkdir()
    monkeypatch.setenv("SENTINEL_API_AUTH_REQUIRED", "false")
    monkeypatch.delenv("RENDER", raising=False)
    worker_started = Event()

    async def blocked_pipeline(_task_id: str) -> None:
        worker_started.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(api_main.lifecycle_manager, "_execute_task_pipeline", blocked_pipeline)

    with TestClient(api_main.app) as client:
        submitted = client.post("/api/v1/tasks", json=_scoped_task_payload())
        assert submitted.status_code == 201, submitted.text
        task_id = submitted.json()["task_id"]
        assert worker_started.wait(timeout=2), "The lifecycle worker never started."

        cancelled = client.post(f"/api/v1/tasks/{task_id}/cancel?reason=local-test-cancellation")
        assert cancelled.status_code == 200, cancelled.text
        assert cancelled.json()["status"] == "cancelled"
        assert "cancelled" in cancelled.json()["message"].lower()

        persisted = client.get(f"/api/v1/tasks/{task_id}")
        assert persisted.status_code == 200, persisted.text
        assert persisted.json()["status"] == "cancelled"

        repeated = client.post(f"/api/v1/tasks/{task_id}/cancel?reason=repeat-check")
        assert repeated.status_code == 200, repeated.text
        assert repeated.json()["status"] == "cancelled"

        deadline = time.monotonic() + 2
        while task_id in api_main.lifecycle_manager._running_jobs and time.monotonic() < deadline:
            time.sleep(0.01)
        assert task_id not in api_main.lifecycle_manager._running_jobs, "Cancelled worker handle leaked."


def test_cancel_routes_are_unambiguous_and_aliases_return_not_found(monkeypatch, tmp_path):
    """Cancellation endpoint aliases must not shadow one another or leak KeyError."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "logs").mkdir()
    monkeypatch.setenv("SENTINEL_API_AUTH_REQUIRED", "false")
    monkeypatch.delenv("RENDER", raising=False)

    matching_routes = [
        route
        for route in api_main.app.routes
        if getattr(route, "path", None) == "/api/v1/tasks/{task_id}/cancel"
        and "POST" in getattr(route, "methods", set())
    ]
    assert len(matching_routes) == 1, f"Duplicate task-cancel routes found: {matching_routes!r}"

    with TestClient(api_main.app) as client:
        for path in (
            "/api/v1/friday/tasks/not-a-real-task/cancel",
            "/api/v1/sentinel/tasks/not-a-real-task/cancel",
        ):
            response = client.post(path)
            assert response.status_code == 404, f"{path}: {response.text}"
