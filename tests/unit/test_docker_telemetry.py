"""Unit and integration tests for Docker Socket Telemetry Collector."""

import pytest
from httpx import ASGITransport, AsyncClient, Response

from sentinel.apps.api.main import app
from sentinel.monitoring.docker_telemetry import (
    DockerTelemetryCollector,
)


@pytest.mark.asyncio
async def test_docker_telemetry_synthetic_fallback_when_socket_missing():
    """Verify collector fails soft into synthetic mode when socket is unmounted."""
    collector = DockerTelemetryCollector(socket_path="/nonexistent/docker.sock")
    report = await collector.audit_containers()

    assert report.socket_available is False
    assert report.mode == "synthetic_fallback"
    assert report.total_containers == 10
    assert report.passed_containers == 10
    assert report.critical_count == 0
    assert report.high_count == 0
    assert len(report.issues) == 0


@pytest.mark.asyncio
async def test_docker_telemetry_live_audit_with_mock_client():
    """Verify live container auditing detects root, port exposures, privileges, and OOM kills."""
    containers_json = [
        {"Id": "c11111111111", "Names": ["/root_agent"]},
        {"Id": "c22222222222", "Names": ["/leaky_port_agent"]},
        {"Id": "c33333333333", "Names": ["/privileged_agent"]},
        {"Id": "c44444444444", "Names": ["/oom_crashed_agent"]},
        {"Id": "c55555555555", "Names": ["/clean_sentinel_agent"]},
    ]

    details_map = {
        "c11111111111": {
            "Config": {"User": "0"},  # Root execution
            "HostConfig": {"Privileged": False, "SecurityOpt": ["no-new-privileges:true"]},
            "State": {"Status": "running", "OOMKilled": False},
        },
        "c22222222222": {
            "Config": {"User": "1000"},
            "HostConfig": {
                "Privileged": False,
                "SecurityOpt": ["no-new-privileges:true"],
                "PortBindings": {"9999/tcp": [{"HostIp": "0.0.0.0", "HostPort": "9999"}]},  # Unapproved 0.0.0.0
            },
            "State": {"Status": "running", "OOMKilled": False},
        },
        "c33333333333": {
            "Config": {"User": "1000"},
            "HostConfig": {"Privileged": True, "SecurityOpt": []},  # Privileged mode
            "State": {"Status": "running", "OOMKilled": False},
        },
        "c44444444444": {
            "Config": {"User": "1000"},
            "HostConfig": {"Privileged": False, "SecurityOpt": ["no-new-privileges:true"]},
            "State": {"Status": "exited", "OOMKilled": True},  # OOM Killed
            "RestartCount": 8,
        },
        "c55555555555": {
            "Config": {"User": "appuser"},
            "HostConfig": {
                "Privileged": False,
                "SecurityOpt": ["no-new-privileges:true"],
                "PortBindings": {},
            },
            "State": {"Status": "running", "OOMKilled": False, "Health": {"Status": "healthy"}},
            "RestartCount": 0,
        },
    }

    async def mock_handler(request):
        url = str(request.url)
        if "/containers/json?all=1" in url:
            return Response(200, json=containers_json)
        for cid, detail in details_map.items():
            if f"/containers/{cid}/json" in url:
                return Response(200, json=detail)
        return Response(404, json={"message": "not found"})

    mock_transport = ASGITransport(app=None)
    mock_client = AsyncClient(transport=mock_transport, base_url="http://docker")
    # Patch mock client's get method
    async def mock_get(url, **kwargs):
        class MockReq:
            pass
        req = MockReq()
        req.url = url
        return await mock_handler(req)
    mock_client.get = mock_get  # type: ignore[assignment]

    collector = DockerTelemetryCollector(socket_path="/mock/docker.sock")
    report = await collector.audit_containers(client=mock_client)

    assert report.socket_available is True
    assert report.total_containers == 5
    assert report.issues_count >= 4

    rule_ids = {i.rule_id for i in report.issues}
    assert "CONTAINER-RUN-AS-ROOT" in rule_ids
    assert "CONTAINER-UNAUTHORIZED-PORT-EXPOSURE" in rule_ids
    assert "CONTAINER-PRIVILEGED-MODE" in rule_ids
    assert "CONTAINER-OOM-KILLED" in rule_ids


@pytest.mark.asyncio
async def test_get_container_telemetry_endpoint():
    """Verify GET /v1/telemetry/containers endpoint."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/v1/telemetry/containers")
        assert res.status_code == 200
        data = res.json()
        assert "container_audit" in data
        assert "mode" in data["container_audit"]
        assert "total_containers" in data["container_audit"]
