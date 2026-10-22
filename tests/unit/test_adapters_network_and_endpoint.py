"""Unit tests for network adapters, endpoint platform adapters, and artifact storage."""

import asyncio
import json
from unittest.mock import MagicMock, patch

import pytest

from sentinel.core.models import ActionRequest
from sentinel.modules.endpoint.adapters import (
    LinuxAdapter,
    MacOSAdapter,
    WindowsAdapter,
)
from sentinel.modules.network.adapters import (
    FirewallConfigReviewAdapter,
    NetworkExposureAdapter,
    SegmentationAnalyzerAdapter,
    TrafficAnalysisAdapter,
)
from sentinel.storage.artifacts.storage import (
    LocalFileSystemStorage,
    MinIOObjectStorage,
    get_artifact_storage,
)

# ============================================================================
# 1. Linux & MacOS Platform Adapters
# ============================================================================


def test_linux_adapter_fs_auditing(tmp_path):
    adapter = LinuxAdapter()

    # Create mock linux directory hierarchy
    etc_dir = tmp_path / "etc"
    etc_dir.mkdir(parents=True)
    ssh_dir = etc_dir / "ssh"
    ssh_dir.mkdir(parents=True)
    systemd_dir = etc_dir / "systemd" / "system"
    systemd_dir.mkdir(parents=True)
    cron_d = etc_dir / "cron.d"
    cron_d.mkdir(parents=True)

    # Populate config files
    (ssh_dir / "sshd_config").write_text(
        "PermitRootLogin yes\nPasswordAuthentication yes\n", encoding="utf-8"
    )
    (etc_dir / "passwd").write_text(
        "root:x:0:0:root:/root:/bin/bash\nuser:x:1001:1001::/home/user:/bin/sh\n",
        encoding="utf-8",
    )
    (etc_dir / "crontab").write_text(
        "* * * * * root /tmp/suspicious_script.sh\n", encoding="utf-8"
    )
    (cron_d / "myjob").write_text(
        "0 0 * * * root /var/tmp/cleanup.sh\n", encoding="utf-8"
    )
    (systemd_dir / "evil.service").write_text(
        "[Service]\nExecStart=/home/user/backdoor.sh\n", encoding="utf-8"
    )

    # Test persistence
    items = adapter.collect_persistence(root_dir=str(tmp_path))
    assert len(items) >= 3
    suspicious = [i for i in items if i.is_suspicious]
    assert len(suspicious) >= 2

    # Test hardening rules
    rules = [
        {
            "id": "EP-LNX-001",
            "name": "SSH Root Login",
            "severity": "HIGH",
            "description": "desc",
            "remediation": "rem",
        },
        {
            "id": "EP-LNX-002",
            "name": "Password Auth",
            "severity": "MEDIUM",
            "description": "desc",
            "remediation": "rem",
        },
        {
            "id": "EP-LNX-005",
            "name": "Suspicious Persistence",
            "severity": "CRITICAL",
            "description": "desc",
            "remediation": "rem",
        },
    ]
    findings = adapter.run_hardening_rules(rules, root_dir=str(tmp_path))
    rule_ids = {f["rule_id"] for f in findings}
    assert "EP-LNX-001" in rule_ids
    assert "EP-LNX-002" in rule_ids
    assert "EP-LNX-005" in rule_ids

    # Test collect_users_privileges
    from unittest.mock import mock_open
    passwd_content = "root:x:0:0:root:/root:/bin/bash\nappuser:x:1000:1000::/home/appuser:/bin/bash\n"
    with (
        patch("os.path.exists", return_value=True),
        patch("builtins.open", mock_open(read_data=passwd_content)),
    ):
        users = adapter.collect_users_privileges()
        assert len(users) == 2
        assert users[0].is_admin is True
        assert users[1].is_admin is False


def test_macos_adapter_fs_auditing(tmp_path):
    adapter = MacOSAdapter()

    launch_daemons = tmp_path / "Library" / "LaunchDaemons"
    launch_daemons.mkdir(parents=True)
    (launch_daemons / "com.test.daemon.plist").write_text(
        "<plist><dict><key>Program</key><string>/tmp/daemon.sh</string></dict></plist>",
        encoding="utf-8",
    )

    items = adapter.collect_persistence(root_dir=str(tmp_path))
    assert len(items) == 1
    assert items[0].is_suspicious is True
    assert items[0].type == "launchd"

    rules = [
        {
            "id": "EP-MAC-001",
            "name": "Suspicious LaunchDaemon",
            "severity": "HIGH",
            "description": "desc",
            "remediation": "rem",
        }
    ]
    findings = adapter.run_hardening_rules(rules, root_dir=str(tmp_path))
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "EP-MAC-001"

    # Quick smoke tests for mac collectors
    assert adapter.collect_services() == []
    assert isinstance(adapter.collect_processes(), list)
    assert isinstance(adapter.collect_listening_ports(), list)


def test_windows_adapter_collectors():
    adapter = WindowsAdapter()
    assert isinstance(adapter.collect_processes(), list)
    assert isinstance(adapter.collect_services(), list)
    assert isinstance(adapter.collect_listening_ports(), list)
    assert isinstance(adapter.collect_users_privileges(), list)
    assert isinstance(adapter.collect_persistence(), list)
    assert adapter.run_hardening_rules([]) == []


# ============================================================================
# 2. Network Tool Adapters
# ============================================================================


@pytest.mark.asyncio
async def test_network_exposure_adapter():
    adapter = NetworkExposureAdapter()
    assert adapter.name == "network_exposure_adapter"
    assert await adapter.health_check() is True

    # Validate failure without target_refs
    action_invalid = ActionRequest(
        id="act-net-1",
        task_id="tsk-net-1",
        agent="network",
        action_type="network.exposure_analysis",
        parameters={},
        target_refs=[],
    )
    ok, err = adapter.validate_params(action_invalid)
    assert ok is False

    # Run with mocked socket connection
    action_valid = ActionRequest(
        id="act-net-2",
        task_id="tsk-net-1",
        agent="network",
        action_type="network.exposure_analysis",
        parameters={"ports": [8080, 9999]},
        target_refs=["http://127.0.0.1:8080"],
    )

    mock_reader = MagicMock()
    mock_reader.read = MagicMock(side_effect=lambda n: asyncio.sleep(0.01, result=b"HTTP/1.1 200 OK\r\n"))
    mock_writer = MagicMock()
    mock_writer.drain = MagicMock(side_effect=lambda: asyncio.sleep(0.01))

    async def mock_open_conn(host, port):
        if port == 8080:
            return mock_reader, mock_writer
        raise ConnectionRefusedError()

    with patch("asyncio.open_connection", side_effect=mock_open_conn):
        res, raw, mime = await adapter.run(action_valid)
        assert res.success is True
        assert mime == "application/json"
        data = json.loads(raw.decode())
        assert 8080 in data["open_ports"]
        assert 9999 not in data["open_ports"]


@pytest.mark.asyncio
async def test_segmentation_analyzer_adapter():
    adapter = SegmentationAnalyzerAdapter()
    assert adapter.name == "segmentation_analyzer_adapter"
    assert await adapter.health_check() is True

    # Validate requires at least two zone targets
    action_invalid = ActionRequest(
        id="act-seg-1",
        task_id="tsk-seg-1",
        agent="network",
        action_type="network.segmentation_check",
        parameters={},
        target_refs=["dmz-zone"],
    )
    ok, err = adapter.validate_params(action_invalid)
    assert ok is False

    action_valid = ActionRequest(
        id="act-seg-2",
        task_id="tsk-seg-1",
        agent="network",
        action_type="network.segmentation_check",
        parameters={"restricted_ports": [3306, 5432]},
        target_refs=["guest-network", "internal-db.corp"],
    )

    mock_writer = MagicMock()
    mock_writer.wait_closed = MagicMock(side_effect=lambda: asyncio.sleep(0.01))

    async def mock_open_conn(host, port):
        if port == 3306:
            return None, mock_writer
        raise ConnectionRefusedError()

    with patch("asyncio.open_connection", side_effect=mock_open_conn):
        res, raw, _ = await adapter.run(action_valid)
        assert res.success is True
        data = json.loads(raw.decode())
        assert data["is_segmented"] is False
        assert len(data["violations"]) == 1
        assert data["violations"][0]["port"] == 3306


@pytest.mark.asyncio
async def test_firewall_config_review_adapter():
    adapter = FirewallConfigReviewAdapter()
    assert adapter.name == "firewall_config_review_adapter"
    assert await adapter.health_check() is True

    # Validate failure without config_data
    action_invalid = ActionRequest(
        id="act-fw-1",
        task_id="tsk-fw-1",
        agent="network",
        action_type="network.firewall_review",
        parameters={},
        target_refs=[],
    )
    ok, err = adapter.validate_params(action_invalid)
    assert ok is False

    # Test AWS SG JSON
    aws_sg = {
        "IpPermissions": [
            {
                "FromPort": 0,
                "ToPort": 65535,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            },
            {
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            },
        ]
    }
    action_json = ActionRequest(
        id="act-fw-2",
        task_id="tsk-fw-1",
        agent="network",
        action_type="network.firewall_review",
        parameters={"config_data": json.dumps(aws_sg)},
        target_refs=[],
    )
    res_json, raw_json, _ = await adapter.run(action_json)
    assert res_json.success is True
    data_json = json.loads(raw_json.decode())
    assert len(data_json["findings"]) == 2
    rule_ids = {f["rule_id"] for f in data_json["findings"]}
    assert "FW-001" in rule_ids
    assert "FW-002" in rule_ids

    # Test iptables text
    iptables_text = "-A INPUT -s 0.0.0.0/0 -j ACCEPT"
    action_txt = ActionRequest(
        id="act-fw-3",
        task_id="tsk-fw-1",
        agent="network",
        action_type="network.firewall_review",
        parameters={"config_data": iptables_text},
        target_refs=[],
    )
    res_txt, raw_txt, _ = await adapter.run(action_txt)
    assert res_txt.success is True
    data_txt = json.loads(raw_txt.decode())
    assert len(data_txt["findings"]) == 1
    assert data_txt["findings"][0]["rule_id"] == "FW-002"


@pytest.mark.asyncio
async def test_traffic_analysis_adapter():
    adapter = TrafficAnalysisAdapter()
    assert adapter.name == "traffic_analysis_adapter"
    assert await adapter.health_check() is True

    # Validate failure without pcap parameters
    action_invalid = ActionRequest(
        id="act-tr-1",
        task_id="tsk-tr-1",
        agent="network",
        action_type="network.traffic_analysis",
        parameters={},
        target_refs=[],
    )
    ok, err = adapter.validate_params(action_invalid)
    assert ok is False

    # Run with empty / non-existent pcap
    action_valid = ActionRequest(
        id="act-tr-2",
        task_id="tsk-tr-1",
        agent="network",
        action_type="network.traffic_analysis",
        parameters={"pcap_path": "/nonexistent/test.pcap"},
        target_refs=[],
    )
    res, raw, _ = await adapter.run(action_valid)
    assert res.success is True
    data = json.loads(raw.decode())
    assert data["packet_count"] == 0
    assert data["potential_beaconing_detected"] is False


# ============================================================================
# 3. Artifact Storage (Local & MinIO)
# ============================================================================


@pytest.mark.asyncio
async def test_minio_object_storage():
    mock_client = MagicMock()
    mock_client.bucket_exists.return_value = False

    with patch("minio.Minio", return_value=mock_client):
        storage = MinIOObjectStorage()
        assert mock_client.make_bucket.called

        # store_artifact
        uri, sha = await storage.store_artifact("test/obj.txt", b"hello minio")
        assert uri.startswith("s3://")
        assert len(sha) == 64
        assert mock_client.put_object.called

        # get_artifact
        mock_response = MagicMock()
        mock_response.read.return_value = b"hello minio"
        mock_client.get_object.return_value = mock_response
        content = await storage.get_artifact("test/obj.txt")
        assert content == b"hello minio"
        assert mock_response.close.called

        # exists
        mock_client.stat_object.return_value = True
        assert await storage.exists("test/obj.txt") is True

        mock_client.stat_object.side_effect = Exception("Not found")
        assert await storage.exists("test/obj.txt") is False

        # delete_artifact
        mock_client.remove_object.side_effect = None
        assert await storage.delete_artifact("test/obj.txt") is True

        mock_client.remove_object.side_effect = Exception("Cannot delete")
        assert await storage.delete_artifact("test/obj.txt") is False


def test_get_artifact_storage_factory():
    with patch("sentinel.storage.artifacts.storage.get_settings") as mock_settings:
        # Local backend
        mock_settings.return_value.storage.backend = "local"
        store_local = get_artifact_storage()
        assert isinstance(store_local, LocalFileSystemStorage)

        # MinIO backend with client mock
        mock_settings.return_value.storage.backend = "minio"
        with patch("minio.Minio"):
            store_minio = get_artifact_storage()
            assert isinstance(store_minio, MinIOObjectStorage)
