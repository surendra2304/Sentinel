"""Comprehensive test suite for Endpoint Security Domain.

Tests:
1. LinuxAdapter with real and simulated fixtures (malicious cron, permissive sshd_config, sudoers NOPASSWD, suspicious systemd unit)
2. WindowsAdapter & MacOSAdapter live queries and rule evaluation
3. OfflineAssessmentAdapter parsing and evaluating Windows, Linux, and macOS host export bundles
4. EndpointAgent analyzing evidence to produce structured Findings in FindingEngine
5. Evidence linkage verification from findings back to collected artifacts
"""

import json

import pytest

from sentinel.core.agents.endpoint_agent import EndpointAgent
from sentinel.core.models import (
    ActionRequest,
    Policy,
    Scope,
    SeverityLevel,
    Target,
    TargetSet,
    Task,
    TaskMode,
)
from sentinel.intelligence.risk.finding_engine import finding_engine
from sentinel.modules.endpoint.adapters import (
    EndpointAssessmentAdapter,
    LinuxAdapter,
    MacOSAdapter,
    WindowsAdapter,
)
from sentinel.modules.endpoint.models import (
    EndpointExportData,
    InstalledSoftware,
    PersistenceItem,
)


@pytest.fixture
def sample_endpoint_task():
    target = Target(id="t-ep-001", type="host", value="target-endpoint-01")
    target_set = TargetSet(id="ts-ep-001", name="Endpoint Target", targets=[target])
    scope = Scope(id="scope-ep-001", name="Endpoint Scope", allowed_targets=["target-endpoint-01", "localhost"])
    policy = Policy(id="policy-ep-001", name="Endpoint Policy")
    return Task(
        id="task-ep-test-01",
        objective="Audit endpoint posture and persistence mechanisms",
        target_set=target_set,
        scope=scope,
        policy=policy,
        mode=TaskMode.ASSESSMENT,
        correlation_id="corr-ep-01",
    )


# ---------------------------------------------------------------------------
# 1. Linux Local & Fixture Tests
# ---------------------------------------------------------------------------

def test_linux_adapter_fixtures(tmp_path):
    """Create fixture filesystem tree simulating misconfigured Linux host."""
    root_dir = tmp_path / "linux_root"
    etc_dir = root_dir / "etc"
    ssh_dir = etc_dir / "ssh"
    cron_dir = etc_dir / "cron.d"
    systemd_dir = etc_dir / "systemd" / "system"

    ssh_dir.mkdir(parents=True)
    cron_dir.mkdir(parents=True)
    systemd_dir.mkdir(parents=True)

    # 1. Permissive sshd_config
    sshd_conf = ssh_dir / "sshd_config"
    sshd_conf.write_text(
        "Port 22\nPermitRootLogin yes\nPasswordAuthentication yes\n",
        encoding="utf-8",
    )

    # 2. Permissive sudoers
    sudoers = etc_dir / "sudoers"
    sudoers.write_text(
        "root ALL=(ALL:ALL) ALL\n%admin ALL=(ALL) NOPASSWD: ALL\n",
        encoding="utf-8",
    )

    # 3. Malicious / Suspicious Cron job executing from /tmp
    mal_cron = cron_dir / "backup_job"
    mal_cron.write_text(
        "* * * * * root /tmp/update_script.sh > /dev/null 2>&1\n",
        encoding="utf-8",
    )

    # 4. Suspicious systemd unit
    mal_unit = systemd_dir / "backdoor.service"
    mal_unit.write_text(
        "[Unit]\nDescription=Backdoor Service\n[Service]\nExecStart=/dev/shm/.rev_shell\n",
        encoding="utf-8",
    )

    adapter = EndpointAssessmentAdapter()
    rules = adapter.rules.get("linux_rules", [])

    lnx = LinuxAdapter()
    findings = lnx.run_hardening_rules(rules, root_dir=str(root_dir))

    # Assert all expected security violations fire
    assert len(findings) >= 4
    rule_ids = {f["rule_id"] for f in findings}
    assert "EP-LNX-001" in rule_ids  # SSH PermitRootLogin
    assert "EP-LNX-002" in rule_ids  # SSH PasswordAuthentication
    assert "EP-LNX-003" in rule_ids  # Sudo NOPASSWD
    assert "EP-LNX-005" in rule_ids or "EP-LNX-006" in rule_ids  # Persistence in /tmp or /dev/shm


# ---------------------------------------------------------------------------
# 2. Windows & macOS Local Adapter Tests
# ---------------------------------------------------------------------------

def test_windows_and_macos_adapters():
    win = WindowsAdapter()
    procs = win.collect_processes()
    assert isinstance(procs, list)
    ports = win.collect_listening_ports()
    assert isinstance(ports, list)

    mac = MacOSAdapter()
    mac_procs = mac.collect_processes()
    assert isinstance(mac_procs, list)


# ---------------------------------------------------------------------------
# 3. Offline Assessment Adapter Tests
# ---------------------------------------------------------------------------

def test_offline_windows_export_evaluation():
    """Verify offline export evaluation detects Windows misconfigurations."""
    export = EndpointExportData(
        os_platform="windows",
        hostname="WIN-CORP-DC01",
        registry_keys={
            "AlwaysInstallElevated": 1,
            "AutoAdminLogon": "1",
            "LAPS_Installed": False,
        },
        persistence_mechanisms=[
            PersistenceItem(
                type="registry_run",
                name="SecurityUpdater",
                path="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                command="C:\\Users\\Bob\\AppData\\Local\\Temp\\update.exe",
                is_suspicious=True,
                suspicion_reason="Run key points to user-writable AppData\\Local\\Temp directory.",
            )
        ],
        installed_software=[InstalledSoftware(name="Google Chrome", version="120.0.0")],
    )

    adp = EndpointAssessmentAdapter()
    findings = adp.offline_adapter.evaluate_export(export, adp.rules)

    rule_ids = {f["rule_id"] for f in findings}
    assert "EP-WIN-001" in rule_ids  # AlwaysInstallElevated
    assert "EP-WIN-002" in rule_ids  # AutoAdminLogon
    assert "EP-WIN-003" in rule_ids  # Missing LAPS
    assert "EP-WIN-004" in rule_ids  # Suspicious Run key in AppData


def test_offline_linux_export_evaluation():
    """Verify offline export evaluation detects Linux misconfigurations."""
    export = EndpointExportData(
        os_platform="linux",
        hostname="srv-prod-app01",
        raw_configs={
            "/etc/ssh/sshd_config": "PermitRootLogin yes\nPasswordAuthentication yes\n",
            "/etc/sudoers": "deploy ALL=(ALL) NOPASSWD: ALL\n",
        },
        persistence_mechanisms=[
            PersistenceItem(
                type="cron",
                name="cron_hourly",
                path="/etc/cron.hourly/sync",
                command="/dev/shm/sync.sh",
                is_suspicious=True,
                suspicion_reason="Cron job executes script from /dev/shm.",
            )
        ],
    )

    adp = EndpointAssessmentAdapter()
    findings = adp.offline_adapter.evaluate_export(export, adp.rules)

    rule_ids = {f["rule_id"] for f in findings}
    assert "EP-LNX-001" in rule_ids
    assert "EP-LNX-002" in rule_ids
    assert "EP-LNX-003" in rule_ids
    assert "EP-LNX-005" in rule_ids


# ---------------------------------------------------------------------------
# 4. EndpointAssessmentAdapter Tool Execution Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_endpoint_tool_adapter_offline_run():
    adapter = EndpointAssessmentAdapter()
    req = ActionRequest(
        id="act-ep-offline",
        task_id="task-ep-01",
        agent="endpoint_agent",
        action_type="endpoint.offline_assess",
        target_refs=["srv-db-01"],
        parameters={
            "export_data": {
                "os_platform": "linux",
                "hostname": "srv-db-01",
                "raw_configs": {
                    "/etc/ssh/sshd_config": "PermitRootLogin yes\n",
                },
            }
        },
    )

    res, raw_data, summary = await adapter.run(req)
    assert res.success is True
    assert "findings" in summary.lower() or "completed" in summary.lower()

    data = json.loads(raw_data.decode("utf-8"))
    assert data["findings_count"] >= 1
    assert data["hostname"] == "srv-db-01"


# ---------------------------------------------------------------------------
# 5. EndpointAgent & FindingEngine Evidence Linkage Integration
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_endpoint_agent_observation_synthesis(sample_endpoint_task):
    agent = EndpointAgent()

    # Provide mocked evidence containing endpoint findings
    mock_evidence = [
        {
            "id": "evi-ep-001",
            "data": {
                "hostname": "workstation-09",
                "os_platform": "linux",
                "findings": [
                    {
                        "rule_id": "EP-LNX-001",
                        "title": "SSH PermitRootLogin Enabled",
                        "severity": "HIGH",
                        "description": "Root login permitted over SSH.",
                        "remediation": "Set PermitRootLogin no.",
                        "target": "workstation-09:/etc/ssh/sshd_config",
                    }
                ],
            },
        }
    ]

    report = await agent.analyze(
        task=sample_endpoint_task,
        target_set=sample_endpoint_task.target_set,
        scope=sample_endpoint_task.scope,
        policy=sample_endpoint_task.policy,
        available_evidence=mock_evidence,
        working_memory={},
    )

    assert len(report.observations) == 1
    obs = report.observations[0]
    assert obs.title == "SSH PermitRootLogin Enabled"
    assert obs.severity == SeverityLevel.HIGH
    assert obs.evidence_refs == ["evi-ep-001"]

    # Ingest observation into FindingEngine and verify evidence integrity
    finding = await finding_engine.ingest_observation(obs)
    assert finding.id.startswith("find-")
    assert finding.severity == SeverityLevel.HIGH
    assert "evi-ep-001" in finding.evidence_refs


def test_endpoint_offline_macos_export_evaluation():
    """Verify offline export evaluation detects macOS misconfigurations."""
    export = EndpointExportData(
        os_platform="macos",
        hostname="MAC-DEV-01",
        raw_configs={
            "/etc/ssh/sshd_config": "PermitRootLogin yes\nPasswordAuthentication yes\n",
        },
        persistence_mechanisms=[
            PersistenceItem(
                type="launchd",
                name="com.apple.badupdater",
                path="/Library/LaunchDaemons/com.apple.badupdater.plist",
                command="/tmp/payload.sh",
                is_suspicious=True,
                suspicion_reason="LaunchDaemon runs script from /tmp.",
            )
        ],
    )

    adp = EndpointAssessmentAdapter()
    findings = adp.offline_adapter.evaluate_export(export, adp.rules)

    rule_ids = {f["rule_id"] for f in findings}
    assert "EP-MAC-001" in rule_ids


def test_endpoint_adapter_helpers_and_parsers(tmp_path):
    adp = EndpointAssessmentAdapter()
    lnx = LinuxAdapter()
    
    # Test user privilege parsing with mocked passwd
    passwd_file = tmp_path / "passwd"
    passwd_file.write_text("root:x:0:0:root:/root:/bin/bash\nuser1:x:1001:1001::/home/user1:/bin/bash\n", encoding="utf-8")
    
    # Test cron parsing with mocked cron file
    cron_dir = tmp_path / "cron.d"
    cron_dir.mkdir()
    (cron_dir / "job1").write_text("* * * * * root /usr/bin/backup\n", encoding="utf-8")
    
    items = lnx.collect_persistence(root_dir=str(tmp_path))
    assert isinstance(items, list)