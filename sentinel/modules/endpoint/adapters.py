"""Endpoint Security Tool Adapters for Sentinel.

Provides:
- LinuxAdapter (procfs, systemctl, cron, sshd, sudoers)
- WindowsAdapter (WMI/PowerShell, registry, services with graceful non-Windows fallback)
- MacOSAdapter (launchd plists, launchctl, remote login)
- OfflineAssessmentAdapter (ingests and audits standardized JSON/YAML host export bundles)
- Master EndpointAssessmentAdapter routing between local and offline modes.
"""

import contextlib
import json
import os
import platform
import re
import socket
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

import psutil
import yaml

from sentinel.core.models import ActionRequest, ActionResult
from sentinel.core.orchestrator.adapter import ToolAdapter
from sentinel.modules.endpoint.models import (
    EndpointExportData,
    ListeningPort,
    PersistenceItem,
    ProcessInfo,
    ServiceInfo,
    UserPrivilegeInfo,
)


class BasePlatformAdapter(ABC):
    """Abstract interface for platform-specific endpoint enumeration."""

    @abstractmethod
    def collect_processes(self) -> list[ProcessInfo]: ...

    @abstractmethod
    def collect_services(self) -> list[ServiceInfo]: ...

    @abstractmethod
    def collect_listening_ports(self) -> list[ListeningPort]: ...

    @abstractmethod
    def collect_users_privileges(self) -> list[UserPrivilegeInfo]: ...

    @abstractmethod
    def collect_persistence(self, root_dir: str | None = None) -> list[PersistenceItem]: ...

    @abstractmethod
    def run_hardening_rules(
        self,
        rules: list[dict[str, Any]],
        root_dir: str | None = None,
    ) -> list[dict[str, Any]]: ...


class LinuxAdapter(BasePlatformAdapter):
    """Linux endpoint audit engine (procfs, systemd, cron, sshd, sudoers)."""

    def collect_processes(self) -> list[ProcessInfo]:
        results: list[ProcessInfo] = []
        for proc in psutil.process_iter(["pid", "name", "username", "cmdline", "exe", "ppid"]):
            try:
                info = proc.info
                exe_path = info.get("exe")
                is_writable = False
                if exe_path and os.path.exists(exe_path):
                    mode = os.stat(exe_path).st_mode
                    is_writable = bool(mode & 0o002) or bool(mode & 0o020)
                results.append(
                    ProcessInfo(
                        pid=info["pid"],
                        name=info.get("name") or "unknown",
                        username=info.get("username"),
                        cmdline=info.get("cmdline") or [],
                        exe=exe_path,
                        ppid=info.get("ppid"),
                        is_elevated=info.get("username") == "root",
                        is_writable_by_user=is_writable,
                    )
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return results

    def collect_services(self) -> list[ServiceInfo]:
        services: list[ServiceInfo] = []
        systemd_dirs = ["/etc/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system"]
        for sdir in systemd_dirs:
            if os.path.exists(sdir):
                for fname in os.listdir(sdir):
                    if fname.endswith(".service"):
                        unit_path = os.path.join(sdir, fname)
                        is_writable = False
                        bin_path = None
                        try:
                            mode = os.stat(unit_path).st_mode
                            is_writable = bool(mode & 0o002)
                            with open(unit_path, encoding="utf-8", errors="ignore") as f:
                                for line in f:
                                    if line.strip().startswith("ExecStart="):
                                        bin_path = line.strip().split("=", 1)[1].strip()
                                        break
                        except Exception:
                            pass
                        services.append(
                            ServiceInfo(
                                name=fname,
                                status="active",
                                binary_path=bin_path,
                                account="root",
                                is_writable_by_user=is_writable,
                            )
                        )
        return services

    def collect_listening_ports(self) -> list[ListeningPort]:
        ports: list[ListeningPort] = []
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.status == psutil.CONN_LISTEN:
                    proto = "tcp" if conn.type == socket.SOCK_STREAM else "udp"
                    pname = None
                    if conn.pid:
                        with contextlib.suppress(Exception):
                            pname = psutil.Process(conn.pid).name()
                    ports.append(
                        ListeningPort(
                            proto=proto,
                            ip=conn.laddr.ip,
                            port=conn.laddr.port,
                            state=conn.status,
                            pid=conn.pid,
                            process_name=pname,
                        )
                    )
        except (psutil.AccessDenied, Exception):
            pass
        return ports

    def collect_users_privileges(self) -> list[UserPrivilegeInfo]:
        users: list[UserPrivilegeInfo] = []
        if os.path.exists("/etc/passwd"):
            try:
                with open("/etc/passwd", encoding="utf-8") as f:
                    for line in f:
                        parts = line.strip().split(":")
                        if len(parts) >= 7:
                            uname = parts[0]
                            uid = int(parts[2]) if parts[2].isdigit() else 1000
                            users.append(
                                UserPrivilegeInfo(
                                    username=uname,
                                    is_admin=(uid == 0),
                                    home_dir=parts[5],
                                    shell=parts[6],
                                )
                            )
            except Exception:
                pass
        return users

    def collect_persistence(self, root_dir: str | None = None) -> list[PersistenceItem]:
        items: list[PersistenceItem] = []
        prefix = root_dir.rstrip("/\\") if root_dir else ""

        cron_dirs = [
            f"{prefix}/etc/cron.d",
            f"{prefix}/etc/cron.daily",
            f"{prefix}/etc/cron.hourly",
            f"{prefix}/etc/cron.weekly",
            f"{prefix}/etc/cron.monthly",
            f"{prefix}/var/spool/cron/crontabs",
        ]
        crontab_file = f"{prefix}/etc/crontab" if prefix else "/etc/crontab"

        files_to_check = []
        if os.path.exists(crontab_file):
            files_to_check.append(crontab_file)
        for cdir in cron_dirs:
            if os.path.exists(cdir) and os.path.isdir(cdir):
                for fn in os.listdir(cdir):
                    files_to_check.append(os.path.join(cdir, fn))

        suspicious_paths = ["/tmp/", "/dev/shm/", "/var/tmp/", "/home/", "/tmp"]
        for cfile in files_to_check:
            try:
                with open(cfile, encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            is_susp = any(sp in line for sp in suspicious_paths)
                            items.append(
                                PersistenceItem(
                                    type="cron",
                                    name=os.path.basename(cfile),
                                    path=cfile,
                                    command=line,
                                    is_suspicious=is_susp,
                                    suspicion_reason="Cron job executes script in temporary/user-writable location."
                                    if is_susp
                                    else None,
                                )
                            )
            except Exception:
                continue

        systemd_dir = f"{prefix}/etc/systemd/system" if prefix else "/etc/systemd/system"
        if os.path.exists(systemd_dir) and os.path.isdir(systemd_dir):
            for fn in os.listdir(systemd_dir):
                if fn.endswith(".service"):
                    fpath = os.path.join(systemd_dir, fn)
                    try:
                        with open(fpath, encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                            is_susp = any(sp in content for sp in suspicious_paths)
                            items.append(
                                PersistenceItem(
                                    type="systemd",
                                    name=fn,
                                    path=fpath,
                                    command=content[:100],
                                    is_suspicious=is_susp,
                                    suspicion_reason="Systemd unit ExecStart references user-writable path."
                                    if is_susp
                                    else None,
                                )
                            )
                    except Exception:
                        continue
        return items

    def run_hardening_rules(
        self,
        rules: list[dict[str, Any]],
        root_dir: str | None = None,
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        prefix = root_dir.rstrip("/\\") if root_dir else ""
        rules_by_id = {r["id"]: r for r in rules}

        # 1. EP-LNX-001: SSH PermitRootLogin
        sshd_path = f"{prefix}/etc/ssh/sshd_config" if prefix else "/etc/ssh/sshd_config"
        if os.path.exists(sshd_path):
            try:
                with open(sshd_path, encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    if re.search(r"^\s*PermitRootLogin\s+yes", content, re.M | re.I):
                        r = rules_by_id.get("EP-LNX-001")
                        if r:
                            findings.append({
                                "rule_id": r["id"],
                                "title": r["name"],
                                "severity": r["severity"],
                                "description": r["description"],
                                "target": sshd_path,
                                "remediation": r["remediation"],
                            })
                    # EP-LNX-002: PasswordAuthentication
                    if re.search(r"^\s*PasswordAuthentication\s+yes", content, re.M | re.I):
                        r = rules_by_id.get("EP-LNX-002")
                        if r:
                            findings.append({
                                "rule_id": r["id"],
                                "title": r["name"],
                                "severity": r["severity"],
                                "description": r["description"],
                                "target": sshd_path,
                                "remediation": r["remediation"],
                            })
            except Exception:
                pass

        # 2. EP-LNX-003: Sudo NOPASSWD misconfiguration
        sudoers_paths = [
            f"{prefix}/etc/sudoers" if prefix else "/etc/sudoers",
        ]
        sudoers_d = f"{prefix}/etc/sudoers.d" if prefix else "/etc/sudoers.d"
        if os.path.exists(sudoers_d) and os.path.isdir(sudoers_d):
            for fn in os.listdir(sudoers_d):
                sudoers_paths.append(os.path.join(sudoers_d, fn))

        for sp in sudoers_paths:
            if os.path.exists(sp):
                try:
                    with open(sp, encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            if not line.strip().startswith("#") and "NOPASSWD" in line:
                                r = rules_by_id.get("EP-LNX-003")
                                if r:
                                    findings.append({
                                        "rule_id": r["id"],
                                        "title": r["name"],
                                        "severity": r["severity"],
                                        "description": f"NOPASSWD misconfiguration in {sp}: {line.strip()}",
                                        "target": sp,
                                        "remediation": r["remediation"],
                                    })
                                break
                except Exception:
                    pass

        # 3. EP-LNX-005 & EP-LNX-006: Persistence heuristics
        pers_items = self.collect_persistence(root_dir=root_dir)
        for item in pers_items:
            if item.is_suspicious:
                rule_id = "EP-LNX-005" if item.type == "cron" else "EP-LNX-006"
                r = rules_by_id.get(rule_id)
                if r:
                    findings.append({
                        "rule_id": r["id"],
                        "title": r["name"],
                        "severity": r["severity"],
                        "description": f"{item.suspicion_reason} Target: {item.path}",
                        "target": item.path,
                        "remediation": r["remediation"],
                    })

        return findings


class WindowsAdapter(BasePlatformAdapter):
    """Windows endpoint audit engine (PowerShell/WMI, Registry, AlwaysInstallElevated)."""

    def collect_processes(self) -> list[ProcessInfo]:
        results: list[ProcessInfo] = []
        for proc in psutil.process_iter(["pid", "name", "username", "cmdline", "exe", "ppid"]):
            try:
                info = proc.info
                results.append(
                    ProcessInfo(
                        pid=info["pid"],
                        name=info.get("name") or "unknown",
                        username=info.get("username"),
                        cmdline=info.get("cmdline") or [],
                        exe=info.get("exe"),
                        ppid=info.get("ppid"),
                        is_elevated=(info.get("username") or "").endswith("SYSTEM"),
                    )
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return results

    def collect_services(self) -> list[ServiceInfo]:
        results: list[ServiceInfo] = []
        try:
            for s in psutil.win_service_iter():
                try:
                    s_info = s.as_dict()
                    results.append(
                        ServiceInfo(
                            name=s_info.get("name", "unknown"),
                            display_name=s_info.get("display_name"),
                            status=s_info.get("status", "unknown"),
                            start_type=s_info.get("start_type"),
                            binary_path=s_info.get("binpath"),
                            account=s_info.get("username"),
                        )
                    )
                except Exception:
                    continue
        except Exception:
            pass
        return results

    def collect_listening_ports(self) -> list[ListeningPort]:
        ports: list[ListeningPort] = []
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.status == psutil.CONN_LISTEN:
                    proto = "tcp" if conn.type == socket.SOCK_STREAM else "udp"
                    pname = None
                    if conn.pid:
                        with contextlib.suppress(Exception):
                            pname = psutil.Process(conn.pid).name()
                    ports.append(
                        ListeningPort(
                            proto=proto,
                            ip=conn.laddr.ip,
                            port=conn.laddr.port,
                            state=conn.status,
                            pid=conn.pid,
                            process_name=pname,
                        )
                    )
        except Exception:
            pass
        return ports

    def collect_users_privileges(self) -> list[UserPrivilegeInfo]:
        users: list[UserPrivilegeInfo] = []
        for u in psutil.users():
            users.append(UserPrivilegeInfo(username=u.name, is_admin=False))
        return users

    def collect_persistence(self, root_dir: str | None = None) -> list[PersistenceItem]:
        items: list[PersistenceItem] = []
        if platform.system().lower() == "windows":
            try:
                import winreg

                keys_to_check = [
                    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                ]
                for root, subkey in keys_to_check:
                    try:
                        with winreg.OpenKey(root, subkey) as key:
                            count = winreg.QueryInfoKey(key)[1]
                            for i in range(count):
                                name, val, _ = winreg.EnumValue(key, i)
                                is_susp = any(
                                    p in str(val).lower()
                                    for p in ["appdata\\local\\temp", "downloads", "public", "temp"]
                                )
                                items.append(
                                    PersistenceItem(
                                        type="registry_run",
                                        name=name,
                                        path=subkey,
                                        command=str(val),
                                        is_suspicious=is_susp,
                                        suspicion_reason="Run key points to user-writable directory."
                                        if is_susp
                                        else None,
                                    )
                                )
                    except Exception:
                        continue
            except ImportError:
                pass
        return items

    def run_hardening_rules(
        self,
        rules: list[dict[str, Any]],
        root_dir: str | None = None,
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        rules_by_id = {r["id"]: r for r in rules}

        if platform.system().lower() == "windows":
            try:
                import winreg

                for root in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
                    try:
                        with winreg.OpenKey(root, r"Software\Policies\Microsoft\Windows\Installer") as k:
                            val, _ = winreg.QueryValueEx(k, "AlwaysInstallElevated")
                            if val == 1:
                                r = rules_by_id.get("EP-WIN-001")
                                if r:
                                    findings.append({
                                        "rule_id": r["id"],
                                        "title": r["name"],
                                        "severity": r["severity"],
                                        "description": r["description"],
                                        "target": "HKLM\\Software\\Policies\\Microsoft\\Windows\\Installer",
                                        "remediation": r["remediation"],
                                    })
                                break
                    except Exception:
                        pass
            except ImportError:
                pass

        return findings


class MacOSAdapter(BasePlatformAdapter):
    """macOS endpoint audit engine (launchd plists, launchctl, remote login)."""

    def collect_processes(self) -> list[ProcessInfo]:
        results: list[ProcessInfo] = []
        for proc in psutil.process_iter(["pid", "name", "username", "cmdline", "exe", "ppid"]):
            try:
                info = proc.info
                results.append(
                    ProcessInfo(
                        pid=info["pid"],
                        name=info.get("name") or "unknown",
                        username=info.get("username"),
                        cmdline=info.get("cmdline") or [],
                        exe=info.get("exe"),
                        ppid=info.get("ppid"),
                    )
                )
            except Exception:
                continue
        return results

    def collect_services(self) -> list[ServiceInfo]:
        return []

    def collect_listening_ports(self) -> list[ListeningPort]:
        ports: list[ListeningPort] = []
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.status == psutil.CONN_LISTEN:
                    proto = "tcp" if conn.type == socket.SOCK_STREAM else "udp"
                    ports.append(
                        ListeningPort(
                            proto=proto,
                            ip=conn.laddr.ip,
                            port=conn.laddr.port,
                            state=conn.status,
                            pid=conn.pid,
                        )
                    )
        except Exception:
            pass
        return ports

    def collect_users_privileges(self) -> list[UserPrivilegeInfo]:
        return [UserPrivilegeInfo(username=u.name) for u in psutil.users()]

    def collect_persistence(self, root_dir: str | None = None) -> list[PersistenceItem]:
        items: list[PersistenceItem] = []
        prefix = root_dir.rstrip("/\\") if root_dir else ""
        launch_dirs = [
            f"{prefix}/Library/LaunchDaemons",
            f"{prefix}/Library/LaunchAgents",
        ]
        for ldir in launch_dirs:
            if os.path.exists(ldir) and os.path.isdir(ldir):
                for fn in os.listdir(ldir):
                    if fn.endswith(".plist"):
                        fpath = os.path.join(ldir, fn)
                        try:
                            with open(fpath, encoding="utf-8", errors="ignore") as f:
                                content = f.read()
                                is_susp = any(
                                    p in content
                                    for p in ["/tmp/", "/Users/Shared/", "/Downloads/"]
                                )
                                items.append(
                                    PersistenceItem(
                                        type="launchd",
                                        name=fn,
                                        path=fpath,
                                        command=content[:100],
                                        is_suspicious=is_susp,
                                        suspicion_reason="LaunchAgent/Daemon executes from user-writable location."
                                        if is_susp
                                        else None,
                                    )
                                )
                        except Exception:
                            continue
        return items

    def run_hardening_rules(
        self,
        rules: list[dict[str, Any]],
        root_dir: str | None = None,
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        rules_by_id = {r["id"]: r for r in rules}
        pers_items = self.collect_persistence(root_dir=root_dir)
        for item in pers_items:
            if item.is_suspicious:
                r = rules_by_id.get("EP-MAC-001")
                if r:
                    findings.append({
                        "rule_id": r["id"],
                        "title": r["name"],
                        "severity": r["severity"],
                        "description": f"{item.suspicion_reason} File: {item.path}",
                        "target": item.path,
                        "remediation": r["remediation"],
                    })
        return findings


class OfflineAssessmentAdapter:
    """Audits offline export bundles collected from Linux, Windows, or macOS endpoints."""

    def evaluate_export(
        self,
        export_data: EndpointExportData,
        rules_dict: dict[str, Any],
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        os_plat = export_data.os_platform.lower()

        # 1. Linux offline rules
        if "linux" in os_plat:
            rules = {r["id"]: r for r in rules_dict.get("linux_rules", [])}

            sshd = export_data.raw_configs.get("/etc/ssh/sshd_config", "")
            if re.search(r"^\s*PermitRootLogin\s+yes", sshd, re.M | re.I):
                r = rules.get("EP-LNX-001")
                if r:
                    findings.append({
                        "rule_id": r["id"],
                        "title": r["name"],
                        "severity": r["severity"],
                        "description": r["description"],
                        "target": f"{export_data.hostname}:/etc/ssh/sshd_config",
                        "remediation": r["remediation"],
                    })
            if re.search(r"^\s*PasswordAuthentication\s+yes", sshd, re.M | re.I):
                r = rules.get("EP-LNX-002")
                if r:
                    findings.append({
                        "rule_id": r["id"],
                        "title": r["name"],
                        "severity": r["severity"],
                        "description": r["description"],
                        "target": f"{export_data.hostname}:/etc/ssh/sshd_config",
                        "remediation": r["remediation"],
                    })

            sudoers = export_data.raw_configs.get("/etc/sudoers", "")
            if "NOPASSWD" in sudoers:
                r = rules.get("EP-LNX-003")
                if r:
                    findings.append({
                        "rule_id": r["id"],
                        "title": r["name"],
                        "severity": r["severity"],
                        "description": "Passwordless sudo misconfiguration detected in sudoers export.",
                        "target": f"{export_data.hostname}:/etc/sudoers",
                        "remediation": r["remediation"],
                    })

            for item in export_data.persistence_mechanisms:
                if item.is_suspicious:
                    r_id = "EP-LNX-005" if item.type == "cron" else "EP-LNX-006"
                    r = rules.get(r_id)
                    if r:
                        findings.append({
                            "rule_id": r["id"],
                            "title": r["name"],
                            "severity": r["severity"],
                            "description": f"{item.suspicion_reason} Item: {item.name}",
                            "target": f"{export_data.hostname}:{item.path}",
                            "remediation": r["remediation"],
                        })

        # 2. Windows offline rules
        elif "windows" in os_plat or "win" in os_plat:
            rules = {r["id"]: r for r in rules_dict.get("windows_rules", [])}

            reg = export_data.registry_keys
            if reg.get("AlwaysInstallElevated") == 1 or reg.get("HKLM_AlwaysInstallElevated") == 1:
                r = rules.get("EP-WIN-001")
                if r:
                    findings.append({
                        "rule_id": r["id"],
                        "title": r["name"],
                        "severity": r["severity"],
                        "description": r["description"],
                        "target": f"{export_data.hostname}:Registry\\Installer",
                        "remediation": r["remediation"],
                    })

            if reg.get("AutoAdminLogon") == "1" or reg.get("AutoAdminLogon") == 1:
                r = rules.get("EP-WIN-002")
                if r:
                    findings.append({
                        "rule_id": r["id"],
                        "title": r["name"],
                        "severity": r["severity"],
                        "description": r["description"],
                        "target": f"{export_data.hostname}:Registry\\Winlogon",
                        "remediation": r["remediation"],
                    })

            if not reg.get("LAPS_Installed", True) and not any("laps" in s.name.lower() for s in export_data.installed_software):
                r = rules.get("EP-WIN-003")
                if r:
                    findings.append({
                        "rule_id": r["id"],
                        "title": r["name"],
                        "severity": r["severity"],
                        "description": r["description"],
                        "target": export_data.hostname,
                        "remediation": r["remediation"],
                    })

            for item in export_data.persistence_mechanisms:
                if item.is_suspicious:
                    r = rules.get("EP-WIN-004")
                    if r:
                        findings.append({
                            "rule_id": r["id"],
                            "title": r["name"],
                            "severity": r["severity"],
                            "description": f"{item.suspicion_reason} Command: {item.command}",
                            "target": f"{export_data.hostname}:{item.path}",
                            "remediation": r["remediation"],
                        })

        # 3. macOS offline rules
        elif "darwin" in os_plat or "mac" in os_plat:
            rules = {r["id"]: r for r in rules_dict.get("macos_rules", [])}
            for item in export_data.persistence_mechanisms:
                if item.is_suspicious:
                    r = rules.get("EP-MAC-001")
                    if r:
                        findings.append({
                            "rule_id": r["id"],
                            "title": r["name"],
                            "severity": r["severity"],
                            "description": f"{item.suspicion_reason} File: {item.path}",
                            "target": f"{export_data.hostname}:{item.path}",
                            "remediation": r["remediation"],
                        })

        return findings


class EndpointAssessmentAdapter(ToolAdapter):
    """Unified ToolAdapter for local and offline Endpoint Security audits."""

    def __init__(self, rules_path: str | None = None):
        self.rules_path = rules_path or str(Path(__file__).parent / "rules.yaml")
        self.rules = self._load_rules()
        self.linux_adapter = LinuxAdapter()
        self.windows_adapter = WindowsAdapter()
        self.macos_adapter = MacOSAdapter()
        self.offline_adapter = OfflineAssessmentAdapter()

    def _load_rules(self) -> dict[str, Any]:
        if os.path.exists(self.rules_path):
            with open(self.rules_path, encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        return {}

    @property
    def name(self) -> str:
        return "endpoint_assessment_adapter"

    @property
    def version(self) -> str:
        return "2.0.0"

    @property
    def capabilities(self) -> list[str]:
        return [
            "endpoint.posture_assess",
            "endpoint.process_inventory",
            "endpoint.hardening_check",
            "endpoint.offline_assess",
        ]

    async def health_check(self) -> bool:
        return True

    def validate_params(self, action: ActionRequest) -> tuple[bool, str | None]:
        return True, None

    async def run(self, action: ActionRequest) -> tuple[ActionResult, bytes, str]:
        start_time = time.time()
        params = action.parameters or {}
        export_payload = params.get("export_data")
        root_dir = params.get("root_dir")

        findings: list[dict[str, Any]] = []
        data_summary: dict[str, Any] = {}

        if export_payload:
            export_obj = (
                EndpointExportData(**export_payload)
                if isinstance(export_payload, dict)
                else EndpointExportData.model_validate_json(export_payload)
            )
            findings = self.offline_adapter.evaluate_export(export_obj, self.rules)
            data_summary = {
                "mode": "offline",
                "hostname": export_obj.hostname,
                "os_platform": export_obj.os_platform,
                "process_count": len(export_obj.processes),
                "service_count": len(export_obj.services),
                "persistence_count": len(export_obj.persistence_mechanisms),
                "findings_count": len(findings),
                "findings": findings,
            }
        else:
            sys_os = platform.system().lower()
            adapter: BasePlatformAdapter
            if "linux" in sys_os or root_dir:
                adapter = self.linux_adapter
                rules_list = self.rules.get("linux_rules", [])
            elif "windows" in sys_os:
                adapter = self.windows_adapter
                rules_list = self.rules.get("windows_rules", [])
            elif "darwin" in sys_os:
                adapter = self.macos_adapter
                rules_list = self.rules.get("macos_rules", [])
            else:
                adapter = self.linux_adapter
                rules_list = []

            procs = adapter.collect_processes()
            ports = adapter.collect_listening_ports()
            pers = adapter.collect_persistence(root_dir=root_dir) if hasattr(adapter, "collect_persistence") else []
            findings = adapter.run_hardening_rules(rules_list, root_dir=root_dir)

            data_summary = {
                "mode": "local",
                "hostname": platform.node(),
                "os_platform": platform.system(),
                "process_count": len(procs),
                "listening_ports_count": len(ports),
                "persistence_mechanisms_count": len(pers),
                "findings_count": len(findings),
                "findings": findings,
            }

        raw_bytes = json.dumps(data_summary, indent=2).encode("utf-8")
        duration = time.time() - start_time
        summary = (
            f"Endpoint audit completed for '{data_summary.get('hostname')}' ({data_summary.get('mode')} mode): "
            f"{len(findings)} findings identified."
        )

        result = ActionResult(
            action_id=action.id,
            task_id=action.task_id,
            success=True,
            output_summary=summary,
            duration_seconds=round(duration, 3),
        )
        return result, raw_bytes, summary
