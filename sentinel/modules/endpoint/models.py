"""Data models and schemas for Endpoint Security Domain in Sentinel."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class OSPlatform(StrEnum):
    LINUX = "linux"
    MACOS = "darwin"
    WINDOWS = "windows"
    UNKNOWN = "unknown"


class ProcessInfo(BaseModel):
    pid: int
    name: str
    username: str | None = None
    cmdline: list[str] = Field(default_factory=list)
    exe: str | None = None
    ppid: int | None = None
    is_elevated: bool = False
    is_writable_by_user: bool = False


class ServiceInfo(BaseModel):
    name: str
    display_name: str | None = None
    status: str  # running, stopped, disabled
    start_type: str | None = None  # auto, manual, disabled
    binary_path: str | None = None
    account: str | None = None  # LocalSystem, root, user
    is_writable_by_user: bool = False


class ListeningPort(BaseModel):
    proto: str  # tcp, udp
    ip: str
    port: int
    state: str  # LISTEN, ESTABLISHED, NONE
    pid: int | None = None
    process_name: str | None = None


class UserPrivilegeInfo(BaseModel):
    username: str
    groups: list[str] = Field(default_factory=list)
    is_admin: bool = False
    has_sudo_nopasswd: bool = False
    home_dir: str | None = None
    shell: str | None = None


class PersistenceItem(BaseModel):
    type: str  # cron, systemd, launchd, registry_run, scheduled_task
    name: str
    path: str
    command: str
    owner: str | None = None
    is_suspicious: bool = False
    suspicion_reason: str | None = None


class InstalledSoftware(BaseModel):
    name: str
    version: str | None = None
    publisher: str | None = None
    install_date: str | None = None


class EndpointExportData(BaseModel):
    """Normalized export format for offline endpoint security audits."""
    version: str = "1.0.0"
    os_platform: str
    os_release: str | None = None
    hostname: str
    collected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    processes: list[ProcessInfo] = Field(default_factory=list)
    services: list[ServiceInfo] = Field(default_factory=list)
    listening_ports: list[ListeningPort] = Field(default_factory=list)
    users: list[UserPrivilegeInfo] = Field(default_factory=list)
    persistence_mechanisms: list[PersistenceItem] = Field(default_factory=list)
    installed_software: list[InstalledSoftware] = Field(default_factory=list)
    raw_configs: dict[str, str] = Field(default_factory=dict)  # e.g., /etc/ssh/sshd_config content, sudoers
    registry_keys: dict[str, Any] = Field(default_factory=dict)  # Windows specific registry dumps
    system_files: dict[str, str] = Field(default_factory=dict)  # launchd plists, cron files
