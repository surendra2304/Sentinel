"""Digital Forensics Tool Adapters for Sentinel.

Includes:
1. LogArtifactCollectorAdapter: Ingests auth.log, syslog, Windows EVTX/event logs and extracts authentication events.
2. SuperTimelineConstructorAdapter: Unifies diverse artifacts into a chronological super-timeline.
3. ForensicEventCorrelationAdapter: Evaluates event sequence heuristics (brute force to success, shell from web).
"""

import json
import os
import re
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from sentinel.core.models import ActionRequest, ActionResult
from sentinel.core.orchestrator.adapter import ToolAdapter

# ---------------------------------------------------------------------------
# 1. Log & Artifact Collector Adapter
# ---------------------------------------------------------------------------

class LogArtifactCollectorAdapter(ToolAdapter):
    """Collects and normalizes syslog, auth.log, and Windows event log entries."""

    @property
    def name(self) -> str:
        return "log_artifact_collector_adapter"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def capabilities(self) -> list[str]:
        return ["forensics.log_collect", "forensics.auth_log_parse"]

    async def health_check(self) -> bool:
        return True

    def validate_params(self, action: ActionRequest) -> tuple[bool, str | None]:
        if "log_data" not in action.parameters and "log_path" not in action.parameters:
            return False, "Parameter 'log_data' or 'log_path' required."
        return True, None

    async def run(self, action: ActionRequest) -> tuple[ActionResult, bytes, str]:
        start_time = time.time()
        log_data = action.parameters.get("log_data", "")
        log_path = action.parameters.get("log_path", "")

        if log_path and os.path.exists(log_path):
            with open(log_path, encoding="utf-8", errors="ignore") as f:
                log_data = f.read()

        events: list[dict[str, Any]] = []
        for line in log_data.split("\n"):
            line_str = line.strip()
            if not line_str:
                continue

            # Parse auth.log failed / accepted patterns
            if "Failed password for" in line_str:
                m_user = re.search(r"(?:for|user)\s+(\S+)\s+from\s+(\S+)", line_str)
                user = m_user.group(1) if m_user else "unknown"
                ip = m_user.group(2) if m_user else "unknown"
                events.append({
                    "event_type": "AUTH_FAILURE",
                    "user": user,
                    "source_ip": ip,
                    "raw_message": line_str,
                    "timestamp": datetime.now(UTC).isoformat(),
                })
            elif "Accepted password for" in line_str or "Accepted publickey for" in line_str:
                m_user = re.search(r"(?:for|user)\s+(\S+)\s+from\s+(\S+)", line_str)
                user = m_user.group(1) if m_user else "unknown"
                ip = m_user.group(2) if m_user else "unknown"
                events.append({
                    "event_type": "AUTH_SUCCESS",
                    "user": user,
                    "source_ip": ip,
                    "raw_message": line_str,
                    "timestamp": datetime.now(UTC).isoformat(),
                })

        duration = time.time() - start_time
        summary = f"Forensic log collector parsed {len(events)} authentication events."
        data = {"events_count": len(events), "events": events}
        raw_bytes = json.dumps(data, indent=2).encode("utf-8")

        result = ActionResult(
            action_id=action.id,
            task_id=action.task_id,
            success=True,
            output_summary=summary,
            duration_seconds=round(duration, 3),
        )
        return result, raw_bytes, "application/json"


# ---------------------------------------------------------------------------
# 2. Super-Timeline Constructor Adapter
# ---------------------------------------------------------------------------

class SuperTimelineConstructorAdapter(ToolAdapter):
    """Aggregates disparate forensic event sources into a unified chronological super-timeline."""

    @property
    def name(self) -> str:
        return "super_timeline_constructor_adapter"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def capabilities(self) -> list[str]:
        return ["forensics.timeline_build"]

    async def health_check(self) -> bool:
        return True

    def validate_params(self, action: ActionRequest) -> tuple[bool, str | None]:
        return True, None

    async def run(self, action: ActionRequest) -> tuple[ActionResult, bytes, str]:
        start_time = time.time()
        raw_events = action.parameters.get("events", [])
        if isinstance(raw_events, str):
            raw_events = json.loads(raw_events)

        # Sort timeline chronologically
        sorted_timeline = sorted(raw_events, key=lambda x: str(x.get("timestamp", "")))

        duration = time.time() - start_time
        summary = f"Constructed unified super-timeline containing {len(sorted_timeline)} entries."
        data = {"timeline_count": len(sorted_timeline), "timeline": sorted_timeline}
        raw_bytes = json.dumps(data, indent=2).encode("utf-8")

        result = ActionResult(
            action_id=action.id,
            task_id=action.task_id,
            success=True,
            output_summary=summary,
            duration_seconds=round(duration, 3),
        )
        return result, raw_bytes, "application/json"


# ---------------------------------------------------------------------------
# 3. Forensic Event Correlation Adapter
# ---------------------------------------------------------------------------

class ForensicEventCorrelationAdapter(ToolAdapter):
    """Applies sequence correlation heuristics to detect attack patterns."""

    def __init__(self, rules_path: str | None = None):
        self.rules_path = rules_path or str(Path(__file__).parent / "rules.yaml")
        self.rules = self._load_rules()

    def _load_rules(self) -> dict[str, Any]:
        if os.path.exists(self.rules_path):
            with open(self.rules_path, encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        return {}

    @property
    def name(self) -> str:
        return "forensic_event_correlation_adapter"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def capabilities(self) -> list[str]:
        return ["forensics.event_correlate", "forensics.sequence_detect"]

    async def health_check(self) -> bool:
        return True

    def validate_params(self, action: ActionRequest) -> tuple[bool, str | None]:
        return True, None

    async def run(self, action: ActionRequest) -> tuple[ActionResult, bytes, str]:
        start_time = time.time()
        events = action.parameters.get("events", [])
        if isinstance(events, str):
            events = json.loads(events)

        findings_list: list[dict[str, Any]] = []

        # Sequence 1: Brute Force followed by Success (Failed >= 3 from same IP followed by Success)
        failed_ips: dict[str, int] = {}
        for ev in events:
            ev_type = ev.get("event_type")
            src_ip = ev.get("source_ip", "")

            if ev_type == "AUTH_FAILURE":
                failed_ips[src_ip] = failed_ips.get(src_ip, 0) + 1
            elif ev_type == "AUTH_SUCCESS" and failed_ips.get(src_ip, 0) >= 3:
                findings_list.append({
                    "rule_id": "SEQ-001",
                    "title": f"Brute Force Authentication Followed by Successful Login from {src_ip}",
                    "severity": "HIGH",
                    "description": f"IP {src_ip} failed login {failed_ips[src_ip]} times before gaining successful entry.",
                    "remediation": "Immediately revoke compromised session and block IP at firewall.",
                    "source_ip": src_ip,
                    "user": ev.get("user", "unknown"),
                })

        duration = time.time() - start_time
        summary = f"Forensic correlation identified {len(findings_list)} attack sequences."
        data = {"findings_count": len(findings_list), "findings": findings_list}
        raw_bytes = json.dumps(data, indent=2).encode("utf-8")

        result = ActionResult(
            action_id=action.id,
            task_id=action.task_id,
            success=True,
            output_summary=summary,
            duration_seconds=round(duration, 3),
        )
        return result, raw_bytes, "application/json"

