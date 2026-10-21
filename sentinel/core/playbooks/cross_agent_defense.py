"""Cross-Agent Automated Threat Defense & Containment Playbook.

Coordinates multi-agent defense when high-severity threats or pre-delivery VETOs occur:
1. Ingests and correlates IntelX threat intelligence with pre-delivery audit findings.
2. Quarantines compromised tokens, malicious IPs, attacker domains, or untrusted containers.
3. Automatically opens and triages Incidents with severity SLAs.
4. Signals IntelX de-confliction blocks to isolate hostile infrastructure.
5. Emits real-time event bus alerts and writes durable cryptographic audit records.
"""

from __future__ import annotations

import contextlib
import logging
import re
import time
import uuid
from typing import Any

from pydantic import BaseModel, Field

from sentinel.audit.audit_logger import audit_logger
from sentinel.core.events.bus import emit_event
from sentinel.core.gateway.models import RiskLevel
from sentinel.core.incident import (
    IncidentManager,
    QuarantineCategory,
    QuarantineManager,
)
from sentinel.core.incident import (
    incident_manager as default_incident_mgr,
)
from sentinel.core.incident import (
    quarantine_manager as default_quarantine_mgr,
)
from sentinel.core.models import EventType
from sentinel.integrations.ecosystem.intelx_bridge import (
    IntelXCoordinationBridge,
)

logger = logging.getLogger("sentinel.playbooks.cross_agent_defense")


class ContainmentAction(BaseModel):
    """Individual containment step executed during playbook enforcement."""

    action: str
    target: str
    category: str
    status: str = "SUCCESS"  # "SUCCESS" | "FAILED" | "SKIPPED"
    reason: str = ""
    timestamp: float = Field(default_factory=time.time)
    metadata: dict[str, Any] = Field(default_factory=dict)


class PlaybookExecutionReport(BaseModel):
    """Complete summary of playbook containment enforcement."""

    playbook_id: str = Field(default_factory=lambda: f"pb-{uuid.uuid4().hex[:8]}")
    playbook_name: str = "cross_agent_threat_containment"
    trigger_source: str  # "security_audit" | "intelx_threat_feed" | "manual"
    incident_id: str
    severity: str  # "CRITICAL" | "HIGH" | "MEDIUM"
    contained_entities: list[str] = Field(default_factory=list)
    actions_taken: list[ContainmentAction] = Field(default_factory=list)
    intelx_deconfliction_blocked: bool = False
    trading_guard_engaged: bool = False
    status: str = "CONTAINED"  # "CONTAINED" | "PARTIAL" | "FAILED"
    executed_at: float = Field(default_factory=time.time)
    duration_seconds: float = 0.0


# Regex patterns for IOC extraction from finding descriptions/titles
IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_REGEX = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")


class CrossAgentDefensePlaybook:
    """Orchestrates real-time threat containment across FRIDAY Universe agents."""

    def __init__(
        self,
        incident_mgr: IncidentManager | None = None,
        quarantine_mgr: QuarantineManager | None = None,
        intelx_bridge: IntelXCoordinationBridge | None = None,
    ) -> None:
        self.incident_mgr = incident_mgr or default_incident_mgr
        self.quarantine_mgr = quarantine_mgr or default_quarantine_mgr
        self.intelx_bridge = intelx_bridge or IntelXCoordinationBridge()

    def _determine_category(self, target: str, rule_id: str) -> QuarantineCategory:
        """Infer QuarantineCategory from target pattern and rule ID."""
        clean = target.strip()
        if "TOKEN" in rule_id or "SECRET" in rule_id or "KEY" in rule_id:
            return QuarantineCategory.TOKEN
        if IP_REGEX.match(clean):
            return QuarantineCategory.IP
        if DOMAIN_REGEX.match(clean) and not clean.endswith(".py"):
            return QuarantineCategory.DOMAIN
        return QuarantineCategory.USER

    async def execute_audit_veto_containment(
        self,
        audit_id: str,
        task_id: str,
        source_service: str,
        operator: str,
        findings: list[dict[str, Any]],
        declared_targets: list[str] | None = None,
        workspace_diff: str | None = None,
    ) -> PlaybookExecutionReport:
        """Enforce automated containment following a Pre-Delivery Security VETO."""
        start_time = time.time()
        crit_count = sum(1 for f in findings if str(f.get("severity", "")).upper() == "CRITICAL")
        severity = RiskLevel.CRITICAL if crit_count > 0 else RiskLevel.HIGH

        incident_id = f"inc-{audit_id}"
        incident_title = (
            f"Pre-Delivery VETO on {source_service} (Audit {audit_id}): {crit_count} Critical findings"
        )
        incident_reason = f"Security audit gate vetoed delivery for operator '{operator}' on task '{task_id}'."

        # 1. Open Incident in IncidentManager
        incident = self.incident_mgr.create(
            id=incident_id,
            tenant_id="default",
            title=incident_title,
            severity=severity,
            reason=incident_reason,
            metadata={
                "audit_id": audit_id,
                "task_id": task_id,
                "source_service": source_service,
                "operator": operator,
                "findings_count": len(findings),
            },
        )

        actions_taken: list[ContainmentAction] = []
        contained_entities: list[str] = []
        trading_guard_engaged = False
        intelx_blocked = False

        # 2. Extract IOCs and Quarantinable Subjects from findings & diff
        entities_to_quarantine: list[tuple[str, QuarantineCategory, str]] = []

        # Quarantine operator if deliberate bypass or secret exposure
        for f in findings:
            rule_id = str(f.get("rule_id", ""))
            desc = str(f.get("description", ""))
            title = str(f.get("title", ""))

            # Reverse shell / code execution / dangerous network calls
            if rule_id in ("NET-001", "CODE-EVAL", "CODE-SHELL", "CODE-TRAVERSAL"):
                trading_guard_engaged = True
                entities_to_quarantine.append(
                    (f"operator:{operator}", QuarantineCategory.USER, f"Triggered dangerous code rule {rule_id}: {title}")
                )

            # Hardcoded secret or compromised token
            if "SECRET" in rule_id or "TOKEN" in rule_id:
                entities_to_quarantine.append(
                    (f"token:{operator}-session", QuarantineCategory.TOKEN, f"Hardcoded credential violation: {title}")
                )

            # Scope violations or extracted targets
            for match in IP_REGEX.findall(desc):
                entities_to_quarantine.append(
                    (match, QuarantineCategory.IP, f"Malicious IP detected in audit finding {rule_id}")
                )

        # Also quarantine out-of-scope declared targets
        if declared_targets:
            for tgt in declared_targets:
                entities_to_quarantine.append(
                    (tgt, self._determine_category(tgt, "SCOPE"), f"Target outside declared scope in audit {audit_id}")
                )

        # 3. Apply Quarantines via QuarantineManager
        for subject, cat, reason in entities_to_quarantine:
            if subject not in contained_entities:
                try:
                    self.quarantine_mgr.put(
                        subject=subject,
                        reason=reason,
                        ttl=3600.0,  # 1 hour containment
                        category=cat,
                        initiator="sentinel_defense_playbook",
                        incident_id=incident_id,
                    )
                    contained_entities.append(subject)
                    actions_taken.append(
                        ContainmentAction(
                            action="QUARANTINE_ENTITY",
                            target=subject,
                            category=cat.value,
                            status="SUCCESS",
                            reason=reason,
                        )
                    )
                except Exception as exc:
                    logger.error(f"Failed to quarantine subject '{subject}': {exc}")
                    actions_taken.append(
                        ContainmentAction(
                            action="QUARANTINE_ENTITY",
                            target=subject,
                            category=cat.value,
                            status="FAILED",
                            reason=str(exc),
                        )
                    )

        # 4. Sync De-confliction Block to IntelX
        if declared_targets:
            for tgt in declared_targets:
                self.intelx_bridge.register_sentinel_engagement(tgt)
                intelx_blocked = True
                actions_taken.append(
                    ContainmentAction(
                        action="INTELX_DECONFLICTION_BLOCK",
                        target=tgt,
                        category="target_lock",
                        status="SUCCESS",
                        reason=f"Locked target '{tgt}' against conflicting IntelX operations.",
                    )
                )

        # 5. Mark Incident as Contained in IncidentManager
        try:
            self.incident_mgr.contain(incident_id)
            actions_taken.append(
                ContainmentAction(
                    action="CONTAIN_INCIDENT",
                    target=incident_id,
                    category="incident_management",
                    status="SUCCESS",
                    reason="Contained incident and applied automated mitigations.",
                )
            )
        except Exception as exc:
            logger.warning(f"Could not contain incident '{incident_id}': {exc}")

        # 6. Publish Real-Time Event & Cryptographic Audit
        duration = round(time.time() - start_time, 3)
        await emit_event(
            EventType.ALERT,
            "playbook.threat_containment.executed",
            "sentinel_defense_playbook",
            {
                "incident_id": incident.id,
                "audit_id": audit_id,
                "severity": severity.value,
                "contained_entities": contained_entities,
                "trading_guard_engaged": trading_guard_engaged,
                "duration_seconds": duration,
            },
            f"pb-{incident_id}",
        )

        audit_logger.log_event(
            entry_id=f"audit-pb-{incident_id}",
            event_type="CROSS_AGENT_DEFENSE_PLAYBOOK",
            actor="sentinel_defense_playbook",
            action_type="THREAT_CONTAINMENT",
            scope_policy="mesh_defense_policy",
            decision="CONTAINED",
            target=source_service,
            details={
                "incident_id": incident.id,
                "contained_count": len(contained_entities),
                "actions_count": len(actions_taken),
                "trading_guard_engaged": trading_guard_engaged,
            },
        )

        return PlaybookExecutionReport(
            incident_id=incident_id,
            trigger_source="security_audit",
            severity=severity.value.upper(),
            contained_entities=contained_entities,
            actions_taken=actions_taken,
            intelx_deconfliction_blocked=intelx_blocked,
            trading_guard_engaged=trading_guard_engaged,
            status="CONTAINED" if contained_entities else "PARTIAL",
            duration_seconds=duration,
        )

    async def execute_intelx_threat_containment(
        self,
        investigation_id: str,
        iocs: list[dict[str, str]],
    ) -> PlaybookExecutionReport:
        """Enforce automated containment when IntelX discovers active malicious indicators."""
        start_time = time.time()
        incident_id = f"inc-intelx-{investigation_id}"
        incident_title = f"IntelX Hostile Intelligence Discovery: Investigation {investigation_id}"
        incident_reason = f"Automated quarantine triggered from IntelX OSINT indicators ({len(iocs)} items)."

        # 1. Ingest IOCs into IntelX Bridge
        ingested = self.intelx_bridge.ingest_osint_findings(investigation_id, iocs)

        # 2. Open Incident
        self.incident_mgr.create(
            id=incident_id,
            tenant_id="default",
            title=incident_title,
            severity=RiskLevel.HIGH,
            reason=incident_reason,
            metadata={"investigation_id": investigation_id, "ioc_count": len(ingested)},
        )

        actions_taken: list[ContainmentAction] = []
        contained_entities: list[str] = []

        # 3. Quarantine High-Confidence IOCs
        for item in ingested:
            val = item.value.strip()
            cat = QuarantineCategory.IP if item.ioc_type.value == "ip" else QuarantineCategory.DOMAIN
            try:
                self.quarantine_mgr.put(
                    subject=val,
                    reason=f"Hostile indicator from IntelX investigation {investigation_id}",
                    ttl=7200.0,  # 2 hour containment
                    category=cat,
                    initiator="intelx_bridge",
                    incident_id=incident_id,
                )
                contained_entities.append(val)
                actions_taken.append(
                    ContainmentAction(
                        action="QUARANTINE_ENTITY",
                        target=val,
                        category=cat.value,
                        status="SUCCESS",
                        reason=item.context,
                    )
                )
            except Exception as exc:
                logger.error(f"Failed to quarantine IntelX IOC '{val}': {exc}")

        # 4. Contain Incident
        with contextlib.suppress(Exception):
            self.incident_mgr.contain(incident_id)

        duration = round(time.time() - start_time, 3)
        await emit_event(
            EventType.ALERT,
            "playbook.intelx_threat.contained",
            "sentinel_defense_playbook",
            {
                "incident_id": incident_id,
                "investigation_id": investigation_id,
                "contained_count": len(contained_entities),
                "duration_seconds": duration,
            },
            f"pb-{incident_id}",
        )

        return PlaybookExecutionReport(
            incident_id=incident_id,
            trigger_source="intelx_threat_feed",
            severity="HIGH",
            contained_entities=contained_entities,
            actions_taken=actions_taken,
            intelx_deconfliction_blocked=True,
            trading_guard_engaged=False,
            status="CONTAINED",
            duration_seconds=duration,
        )


# Global singleton instance
cross_agent_defense_playbook = CrossAgentDefensePlaybook()
