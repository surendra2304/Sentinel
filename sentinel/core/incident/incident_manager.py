"""Sentinel Incident Management."""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from sentinel.core.gateway.models import RiskLevel


@dataclass(slots=True)
class Incident:
    id: str
    tenant_id: str
    title: str
    severity: RiskLevel
    reason: str
    created_at: float = field(default_factory=time.time)
    contained: bool = False
    evidence_refs: list[str] = field(default_factory=list)


class IncidentManager:
    def __init__(self):
        self.incidents: dict[str, Incident] = {}

    def open(self, incident: Incident) -> Incident:
        self.incidents[incident.id] = incident
        return incident

    def contain(self, incident_id: str) -> None:
        if incident_id in self.incidents:
            self.incidents[incident_id].contained = True

    def active(self, tenant_id: str) -> list[Incident]:
        return [
            i for i in self.incidents.values()
            if i.tenant_id == tenant_id and not i.contained
        ]
