"""Incident management and entity quarantine subsystem for Sentinel."""

from sentinel.core.incident.incident_manager import (
    DEFAULT_CONTAINMENT_SLAS,
    Incident,
    IncidentManager,
    IncidentState,
)
from sentinel.core.incident.quarantine_manager import (
    QuarantineCategory,
    QuarantineManager,
    QuarantineRecord,
)

# Global default singletons
quarantine_manager = QuarantineManager()
incident_manager = IncidentManager(quarantine_manager=quarantine_manager)

__all__ = [
    "DEFAULT_CONTAINMENT_SLAS",
    "Incident",
    "IncidentManager",
    "IncidentState",
    "QuarantineCategory",
    "QuarantineManager",
    "QuarantineRecord",
    "incident_manager",
    "quarantine_manager",
]
