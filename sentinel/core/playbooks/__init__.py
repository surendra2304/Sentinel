"""Automated defensive and incident containment playbooks for Sentinel."""

from sentinel.core.playbooks.cross_agent_defense import (
    ContainmentAction,
    CrossAgentDefensePlaybook,
    PlaybookExecutionReport,
    cross_agent_defense_playbook,
)

__all__ = [
    "ContainmentAction",
    "CrossAgentDefensePlaybook",
    "PlaybookExecutionReport",
    "cross_agent_defense_playbook",
]
