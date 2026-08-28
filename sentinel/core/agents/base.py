"""Agent Contract and Registry for Sentinel.

Defines the abstract BaseAgent and typed AgentReport contracts.
All autonomous agents in Sentinel output structured reports with typed ActionRequests,
observations, evidence references, and next-step recommendations.
"""

from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, Field

from sentinel.core.models import (
    ActionRequest,
    Finding,
    Policy,
    Scope,
    TargetSet,
    Task,
)
from sentinel.intelligence.risk.finding_engine import Observation


class AgentReport(BaseModel):
    """Structured report returned by an Agent execution step."""
    agent_name: str
    task_id: str
    observations: list[Observation] = Field(default_factory=list)
    actions_requested: list[ActionRequest] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    recommended_next_step: str | None = None
    reasoning: str | None = None


class BaseAgent(ABC):
    """Abstract Base Agent for all specialized Sentinel autonomous agents."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique agent name (e.g. 'recon_agent', 'vuln_agent')."""
        pass

    @property
    @abstractmethod
    def domain(self) -> str:
        """Operational domain (e.g. 'reconnaissance', 'web_security', 'network_security')."""
        pass

    @property
    @abstractmethod
    def capabilities(self) -> list[str]:
        """List of action types this agent knows how to request and analyze."""
        pass

    @abstractmethod
    async def analyze(
        self,
        task: Task,
        target_set: TargetSet,
        scope: Scope,
        policy: Policy,
        available_evidence: list[dict[str, Any]],
        working_memory: dict[str, Any],
    ) -> AgentReport:
        """Analyze current context, synthesize observations, and propose next actions."""
        pass


class AgentRegistry:
    """Central registry indexing available agents and their operational domains."""

    def __init__(self):
        self._agents: dict[str, BaseAgent] = {}

    def register(self, agent: BaseAgent) -> None:
        self._agents[agent.name] = agent

    def get_agent(self, name: str) -> BaseAgent | None:
        return self._agents.get(name)

    def list_agents(self) -> list[BaseAgent]:
        return list(self._agents.values())


# Global Agent Registry Singleton
agent_registry = AgentRegistry()
