"""Per-Task Working Memory for Sentinel.

Provides structured, evolving state for assets, observations, evidence, and findings,
giving the autonomous planner and agents rich contextual state.
"""

from typing import Any

from pydantic import BaseModel, Field

from sentinel.core.models import Finding, Target
from sentinel.intelligence.risk.finding_engine import Observation


class TaskWorkingMemory(BaseModel):
    """Structured memory state for an active task."""
    task_id: str
    discovered_assets: list[Target] = Field(default_factory=list)
    observations: list[Observation] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    completed_actions: list[str] = Field(default_factory=list)
    execution_trace: list[dict[str, Any]] = Field(default_factory=list)
    state_flags: dict[str, Any] = Field(default_factory=dict)

    def add_asset(self, target: Target) -> None:
        if not any(a.value == target.value for a in self.discovered_assets):
            self.discovered_assets.append(target)

    def record_step(self, step_name: str, details: dict[str, Any]) -> None:
        self.execution_trace.append({
            "step": step_name,
            "details": details,
        })


class MemoryStore:
    """In-memory or persistent store for TaskWorkingMemory instances."""

    def __init__(self):
        self._memories: dict[str, TaskWorkingMemory] = {}

    def get_memory(self, task_id: str) -> TaskWorkingMemory:
        if task_id not in self._memories:
            self._memories[task_id] = TaskWorkingMemory(task_id=task_id)
        return self._memories[task_id]

    def clear_memory(self, task_id: str) -> None:
        self._memories.pop(task_id, None)


# Global Memory Store Singleton
memory_store = MemoryStore()
