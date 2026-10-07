"""Per-task working memory with versioned durable checkpoint support."""

import json
from typing import Any

from pydantic import BaseModel, Field

from sentinel.core.models import AgentHandoff, Finding, Target
from sentinel.intelligence.risk.finding_engine import Observation


class TaskWorkingMemory(BaseModel):
    """Structured, serializable state for an active task."""

    task_id: str
    discovered_assets: list[Target] = Field(default_factory=list)
    observations: list[Observation] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    completed_actions: list[str] = Field(default_factory=list)
    execution_trace: list[dict[str, Any]] = Field(default_factory=list)
    state_flags: dict[str, Any] = Field(default_factory=dict)
    pending_handoffs: list[AgentHandoff] = Field(default_factory=list)
    handoff_trace: list[dict[str, Any]] = Field(default_factory=list)
    proposal_fingerprints: set[str] = Field(default_factory=set)
    proposal_keys: dict[str, str] = Field(default_factory=dict)
    completed_action_fingerprints: set[str] = Field(default_factory=set)
    attempted_action_fingerprints: set[str] = Field(default_factory=set)
    deferred_plan_steps: list[dict[str, Any]] = Field(default_factory=list)
    agent_action_counts: dict[str, int] = Field(default_factory=dict)
    action_outcomes: dict[str, dict[str, Any]] = Field(default_factory=dict)
    in_flight_action: dict[str, Any] | None = None
    last_iteration: int = 0

    def add_asset(self, target: Target) -> None:
        if not any(asset.value == target.value for asset in self.discovered_assets):
            self.discovered_assets.append(target)

    def record_step(self, step_name: str, details: dict[str, Any]) -> None:
        self.execution_trace.append({"step": step_name, "details": details})
        if len(self.execution_trace) > 1_000:
            del self.execution_trace[:-1_000]


class MemoryStore:
    """Cache task memory while persisting complete checkpoints through TaskRepository."""

    def __init__(
        self,
        checkpoint_repository: Any | None = None,
        max_checkpoint_bytes: int = 2_000_000,
    ) -> None:
        self._memories: dict[str, TaskWorkingMemory] = {}
        self._versions: dict[str, int] = {}
        self._checkpoint_repository = checkpoint_repository
        self.max_checkpoint_bytes = max_checkpoint_bytes

    @property
    def checkpoint_repository(self) -> Any:
        if self._checkpoint_repository is None:
            from sentinel.storage.repositories.factory import get_task_repository

            self._checkpoint_repository = get_task_repository()
        return self._checkpoint_repository

    def get_memory(self, task_id: str) -> TaskWorkingMemory:
        """Get or create cached memory synchronously for legacy callers."""
        if task_id not in self._memories:
            self._memories[task_id] = TaskWorkingMemory(task_id=task_id)
            self._versions[task_id] = 0
        return self._memories[task_id]

    async def load_memory(self, task_id: str) -> TaskWorkingMemory:
        """Load a checkpoint once, or create a new task-memory record."""
        if task_id in self._memories:
            return self._memories[task_id]

        checkpoint = await self.checkpoint_repository.get_checkpoint(task_id)
        if checkpoint is None:
            memory = TaskWorkingMemory(task_id=task_id)
            version = 0
        else:
            payload = checkpoint.get("payload")
            if not isinstance(payload, dict):
                raise ValueError(f"Checkpoint payload for task {task_id} is malformed.")
            memory = TaskWorkingMemory.model_validate(payload)
            if memory.task_id != task_id:
                raise ValueError(f"Checkpoint task identity mismatch for task {task_id}.")
            version = int(checkpoint.get("version", 0))

        self._memories[task_id] = memory
        self._versions[task_id] = version
        return memory

    async def persist_memory(self, memory: TaskWorkingMemory) -> int:
        """Persist a bounded JSON checkpoint before and after each action boundary."""
        payload = memory.model_dump(mode="json")
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if len(encoded) > self.max_checkpoint_bytes:
            raise ValueError(
                f"Task checkpoint exceeds configured in-memory safety bound "
                f"({len(encoded)} > {self.max_checkpoint_bytes} bytes)."
            )

        if memory.task_id not in self._versions:
            await self.load_memory(memory.task_id)

        version = int(await self.checkpoint_repository.save_checkpoint(memory.task_id, payload))
        self._memories[memory.task_id] = memory
        self._versions[memory.task_id] = version
        return version

    def clear_memory(self, task_id: str) -> None:
        """Drop only the process-local cache; durable checkpoints remain available."""
        self._memories.pop(task_id, None)
        self._versions.pop(task_id, None)


# Global process-local cache backed by the configured task repository.
memory_store = MemoryStore()
