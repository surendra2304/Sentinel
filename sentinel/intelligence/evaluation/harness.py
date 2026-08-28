"""Evaluation Harness for SENTINEL Intelligence Layer.

Provides record/replay infrastructure for AI Universe integration testing.
Fixtures are stored as JSON under tests/fixtures/intelligence/.
"""

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sentinel.core.intelligence.interface import (
    IntelligenceProvider,
    IntelligenceRequest,
    IntelligenceRole,
)
from sentinel.core.models import Finding, Task
from sentinel.logging.logger import get_logger

logger = get_logger("sentinel.intelligence.evaluation")

FIXTURE_DIR = Path("tests/fixtures/intelligence")


@dataclass
class TaskContext:
    """Snapshot of a task execution context for replay-based evaluation."""

    task_id: str
    objective: str
    targets: list[dict[str, Any]]
    findings: list[dict[str, Any]] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)
    expected_plan_phases: list[str] = field(default_factory=list)
    timeline_events: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "objective": self.objective,
            "targets": self.targets,
            "findings": self.findings,
            "evidence_refs": self.evidence_refs,
            "expected_plan_phases": self.expected_plan_phases,
            "timeline_events": self.timeline_events,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TaskContext":
        return cls(**data)

    @classmethod
    def from_task(
        cls,
        task: Task,
        findings: list[Finding] | None = None,
        evidence_refs: list[str] | None = None,
        expected_phases: list[str] | None = None,
    ) -> "TaskContext":
        return cls(
            task_id=task.id,
            objective=task.objective,
            targets=[{"type": t.type.value, "value": t.value} for t in task.target_set.targets],
            findings=[f.model_dump() for f in (findings or [])],
            evidence_refs=evidence_refs or [],
            expected_plan_phases=expected_phases or [],
        )


@dataclass
class EvaluationResult:
    """Scoring result from a replay run."""

    fixture_path: str
    provider_name: str
    role: IntelligenceRole
    schema_valid: bool
    latency_ms: float
    # Planning-specific scores
    plan_sanity_score: float = 0.0  # fraction of expected_plan_phases found in output
    # Quality review
    quality_review_caught_weak_finding: bool = False
    # Full structured output for inspection
    structured_output: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


class EvaluationHarness:
    """Replay-based evaluation framework for IntelligenceProvider implementations."""

    def __init__(self, fixture_dir: Path | None = None) -> None:
        self._fixture_dir = fixture_dir or FIXTURE_DIR
        self._fixture_dir.mkdir(parents=True, exist_ok=True)

    def record(self, context: TaskContext, name: str | None = None) -> Path:
        """Serialize a TaskContext to a JSON fixture file."""
        fname = name or f"ctx-{context.task_id}.json"
        path = self._fixture_dir / fname
        path.write_text(json.dumps(context.to_dict(), indent=2, default=str), encoding="utf-8")
        logger.info("Recorded fixture", extra={"path": str(path)})
        return path

    async def replay(
        self,
        fixture_path: Path | str,
        provider: IntelligenceProvider,
        role: IntelligenceRole = IntelligenceRole.PLANNING,
    ) -> EvaluationResult:
        """Replay a fixture through a provider and score the output."""
        path = Path(fixture_path)
        ctx = TaskContext.from_dict(json.loads(path.read_text(encoding="utf-8")))

        context_payload = self._build_context(ctx, role)
        req = IntelligenceRequest(
            role=role,
            context=context_payload,
            request_id=f"eval-{ctx.task_id[:8]}",
        )

        start = time.monotonic()
        result = await provider.request(req)
        latency = (time.monotonic() - start) * 1000

        eval_result = EvaluationResult(
            fixture_path=str(path),
            provider_name=result.provider_used,
            role=role,
            schema_valid=result.schema_valid,
            latency_ms=latency,
            structured_output=result.structured_output,
            error=result.error,
        )

        # Role-specific scoring
        if role == IntelligenceRole.PLANNING:
            eval_result.plan_sanity_score = self._score_plan(
                result.structured_output, ctx.expected_plan_phases
            )
        elif role == IntelligenceRole.QUALITY_REVIEW:
            eval_result.quality_review_caught_weak_finding = self._score_quality_review(
                result.structured_output
            )

        return eval_result

    def _build_context(self, ctx: TaskContext, role: IntelligenceRole) -> dict[str, Any]:
        match role:
            case IntelligenceRole.PLANNING:
                return {
                    "task_id": ctx.task_id,
                    "objective": ctx.objective,
                    "targets": ctx.targets,
                    "state_flags": {},
                    "evidence_count": len(ctx.evidence_refs),
                    "agent_capabilities": [],
                }
            case IntelligenceRole.CORRELATION | IntelligenceRole.QUALITY_REVIEW:
                return {"findings": ctx.findings, "task_id": ctx.task_id}
            case IntelligenceRole.FORENSICS_REASONING:
                return {"timeline_events": ctx.timeline_events, "task_id": ctx.task_id}
            case IntelligenceRole.REPORT_SYNTHESIS:
                critical = sum(1 for f in ctx.findings if f.get("severity") == "critical")
                return {
                    "task_objective": ctx.objective,
                    "total_findings": len(ctx.findings),
                    "critical_count": critical,
                    "risk_score": 7.5 if critical else 4.0,
                }
            case _:
                return {"task_id": ctx.task_id, "objective": ctx.objective}

    @staticmethod
    def _score_plan(output: dict[str, Any], expected_phases: list[str]) -> float:
        if not expected_phases:
            return 1.0 if output.get("steps") else 0.0
        phases_found = {s.get("phase", "") for s in output.get("steps", [])}
        phases_covered = output.get("phases_covered", list(phases_found))
        all_phases = set(phases_covered) | phases_found
        matched = sum(1 for p in expected_phases if p in all_phases)
        return matched / len(expected_phases)

    @staticmethod
    def _score_quality_review(output: dict[str, Any]) -> bool:
        return any(
            r.get("verdict") == "flag" and (r.get("confidence_adjustment", 0) or 0) < 0
            for r in output.get("reviewed_findings", [])
        )
