"""Sentinel hardened process runner.

Executes explicit argv, bounds retained output, and enforces timeout cleanup.
"""

from __future__ import annotations

from dataclasses import dataclass

from sentinel.core.sandbox.bounded_process import run_bounded_process


@dataclass(frozen=True, slots=True)
class ProcessLimits:
    timeout_seconds: float = 30.0
    max_output_bytes: int = 1_000_000


class ProcessExecutionError(RuntimeError):
    """Raised when process execution fails or times out."""


class SafeProcessRunner:
    """Runs argv without a shell and terminates the process group on timeout."""

    def __init__(self, limits: ProcessLimits | None = None):
        self.limits = limits or ProcessLimits()

    async def run(
        self, argv: list[str], *, cwd: str, env: dict[str, str]
    ) -> tuple[int, bytes, bytes, bool]:
        if not argv:
            raise ProcessExecutionError("empty argv")

        try:
            returncode, stdout, stderr, stdout_truncated, stderr_truncated = (
                await run_bounded_process(
                    argv,
                    cwd=cwd,
                    env=env,
                    timeout_seconds=self.limits.timeout_seconds,
                    max_output_bytes=self.limits.max_output_bytes,
                    termination_grace_seconds=1.0,
                )
            )
        except TimeoutError as exc:
            raise ProcessExecutionError(
                f"process timeout after {self.limits.timeout_seconds}s: {argv[0]}"
            ) from exc

        marker = bytes((10,)) + b"[TRUNCATED]"
        if stdout_truncated:
            stdout += marker
        if stderr_truncated:
            stderr += marker

        return (
            returncode,
            stdout,
            stderr,
            stdout_truncated or stderr_truncated,
        )
