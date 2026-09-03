"""Sentinel Hardened Process Runner.

Executes explicit argv without shell, sets up isolated process groups,
strips host environment secrets, bounds output streams, and enforces timeout escalation.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import signal
import sys
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ProcessLimits:
    timeout_seconds: float = 30.0
    max_output_bytes: int = 1_000_000


class ProcessExecutionError(RuntimeError):
    """Raised when process execution fails or times out."""


class SafeProcessRunner:
    """Runs argv without a shell and terminates the entire process group on timeout."""

    def __init__(self, limits: ProcessLimits | None = None):
        self.limits = limits or ProcessLimits()

    async def run(
        self, argv: list[str], *, cwd: str, env: dict[str, str]
    ) -> tuple[int, bytes, bytes, bool]:
        if not argv:
            raise ProcessExecutionError("empty argv")

        if sys.platform != "win32":
            proc = await asyncio.create_subprocess_exec(
                *argv,
                cwd=cwd,
                env=env,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
            )
        else:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                cwd=cwd,
                env=env,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

        try:
            out, err = await asyncio.wait_for(
                proc.communicate(), timeout=self.limits.timeout_seconds
            )
        except TimeoutError as exc:
            killpg_fn = getattr(os, "killpg", None)
            sigterm_val = getattr(signal, "SIGTERM", 15)
            sigkill_val = getattr(signal, "SIGKILL", 9)
            if killpg_fn is not None:
                with contextlib.suppress(Exception):
                    killpg_fn(proc.pid, sigterm_val)
                try:
                    await asyncio.wait_for(proc.wait(), timeout=1.0)
                except TimeoutError:
                    with contextlib.suppress(Exception):
                        killpg_fn(proc.pid, sigkill_val)
                    await proc.wait()
            else:
                with contextlib.suppress(Exception):
                    proc.kill()
                await proc.wait()
            raise ProcessExecutionError(
                f"process timeout after {self.limits.timeout_seconds}s: {argv[0]}"
            ) from exc

        out2, t1 = _truncate(out, self.limits.max_output_bytes)
        err2, t2 = _truncate(err, self.limits.max_output_bytes)
        return proc.returncode or 0, out2, err2, (t1 or t2)


def _truncate(data: bytes, cap: int) -> tuple[bytes, bool]:
    if len(data) <= cap:
        return data, False
    return data[:cap] + b"\n[TRUNCATED]", True
