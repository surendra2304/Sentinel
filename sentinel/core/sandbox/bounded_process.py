"""Run subprocesses while retaining only bounded stdout and stderr prefixes."""

from __future__ import annotations

import asyncio
import contextlib
import os
import signal
from collections.abc import Sequence

_STREAM_CHUNK_BYTES = 64 * 1024
_STREAM_READER_LIMIT_BYTES = 64 * 1024


async def _capture_stream(
    stream: asyncio.StreamReader, max_output_bytes: int
) -> tuple[bytes, bool]:
    """Drain a pipe to EOF while retaining at most ``max_output_bytes``."""
    retained = bytearray()
    truncated = False

    while chunk := await stream.read(_STREAM_CHUNK_BYTES):
        available = max_output_bytes - len(retained)
        if available > 0:
            retained.extend(chunk[:available])
        if len(chunk) > available:
            truncated = True

    return bytes(retained), truncated


async def _collect_output(
    proc: asyncio.subprocess.Process, max_output_bytes: int
) -> tuple[int, bytes, bytes, bool, bool]:
    stdout_stream = proc.stdout
    stderr_stream = proc.stderr
    if stdout_stream is None or stderr_stream is None:
        raise RuntimeError("subprocess stdout and stderr pipes are required")

    stdout_task = asyncio.create_task(_capture_stream(stdout_stream, max_output_bytes))
    stderr_task = asyncio.create_task(_capture_stream(stderr_stream, max_output_bytes))
    reader_tasks = (stdout_task, stderr_task)

    try:
        await asyncio.gather(proc.wait(), *reader_tasks)
        stdout_data, stdout_truncated = stdout_task.result()
        stderr_data, stderr_truncated = stderr_task.result()
        return (
            proc.returncode if proc.returncode is not None else 0,
            stdout_data,
            stderr_data,
            stdout_truncated,
            stderr_truncated,
        )
    finally:
        for task in reader_tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*reader_tasks, return_exceptions=True)


async def _kill_and_reap(
    proc: asyncio.subprocess.Process,
    *,
    process_group: bool,
    termination_grace_seconds: float,
) -> None:
    if process_group and os.name != "nt" and termination_grace_seconds > 0:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(proc.pid, signal.SIGTERM)
        try:
            await asyncio.wait_for(proc.wait(), timeout=termination_grace_seconds)
        except TimeoutError:
            pass
        else:
            return

    if process_group and os.name != "nt":
        with contextlib.suppress(ProcessLookupError):
            os.killpg(proc.pid, signal.SIGKILL)
    elif proc.returncode is None:
        with contextlib.suppress(ProcessLookupError):
            proc.kill()

    await proc.wait()


async def _abort_process(
    proc: asyncio.subprocess.Process,
    *,
    process_group: bool,
    termination_grace_seconds: float,
) -> None:
    """Finish process cleanup even if the caller is cancelled again."""
    cleanup_task = asyncio.create_task(
        _kill_and_reap(
            proc,
            process_group=process_group,
            termination_grace_seconds=termination_grace_seconds,
        )
    )
    while not cleanup_task.done():
        try:
            await asyncio.shield(cleanup_task)
        except asyncio.CancelledError:
            continue
    cleanup_task.result()


async def run_bounded_process(
    argv: Sequence[str],
    *,
    cwd: str | None,
    env: dict[str, str] | None,
    timeout_seconds: float | None,
    max_output_bytes: int,
    termination_grace_seconds: float = 0.0,
) -> tuple[int, bytes, bytes, bool, bool]:
    """Execute explicit argv and cap retained bytes independently per stream.

    Both pipes continue to be drained after their retention caps are reached, so
    a verbose child cannot block on a full pipe or grow the parent's output
    buffers without bound. On timeout or cancellation, the child is terminated
    and reaped; on POSIX, its dedicated process group is signalled as well. A
    positive termination grace is applied only to timeout handling.
    """
    if not argv:
        raise ValueError("argv must not be empty")
    if type(max_output_bytes) is not int or max_output_bytes < 0:
        raise ValueError("max_output_bytes must be a non-negative integer")
    if termination_grace_seconds < 0:
        raise ValueError("termination_grace_seconds must be non-negative")

    process_group = os.name != "nt"
    if process_group:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            cwd=cwd,
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=_STREAM_READER_LIMIT_BYTES,
            start_new_session=True,
        )
    else:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            cwd=cwd,
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=_STREAM_READER_LIMIT_BYTES,
        )

    try:
        return await asyncio.wait_for(
            _collect_output(proc, max_output_bytes), timeout=timeout_seconds
        )
    except TimeoutError:
        await _abort_process(
            proc,
            process_group=process_group,
            termination_grace_seconds=termination_grace_seconds,
        )
        raise
    except BaseException:
        await _abort_process(
            proc,
            process_group=process_group,
            termination_grace_seconds=0.0,
        )
        raise
