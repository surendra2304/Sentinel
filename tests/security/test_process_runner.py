import os
import sys
import time

import pytest

from sentinel.core.sandbox.process_runner import (
    ProcessExecutionError,
    ProcessLimits,
    SafeProcessRunner,
)


@pytest.mark.asyncio
async def test_process_runner_executes_argv(tmp_path):
    runner = SafeProcessRunner()
    code, out, err, truncated = await runner.run(
        [sys.executable, "-c", "print('hello sentinel')"],
        cwd=str(tmp_path),
        env={"PATH": os.environ.get("PATH", "")} if "os" in globals() else {},
    )
    assert code == 0
    assert b"hello sentinel" in out
    assert truncated is False

@pytest.mark.asyncio
async def test_process_runner_caps_both_output_streams(tmp_path):
    cap = 128
    runner = SafeProcessRunner(ProcessLimits(timeout_seconds=5, max_output_bytes=cap))
    script = """\\
import sys
sys.stdout.buffer.write(b'o' * 200000)
sys.stderr.buffer.write(b'e' * 200000)
"""

    code, out, err, truncated = await runner.run(
        [sys.executable, "-c", script],
        cwd=str(tmp_path),
        env={"PATH": os.environ.get("PATH", "")},
    )

    assert code == 0
    marker = bytes((10,)) + b"[TRUNCATED]"
    assert out == b"o" * cap + marker
    assert err == b"e" * cap + marker
    assert truncated is True


@pytest.mark.asyncio
async def test_process_runner_timeout_raises(tmp_path):
    runner = SafeProcessRunner(ProcessLimits(timeout_seconds=0.1))
    with pytest.raises(ProcessExecutionError, match="process timeout"):
        await runner.run(
            [sys.executable, "-c", "import time; time.sleep(1.0)"],
            cwd=str(tmp_path),
            env={},
        )


@pytest.mark.skipif(os.name == "nt", reason="POSIX signal escalation semantics")
@pytest.mark.asyncio
async def test_process_runner_escalates_timeout_when_sigterm_is_ignored(tmp_path):
    runner = SafeProcessRunner(ProcessLimits(timeout_seconds=0.1))
    script = """\\
import signal
import time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
time.sleep(30)
"""
    started = time.monotonic()

    with pytest.raises(ProcessExecutionError, match="process timeout"):
        await runner.run(
            [sys.executable, "-c", script],
            cwd=str(tmp_path),
            env={},
        )

    assert 0.9 <= time.monotonic() - started < 5.0
