import os
import sys

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
async def test_process_runner_timeout_raises(tmp_path):
    runner = SafeProcessRunner(ProcessLimits(timeout_seconds=0.1))
    with pytest.raises(ProcessExecutionError, match="process timeout"):
        await runner.run(
            [sys.executable, "-c", "import time; time.sleep(1.0)"],
            cwd=str(tmp_path),
            env={},
        )
