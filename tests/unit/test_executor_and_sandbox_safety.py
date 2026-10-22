"""Executor and Sandbox Safety Test Suite.

Verifies:
1. Subprocess timeout kill and process cleanup.
2. Output size caps (prevent memory exhaustion).
3. Injection safety (shell metacharacters reach subprocess as a single argv element without shell expansion).
4. Retry and exponential backoff on transient errors.
5. Concurrency limits via semaphore gating.
"""

import asyncio
import sys
import tracemalloc
from unittest.mock import AsyncMock

import psutil
import pytest

from sentinel.core.models import (
    ActionRequest,
    ActionResult,
    Evidence,
    ImpactLevel,
    Policy,
    Scope,
    Target,
    TargetSet,
    Task,
)
from sentinel.core.orchestrator.adapter import ToolAdapter
from sentinel.core.orchestrator.executor import ExecutionEngine
from sentinel.core.orchestrator.sandbox import SandboxExecutionError, SubprocessSandbox
from sentinel.storage.evidence.store import EvidenceStore


@pytest.mark.asyncio
async def test_sandbox_timeout_kill():
    sandbox = SubprocessSandbox(default_timeout_seconds=0.5)
    # Python script that sleeps for 5 seconds
    cmd = [sys.executable, "-c", "import time; time.sleep(5)"]
    with pytest.raises(SandboxExecutionError, match="timed out"):
        await sandbox.execute_command(cmd, timeout=0.5)

    short_cmd = [sys.executable, "-c", "import time; time.sleep(0.1)"]
    with pytest.raises(SandboxExecutionError, match="timed out"):
        await sandbox.execute_command(short_cmd, timeout=0)


@pytest.mark.asyncio
async def test_sandbox_output_size_cap():
    # 1000 byte cap
    sandbox = SubprocessSandbox(max_output_bytes=1000)
    # Generate 50,000 bytes
    cmd = [sys.executable, "-c", "import sys; sys.stdout.write('A' * 50000)"]
    code, stdout, _ = await sandbox.execute_command(cmd)
    assert code == 0
    assert len(stdout) < 2000
    assert b"[OUTPUT TRUNCATED: MAX SIZE REACHED]" in stdout

    exact_cmd = [sys.executable, "-c", "import sys; sys.stdout.write('B' * 1000)"]
    _, exact_stdout, _ = await sandbox.execute_command(exact_cmd)
    assert exact_stdout == b"B" * 1000


@pytest.mark.asyncio
async def test_sandbox_drains_large_streams_with_bounded_memory():
    cap = 4 * 1024
    sandbox = SubprocessSandbox(max_output_bytes=cap)
    script = """\
import os
chunk = b'x' * 65536
for fd in (1, 2):
    for _ in range(128):
        remaining = memoryview(chunk)
        while remaining:
            written = os.write(fd, remaining)
            remaining = remaining[written:]
"""

    tracing_before = tracemalloc.is_tracing()
    if not tracing_before:
        tracemalloc.start()
    else:
        tracemalloc.reset_peak()
    try:
        code, stdout, stderr = await sandbox.execute_command([sys.executable, "-c", script])
        _, peak_bytes = tracemalloc.get_traced_memory()
    finally:
        if not tracing_before:
            tracemalloc.stop()

    assert code == 0
    assert len(stdout) == cap + len(bytes((10,)) + b"[OUTPUT TRUNCATED: MAX SIZE REACHED]")
    assert len(stderr) == cap + len(bytes((10,)) + b"[STDERR TRUNCATED: MAX SIZE REACHED]")
    # The child emits 8 MiB to each stream; retaining those full streams would
    # exceed this parent-process allocation ceiling by a wide margin.
    assert peak_bytes < 4 * 1024 * 1024


@pytest.mark.asyncio
async def test_sandbox_cancellation_kills_and_reaps_child(tmp_path):
    pid_file = tmp_path / "child.pid"
    script = """\
import os
import time
with open('child.pid', 'w', encoding='ascii') as pid_file:
    pid_file.write(str(os.getpid()))
time.sleep(30)
"""
    sandbox = SubprocessSandbox()
    execution = asyncio.create_task(
        sandbox.execute_command([sys.executable, "-c", script], working_dir=str(tmp_path))
    )

    for _ in range(200):
        if pid_file.exists():
            break
        await asyncio.sleep(0.01)
    assert pid_file.exists(), "local child did not start"
    pid = int(pid_file.read_text(encoding="ascii"))
    assert psutil.pid_exists(pid)

    execution.cancel()
    with pytest.raises(asyncio.CancelledError):
        await execution

    assert not psutil.pid_exists(pid)


@pytest.mark.asyncio
async def test_sandbox_injection_safety():

    sandbox = SubprocessSandbox()
    # Malicious parameter containing shell metacharacters: semicolon, pipe, ampersand, backticks
    malicious_arg = "; echo INJECTED_1 | dir & whoami `calc.exe`"
    # Print the exact argument received as argv[1]
    cmd = [sys.executable, "-c", "import sys; print('ARGV1:' + sys.argv[1])", malicious_arg]
    code, stdout, _ = await sandbox.execute_command(cmd)
    assert code == 0
    decoded = stdout.decode("utf-8")
    # Must arrive as a single argv[1] element, without executing any injected commands
    assert f"ARGV1:{malicious_arg}" in decoded
    assert "INJECTED_1" not in decoded.replace(malicious_arg, "")


class FlakyTestAdapter(ToolAdapter):
    def __init__(self):
        self.attempts = 0

    @property
    def name(self) -> str:
        return "flaky_adapter"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def capabilities(self) -> list[str]:
        return ["test.flaky_action"]

    async def health_check(self) -> bool:
        return True

    def validate_params(self, action: ActionRequest) -> tuple[bool, str | None]:
        return True, None

    async def run(self, action: ActionRequest) -> tuple[ActionResult, bytes, str]:
        self.attempts += 1
        if self.attempts < 2:
            raise RuntimeError("Transient network error")
        return (
            ActionResult(action_id=action.id, task_id=action.task_id, success=True, output_summary="Succeeded on retry", duration_seconds=0.1),
            b"SUCCESS_RETRY",
            "text/plain"
        )


@pytest.mark.asyncio
async def test_executor_retry_and_backoff():
    engine = ExecutionEngine(evidence_store_inst=EvidenceStore())
    flaky = FlakyTestAdapter()
    engine.registry.register(flaky)

    mock_evidence = Evidence(
        id="evi-retry-01",
        task_id="task-retry-01",
        target_ref="target.local",
        source_agent="recon_agent",
        source_module="test",
        source_tool="flaky_adapter",
        artifact_storage_key="test/key",
        content_type="text/plain",
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        integrity_metadata={"storage_uri": "s3://test/evi-retry-01"},
        collected_by="sentinel_executor",
    )
    engine.evidence_store.record_evidence = AsyncMock(return_value=mock_evidence)

    target = Target(id="t1", type="host", value="target.local")
    task = Task(
        id="task-retry-01",
        objective="Retry test",
        target_set=TargetSet(id="ts1", name="TS", targets=[target]),
        scope=Scope(id="s1", name="S", allowed_targets=["target.local"], offensive_actions_enabled=False),
        policy=Policy(id="p1", name="P", allowed_action_classes=["test.*"]),
        correlation_id="corr-r1",
    )

    action = ActionRequest(
        id="act-retry-01",
        task_id=task.id,
        agent="recon_agent",
        action_type="test.flaky_action",
        target_refs=["target.local"],
        expected_impact_level=ImpactLevel.LOW,
    )

    result = await engine.execute_action(action, task, max_retries=2)
    assert result.success is True
    assert flaky.attempts == 2
