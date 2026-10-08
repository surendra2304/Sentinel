"""Subprocess execution sandbox for Sentinel CLI security tools.

Enforces:
- Hard execution timeouts
- Bounded stdout/stderr retention while pipes continue to drain
- Isolated temporary working directories
- Safe parameter passing (argument lists only, strict shell=False)
"""

import os
import shutil
import tempfile

from sentinel.core.sandbox.bounded_process import run_bounded_process
from sentinel.core.security.command_policy import CommandPolicy


class SandboxExecutionError(Exception):
    """Raised when sandboxed execution fails or violates limits."""


class SubprocessSandbox:
    """Security-hardened subprocess execution wrapper."""

    def __init__(
        self,
        default_timeout_seconds: float = 30.0,
        max_output_bytes: int = 10 * 1024 * 1024,  # 10MB per stream
        command_policy: "CommandPolicy | None" = None,
        safe_path: object | None = None,
    ):
        self.default_timeout = default_timeout_seconds
        self.max_output_bytes = max_output_bytes
        self.command_policy = command_policy
        self.safe_path = safe_path

    async def execute_command(
        self,
        cmd_args: list[str],
        timeout: float | None = None,
        env: dict[str, str] | None = None,
        working_dir: str | None = None,
    ) -> tuple[int, bytes, bytes]:
        """Execute command safely without shell expansion.

        Returns ``(returncode, stdout_bytes, stderr_bytes)``. Each stream retains
        at most ``max_output_bytes`` plus its existing truncation marker.
        """
        if (
            not isinstance(cmd_args, list)
            or not cmd_args
            or any(not isinstance(arg, str) for arg in cmd_args)
        ):
            raise SandboxExecutionError("Command arguments must be a non-empty list of strings.")

        if self.command_policy is not None:
            decision = self.command_policy.validate(cmd_args)
            if not decision.allowed:
                raise SandboxExecutionError(f"CommandPolicy DENIED: {decision.reason}")

        eff_timeout = timeout if timeout is not None else self.default_timeout
        temp_dir = None
        work_dir = working_dir

        if not work_dir:
            temp_dir = tempfile.mkdtemp(prefix="sentinel_sandbox_")
            work_dir = temp_dir

        safe_env = os.environ.copy()
        if env:
            safe_env.update(env)

        try:
            try:
                (
                    returncode,
                    stdout_data,
                    stderr_data,
                    stdout_truncated,
                    stderr_truncated,
                ) = await run_bounded_process(
                    cmd_args,
                    cwd=work_dir,
                    env=safe_env,
                    timeout_seconds=eff_timeout,
                    max_output_bytes=self.max_output_bytes,
                )
            except FileNotFoundError as err:
                raise SandboxExecutionError(f"Executable not found: {cmd_args[0]}") from err
            except TimeoutError as err:
                raise SandboxExecutionError(
                    f"Command execution timed out after {eff_timeout} seconds: {' '.join(cmd_args)}"
                ) from err

            if stdout_truncated:
                stdout_data += b"\n[OUTPUT TRUNCATED: MAX SIZE REACHED]"
            if stderr_truncated:
                stderr_data += b"\n[STDERR TRUNCATED: MAX SIZE REACHED]"

            return returncode, stdout_data, stderr_data
        finally:
            if temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)
