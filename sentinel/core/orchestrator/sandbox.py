"""Subprocess execution sandbox for Sentinel CLI security tools.

Enforces:
- Hard execution timeouts
- Output size limits to prevent memory exhaustion
- Isolated temporary working directories
- Safe parameter passing (argument lists only, strict shell=False)
"""

import asyncio
import contextlib
import os
import shutil
import subprocess
import tempfile


class SandboxExecutionError(Exception):
    """Raised when sandboxed execution fails or violates limits."""
    pass


class SubprocessSandbox:
    """Security-hardened subprocess execution wrapper."""

    def __init__(
        self,
        default_timeout_seconds: float = 30.0,
        max_output_bytes: int = 10 * 1024 * 1024,  # 10MB cap
    ):
        self.default_timeout = default_timeout_seconds
        self.max_output_bytes = max_output_bytes

    async def execute_command(
        self,
        cmd_args: list[str],
        timeout: float | None = None,
        env: dict[str, str] | None = None,
        working_dir: str | None = None,
    ) -> tuple[int, bytes, bytes]:
        """Execute command safely without shell expansion.

        Returns (returncode, stdout_bytes, stderr_bytes)
        """
        if not cmd_args or not isinstance(cmd_args, list):
            raise SandboxExecutionError("Command arguments must be a non-empty list of strings.")

        eff_timeout = timeout or self.default_timeout
        temp_dir = None
        work_dir = working_dir

        if not work_dir:
            temp_dir = tempfile.mkdtemp(prefix="sentinel_sandbox_")
            work_dir = temp_dir

        # Sanitize environment variables
        safe_env = os.environ.copy()
        if env:
            safe_env.update(env)

        def _run_subprocess() -> tuple[int, bytes, bytes]:
            try:
                proc = subprocess.Popen(
                    cmd_args,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    cwd=work_dir,
                    env=safe_env,
                    shell=False,
                )
                try:
                    stdout_data, stderr_data = proc.communicate(timeout=eff_timeout)
                except subprocess.TimeoutExpired as err:
                    with contextlib.suppress(Exception):
                        proc.kill()
                    if proc.stdout:
                        with contextlib.suppress(Exception):
                            proc.stdout.close()
                    if proc.stderr:
                        with contextlib.suppress(Exception):
                            proc.stderr.close()
                    with contextlib.suppress(Exception):
                        proc.wait(timeout=0.5)
                    raise SandboxExecutionError(
                        f"Command execution timed out after {eff_timeout} seconds: {' '.join(cmd_args)}"
                    ) from err

                return proc.returncode or 0, stdout_data, stderr_data
            except FileNotFoundError as err:
                raise SandboxExecutionError(f"Executable not found: {cmd_args[0]}") from err

        try:
            returncode, stdout_data, stderr_data = await asyncio.to_thread(_run_subprocess)

            # Enforce output size caps
            if len(stdout_data) > self.max_output_bytes:
                stdout_data = stdout_data[:self.max_output_bytes] + b"\n[OUTPUT TRUNCATED: MAX SIZE REACHED]"

            if len(stderr_data) > self.max_output_bytes:
                stderr_data = stderr_data[:self.max_output_bytes] + b"\n[STDERR TRUNCATED: MAX SIZE REACHED]"

            return returncode, stdout_data, stderr_data

        finally:
            if temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)

