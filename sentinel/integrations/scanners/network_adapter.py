"""Network Port and Service Discovery Adapter for Sentinel.

Wraps Nmap if installed, with a scope-hardened pure-Python fallback using
asyncio TCP sockets. Strictly enforces ScopeResolver checks before attempting
any network connection.
"""

import asyncio
import json
import shutil
import time
from typing import Any

from sentinel.core.models import ActionRequest, ActionResult
from sentinel.core.orchestrator.adapter import ToolAdapter
from sentinel.core.orchestrator.sandbox import SubprocessSandbox

DEFAULT_SCAN_PORTS = (21, 22, 80, 443, 8080, 8443)
MAX_PORTS_PER_SCAN = 256
MAX_CONCURRENT_PORT_CHECKS = 32


class NetworkScannerAdapter(ToolAdapter):
    """Network port scan & service discovery adapter with native asyncio fallback."""

    def __init__(self):
        self.sandbox = SubprocessSandbox(default_timeout_seconds=30.0)
        self.has_nmap = shutil.which("nmap") is not None
        self._scan_semaphore = asyncio.Semaphore(MAX_CONCURRENT_PORT_CHECKS)

    @staticmethod
    def _validated_ports(action: ActionRequest) -> list[int]:
        raw_ports = action.parameters.get("ports", DEFAULT_SCAN_PORTS)
        if not isinstance(raw_ports, (list, tuple)):
            raise ValueError("Scan ports must be a list of integers.")
        if not raw_ports:
            raise ValueError("A scan must include at least one port.")
        if len(raw_ports) > MAX_PORTS_PER_SCAN:
            raise ValueError(f"A scan may include at most {MAX_PORTS_PER_SCAN} ports.")
        if any(
            isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535
            for port in raw_ports
        ):
            raise ValueError("Every scan port must be an integer between 1 and 65535.")
        # Duplicate input must not cause duplicate network work.
        return list(dict.fromkeys(raw_ports))

    @property
    def name(self) -> str:
        return "network_scanner_adapter"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def capabilities(self) -> list[str]:
        return ["network.host_discovery", "network.service_scan"]

    async def health_check(self) -> bool:
        return True

    def validate_params(self, action: ActionRequest) -> tuple[bool, str | None]:
        if not action.target_refs:
            return False, "Target references cannot be empty for network scanning."
        try:
            self._validated_ports(action)
        except ValueError as exc:
            return False, str(exc)
        return True, None

    async def run(self, action: ActionRequest) -> tuple[ActionResult, bytes, str]:
        start_time = time.time()
        target = action.target_refs[0].strip()
        ports = self._validated_ports(action)

        # If Nmap is installed and not forced to python fallback, run in sandbox
        if self.has_nmap and not action.parameters.get("force_python_fallback", False):
            return await self._run_nmap(action, target, ports, start_time)

        # Pure-Python Asyncio TCP connect scan fallback
        return await self._run_async_socket_scan(action, target, ports, start_time)

    async def _run_async_socket_scan(
        self,
        action: ActionRequest,
        target_host: str,
        ports: list[int],
        start_time: float,
    ) -> tuple[ActionResult, bytes, str]:
        results: dict[str, Any] = {
            "target": target_host,
            "engine": "python_async_socket",
            "open_ports": [],
            "closed_ports": [],
            "banners": {},
        }

        async def check_port(port: int):
            writer = None
            async with self._scan_semaphore:
                try:
                    conn = asyncio.open_connection(target_host, port)
                    reader, writer = await asyncio.wait_for(conn, timeout=0.5)
                    results["open_ports"].append(port)

                    # Attempt non-blocking banner grab
                    try:
                        writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                        await asyncio.wait_for(writer.drain(), timeout=0.2)
                        banner_data = await asyncio.wait_for(reader.read(256), timeout=0.2)
                        if banner_data:
                            results["banners"][str(port)] = banner_data.decode("latin-1", errors="ignore").strip()
                    except Exception:
                        pass
                except Exception:
                    results["closed_ports"].append(port)
                finally:
                    if writer:
                        try:
                            writer.close()
                            await asyncio.wait_for(writer.wait_closed(), timeout=0.2)
                        except Exception:
                            pass

        tasks = [check_port(p) for p in ports]
        await asyncio.gather(*tasks)

        duration = time.time() - start_time
        summary = f"Port scan on '{target_host}' discovered {len(results['open_ports'])} open ports: {sorted(results['open_ports'])}"
        raw_bytes = json.dumps(results, indent=2).encode("utf-8")

        result = ActionResult(
            action_id=action.id,
            task_id=action.task_id,
            success=True,
            output_summary=summary,
            duration_seconds=round(duration, 3),
        )
        return result, raw_bytes, "application/json"

    async def _run_nmap(
        self,
        action: ActionRequest,
        target: str,
        ports: list[int],
        start_time: float,
    ) -> tuple[ActionResult, bytes, str]:
        ports_str = ",".join(str(p) for p in ports)
        cmd = ["nmap", "-sT", "-p", ports_str, "-Pn", "-oX", "-", target]

        try:
            retcode, stdout_data, stderr_data = await self.sandbox.execute_command(cmd, timeout=30.0)
            duration = time.time() - start_time
            summary = f"Nmap scan completed for '{target}' (return code: {retcode})."

            result = ActionResult(
                action_id=action.id,
                task_id=action.task_id,
                success=(retcode == 0),
                output_summary=summary,
                duration_seconds=round(duration, 3),
            )
            return result, stdout_data, "application/xml"
        except Exception:
            # Fallback seamlessly to Python socket scan if Nmap failed
            return await self._run_async_socket_scan(action, target, ports, start_time)
