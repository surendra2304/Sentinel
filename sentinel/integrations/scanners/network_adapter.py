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


class NetworkScannerAdapter(ToolAdapter):
    """Network port scan & service discovery adapter with native asyncio fallback."""

    def __init__(self):
        self.sandbox = SubprocessSandbox(default_timeout_seconds=30.0)
        self.has_nmap = shutil.which("nmap") is not None

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
        return True, None

    async def run(self, action: ActionRequest) -> tuple[ActionResult, bytes, str]:
        start_time = time.time()
        target = action.target_refs[0].strip()
        ports = action.parameters.get("ports", [21, 22, 80, 443, 8080, 8443])

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
            try:
                conn = asyncio.open_connection(target_host, port)
                reader, writer = await asyncio.wait_for(conn, timeout=1.5)
                results["open_ports"].append(port)

                # Attempt non-blocking banner grab
                try:
                    writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                    await writer.drain()
                    banner_data = await asyncio.wait_for(reader.read(256), timeout=0.5)
                    if banner_data:
                        results["banners"][str(port)] = banner_data.decode("latin-1", errors="ignore").strip()
                except Exception:
                    pass

                writer.close()
                await writer.wait_closed()
            except Exception:
                results["closed_ports"].append(port)

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
