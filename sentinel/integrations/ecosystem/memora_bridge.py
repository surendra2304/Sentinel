"""Sentinel Memora Ecosystem Bridge."""

from __future__ import annotations

from sentinel.intelligence.scanners.registry import redact_text


class MemoraSentinelAdapter:
    """Provides safe redacted event feeds to Memora memory."""

    def format_event_for_memory(self, event_data: dict) -> dict:
        return {
            k: redact_text(v) if isinstance(v, str) else v
            for k, v in event_data.items()
        }
