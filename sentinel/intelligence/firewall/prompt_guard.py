"""Sentinel Prompt Guard & Context Firewall."""

from __future__ import annotations

from dataclasses import dataclass

from sentinel.intelligence.scanners.registry import SecurityScannerSuite, redact_text


@dataclass(frozen=True, slots=True)
class SafetyContext:
    trusted_instructions: str
    untrusted_input: str
    findings: tuple


class ContextFirewall:
    """Keeps external content data-only and scans it before LLM/tool routing."""

    def __init__(self, scanners: SecurityScannerSuite | None = None):
        self.scanners = scanners or SecurityScannerSuite()

    def prepare(self, trusted_instructions: str, external_text: str) -> SafetyContext:
        result = self.scanners.scan(external_text, "external_input")
        return SafetyContext(trusted_instructions, redact_text(external_text), result.findings)
