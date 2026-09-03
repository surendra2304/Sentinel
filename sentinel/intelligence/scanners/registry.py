"""Sentinel Modular Security Scanners & PII Redaction."""

from __future__ import annotations

import re
from dataclasses import dataclass

from sentinel.core.gateway.models import Finding, RiskLevel


@dataclass(frozen=True, slots=True)
class ScannerResult:
    findings: tuple[Finding, ...]
    clean: bool


class Scanner:
    def scan(self, text: str, source: str = "input") -> ScannerResult:
        raise NotImplementedError


class SecretScanner(Scanner):
    PATTERNS = [
        ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
        ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
        ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
        ("generic_secret", re.compile(r"(?i)\b(?:api[_-]?key|secret|password)\s*[:=]\s*[\'\"]?[A-Za-z0-9_\-]{8,}[\'\"]?")),
    ]

    def scan(self, text: str, source: str = "input") -> ScannerResult:
        found = []
        for rid, rx in self.PATTERNS:
            if rx.search(text):
                found.append(
                    Finding(
                        rid,
                        RiskLevel.HIGH,
                        "Potential secret",
                        f"{rid} detected in {source}",
                        source,
                        confidence=0.9,
                    )
                )
        return ScannerResult(tuple(found), not found)


class PromptInjectionScanner(Scanner):
    PATTERNS = [
        r"ignore\s+(?:all\s+)?previous\s+instructions",
        r"reveal\s+(?:the\s+)?system\s+prompt",
        r"disable\s+(?:all\s+)?safety",
        r"you\s+are\s+now\s+an\s+unrestricted",
        r"follow\s+these\s+instructions\s+instead",
    ]

    def scan(self, text: str, source: str = "input") -> ScannerResult:
        found = [
            Finding(
                "prompt_injection",
                RiskLevel.HIGH,
                "Prompt injection signal",
                "Instruction hierarchy manipulation detected",
                source,
                confidence=0.86,
            )
            for p in self.PATTERNS
            if re.search(p, text, flags=re.IGNORECASE)
        ]
        return ScannerResult(tuple(found), not found)


class PiiScanner(Scanner):
    PATTERNS = [
        ("email", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        ("phone", r"\b(?:\+91[- ]?)?[6-9]\d{9}\b"),
        ("ipv4", r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    ]

    def scan(self, text: str, source: str = "input") -> ScannerResult:
        found = []
        for name, pattern in self.PATTERNS:
            if re.search(pattern, text):
                found.append(
                    Finding(
                        "pii_" + name,
                        RiskLevel.MEDIUM,
                        f"Possible {name}",
                        f"Potential PII detected: {name}",
                        source,
                        confidence=0.75,
                    )
                )
        return ScannerResult(tuple(found), not found)


class SecurityScannerSuite:
    def __init__(self, scanners: list[Scanner] | None = None):
        self.scanners = scanners or [SecretScanner(), PromptInjectionScanner(), PiiScanner()]

    def scan(self, text: str, source: str = "input") -> ScannerResult:
        all_findings: list[Finding] = []
        for scanner in self.scanners:
            result = scanner.scan(text, source)
            all_findings.extend(result.findings)
        return ScannerResult(tuple(all_findings), not all_findings)


def redact_text(text: str) -> str:
    """Redact known secret patterns from text."""
    for _, rx in SecretScanner.PATTERNS:
        text = rx.sub("[REDACTED]", text)
    return text
