"""Secret & Credential Scanning Module for Sentinel."""

from sentinel.modules.secret_scanner.entropy import calculate_shannon_entropy
from sentinel.modules.secret_scanner.patterns import SECRET_PATTERNS, SecretPattern
from sentinel.modules.secret_scanner.scanner import SecretFinding, SecretScanner

__all__ = [
    "SecretFinding",
    "SecretPattern",
    "SecretScanner",
    "SECRET_PATTERNS",
    "calculate_shannon_entropy",
]
