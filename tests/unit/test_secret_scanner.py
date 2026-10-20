"""Unit tests for Sentinel's continuous secret and credential scanner."""


from sentinel.core.models import SeverityLevel
from sentinel.modules.secret_scanner import (
    SecretScanner,
    calculate_shannon_entropy,
)


def test_shannon_entropy_calculation():
    # Low entropy for repetitive strings
    assert calculate_shannon_entropy("") == 0.0
    assert calculate_shannon_entropy("aaaaaaaa") == 0.0
    assert calculate_shannon_entropy("abababab") == 1.0

    # High entropy for random/hex/base64 strings
    high_entropy = calculate_shannon_entropy("4f8a2b9c7e1d5f0e3a6c8b2d4e7f1a9c")
    assert high_entropy > 3.0


def test_secret_scanner_detects_google_api_key():
    scanner = SecretScanner()
    code = 'client = GoogleGemini(api_key="AIzaSyD1234567890abcdefghijklmnopqrstuv")'
    findings = scanner.scan_text(code, filename="service.py")

    rule_ids = {f.rule_id for f in findings}
    assert "SEC-GOOGLE-API" in rule_ids
    for f in findings:
        if f.rule_id == "SEC-GOOGLE-API":
            assert f.severity == SeverityLevel.CRITICAL
            assert "AIza" in f.redacted_value
            assert "[REDACTED]" in f.redacted_value
            assert f.file_path == "service.py"
            assert f.line_number == 1


def test_secret_scanner_detects_openai_and_anthropic_keys():
    scanner = SecretScanner()
    code = """
    openai_key = "sk-proj-abcde12345fghij67890klmno12345pqrst67890"
    claude_key = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789"
    """
    findings = scanner.scan_text(code)
    rule_ids = {f.rule_id for f in findings}
    assert "SEC-OPENAI-API" in rule_ids
    assert "SEC-ANTHROPIC-API" in rule_ids


def test_secret_scanner_detects_github_pat_and_pem_keys():
    scanner = SecretScanner()
    code = """
    pat = "ghp_1234567890abcdefghijklmnopqrstuvwxyz12"
    pem = "-----BEGIN RSA PRIVATE KEY-----"
    """
    findings = scanner.scan_text(code)
    rule_ids = {f.rule_id for f in findings}
    assert "SEC-GITHUB-PAT" in rule_ids
    assert "SEC-PEM-KEY" in rule_ids


def test_secret_scanner_scan_diff():
    scanner = SecretScanner()
    diff = """--- a/backend/auth.py
+++ b/backend/auth.py
@@ -14,4 +14,5 @@
 def setup():
     pass
+    token = "ghp_AbCdEf1234567890GhIjKlMnOpQrStUvWxYz"
+    return token
"""
    findings = scanner.scan_diff(diff)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-GITHUB-PAT"
    assert findings[0].file_path == "backend/auth.py"
    assert findings[0].line_number == 16


def test_secret_scanner_redaction():
    scanner = SecretScanner()
    raw = 'export OPENAI_KEY="sk-proj-abcde12345fghij67890klmno12345pqrst67890"'
    redacted = scanner.redact(raw)
    assert "sk-proj-abcde12345fghij67890klmno12345pqrst67890" not in redacted
    assert "[REDACTED]" in redacted
