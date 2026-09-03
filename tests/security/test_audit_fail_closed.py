import json

import pytest

from sentinel.audit.audit_logger import AuditIntegrityError, AuditLogger

KEY = "super-secure-audit-secret-key-32b-length"

def test_audit_chain_valid_and_append(tmp_path):
    log_file = tmp_path / "audit.jsonl"
    logger = AuditLogger(str(log_file), signing_key=KEY)
    e1 = logger.log_event("e1", "TASK_CREATE", "actor1", "CREATE", "POL1", "ACCEPTED")
    e2 = logger.log_event("e2", "ACTION_RUN", "actor1", "EXEC", "POL1", "SUCCESS")
    assert e2.previous_hash == e1.current_hash
    assert logger.verify_integrity() is True

def test_audit_pre_log_secret_redaction(tmp_path):
    log_file = tmp_path / "audit.jsonl"
    logger = AuditLogger(str(log_file), signing_key=KEY)
    entry = logger.log_event(
        "e1", "AUTH", "admin", "LOGIN", "POL1", "SUCCESS",
        details={"password": "super_secret_password_123", "api_key": "sk-12345678", "user": "admin"}
    )
    assert entry.details["password"] == "[REDACTED]"
    assert entry.details["api_key"] == "[REDACTED]"
    assert entry.details["user"] == "admin"

def test_audit_tampered_record_causes_startup_failure(tmp_path):
    log_file = tmp_path / "audit.jsonl"
    logger = AuditLogger(str(log_file), signing_key=KEY)
    logger.log_event("e1", "TASK_CREATE", "actor1", "CREATE", "POL1", "ACCEPTED")
    logger.log_event("e2", "ACTION_RUN", "actor1", "EXEC", "POL1", "SUCCESS")

    lines = log_file.read_text(encoding="utf-8").splitlines()
    tampered_row = json.loads(lines[0])
    tampered_row["actor"] = "evil_hacker"
    lines[0] = json.dumps(tampered_row)
    log_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with pytest.raises(AuditIntegrityError):
        AuditLogger(str(log_file), signing_key=KEY, fail_closed=True)
