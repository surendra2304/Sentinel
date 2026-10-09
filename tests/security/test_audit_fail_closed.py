import json

import pytest

from sentinel.audit.audit_logger import AuditIntegrityError, AuditLogger

KEY = "super-secure-audit-secret-key-32b-length"

def test_audit_logger_requires_explicit_signing_key(tmp_path, monkeypatch):
    monkeypatch.delenv("SENTINEL_AUDIT_HMAC_KEY", raising=False)
    monkeypatch.delenv("SENTINEL_AUDIT_SIGNING_KEY", raising=False)
    with pytest.raises(ValueError, match="Audit signing key is required"):
        AuditLogger(str(tmp_path / "audit.jsonl"))


def test_audit_signing_key_loads_from_dotenv(tmp_path, monkeypatch):
    from sentinel.config.settings import get_settings

    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("SENTINEL_AUDIT_SIGNING_KEY", raising=False)
    (tmp_path / ".env").write_text(
        "SENTINEL_AUDIT_SIGNING_KEY=dotenv-audit-test-key-0123456789abcdef\n",
        encoding="utf-8",
    )
    get_settings.cache_clear()
    try:
        assert get_settings().audit.signing_key == "dotenv-audit-test-key-0123456789abcdef"
    finally:
        get_settings.cache_clear()


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


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("seq", 99),
        ("timestamp", "2030-01-01T00:00:00+00:00"),
        ("tenant_id", "other-tenant"),
        ("action_id", "other-action"),
    ],
)
def test_audit_v2_signs_sequence_and_context_metadata(tmp_path, field, replacement):
    log_file = tmp_path / f"audit-{field}.jsonl"
    logger = AuditLogger(str(log_file), signing_key=KEY)
    logger.log_event(
        "e1",
        "ACTION_RUN",
        "actor1",
        "EXEC",
        "POL1",
        "SUCCESS",
        tenant_id="tenant-one",
        action_id="action-one",
    )
    row = json.loads(log_file.read_text(encoding="utf-8"))
    row[field] = replacement
    log_file.write_text(json.dumps(row) + "\n", encoding="utf-8")

    assert logger.verify_integrity() is False
    with pytest.raises(AuditIntegrityError):
        AuditLogger(str(log_file), signing_key=KEY, fail_closed=True)


def test_audit_v1_ledger_can_be_verified_and_extended(tmp_path):
    log_file = tmp_path / "legacy-audit.jsonl"
    logger = AuditLogger(str(log_file), signing_key=KEY)
    legacy_payload = {
        "entry_id": "legacy-one",
        "event_type": "TASK_CREATE",
        "actor": "legacy-actor",
        "target": None,
        "action_type": "SYSTEM",
        "scope_policy": "DEFAULT",
        "decision": "ALLOWED",
        "details": {},
    }
    legacy_hash = logger._calculate_hash(legacy_payload, AuditLogger.GENESIS)
    legacy_row = {
        "seq": 1,
        "entry_id": "legacy-one",
        "timestamp": "2025-01-01T00:00:00+00:00",
        "event_type": "TASK_CREATE",
        "actor": "legacy-actor",
        "tenant_id": "default",
        "action_id": None,
        "target": None,
        "action_type": "SYSTEM",
        "scope_policy": "DEFAULT",
        "decision": "ALLOWED",
        "details": {},
        "previous_hash": AuditLogger.GENESIS,
        "current_hash": legacy_hash,
        "signature": logger._sign_hash(legacy_hash),
    }
    log_file.write_text(json.dumps(legacy_row) + "\n", encoding="utf-8")

    migrated = AuditLogger(str(log_file), signing_key=KEY)
    assert migrated.verify_integrity() is True
    appended = migrated.log_event("next", "ACTION_RUN", "new-actor", "EXEC", "POL1", "SUCCESS")
    assert appended.seq == 2
    assert appended.integrity_version == 2
    assert migrated.verify_integrity() is True
