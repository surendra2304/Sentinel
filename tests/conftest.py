import asyncio
import contextlib
import os
import sys

import pytest

os.environ["SENTINEL_ENVIRONMENT"] = "testing"
os.environ["ENVIRONMENT"] = "development"
os.environ["SENTINEL_STORAGE_BACKEND"] = "memory"
os.environ.setdefault("SENTINEL_API_KEY", "sentinel_test_key_at_least_16_chars")
os.environ.setdefault(
    "SENTINEL_AUDIT_SIGNING_KEY",
    "sentinel-pytest-audit-key-not-for-deployment",
)
_startup_log_path = "logs/audit.jsonl"
if os.path.exists(_startup_log_path):
    with contextlib.suppress(Exception):
        os.remove(_startup_log_path)

if sys.platform == "win32":
    with contextlib.suppress(Exception):
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())


@pytest.fixture(autouse=True)
def clean_test_audit_log():
    """Ensure clean audit log and isolated settings/repo state across test executions."""
    from sentinel.config.settings import get_settings
    from sentinel.storage.database import session as db_session_module
    from sentinel.storage.repositories import factory as repo_factory

    get_settings.cache_clear()
    repo_factory._task_repo = None
    repo_factory._finding_repo = None
    repo_factory._evidence_repo = None
    repo_factory._approval_repo = None
    repo_factory._risk_repo = None
    repo_factory._audit_repo = None
    repo_factory._event_repo = None
    db_session_module._engine = None
    db_session_module._session_factory = None

    log_path = "logs/audit.jsonl"
    if os.path.exists(log_path):
        with contextlib.suppress(Exception):
            os.remove(log_path)
    yield
    get_settings.cache_clear()
    repo_factory._task_repo = None
    repo_factory._finding_repo = None
    repo_factory._evidence_repo = None
    repo_factory._approval_repo = None
    repo_factory._risk_repo = None
    repo_factory._audit_repo = None
    repo_factory._event_repo = None
    db_session_module._engine = None
    db_session_module._session_factory = None
