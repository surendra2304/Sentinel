import asyncio
import contextlib
import os
import sys

import pytest

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
    db_session_module._engine = None
    db_session_module._session_factory = None

