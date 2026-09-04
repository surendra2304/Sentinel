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
    """Ensure clean audit log state across test executions."""
    log_path = "logs/audit.jsonl"
    if os.path.exists(log_path):
        with contextlib.suppress(Exception):
            os.remove(log_path)
    yield

