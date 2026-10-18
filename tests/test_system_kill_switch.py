"""Coverage tests for the global emergency kill-switch API."""
from __future__ import annotations

from unittest.mock import AsyncMock

from fastapi.testclient import TestClient

from sentinel.apps.api import main as api_main


def test_global_kill_switch_activation_reports_cancelled_tasks(monkeypatch):
    activate = AsyncMock(return_value=3)
    monkeypatch.setattr(api_main.lifecycle_manager, "activate_global_kill_switch", activate)

    response = TestClient(api_main.app).post(
        f"{api_main.settings.api_prefix}/system/kill-switch",
        json={"active": True, "reason": "coverage-test"},
    )

    assert response.status_code == 200
    assert response.json() == {
        "kill_switch_active": True,
        "action": "ACTIVATED",
        "cancelled_tasks": 3,
        "reason": "coverage-test",
    }
    activate.assert_awaited_once_with(reason="coverage-test")


def test_global_kill_switch_deactivation_calls_lifecycle_manager(monkeypatch):
    deactivate = AsyncMock(return_value=None)
    monkeypatch.setattr(api_main.lifecycle_manager, "deactivate_global_kill_switch", deactivate)

    response = TestClient(api_main.app).post(
        f"{api_main.settings.api_prefix}/system/kill-switch",
        json={"active": False},
    )

    assert response.status_code == 200
    assert response.json() == {"kill_switch_active": False, "action": "DEACTIVATED"}
    deactivate.assert_awaited_once_with()


def test_global_kill_switch_status_reports_current_setting(monkeypatch):
    monkeypatch.setattr(api_main.settings, "kill_switch_active", True)

    response = TestClient(api_main.app).get(
        f"{api_main.settings.api_prefix}/system/kill-switch"
    )

    assert response.status_code == 200
    assert response.json() == {"kill_switch_active": True}
