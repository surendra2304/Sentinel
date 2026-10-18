"""Authenticated, fail-closed contract tests for VyralX publishing policy."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from sentinel.apps.api import main as api_main

API_KEY = "vyralx-sentinel-test-key-is-longer-than-thirty-two-characters"
POLICY_URL = "/api/v1/vyralx/publish-policy"


def _configure_gate(monkeypatch, *, enabled=False, kill_switch=False, allow_unlisted=False, allow_public=False):
    monkeypatch.delenv("RENDER", raising=False)
    monkeypatch.setenv("SENTINEL_API_AUTH_REQUIRED", "false")
    monkeypatch.setenv("SENTINEL_API_KEY", API_KEY)
    monkeypatch.setattr(api_main.settings, "api_key", SecretStr(API_KEY))
    monkeypatch.setattr(api_main.settings, "youtube_publish_enabled", enabled)
    monkeypatch.setattr(api_main.settings, "youtube_publish_allow_unlisted", allow_unlisted)
    monkeypatch.setattr(api_main.settings, "youtube_publish_allow_public", allow_public)
    monkeypatch.setattr(api_main.settings, "kill_switch_active", kill_switch)
    audit_events = []
    monkeypatch.setattr(api_main.audit_logger, "append", lambda **kwargs: audit_events.append(kwargs))
    return audit_events


def _headers(key: str = API_KEY, *, agent: str = "vyralx") -> dict[str, str]:
    return {"X-Agent-Name": agent, "X-API-Key": key}


def _payload(**overrides) -> dict:
    body = {
        "action": "youtube.publish",
        "job_id": 41,
        "asset_id": 17,
        "title": "How solar panels work",
        "privacy_status": "private",
        "scheduled_at": "",
        "operator_review_acknowledged": True,
        "rights_verified": True,
    }
    body.update(overrides)
    return body


def test_publish_policy_requires_vyralx_identity_even_with_a_valid_key(monkeypatch):
    _configure_gate(monkeypatch, enabled=True)
    response = TestClient(api_main.app).post(POLICY_URL, headers=_headers(agent="forge"), json=_payload())

    assert response.status_code == 403
    assert "VyralX service identity" in response.json()["detail"]


def test_publish_policy_authentication_fails_closed_without_a_configured_strong_key(monkeypatch):
    monkeypatch.delenv("SENTINEL_API_KEY", raising=False)
    monkeypatch.setenv("SENTINEL_API_AUTH_REQUIRED", "false")
    monkeypatch.setattr(api_main.settings, "api_key", SecretStr(""))
    response = TestClient(api_main.app).post(POLICY_URL, headers=_headers(), json=_payload())

    assert response.status_code == 503
    assert "configure a unique Sentinel API key" in response.json()["detail"]


def test_publish_policy_denies_by_default_and_audits_the_decision(monkeypatch):
    audits = _configure_gate(monkeypatch, enabled=False)
    response = TestClient(api_main.app).post(POLICY_URL, headers=_headers(), json=_payload())

    assert response.status_code == 200
    body = response.json()
    assert body["allowed"] is False
    assert body["decision"] == "deny"
    assert "disabled" in body["reason"]
    assert body["policy"] == "vyralx-publish-policy-v1"
    assert len(audits) == 1
    assert audits[0]["event_type"] == "publish_policy.decision"
    assert audits[0]["actor_id"] == "vyralx"
    assert audits[0]["payload"]["decision"] == "DENY"


def test_publish_policy_allows_reviewed_rights_verified_private_job_when_enabled(monkeypatch):
    audits = _configure_gate(monkeypatch, enabled=True)
    response = TestClient(api_main.app).post(POLICY_URL, headers=_headers(), json=_payload())

    assert response.status_code == 200
    body = response.json()
    assert body["allowed"] is True
    assert body["decision"] == "allow"
    assert body["job_id"] == 41
    assert len(audits) == 1
    assert audits[0]["payload"]["operator_review_acknowledged"] is True
    assert audits[0]["payload"]["rights_verified_asserted_by_vyralx"] is True


@pytest.mark.parametrize(
    "overrides, expected_reason",
    [
        ({"operator_review_acknowledged": False}, "operator review acknowledgment"),
        ({"rights_verified": False}, "rights checks"),
        ({"title": "   "}, "non-empty YouTube title"),
    ],
)
def test_publish_policy_denies_missing_operator_or_rights_guards(monkeypatch, overrides, expected_reason):
    _configure_gate(monkeypatch, enabled=True)
    response = TestClient(api_main.app).post(POLICY_URL, headers=_headers(), json=_payload(**overrides))

    assert response.status_code == 200
    assert response.json()["allowed"] is False
    assert expected_reason in response.json()["reason"]


@pytest.mark.parametrize(
    "privacy_status, flag_name",
    [("unlisted", "allow_unlisted"), ("public", "allow_public")],
)
def test_publish_policy_denies_visibility_that_has_not_been_opted_in(monkeypatch, privacy_status, flag_name):
    audits = _configure_gate(monkeypatch, enabled=True)
    response = TestClient(api_main.app).post(
        POLICY_URL, headers=_headers(), json=_payload(privacy_status=privacy_status)
    )

    assert response.status_code == 200
    assert response.json()["allowed"] is False
    assert "disabled" in response.json()["reason"]
    assert len(audits) == 1


def test_publish_policy_allows_public_only_with_explicit_configuration(monkeypatch):
    _configure_gate(monkeypatch, enabled=True, allow_public=True)
    response = TestClient(api_main.app).post(
        POLICY_URL, headers=_headers(), json=_payload(privacy_status="public")
    )

    assert response.status_code == 200
    assert response.json()["allowed"] is True


@pytest.mark.parametrize(
    "scheduled_at, privacy_status, reason",
    [
        ("not-a-date", "private", "valid ISO-8601"),
        ("2035-01-01T12:00:00", "private", "explicit timezone"),
        ((datetime.now(UTC) - timedelta(minutes=5)).isoformat(), "private", "in the future"),
        ((datetime.now(UTC) + timedelta(days=1)).isoformat(), "public", "must use private privacy"),
    ],
)
def test_publish_policy_rejects_invalid_or_unsafe_schedule(monkeypatch, scheduled_at, privacy_status, reason):
    _configure_gate(monkeypatch, enabled=True, allow_public=True)
    response = TestClient(api_main.app).post(
        POLICY_URL,
        headers=_headers(),
        json=_payload(scheduled_at=scheduled_at, privacy_status=privacy_status),
    )

    assert response.status_code == 200
    assert response.json()["allowed"] is False
    assert reason in response.json()["reason"]


def test_publish_policy_kill_switch_denies_even_when_enabled(monkeypatch):
    _configure_gate(monkeypatch, enabled=True, kill_switch=True)
    response = TestClient(api_main.app).post(POLICY_URL, headers=_headers(), json=_payload())

    assert response.status_code == 200
    assert response.json()["allowed"] is False
    assert "kill switch" in response.json()["reason"]


def test_publish_policy_audit_failure_cannot_become_an_allow(monkeypatch):
    _configure_gate(monkeypatch, enabled=True)

    def fail_audit(**_kwargs):
        raise OSError("audit backend unavailable")

    monkeypatch.setattr(api_main.audit_logger, "append", fail_audit)
    response = TestClient(api_main.app).post(POLICY_URL, headers=_headers(), json=_payload())

    assert response.status_code == 200
    assert response.json()["allowed"] is False
    assert "audit logging is unavailable" in response.json()["reason"]


def test_publish_policy_accepts_bearer_authorization_header(monkeypatch):
    _configure_gate(monkeypatch, enabled=True)
    response = TestClient(api_main.app).post(
        POLICY_URL,
        headers={"X-Agent-Name": "vyralx", "Authorization": f"Bearer {API_KEY}"},
        json=_payload(),
    )

    assert response.status_code == 200
    assert response.json()["allowed"] is True


@pytest.mark.parametrize(
    "headers, expected_status, expected_detail",
    [
        ({"X-Agent-Name": "vyralx"}, 401, "A Sentinel API key is required"),
        (
            {"X-Agent-Name": "vyralx", "X-API-Key": "not-the-configured-key"},
            403,
            "The Sentinel API key is invalid",
        ),
    ],
)
def test_publish_policy_rejects_missing_or_invalid_key(
    monkeypatch, headers, expected_status, expected_detail
):
    _configure_gate(monkeypatch, enabled=True)
    response = TestClient(api_main.app).post(POLICY_URL, headers=headers, json=_payload())

    assert response.status_code == expected_status
    assert expected_detail in response.json()["detail"]


def test_publish_policy_falls_back_to_settings_key_when_environment_key_is_blank(monkeypatch):
    _configure_gate(monkeypatch, enabled=True)
    monkeypatch.setenv("SENTINEL_API_KEY", "")
    response = TestClient(api_main.app).post(POLICY_URL, headers=_headers(), json=_payload())

    assert response.status_code == 200
    assert response.json()["allowed"] is True


def test_publish_policy_allows_unlisted_only_with_explicit_configuration(monkeypatch):
    _configure_gate(monkeypatch, enabled=True, allow_unlisted=True)
    response = TestClient(api_main.app).post(
        POLICY_URL, headers=_headers(), json=_payload(privacy_status="unlisted")
    )

    assert response.status_code == 200
    assert response.json()["allowed"] is True


def test_publish_policy_allows_valid_future_private_schedule(monkeypatch):
    _configure_gate(monkeypatch, enabled=True)
    scheduled_at = (datetime.now(UTC) + timedelta(days=1)).isoformat()
    response = TestClient(api_main.app).post(
        POLICY_URL, headers=_headers(), json=_payload(scheduled_at=scheduled_at)
    )

    assert response.status_code == 200
    assert response.json()["allowed"] is True


def test_publish_policy_flags_are_wired_as_default_deny_in_both_compose_files():
    import yaml

    root = Path(__file__).resolve().parents[2]
    expected = {
        "SENTINEL_YOUTUBE_PUBLISH_ENABLED": "${SENTINEL_YOUTUBE_PUBLISH_ENABLED:-false}",
        "SENTINEL_YOUTUBE_PUBLISH_ALLOW_UNLISTED": "${SENTINEL_YOUTUBE_PUBLISH_ALLOW_UNLISTED:-false}",
        "SENTINEL_YOUTUBE_PUBLISH_ALLOW_PUBLIC": "${SENTINEL_YOUTUBE_PUBLISH_ALLOW_PUBLIC:-false}",
    }
    for filename, service in (("docker-compose.yml", "sentinel-api"), ("docker-compose.production.yml", "api")):
        compose = yaml.safe_load((root / filename).read_text(encoding="utf-8"))
        environment = compose["services"][service]["environment"]
        for name, value in expected.items():
            assert environment[name] == value
