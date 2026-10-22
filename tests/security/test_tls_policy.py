"""Regression tests for the default-on outbound TLS verification policy."""

from sentinel.core.tls_policy import tls_verification_enabled


def _clear_tls_settings(monkeypatch):
    for name in (
        "SENTINEL_TLS_VERIFY",
        "SENTINEL_ALLOW_INSECURE_TLS_PRODUCTION",
        "SENTINEL_ENVIRONMENT",
        "ENVIRONMENT",
    ):
        monkeypatch.delenv(name, raising=False)


def test_tls_verification_defaults_to_enabled(monkeypatch):
    _clear_tls_settings(monkeypatch)
    assert tls_verification_enabled() is True


def test_local_assessment_can_explicitly_allow_self_signed_targets(monkeypatch):
    _clear_tls_settings(monkeypatch)
    monkeypatch.setenv("SENTINEL_ENVIRONMENT", "development")
    monkeypatch.setenv("SENTINEL_TLS_VERIFY", "false")
    assert tls_verification_enabled() is False


def test_production_ignores_single_flag_disabling_tls_verification(monkeypatch):
    _clear_tls_settings(monkeypatch)
    monkeypatch.setenv("SENTINEL_ENVIRONMENT", "production")
    monkeypatch.setenv("SENTINEL_TLS_VERIFY", "false")
    assert tls_verification_enabled() is True


def test_production_break_glass_requires_both_explicit_flags(monkeypatch):
    _clear_tls_settings(monkeypatch)
    monkeypatch.setenv("SENTINEL_ENVIRONMENT", "production")
    monkeypatch.setenv("SENTINEL_TLS_VERIFY", "false")
    monkeypatch.setenv("SENTINEL_ALLOW_INSECURE_TLS_PRODUCTION", "true")
    assert tls_verification_enabled() is False
