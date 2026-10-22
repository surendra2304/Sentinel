import pytest
from pydantic import SecretStr

from sentinel.config.settings import EnvironmentType, get_settings
from sentinel.config.validator import (
    ConfigurationValidationError,
    enforce_startup_configuration,
    validate_startup_configuration,
)


def test_validator_passes_in_development():
    settings = get_settings()
    settings.environment = EnvironmentType.DEVELOPMENT
    errors = validate_startup_configuration(settings)
    assert isinstance(errors, list)


def test_validator_fails_in_production_with_in_memory_or_weak_keys(monkeypatch):
    settings = get_settings()
    settings.environment = EnvironmentType.PRODUCTION
    settings.storage_backend = "memory"
    monkeypatch.setattr(settings, "api_key", SecretStr("short"))

    errors = validate_startup_configuration(settings)
    assert any("SENTINEL_API_KEY is required" in e for e in errors)
    assert any("In-memory storage backend is forbidden in production" in e for e in errors)

    with pytest.raises(ConfigurationValidationError):
        enforce_startup_configuration(settings, fail_fast=True)


def test_validator_invalid_port(monkeypatch):
    monkeypatch.setenv("PORT", "invalid_port")
    settings = get_settings()
    errors = validate_startup_configuration(settings)
    assert any("Invalid PORT value" in e for e in errors)
