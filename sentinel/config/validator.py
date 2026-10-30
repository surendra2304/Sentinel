"""Zero-Trust Startup Configuration Validator for Sentinel."""

from __future__ import annotations

import logging
import os

from sentinel.config.settings import (
    DURABLE_STORAGE_BACKENDS,
    REMOVED_STORAGE_BACKENDS,
    EnvironmentType,
    SentinelSettings,
)

logger = logging.getLogger("sentinel.config.validator")


class ConfigurationValidationError(RuntimeError):
    """Raised when critical configuration invariants are violated."""

    def __init__(self, errors: list[str]):
        detail = "\n - ".join(errors)
        super().__init__(
            f"Zero-Trust Configuration Validation Failed:\n - {detail}\n"
            f"Please review .env.example and populate required environment variables."
        )
        self.errors = errors


def validate_startup_configuration(settings: SentinelSettings) -> list[str]:
    """Validate environment variables and security parameters at startup."""
    errors: list[str] = []

    # Check port configuration
    port_env = os.getenv("PORT", "8000")
    try:
        port = int(port_env)
        if not (1 <= port <= 65535):
            errors.append(f"Invalid PORT value '{port_env}'. Must be between 1 and 65535.")
    except ValueError:
        errors.append(f"Invalid PORT value '{port_env}'. Must be an integer.")

    # In production, enforce zero-trust secret management
    if settings.environment == EnvironmentType.PRODUCTION:
        raw_api_key = settings.api_key.get_secret_value() if hasattr(settings.api_key, "get_secret_value") else str(settings.api_key or "")
        if not raw_api_key or len(raw_api_key.strip()) < 16:
            errors.append("SENTINEL_API_KEY is required and must be at least 16 characters in production.")

        signing_key = settings.audit.signing_key or os.getenv("SENTINEL_AUDIT_SIGNING_KEY", "")
        if not signing_key or signing_key in {"dev-signing-key", "default", "sentinel-deterministic-key-fallback"}:
            errors.append("SENTINEL_AUDIT_SIGNING_KEY must be securely configured in production.")

        backend = (settings.storage_backend or "").strip().lower()
        if backend == "memory":
            errors.append(
                "In-memory storage backend is forbidden in production; "
                "use oracle (default) or the legacy postgresql backend."
            )
        elif backend in REMOVED_STORAGE_BACKENDS:
            errors.append(
                f"Storage backend '{settings.storage_backend}' is not durable and is no longer "
                f"supported; configure DATABASE_URL=oracle+oracledb://... and use "
                f"SENTINEL_STORAGE_BACKEND=oracle."
            )
        elif backend not in DURABLE_STORAGE_BACKENDS:
            errors.append(f"Storage backend '{settings.storage_backend}' not supported.")

        if backend in DURABLE_STORAGE_BACKENDS and not settings.database_url_configured:
            errors.append(
                "No database URL is configured for storage_backend="
                f"'{settings.storage_backend}'. Set DATABASE_URL="
                "oracle+oracledb://SENTINEL:<password>@<adb-host>:1522/"
                "?service_name=<service> (or SENTINEL_ORACLE_DSN / "
                "SENTINEL_ORACLE_HOST + SENTINEL_ORACLE_SERVICE_NAME). "
                "SQLite is no longer supported."
            )

    return errors


def enforce_startup_configuration(settings: SentinelSettings, fail_fast: bool = False) -> list[str]:
    """Validate startup configuration, logging warnings or failing fast if requested."""
    errors = validate_startup_configuration(settings)
    if errors:
        for err in errors:
            logger.error(f"[CONFIG ZERO-TRUST VIOLATION]: {err}")
        if fail_fast or settings.environment == EnvironmentType.PRODUCTION:
            raise ConfigurationValidationError(errors)
    else:
        logger.info("Zero-trust startup configuration validation passed successfully.")
    return errors
