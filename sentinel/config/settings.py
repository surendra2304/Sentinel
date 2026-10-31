"""Sentinel Typed Configuration System using pydantic-settings.

Durable persistence targets Oracle Autonomous Database (26ai / 23.26). SQLite is
no longer an accepted backend: a filesystem database cannot hold the hash-chained
audit record across redeploys, and it was the silent default in earlier releases.
"""

import logging
import os
from enum import StrEnum
from functools import lru_cache
from typing import Any
from urllib.parse import quote_plus

from pydantic import AliasChoices, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger("sentinel.config.settings")

#: The only first-class durable backend.
ORACLE_STORAGE_BACKEND = "oracle"
#: Process-local; allowed for tests and local development only.
NON_DURABLE_STORAGE_BACKENDS = frozenset({"memory"})
#: Backends that survive a restart. Oracle is the only one.
DURABLE_STORAGE_BACKENDS = frozenset({ORACLE_STORAGE_BACKEND})
#: Backends that were accepted before the Oracle migration and are now refused.
#: SQLite cannot hold the security record across redeploys; PostgreSQL is not a
#: database Sentinel owns and its driver (asyncpg/psycopg) must never be imported.
REMOVED_STORAGE_BACKENDS = frozenset(
    {
        "sqlite",
        "sqlite3",
        "aiosqlite",
        "postgres",
        "postgresql",
        "postgresql+asyncpg",
        "asyncpg",
        "psycopg",
        "psycopg2",
    }
)


class DatabaseNotConfiguredError(RuntimeError):
    """Raised when no database URL is configured for a durable backend.

    Sentinel fails closed here rather than falling back to a filesystem database:
    silently writing the security record to a local file is how findings,
    evidence and approvals were lost on every redeploy.
    """


def database_url_from_environment() -> str:
    """Return an explicitly configured database URL, or an empty string."""
    for key in (
        "SENTINEL_DATABASE_URL",
        "DATABASE_URL",
        "SENTINEL_ORACLE_URL",
        "ORACLE_DATABASE_URL",
    ):
        value = os.environ.get(key, "").strip()
        if value:
            return value
    return ""


def _swapscheme(url: str, *, asynchronous: bool) -> str:
    """Normalise a database URL onto the requested Oracle driver.

    Oracle Autonomous Database is the only supported target. A SQLite or
    PostgreSQL URL is refused here rather than silently opening a different
    database: the security record must live in the Sentinel Oracle schema.
    """
    scheme = url.split("://", 1)[0].strip().lower()
    dialect = scheme.split("+", 1)[0]
    if dialect in {"sqlite", "postgres", "postgresql", "psycopg", "psycopg2", "asyncpg"}:
        raise DatabaseNotConfiguredError(
            f"Unsupported database URL scheme '{scheme}': Sentinel requires Oracle "
            "Autonomous Database. Set DATABASE_URL=oracle+oracledb://SENTINEL:"
            "<password>@<adb-host>:1522/?service_name=<service>. SQLite and "
            "PostgreSQL are not supported backends."
        )
    if url.startswith("oracle+oracledb_async://"):
        return url.replace("oracle+oracledb_async://", "oracle+oracledb://", 1) if not asynchronous else url
    if url.startswith("oracle+oracledb://"):
        return url if not asynchronous else url.replace("oracle+oracledb://", "oracle+oracledb_async://", 1)
    if url.startswith("oracle://"):
        suffix = url[len("oracle://"):]
        scheme = "oracle+oracledb_async" if asynchronous else "oracle+oracledb"
        return f"{scheme}://{suffix}"
    raise DatabaseNotConfiguredError(
        f"Unsupported database URL scheme '{scheme}': Sentinel requires "
        "oracle+oracledb:// (or oracle+oracledb_async://)."
    )


class OracleSettings(BaseSettings):
    """Oracle Autonomous Database connection settings (``SENTINEL_ORACLE_*``).

    Used only when neither ``SENTINEL_DATABASE_URL`` nor ``DATABASE_URL`` is set.
    Either a TNS alias (``dsn``, as shipped in the Autonomous Database wallet) or
    an explicit ``host`` + ``service_name`` pair must be supplied.
    """

    model_config = SettingsConfigDict(
        env_prefix="SENTINEL_ORACLE_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    dsn: str = ""
    host: str = ""
    port: int = 1522
    service_name: str = ""
    user: str = "SENTINEL"
    password: SecretStr = Field(default=SecretStr(""))
    #: Wallet/keystore directory for mTLS connections to Autonomous Database.
    wallet_location: str = ""
    wallet_password: SecretStr = Field(default=SecretStr(""))
    #: Schema (database user) that owns the Sentinel tables. Names are written
    #: unqualified, so this must match the user Sentinel connects as.
    schema: str = "SENTINEL"
    echo: bool = False
    pool_size: int = 8
    max_overflow: int = 8
    pool_recycle: int = 1800
    pool_timeout: int = 30

    @property
    def owner(self) -> str:
        """Upper-case schema owner used for the startup ownership check."""
        return (self.schema or self.user or "SENTINEL").strip().upper()

    def build_url(self, *, asynchronous: bool = True) -> str:
        """Compose an ``oracle+oracledb[+_async]://`` URL from the settings."""
        driver = "oracle+oracledb_async" if asynchronous else "oracle+oracledb"
        if not self.dsn and not (self.host and self.service_name):
            raise DatabaseNotConfiguredError(
                "No database URL is configured. Set DATABASE_URL="
                "oracle+oracledb://SENTINEL:<password>@<adb-host>:1522/?service_name=<service> "
                "(or SENTINEL_DATABASE_URL), or provide SENTINEL_ORACLE_DSN / "
                "SENTINEL_ORACLE_HOST + SENTINEL_ORACLE_SERVICE_NAME together with "
                "SENTINEL_ORACLE_USER and SENTINEL_ORACLE_PASSWORD. SQLite is no longer supported."
            )

        user = quote_plus(self.user or "SENTINEL")
        password = quote_plus(self.password.get_secret_value())
        query: list[tuple[str, str]] = []
        if self.dsn:
            location = self.dsn
        else:
            location = f"{self.host}:{self.port}"
            query.append(("service_name", self.service_name))
        if self.wallet_location:
            query.append(("config_dir", self.wallet_location))
        if self.wallet_password.get_secret_value():
            query.append(("wallet_password", self.wallet_password.get_secret_value()))
        query_string = "&".join(f"{key}={quote_plus(value)}" for key, value in query)
        return f"{driver}://{user}:{password}@{location}/?{query_string}" if query_string else (
            f"{driver}://{user}:{password}@{location}"
        )


class EnvironmentType(StrEnum):
    DEVELOPMENT = "development"
    TESTING = "testing"
    STAGING = "staging"
    PRODUCTION = "production"


class LogLevel(StrEnum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class DatabaseSettings(BaseSettings):
    """Database configuration.

    ``DATABASE_URL`` / ``SENTINEL_DATABASE_URL`` is the authoritative source;
    ``SENTINEL_ORACLE_*`` is the second supported form. The legacy
    ``SENTINEL_DB_*`` host/port/user/name fields are parsed for backward
    compatibility only and never produce a connection URL. Oracle is the only
    supported backend.
    """
    model_config = SettingsConfigDict(
        env_prefix="SENTINEL_DB_",
        env_file=".env",
        extra="ignore",
    )

    host: str = ""
    port: int = 0
    user: str = ""
    password: str = ""
    name: str = ""
    echo: bool = False
    pool_size: int = 20
    max_overflow: int = 10
    #: Set by the owning ``Settings`` instance so URL resolution uses *its*
    #: ``database_url`` rather than the process-wide cached settings.
    _parent: Any = None

    def resolved_url(self, *, asynchronous: bool) -> str:
        """Resolve the configured URL, failing closed when nothing is configured.

        Resolution order:
        1. ``SENTINEL_DATABASE_URL`` / ``DATABASE_URL`` (process env or owning settings).
        2. ``SENTINEL_ORACLE_*`` settings composed into an ``oracle+oracledb://`` URL.
        3. Fail closed. Oracle is the only supported backend.
        """
        raw = database_url_from_environment()
        settings = self._parent or get_settings()
        if not raw:
            configured = (settings.database_url or "").strip()
            if configured:
                raw = configured
            elif settings.oracle.dsn or settings.oracle.host:
                return settings.oracle.build_url(asynchronous=asynchronous)
            elif settings.storage_backend.strip().lower() in DURABLE_STORAGE_BACKENDS:
                # Durable backend but nothing to connect to: fail closed instead of
                # opening a local file.
                raise DatabaseNotConfiguredError(
                    "No database URL is configured for storage_backend="
                    f"'{settings.storage_backend}'. Set DATABASE_URL=oracle+oracledb://"
                    "SENTINEL:<password>@<adb-host>:1522/?service_name=<service> "
                    "(accepts oracle+oracledb:// and oracle+oracledb_async://) or the "
                    "SENTINEL_ORACLE_DSN / SENTINEL_ORACLE_HOST + SENTINEL_ORACLE_SERVICE_NAME "
                    "pair. SQLite is no longer supported."
                )
            else:
                raise DatabaseNotConfiguredError(
                    "No database URL is configured. Set DATABASE_URL=oracle+oracledb://"
                    "SENTINEL:<password>@<adb-host>:1522/?service_name=<service> or the "
                    "SENTINEL_ORACLE_DSN / SENTINEL_ORACLE_HOST + SENTINEL_ORACLE_SERVICE_NAME "
                    "pair. PostgreSQL and SQLite are not supported backends."
                )
        return _swapscheme(raw, asynchronous=asynchronous)

    @property
    def async_url(self) -> str:
        return self.resolved_url(asynchronous=True)

    @property
    def sync_url(self) -> str:
        return self.resolved_url(asynchronous=False)


class ObjectStorageSettings(BaseSettings):
    """MinIO / S3-compatible Object Storage configuration for artifacts."""
    model_config = SettingsConfigDict(env_prefix="SENTINEL_S3_")

    backend: str = "local"  # "local" or "s3"
    endpoint: str = "localhost:9000"
    access_key: str = ""
    secret_key: str = ""
    bucket_name: str = "sentinel-evidence"
    secure: bool = False
    region: str = "us-east-1"


class AuditSettings(BaseSettings):
    """Tamper-evident audit logging configuration."""
    model_config = SettingsConfigDict(
        env_prefix="SENTINEL_AUDIT_",
        env_file=".env",
        env_file_encoding="utf-8",
        # Ignore unrelated keys in the shared .env file (e.g. SENTINEL_PORT, APP_ENV)
        # so only SENTINEL_AUDIT_-prefixed values feed audit settings.
        extra="ignore",
    )

    log_file_path: str = "logs/audit.jsonl"
    enable_hash_chain: bool = True
    # Inject a deployment-specific signing key from the environment/secret manager.
    # There is deliberately no source-controlled fallback.
    signing_key: str = Field(
        default_factory=lambda: os.environ.get("SENTINEL_AUDIT_SIGNING_KEY", "")
    )


class ModuleFlags(BaseSettings):
    """Feature toggles for pluggable domain modules."""
    model_config = SettingsConfigDict(env_prefix="SENTINEL_MODULE_")

    recon: bool = True
    dns: bool = True
    network: bool = True
    wireless: bool = True
    web: bool = True
    api_security: bool = True
    mobile: bool = True
    endpoint: bool = True
    cloud: bool = True
    vulnerability: bool = True
    forensics: bool = True
    threat_intel: bool = True
    incident_response: bool = True


class Settings(BaseSettings):
    """Global Sentinel Platform Settings."""
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="SENTINEL_",
        extra="ignore"
    )

    app_name: str = "Sentinel Cybersecurity Platform"
    environment: EnvironmentType = EnvironmentType.DEVELOPMENT
    debug: bool = True
    log_level: LogLevel = LogLevel.INFO
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    api_prefix: str = "/api/v1"
    api_url: str = ""
    api_key: SecretStr = Field(default=SecretStr(""))
    api_auth_required: bool = False
    secret_key: str = ""
    # Capability signatures must use a deployment-specific secret. Never embed a
    # fallback signing key in source: tokens signed with a public key are forgeable.
    capability_signing_key: str = Field(
        default_factory=lambda: os.environ.get("SENTINEL_CAPABILITY_SIGNING_KEY", "")
    )

    # Sub-configurations
    db: DatabaseSettings = Field(default_factory=DatabaseSettings)
    oracle: OracleSettings = Field(default_factory=OracleSettings)
    storage: ObjectStorageSettings = Field(default_factory=ObjectStorageSettings)
    audit: AuditSettings = Field(default_factory=AuditSettings)
    modules: ModuleFlags = Field(default_factory=ModuleFlags)

    # Authoritative database URL. Accepts oracle+oracledb:// and
    # oracle+oracledb_async://. SQLite and PostgreSQL URLs are refused.
    database_url: str = Field(
        default="",
        validation_alias=AliasChoices("SENTINEL_DATABASE_URL", "DATABASE_URL", "SENTINEL_ORACLE_URL"),
    )

    # Persistence backend: "oracle" (durable, default) | "memory" (tests/dev
    # only). "sqlite"/"postgres"/"postgresql" are rejected: they are not durable
    # or are not a database Sentinel owns.
    storage_backend: str = ORACLE_STORAGE_BACKEND

    # External Threat Intelligence Feeds
    shodan_api_key: SecretStr = Field(
        default=SecretStr(""),
        validation_alias=AliasChoices("SENTINEL_SHODAN_API_KEY", "SHODAN_API_KEY"),
    )
    nvd_api_key: SecretStr = Field(
        default=SecretStr(""),
        validation_alias=AliasChoices("SENTINEL_NVD_API_KEY", "NVD_API_KEY"),
    )
    virustotal_api_key: SecretStr = Field(
        default=SecretStr(""),
        validation_alias=AliasChoices("SENTINEL_VIRUSTOTAL_API_KEY", "VIRUSTOTAL_API_KEY"),
    )

    # Autonomy & Policy Gates
    kill_switch_active: bool = False
    block_on_medium_cves: bool = Field(
        default=False,
        validation_alias=AliasChoices("SENTINEL_BLOCK_ON_MEDIUM_CVES", "BLOCK_ON_MEDIUM_CVES"),
    )
    auto_kill_switch_enabled: bool = Field(
        default=False,
        validation_alias=AliasChoices("SENTINEL_AUTO_KILL_SWITCH_ENABLED", "AUTO_KILL_SWITCH_ENABLED"),
    )
    docker_socket_path: str = Field(
        default="/var/run/docker.sock",
        validation_alias=AliasChoices("SENTINEL_DOCKER_SOCKET_PATH", "DOCKER_SOCKET_PATH"),
    )
    # VyralX publication is denied by default. The dedicated authenticated endpoint
    # can allow only operator-reviewed jobs with explicit rights verification.
    youtube_publish_enabled: bool = False
    youtube_publish_allow_unlisted: bool = False
    youtube_publish_allow_public: bool = False
    require_human_approval_for_offensive: bool = True
    global_rate_limit_rps: int = 50
    max_http_concurrency: int = Field(default=256, ge=1, le=10_000)
    max_health_concurrency: int = Field(default=16, ge=1, le=1_000)
    max_agent_proposals_per_task: int = Field(default=8, ge=0, le=100)
    max_plan_steps_per_iteration: int = Field(default=16, ge=1, le=256)
    max_actions_per_agent_per_task: int = Field(default=32, ge=1, le=1_000)
    max_agent_analysis_seconds: float = Field(default=15.0, gt=0.0, le=300.0)
    max_task_iterations: int = Field(default=10, ge=1, le=100)

    @model_validator(mode="after")
    def _link_database_settings(self) -> "Settings":
        """Let the nested database settings resolve this instance's URL.

        ``DatabaseSettings`` used to fall back to the process-wide cached
        ``Settings`` for ``database_url``, so a directly constructed
        ``Settings(database_url=...)`` silently resolved the ``.env`` value.
        """
        self.db._parent = self
        return self

    @field_validator("storage_backend", mode="before")
    @classmethod
    def _validate_storage_backend(cls, value: object) -> str:
        """Normalise the backend name and refuse removed backends outright."""
        if value is None:
            return ORACLE_STORAGE_BACKEND
        normalised = str(value).strip().lower()
        if not normalised:
            return ORACLE_STORAGE_BACKEND
        if normalised in REMOVED_STORAGE_BACKENDS:
            raise ValueError(
                f"Storage backend '{value}' is no longer supported: it discards the security "
                "record or stores it outside Sentinel's Oracle schema. Configure "
                "DATABASE_URL=oracle+oracledb://... (or the SENTINEL_ORACLE_* variables) and "
                "leave SENTINEL_STORAGE_BACKEND unset or set it to 'oracle'."
            )
        if normalised in {"oracledb", "oracle+oracledb", "oracle+oracledb_async"}:
            return ORACLE_STORAGE_BACKEND
        if normalised not in DURABLE_STORAGE_BACKENDS | NON_DURABLE_STORAGE_BACKENDS:
            raise ValueError(
                f"Unsupported storage_backend '{value}': use 'oracle' (default) or 'memory' "
                "(tests/dev only)."
            )
        return normalised

    @property
    def storage_backend_normalized(self) -> str:
        return (self.storage_backend or ORACLE_STORAGE_BACKEND).strip().lower()

    @property
    def database_url_configured(self) -> bool:
        """True when a database URL or SENTINEL_ORACLE_* coordinates are configured."""
        return bool(
            database_url_from_environment()
            or (self.database_url or "").strip()
            or self.oracle.dsn
            or (self.oracle.host and self.oracle.service_name)
        )

    @property
    def database_url_resolved(self) -> str:
        """The configured async database URL; raises when nothing is configured."""
        return self.db.resolved_url(asynchronous=True)

    @property
    def database_dialect(self) -> str:
        """Dialect selected by the configured URL (always ``oracle`` when set)."""
        try:
            url = self.database_url_resolved
        except DatabaseNotConfiguredError:
            return ""
        if url.startswith("oracle"):
            return "oracle"
        raise DatabaseNotConfiguredError(
            f"Unsupported database dialect in {url.split('://', 1)[0]!r}: Sentinel requires "
            "Oracle Autonomous Database (oracle+oracledb://)."
        )

    @property
    def is_oracle_database(self) -> bool:
        return self.database_dialect == "oracle"

    @property
    def uses_database_backend(self) -> bool:
        """True when a durable, database-backed storage backend is selected."""
        return self.storage_backend_normalized in DURABLE_STORAGE_BACKENDS


@lru_cache
def get_settings() -> Settings:
    """Retrieve cached global settings instance."""
    return Settings()


SentinelSettings = Settings
