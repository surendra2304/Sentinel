"""Sentinel Typed Configuration System using pydantic-settings."""

import os
from enum import StrEnum
from functools import lru_cache

from pydantic import AliasChoices, Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


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
    """PostgreSQL Async Database configuration."""
    model_config = SettingsConfigDict(
        env_prefix="SENTINEL_DB_",
        env_file=".env",
        extra="ignore",
    )

    host: str = "dokploy-postgres"
    port: int = 5432
    user: str = "sentinel_user"
    password: str = "uyNl63UsjQqe1tI16G68fylb"
    name: str = "sentinel_db"
    echo: bool = False
    pool_size: int = 20
    max_overflow: int = 10

    @property
    def async_url(self) -> str:
        url = os.environ.get("SENTINEL_DATABASE_URL") or os.environ.get("DATABASE_URL")
        if url:
            if url.startswith("postgres://"):
                url = url.replace("postgres://", "postgresql+asyncpg://", 1)
            elif url.startswith("postgresql://") and not url.startswith("postgresql+asyncpg://"):
                url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
            return url
        return f"postgresql+asyncpg://{self.user}:{self.password}@{self.host}:{self.port}/{self.name}"

    @property
    def sync_url(self) -> str:
        url = os.environ.get("SENTINEL_DATABASE_URL") or os.environ.get("DATABASE_URL")
        if url:
            if url.startswith("postgresql+asyncpg://"):
                url = url.replace("postgresql+asyncpg://", "postgresql://", 1)
            return url
        return f"postgresql://{self.user}:{self.password}@{self.host}:{self.port}/{self.name}"


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
    storage: ObjectStorageSettings = Field(default_factory=ObjectStorageSettings)
    audit: AuditSettings = Field(default_factory=AuditSettings)
    modules: ModuleFlags = Field(default_factory=ModuleFlags)

    # Persistence Backend: "memory" (fast tests/dev) | "postgres" (durable production)
    storage_backend: str = "memory"

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


@lru_cache
def get_settings() -> Settings:
    """Retrieve cached global settings instance."""
    return Settings()


SentinelSettings = Settings
