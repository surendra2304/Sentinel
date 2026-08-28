"""Sentinel Typed Configuration System using pydantic-settings."""

from enum import StrEnum

from pydantic import Field
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
    model_config = SettingsConfigDict(env_prefix="SENTINEL_DB_")

    host: str = "localhost"
    port: int = 5432
    user: str = "sentinel"
    password: str = "sentinel_secret_dev"
    name: str = "sentinel_db"
    echo: bool = False
    pool_size: int = 20
    max_overflow: int = 10

    @property
    def async_url(self) -> str:
        return f"postgresql+asyncpg://{self.user}:{self.password}@{self.host}:{self.port}/{self.name}"

    @property
    def sync_url(self) -> str:
        return f"postgresql://{self.user}:{self.password}@{self.host}:{self.port}/{self.name}"


class ObjectStorageSettings(BaseSettings):
    """MinIO / S3-compatible Object Storage configuration for artifacts."""
    model_config = SettingsConfigDict(env_prefix="SENTINEL_S3_")

    endpoint: str = "localhost:9000"
    access_key: str = "sentinel_minio_user"
    secret_key: str = "sentinel_minio_secret"
    bucket_name: str = "sentinel-evidence"
    secure: bool = False
    region: str = "us-east-1"


class AuditSettings(BaseSettings):
    """Tamper-evident audit logging configuration."""
    model_config = SettingsConfigDict(env_prefix="SENTINEL_AUDIT_")

    log_file_path: str = "logs/audit.jsonl"
    enable_hash_chain: bool = True
    signing_key: str = "sentinel-audit-hmac-secret-key-change-in-prod"


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
    secret_key: str = "sentinel-insecure-secret-key-change-in-production"

    # Sub-configurations
    db: DatabaseSettings = Field(default_factory=DatabaseSettings)
    storage: ObjectStorageSettings = Field(default_factory=ObjectStorageSettings)
    audit: AuditSettings = Field(default_factory=AuditSettings)
    modules: ModuleFlags = Field(default_factory=ModuleFlags)

    # Persistence Backend: "memory" (fast tests/dev) | "postgres" (durable production)
    storage_backend: str = "memory"

    # Autonomy & Policy Gates
    kill_switch_active: bool = False
    require_human_approval_for_offensive: bool = True
    global_rate_limit_rps: int = 50


def get_settings() -> Settings:
    """Retrieve cached global settings instance."""
    return Settings()
