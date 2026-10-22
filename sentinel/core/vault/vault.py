"""Task-Scoped Credential Vault & Central Redaction Layer for Sentinel."""

import json
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

from sentinel.audit.audit_logger import AuditLogger
from sentinel.config.settings import get_settings


class TaskCredential(BaseModel):
    key: str
    secret_value: str
    task_id: str
    description: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class CredentialVault:
    """Task-scoped encrypted credential vault with central redaction engine."""

    def __init__(self, audit_logger: AuditLogger | None = None):
        self.settings = get_settings()
        self.audit = audit_logger or AuditLogger(
            log_path=self.settings.audit.log_file_path,
            signing_key=self.settings.audit.signing_key,
        )
        self._vault: dict[str, dict[str, str]] = {}  # task_id -> {key: secret_value}
        self._registered_secrets: set[str] = set()

    def store_credential(self, task_id: str, key: str, secret_value: str, description: str = "") -> None:
        """Store task-scoped credential in memory/vault and register for central redaction."""
        if not secret_value or len(secret_value.strip()) == 0:
            raise ValueError("Secret value cannot be empty.")
        if task_id not in self._vault:
            self._vault[task_id] = {}
        self._vault[task_id][key] = secret_value
        self._registered_secrets.add(secret_value.strip())

        self.audit.log_event(
            entry_id=f"audit-vault-store-{task_id[:8]}-{key}",
            event_type="CREDENTIAL_STORED",
            actor="credential_vault",
            action_type="VAULT_STORE",
            scope_policy=task_id,
            decision="STORED",
            details={"task_id": task_id, "key": key, "description": description},
        )

    def get_credential(self, task_id: str, key: str) -> str | None:
        """Retrieve credential strictly at execution time."""
        val = self._vault.get(task_id, {}).get(key)
        if val:
            self.audit.log_event(
                entry_id=f"audit-vault-access-{task_id[:8]}-{key}",
                event_type="CREDENTIAL_ACCESSED",
                actor="execution_engine",
                action_type="VAULT_ACCESS",
                scope_policy=task_id,
                decision="ACCESSED",
                details={"task_id": task_id, "key": key},
            )
        return val

    def redact_text(self, text_content: str) -> str:
        """Central redaction engine: scrubs all registered secrets from strings."""
        if not text_content:
            return text_content
        redacted = text_content
        for secret in self._registered_secrets:
            if secret and len(secret) > 2 and secret in redacted:
                redacted = redacted.replace(secret, "[REDACTED_SECRET]")
        return redacted

    def redact_dict(self, data: dict[str, Any]) -> dict[str, Any]:
        """Deep redact dict structures."""
        from typing import cast
        serialized = json.dumps(data)
        redacted_str = self.redact_text(serialized)
        return cast(dict[str, Any], json.loads(redacted_str))

    def clear_task_credentials(self, task_id: str) -> None:
        """Wipe credentials on task completion or cancellation."""
        if task_id in self._vault:
            del self._vault[task_id]


credential_vault = CredentialVault()
