"""Evidence Store for Sentinel.

Provides forensics-grade persistence, chain-of-custody logging, rich queries,
and self-contained hash-verified export bundles for reports and external auditors.
"""

import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from sentinel.audit.audit_logger import AuditLogger
from sentinel.config.settings import get_settings
from sentinel.core.events.bus import emit_event
from sentinel.core.models import (
    ChainOfCustodyEvent,
    EventType,
    Evidence,
)
from sentinel.storage.artifacts.storage import ArtifactStorage, get_artifact_storage


class EvidenceStore:
    """Forensics-grade evidence store with immutable chain-of-custody tracking."""

    def __init__(
        self,
        storage: ArtifactStorage | None = None,
        audit_logger: AuditLogger | None = None,
    ):
        self.storage = storage or get_artifact_storage()
        self.settings = get_settings()
        self.audit = audit_logger or AuditLogger(
            log_path=self.settings.audit.log_file_path,
            signing_key=self.settings.audit.signing_key,
        )
        self._evidence_records: dict[str, Evidence] = {}

    async def record_evidence(
        self,
        task_id: str,
        target_ref: str,
        source_agent: str,
        source_module: str,
        source_tool: str,
        raw_data: bytes | bytearray,
        content_type: str = "application/json",
        collected_by: str = "sentinel_executor",
        context_metadata: dict[str, Any] | None = None,
    ) -> Evidence:
        """Store raw artifact, compute SHA-256, record chain-of-custody, and index."""
        evidence_id = f"evi-{uuid.uuid4().hex[:12]}"
        timestamp = datetime.now(UTC)
        storage_key = f"evidence/{task_id}/{evidence_id}_{int(timestamp.timestamp())}.dat"

        # Store in object storage
        storage_uri, sha256_hash = await self.storage.store_artifact(
            key=storage_key,
            data=raw_data,
            content_type=content_type,
        )

        initial_custody = ChainOfCustodyEvent(
            timestamp=timestamp,
            actor=collected_by,
            action="COLLECTION",
            notes=f"Collected by {source_tool} from {target_ref}",
        )

        evidence = Evidence(
            id=evidence_id,
            task_id=task_id,
            target_ref=target_ref,
            source_agent=source_agent,
            source_module=source_module,
            source_tool=source_tool,
            timestamp=timestamp,
            artifact_storage_key=storage_key,
            content_type=content_type,
            sha256_hash=sha256_hash,
            collected_by=collected_by,
            chain_of_custody=[initial_custody],
            integrity_metadata={"storage_uri": storage_uri, "size_bytes": len(raw_data)},
            context_metadata=context_metadata or {},
        )

        self._evidence_records[evidence_id] = evidence

        # Audit and Event dispatch
        self.audit.log_event(
            entry_id=f"audit-evi-{evidence_id}",
            event_type="EVIDENCE_RECORDED",
            actor=collected_by,
            target=target_ref,
            action_type="EVIDENCE_CAPTURE",
            scope_policy=task_id,
            decision="STORED",
            details={"evidence_id": evidence_id, "sha256": sha256_hash, "size": len(raw_data)},
        )

        await emit_event(
            event_type=EventType.EVIDENCE,
            topic="evidence.collected",
            source="sentinel.storage.evidence",
            payload={"evidence_id": evidence.id, "task_id": task_id, "sha256": sha256_hash},
            correlation_id=task_id,
        )

        return evidence

    async def get_evidence(self, evidence_id: str, actor: str = "operator") -> tuple[Evidence, bytes]:
        """Retrieve evidence record and raw artifact bytes with read custody logging."""
        evidence = self._evidence_records.get(evidence_id)
        if not evidence:
            raise KeyError(f"Evidence record '{evidence_id}' not found.")

        # Log custody access
        custody_event = ChainOfCustodyEvent(
            timestamp=datetime.now(UTC),
            actor=actor,
            action="ACCESS",
            notes="Artifact read for analysis/export",
        )
        evidence.chain_of_custody.append(custody_event)

        raw_bytes = await self.storage.get_artifact(evidence.artifact_storage_key)

        # Integrity verification on read
        computed_hash = hashlib.sha256(raw_bytes).hexdigest()
        if computed_hash.lower() != evidence.sha256_hash.lower():
            raise ValueError(f"CRITICAL: Evidence '{evidence_id}' failed SHA-256 integrity check!")

        return evidence, raw_bytes

    def query_evidence(
        self,
        task_id: str | None = None,
        target_ref: str | None = None,
        source_module: str | None = None,
        source_tool: str | None = None,
    ) -> list[Evidence]:
        """Query indexed evidence records by criteria."""
        results = []
        for evi in self._evidence_records.values():
            if task_id and evi.task_id != task_id:
                continue
            if target_ref and evi.target_ref != target_ref:
                continue
            if source_module and evi.source_module != source_module:
                continue
            if source_tool and evi.source_tool != source_tool:
                continue
            results.append(evi)
        return results

    async def export_evidence_bundle(self, task_id: str, exported_by: str = "operator") -> dict[str, Any]:
        """Produce a self-contained, hash-verified bundle (manifest + artifacts) for auditors."""
        task_evidence = self.query_evidence(task_id=task_id)
        manifest_items: list[dict[str, Any]] = []

        for evi in task_evidence:
            _, raw_bytes = await self.get_evidence(evi.id, actor=exported_by)
            manifest_items.append({
                "evidence_id": evi.id,
                "target_ref": evi.target_ref,
                "source_tool": evi.source_tool,
                "timestamp": evi.timestamp.isoformat(),
                "content_type": evi.content_type,
                "sha256_hash": evi.sha256_hash,
                "chain_of_custody": [
                    {
                        "timestamp": c.timestamp.isoformat() if isinstance(c.timestamp, datetime) else str(c.timestamp),
                        "actor": c.actor,
                        "action": c.action,
                        "notes": c.notes,
                    }
                    for c in evi.chain_of_custody
                ],
                "raw_payload_str": raw_bytes.decode("utf-8", errors="replace"),
            })

        bundle_manifest: dict[str, Any] = {
            "task_id": task_id,
            "export_timestamp": datetime.now(UTC).isoformat(),
            "exported_by": exported_by,
            "evidence_count": len(manifest_items),
            "manifest": manifest_items,
        }

        # Calculate overall bundle integrity digest
        manifest_str = json.dumps(bundle_manifest, sort_keys=True)
        bundle_hash = hashlib.sha256(manifest_str.encode("utf-8")).hexdigest()
        bundle_manifest["bundle_sha256_digest"] = bundle_hash

        return bundle_manifest


# Global Evidence Store Singleton
evidence_store = EvidenceStore()
