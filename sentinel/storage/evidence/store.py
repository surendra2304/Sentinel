"""Evidence Store for Sentinel with Forensic Zip Bundle Export and Tamper Verification."""

import hashlib
import io
import json
import uuid
import zipfile
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
from sentinel.storage.repositories.factory import get_evidence_repository


class EvidenceStore:
    """Forensics-grade evidence store with immutable chain-of-custody tracking and bundle export."""

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

    @property
    def repo(self):
        return get_evidence_repository()

    async def record_evidence(
        self,
        task_id: str,
        target_ref: str,
        source_agent: str,
        source_module: str,
        source_tool: str,
        raw_data: bytes,
        content_type: str = "application/octet-stream",
        collected_by: str = "sentinel",
        context_metadata: dict[str, Any] | None = None,
    ) -> Evidence:
        """Store immutable raw artifact and register indexed Evidence metadata."""
        sha256_hash = hashlib.sha256(raw_data).hexdigest()
        size_bytes = len(raw_data)
        evidence_id = f"evi-{uuid.uuid4().hex[:12]}"

        storage_uri, _ = await self.storage.store_artifact(
            key=f"{task_id}/{evidence_id}",
            data=raw_data,
            content_type=content_type,
        )

        initial_custody = ChainOfCustodyEvent(
            timestamp=datetime.now(UTC),
            actor=collected_by,
            action="COLLECTION",
            notes=f"Collected by {source_agent} via {source_tool} ({size_bytes} bytes)",
        )

        evidence = Evidence(
            id=evidence_id,
            task_id=task_id,
            target_ref=target_ref,
            source_agent=source_agent,
            source_module=source_module,
            source_tool=source_tool,
            artifact_storage_key=f"{task_id}/{evidence_id}",
            collected_by=collected_by,
            content_type=content_type,
            size_bytes=size_bytes,
            sha256_hash=sha256_hash,
            chain_of_custody=[initial_custody],
            integrity_metadata={
                "storage_uri": storage_uri,
                "verified": True,
                "context": context_metadata or {},
            },
        )

        self._evidence_records[evidence_id] = evidence
        await self.repo.save_evidence_record(evidence)

        self.audit.log_event(
            entry_id=f"audit-{evidence_id}",
            event_type="EVIDENCE_RECORDED",
            actor=collected_by,
            action_type="RECORD_EVIDENCE",
            scope_policy=task_id,
            decision="RECORDED",
            details={
                "evidence_id": evidence_id,
                "sha256": sha256_hash,
                "size_bytes": size_bytes,
                "source_tool": source_tool,
            },
        )

        await emit_event(
            event_type=EventType.EVIDENCE,
            topic="evidence.recorded",
            source="sentinel.storage.evidence",
            payload={
                "evidence_id": evidence_id,
                "task_id": task_id,
                "target_ref": target_ref,
                "sha256_hash": sha256_hash,
            },
            correlation_id=task_id,
        )

        return evidence

    async def get_evidence(self, evidence_id: str, actor: str = "operator") -> tuple[Evidence, bytes]:
        """Retrieve evidence metadata and raw artifact with chain-of-custody logging."""
        evidence = self._evidence_records.get(evidence_id)
        if not evidence:
            evidence = await self.repo.get_evidence_record(evidence_id)
        if not evidence:
            raise KeyError(f"Evidence '{evidence_id}' not found.")

        raw_bytes = await self.storage.get_artifact(f"{evidence.task_id}/{evidence_id}")
        calc_hash = hashlib.sha256(raw_bytes).hexdigest()
        if calc_hash != evidence.sha256_hash:
            raise ValueError(f"Evidence '{evidence_id}' integrity violation: hash mismatch!")

        evidence.log_access(actor=actor, reason="Retrieved raw artifact.")
        await self.repo.save_evidence_record(evidence)

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

        manifest_str = json.dumps(bundle_manifest, sort_keys=True)
        bundle_hash = hashlib.sha256(manifest_str.encode("utf-8")).hexdigest()
        bundle_manifest["bundle_sha256_digest"] = bundle_hash

        return bundle_manifest

    async def create_evidence_zip_bundle(self, task_id: str, finding_links: dict[str, list[str]] | None = None) -> bytes:
        """Generate standalone evidence zip containing manifest.json, raw artifacts, and finding link map."""
        task_evidence = self.query_evidence(task_id=task_id)
        manifest_items: list[dict[str, Any]] = []
        artifact_files: dict[str, bytes] = {}

        for evi in task_evidence:
            _, raw_bytes = await self.get_evidence(evi.id, actor="bundle_exporter")
            filename = f"artifacts/{evi.id}.bin"
            artifact_files[filename] = raw_bytes

            manifest_items.append({
                "id": evi.id,
                "source_tool": evi.source_tool,
                "source_module": evi.source_module,
                "target_ref": evi.target_ref,
                "timestamp": evi.timestamp.isoformat(),
                "sha256": evi.sha256_hash,
                "filename": filename,
                "size_bytes": len(raw_bytes),
            })

        manifest = {
            "task_id": task_id,
            "exported_at": datetime.now(UTC).isoformat(),
            "evidence_count": len(manifest_items),
            "records": manifest_items,
            "finding_to_evidence_map": finding_links or {},
        }

        manifest_bytes = json.dumps(manifest, indent=2).encode("utf-8")
        manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()
        manifest["manifest_sha256"] = manifest_hash

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_STORED) as zf:
            zf.writestr("manifest.json", json.dumps(manifest, indent=2))
            for path, raw_data in artifact_files.items():
                zf.writestr(path, raw_data)

        return zip_buffer.getvalue()

    @staticmethod
    def verify_evidence_zip_bundle(zip_bytes_or_path: bytes | str) -> dict[str, Any]:
        """Re-hash every artifact inside evidence bundle and assert manifest match with tamper detection."""
        if isinstance(zip_bytes_or_path, (bytes, bytearray)):
            zf_source = io.BytesIO(zip_bytes_or_path)
        else:
            zf_source = zip_bytes_or_path  # type: ignore[assignment]

        try:
            with zipfile.ZipFile(zf_source, "r") as zf:
                if "manifest.json" not in zf.namelist():
                    raise ValueError("Evidence bundle corrupted: missing manifest.json")

                manifest_raw = zf.read("manifest.json")
                manifest = json.loads(manifest_raw.decode("utf-8"))

                records = manifest.get("records", [])
                verified_count = 0

                for rec in records:
                    fname = rec["filename"]
                    expected_hash = rec["sha256"]
                    if fname not in zf.namelist():
                        raise ValueError(f"Integrity violation: artifact file '{fname}' missing from bundle.")

                    data = zf.read(fname)
                    calc_hash = hashlib.sha256(data).hexdigest()
                    if calc_hash != expected_hash:
                        raise ValueError(
                            f"Tamper detected in artifact '{fname}': expected {expected_hash}, calculated {calc_hash}!"
                        )
                    verified_count += 1
        except zipfile.BadZipFile as err:
            raise ValueError(f"Evidence bundle corrupted or tampered: {err}") from err

        return {
            "valid": True,
            "task_id": manifest.get("task_id"),
            "verified_records": verified_count,
            "manifest_hash": manifest.get("manifest_sha256"),
        }


# Global Evidence Store Singleton
evidence_store = EvidenceStore()
