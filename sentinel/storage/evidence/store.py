"""Evidence Store for Sentinel with Forensic Zip Bundle Export and Tamper Verification."""

import hashlib
import hmac
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
        self._evidence_records[evidence_id] = evidence

        raw_bytes = await self.storage.get_artifact(evidence.artifact_storage_key)
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

    async def query_evidence_async(
        self,
        task_id: str | None = None,
        target_ref: str | None = None,
        source_module: str | None = None,
        source_tool: str | None = None,
    ) -> list[Evidence]:
        """Query persistent evidence metadata and hydrate the local cache."""
        records = await self.repo.list_evidence(task_id=task_id, target_ref=target_ref)
        filtered = [
            evidence
            for evidence in records
            if (source_module is None or evidence.source_module == source_module)
            and (source_tool is None or evidence.source_tool == source_tool)
        ]
        self._evidence_records.update({evidence.id: evidence for evidence in filtered})
        return filtered

    async def export_evidence_bundle(self, task_id: str, exported_by: str = "operator") -> dict[str, Any]:
        """Produce a self-contained, hash-verified bundle (manifest + artifacts) for auditors."""
        task_evidence = await self.query_evidence_async(task_id=task_id)
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
            "bundle_version": 2,
            "task_id": task_id,
            "export_timestamp": datetime.now(UTC).isoformat(),
            "exported_by": exported_by,
            "evidence_count": len(manifest_items),
            "manifest": manifest_items,
        }

        manifest_str = json.dumps(bundle_manifest, sort_keys=True)
        bundle_hash = hashlib.sha256(manifest_str.encode("utf-8")).hexdigest()
        bundle_manifest["bundle_sha256_digest"] = bundle_hash
        bundle_manifest["bundle_signature"] = self.audit._sign_hash(bundle_hash)

        return bundle_manifest

    async def create_evidence_zip_bundle(self, task_id: str, finding_links: dict[str, list[str]] | None = None) -> bytes:
        """Generate standalone evidence zip containing manifest.json, raw artifacts, and finding link map."""
        task_evidence = await self.query_evidence_async(task_id=task_id)
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
            "bundle_version": 2,
            "task_id": task_id,
            "exported_at": datetime.now(UTC).isoformat(),
            "evidence_count": len(manifest_items),
            "records": manifest_items,
            "finding_to_evidence_map": finding_links or {},
        }

        manifest_bytes = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")
        manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()
        manifest["manifest_sha256"] = manifest_hash
        manifest["manifest_signature"] = self.audit._sign_hash(manifest_hash)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_STORED) as zf:
            zf.writestr("manifest.json", json.dumps(manifest, indent=2, sort_keys=True))
            for path, raw_data in artifact_files.items():
                zf.writestr(path, raw_data)

        return zip_buffer.getvalue()

    def verify_evidence_zip_bundle(self, zip_bytes_or_path: bytes | str) -> dict[str, Any]:
        """Verify manifest authenticity and every artifact in an evidence bundle.

        Version 2 bundles use a canonical manifest checksum plus the configured
        audit HMAC key. Legacy v1 bundles remain readable with checksum-only
        integrity; their authenticity cannot be established after the fact.
        """
        if isinstance(zip_bytes_or_path, (bytes, bytearray)):
            zf_source = io.BytesIO(zip_bytes_or_path)
        else:
            zf_source = zip_bytes_or_path  # type: ignore[assignment]

        try:
            with zipfile.ZipFile(zf_source, "r") as zf:
                names = zf.namelist()
                if "manifest.json" not in names:
                    raise ValueError("Evidence bundle corrupted: missing manifest.json")
                if len(names) != len(set(names)):
                    raise ValueError("Evidence bundle corrupted: duplicate archive member names.")

                manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
                if not isinstance(manifest, dict):
                    raise ValueError("Evidence bundle corrupted: manifest must be a JSON object.")
                records = manifest.get("records")
                if not isinstance(records, list):
                    raise ValueError("Evidence bundle corrupted: manifest records must be a list.")
                if manifest.get("evidence_count") != len(records):
                    raise ValueError("Evidence bundle corrupted: evidence_count does not match records.")

                version = manifest.get("bundle_version", 1)
                if isinstance(version, bool) or not isinstance(version, int) or version not in (1, 2):
                    raise ValueError(f"Unsupported evidence bundle version: {version}")
                expected_manifest_hash = manifest.get("manifest_sha256")
                manifest_signature = manifest.get("manifest_signature")
                manifest_payload = dict(manifest)
                manifest_payload.pop("manifest_sha256", None)
                manifest_payload.pop("manifest_signature", None)
                canonical_manifest = json.dumps(
                    manifest_payload,
                    indent=2,
                    sort_keys=(version == 2),
                ).encode("utf-8")
                actual_manifest_hash = hashlib.sha256(canonical_manifest).hexdigest()
                if not isinstance(expected_manifest_hash, str) or not hmac.compare_digest(
                    actual_manifest_hash, expected_manifest_hash
                ):
                    raise ValueError("Tamper detected in evidence bundle manifest checksum.")

                signature_verified = False
                if manifest_signature is not None:
                    expected_signature = self.audit._sign_hash(expected_manifest_hash)
                    if not isinstance(manifest_signature, str) or not hmac.compare_digest(
                        expected_signature, manifest_signature
                    ):
                        raise ValueError("Tamper detected in evidence bundle manifest signature.")
                    signature_verified = True
                elif version == 2:
                    raise ValueError("Evidence bundle v2 is missing its manifest signature.")

                verified_count = 0
                artifact_names: set[str] = set()
                for record in records:
                    if not isinstance(record, dict):
                        raise ValueError("Evidence bundle corrupted: each record must be an object.")
                    filename = record.get("filename")
                    record_id = record.get("id")
                    expected_hash = record.get("sha256")
                    expected_size = record.get("size_bytes")
                    if not isinstance(record_id, str) or not isinstance(filename, str):
                        raise ValueError("Evidence bundle corrupted: record ID or filename is missing.")
                    if (
                        filename != f"artifacts/{record_id}.bin"
                        or any(part in {"", ".", ".."} for part in filename.split("/"))
                    ):
                        raise ValueError(f"Evidence bundle corrupted: unsafe artifact path '{filename}'.")
                    if filename in artifact_names:
                        raise ValueError(f"Evidence bundle corrupted: duplicate artifact reference '{filename}'.")
                    artifact_names.add(filename)
                    if filename not in names:
                        raise ValueError(f"Integrity violation: artifact file '{filename}' missing from bundle.")

                    data = zf.read(filename)
                    if len(data) != expected_size:
                        raise ValueError(f"Tamper detected in artifact '{filename}': size mismatch.")
                    actual_hash = hashlib.sha256(data).hexdigest()
                    if not isinstance(expected_hash, str) or not hmac.compare_digest(actual_hash, expected_hash):
                        raise ValueError(
                            f"Tamper detected in artifact '{filename}': expected {expected_hash}, calculated {actual_hash}."
                        )
                    verified_count += 1

                expected_members = {"manifest.json", *artifact_names}
                if set(names) != expected_members:
                    raise ValueError("Evidence bundle corrupted: archive contains unreferenced or unexpected files.")
        except zipfile.BadZipFile as err:
            raise ValueError(f"Evidence bundle corrupted or tampered: {err}") from err
        except (json.JSONDecodeError, KeyError, TypeError) as err:
            raise ValueError(f"Evidence bundle corrupted or malformed: {err}") from err

        return {
            "valid": True,
            "signature_verified": signature_verified,
            "task_id": manifest.get("task_id"),
            "verified_records": verified_count,
            "manifest_hash": expected_manifest_hash,
        }


# Global Evidence Store Singleton
evidence_store = EvidenceStore()
