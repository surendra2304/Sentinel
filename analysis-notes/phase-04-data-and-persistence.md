# Phase 4 — Domain model, persistence, artifacts, and data lifecycle

## Domain/data model

[FACT] `sentinel/core/models.py` defines typed Pydantic v2 models for targets/target sets, explicit assessment scope/time window, policy, task/status transitions, action requests/results, agent handoffs, evidence/chain-of-custody, findings, contextual risk and events. A `Finding` requires at least one evidence reference, but that validator checks only non-emptiness; foreign-task evidence validation is a separate coordinator responsibility.

[FACT] SQLAlchemy maps 14 tables plus a target-set/target association: targets, target sets, scopes, policies, tasks, task checkpoints, action requests, approvals, action results, evidence, findings, risks, events and audit records. Task is relationally linked to target set, scope and policy. A JSON `scope_contract`/`policy_contract` preserves full Pydantic contracts alongside legacy columns. There is no tenant/user/organization ownership column on Task, Scope, Evidence, Finding, Approval, or AuditLogRecord.

## Persistence paths

[FACT] Repository factory selects in-memory or PostgreSQL task/finding/evidence/approval repositories based on `SENTINEL_STORAGE_BACKEND`; its default is `memory`. Local Compose production selects PostgreSQL; Render YAML selects memory. Postgres session pool defaults to 20 connections plus 10 overflow per process; no database pool override is listed in the deployment manifests.

[FACT] PostgreSQL schemas define action-request/action-result/risk/event/audit tables, but repository search finds no writers for those ORM classes. Audit entries go to append-only JSONL, event history is in an in-process event bus, risk summaries are in a process-local `RiskEngine` dictionary, and action results remain in executor/task memory rather than `ActionResultModel`.

[FACT] `EvidenceStore.record_evidence` stores raw bytes under `task_id/evidence_id` in local filesystem or MinIO, stores a SHA-256 and metadata in the selected evidence repository, and appends an audit event. The database `EvidenceModel` lacks `size_bytes`; `_to_domain_evidence` does not supply it, so persisted/reloaded evidence gets the Pydantic default `0`. The model/store also keeps chain-of-custody as JSON. MinIO methods call synchronous MinIO client operations from `async` methods; local writes use aiofiles.

[FACT] `LocalFileSystemStorage._resolve_path` strips only leading slash/backslash then joins the supplied key to `data/artifacts`; it does not resolve/reject `..` segments. Current `EvidenceStore` generates keys from task/evidence identifiers, not a public arbitrary path parameter; path traversal therefore needs a caller able to supply a crafted storage key and is not established as a remote API exploit.

[FACT] `MemoryStore` caps serialized checkpoint payloads at 2,000,000 bytes and caps the execution trace at 1,000 entries (`sentinel/core/memory/working_memory.py`, reviewed in prior phase). `PostgresTaskRepository.save_checkpoint` increments a row version but has no expected-version compare-and-swap or worker lease. Active-task enumeration is a plain query; no row claim/locking is used.

## Lifecycle / durability implications

[INFERENCE] Because task repositories, event queues, risk records and job maps are per-process, the three-replica Kubernetes manifest (which also omits storage/service/secrets configuration) cannot provide coherent task state as written. If an operator injects shared PostgreSQL without adding a claim protocol, every API process's startup recovery can independently discover and start the same submitted/nonterminal task. Cancellation and kill-switch consequences are analyzed in the security/operations phases.

[FACT] Render's declared memory backend and local artifacts mean a service restart loses task, approval, finding/evidence metadata and evidence bytes; audit JSONL may persist only according to the platform filesystem policy, which is not declared in the manifest.

## Confidence

High for model fields, selected repositories, mapped tables and conversion behavior read statically. Medium for production consequences because the Compose, Kubernetes and Render environments were not started or connectivity-tested.

## Post-baseline artifact path hardening (2026-10-07)

[FACT] The earlier `LocalFileSystemStorage._resolve_path` finding has been fixed: local keys must be non-empty relative paths without dot/dot-dot/empty components, POSIX or Windows absolute prefixes/drives are rejected, both slash conventions are normalized, and the resolved candidate must remain under the real configured root. Existing symlink components that resolve outside the root are rejected. [FACT] The new path regression suite first failed all seven cases against the old implementation, then passed after the guard; the tests cover store/read/exists/delete and symlink escape (`sentinel/storage/artifacts/storage.py:48-76`; `tests/security/test_artifact_storage_paths.py:8-48`).

[HYPOTHESIS] A concurrent symlink replacement between path validation and file open could still race the resolve-then-open check if an attacker can mutate the artifact tree. No hostile concurrent race test or descriptor-relative `openat` implementation was added. Current evidence keys remain generated internally from task/evidence IDs.
