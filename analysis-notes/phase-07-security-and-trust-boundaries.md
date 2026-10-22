# Phase 7 — Security and trust-boundary review

## Priority findings (static review; exploitability caveats kept explicit)

### S1 — FRIDAY delegation fabricates authorization context (high)

[FACT] `FridayPolicyContext.authorization_reference` defaults to `FRIDAY_DIRECTIVE`. In `/friday/delegate`, a missing scope is replaced with a reference derived from payload/policy context or `FRIDAY-{request_id or AUTH}`, a 24-hour window, default methods and `maximum_impact=LOW`; partial `scope_override` gets equivalent owner/reference/time/method defaults. The route then validates only structural scope and passes it to the normal lifecycle. Existing `tests/unit/test_friday_enhancements.py` exercises a delegation with only `scope_override.allowed_targets` and asserts HTTP 200. This contradicts the normal API's explicit, non-synthetic authorization requirement and README wording. It means a service-key holder can submit a target with a made-up directive/reference; it does not prove real written consent exists.

### S2 — Scope claims are not tied to a verified actor/authorization source

[FACT] Normal lifecycle checks scope owner/reference for non-empty strings and validates target/time/method/impact/rate shape. `ScopeResolver.validate_scope` does not query an authorization system, verify a signature/ticket, or reject `AuthorizationType.UNAUTHORIZED`; `Scope.authorization` defaults to `OWNED`. The `owner` and reference are caller-provided body fields. There is no authenticated human identity or tenant field on Task. The API key is a single service credential, not an operator/tenant identity.

[INFERENCE] In a deployment intended for multiple customers or named operators, task/evidence/approval access is not tenant-isolated: any accepted API key can list/read all tasks and findings and cancel/decide approvals by object ID. If the deployment is strictly one trusted operator boundary, the risk is narrower but still lacks per-human attribution.

### S3 — Audit chain does not authenticate all persisted metadata and cannot detect truncation

[FACT] `AuditLogger` signs a hash payload containing entry ID/event type/actor/target/action type/scope/decision/details, but omits persisted `seq`, `timestamp`, `tenant_id`, and `action_id`; startup and `verify_integrity` do not validate persisted sequence continuity. A missing ledger returns “valid” (`True`), and a valid prefix after tail deletion also verifies. Thus those omitted fields can be changed, and ledger removal/truncation is not detectable without an external trusted anchor. Runtime appends re-read all existing nonblank log lines on each append; locking is process-local only.

[FACT] Redaction is recursive and key-name based. It redacts names containing `secret`, `token`, `password`, `api_key`, `private_key`, `credential`, or `auth_header`; it does not redact arbitrary values/PII in strings such as `justification` or objective text. The docstring's broader PII-redaction claim is not guaranteed by implementation.

### S4 — Evidence ZIP manifest digest is written but never checked

[FACT] Bundle creation hashes the JSON manifest before adding `manifest_sha256`. The verifier re-hashes artifact files against manifest entries but never recomputes/compares the manifest digest. It returns `valid=True` after checking only listed artifact bytes. Manifest metadata, record-to-finding map, target/source/timestamp fields can be changed without the verifier noticing, and there is no keyed signature for the manifest. This weakens chain-of-custody claims even when artifact bytes still match their listed hashes.

### S5 — Cancellation/global kill switch are process-local in the multi-replica topology

[FACT] `_running_jobs` and `settings.kill_switch_active` are process-local. `cancel_task` can cancel only a local asyncio job; orchestrator checks its task snapshot/local setting rather than reloading persisted cancellation state between actions. Startup recovery queries all nonterminal tasks without a DB claim/lease/row lock. The Kubernetes manifest declares three API replicas and an HPA targeting a separate, undefined `sentinel-worker` deployment.

[INFERENCE] If shared persistence is configured behind multiple replicas, two replicas can recover/run the same task; a cancellation or global switch handled by another replica may update DB but fail to stop the worker, while the worker can later overwrite terminal state. As written, the Kubernetes manifest instead omits DB/backend/service/secrets and each replica defaults to its own in-memory store, so state can also be inconsistent across pods.

### S6 — Optional enrichment/research endpoints can transmit query data without task consent

[FACT] Planner recon adapters honor `allow_third_party_enrichment` for `crt.sh` and IP-API, and passive tests assert no DNS resolution / mock CT. However `POST /api/v1/friday/research` passes an arbitrary query directly to the configured IntelX service, `/friday/research-context/{finding_id}` sends a finding title to threat research, and `/ask-inference` forwards a caller-supplied question to `INFERENCE_URL`; these routes do not consult an AssessmentScope consent flag. A background Memora poller can also send advisory event data to `MEMORA_URL` when enabled. The repository was not asked to contact these services, and no outbound request was made during the audit.

[FACT] Render sets `MEMORA_API_KEY`, but the cloud client chooses `<AGENT>_API_KEY`; for the `sentinel` consumer it selects `SENTINEL_API_KEY`. Whether these values are intentionally identical is not established; the named `MEMORA_API_KEY` has no use in this client.

### S7 — TLS peer verification is disabled in multiple outbound/target adapters

[FACT] `httpx.AsyncClient(verify=False)` appears in web, recon, API-security, browser and HTTP observer adapters. This permits self-signed targets but also removes certificate/peer authenticity checks; resulting HTTPS content/evidence can be influenced by an on-path proxy. Several adapters separately disable redirect following or scope-check redirects; that does not restore TLS validation.

### S8 — Default authentication is off outside Render

[FACT] Global API auth defaults false; middleware forces it on only when `RENDER` is set or the setting is true. Production Compose turns it on and checks API-key length/placeholder, but a non-Render deployment using defaults can expose task, approval, cancellation and administration endpoints without a key. Development Compose publishes API port 8000 to all host interfaces unless the environment/network constrains it. The FRIDAY reference client also embeds a short development key and localhost URL; the current production key guard would reject that key if used as the configured service key.

### S9 — API-key holder can assert operator identity and is not a tenant identity

[FACT] Approval API accepts `operator` and justification from the request body and records that string as `approved_by`; only non-empty text is required. The kill-switch deactivation route calls the default `operator` identity. FRIDAY service identity is an optional allowlisted header, not bound to a distinct credential; nonce/timestamp checks accept both fields being absent. FRIDAY-specific key behavior is prefix/rate-limit logic around the same single configured API key, not a separate `SENTINEL_FRIDAY_API_KEY` credential.

### S10 — Resource guardrails have gaps

[FACT — baseline resource issues, mitigated in follow-up] At initial review, scanner `ports` input was unbounded and its Python fallback gathered one coroutine per port; the scanner now caps each request at 256 validated ports and the fallback at 32 shared socket checks per adapter instance. The former `communicate()` buffering risk in both `SubprocessSandbox` and `SafeProcessRunner` is also fixed: a shared async reader retains only each configured stdout/stderr prefix while draining both pipes. Cancellation/timeouts reap the direct child; POSIX sends termination signals to its dedicated process group. The standalone runner retains its one-second SIGTERM grace before SIGKILL when the process remains alive. Descendant-tree cleanup is not separately verified. These limits bound retained parent-side output, not the child’s own memory/CPU or aggregate work across processes. Remaining resource concerns include the active sandbox’s inherited environment/no `CommandPolicy`, unbounded EventBus SSE queues, per-key/IP limiter state retaining inactive identities, and audit append cost growing with the ledger.

[FACT] Local artifact storage normalizes only leading slashes and does not reject `..`; current evidence keys are generated internally from task/evidence identifiers, so the reviewed public API does not supply an arbitrary storage key. Treat as defense-in-depth hardening, not a demonstrated remote exploit.

### S11 — Readiness and durability signals are partly configuration-only

[FACT] `/api/v1/health/ready` calls `FailClosedHealth.check` with `persistence_ok=False` unconditionally, so it returns 503 even if the selected backend is PostgreSQL. `/ready` treats any non-empty backend string as configured and, in production, marks durability based on the string `postgres` without a database health query. `/health` is process liveness, returns 200 with a missing/vacuously valid audit ledger, and reports the entry count separately. MinIO initialization errors silently select local artifacts.

## Security checklist sweep

- Python: no direct use of `eval`, `exec`, `os.system`, or `shell=True` was found in executable project code during the scan. SQLAlchemy uses ORM/parameterized selects. Both subprocess runners use argv and shared bounded streaming capture; the active scanner sandbox still inherits the environment and is not configured with `CommandPolicy`. The configured output cap is per stream and does not constrain a child’s own memory/CPU; the POSIX `killpg` path was exercised on a local child, but descendant-tree behavior and Windows descendant cleanup were not separately verified. Multiple `verify=False` HTTP clients, optional external data forwarding, user-asserted authorization/operator identity, process-local abuse controls, unbounded queues, and remaining evidence/audit integrity gaps require attention. Scanner port count and Python-fallback socket concurrency are also bounded (post-baseline note above).
- TypeScript: no `dangerouslySetInnerHTML`, `innerHTML`, `eval`, or `localStorage` use was found in the dashboard scan. React renders normal escaped text. API key is held in `sessionStorage` (same-origin script-accessible); an XSS compromise would expose it. API errors are truncated before display; user values remain in ordinary React inputs. No external browser call to localhost is in the default client; API URLs are same-origin unless `VITE_API_URL` is set.

## Triage confidence

High for implementation gaps and route wiring, medium for exploitability and severity because deployment identity/network topology and third-party consent policy are not specified. None of these findings was exploited against a live service. The findings below describe the source baseline before follow-up fixes; current deltas are recorded separately.

## Post-baseline remediation status (2026-10-07)

- **S1 — FRIDAY synthetic scope (fixed at the ingress):** `/friday/delegate` now rejects missing or partial scope, refuses to synthesize owner/reference/window/methods/impact/rate, treats `policy_context` as advisory, and maps `assessment` to `TaskMode.ASSESSMENT`. Only `passive_recon`, `assessment`, `authorized_assessment` and the legacy `active` alias are accepted. Focused tests reject no/partial scope and unsupported `forensics`; docs and `contracts/friday_delegation.schema.json` now describe the explicit-scope contract (`sentinel/apps/api/main.py:623-722`; `tests/security/test_friday_explicit_scope.py:30-84`; `docs/friday-integration.md:9-46`). **Not fixed:** the owner/reference remain caller claims; no external ticket/identity authority verifies them (S2 remains).
- **S3 — audit metadata (partially fixed):** integrity v2 includes `seq`, timestamp, tenant, action ID and integrity version in the signed payload and enforces v2 sequence continuity. Existing v1 rows remain verifiable/extendable with their original weaker coverage. Mutation tests now reject changed v2 sequence/time/tenant/action fields (`sentinel/audit/audit_logger.py:20-30, 100-150, 190-275`; `tests/security/test_audit_fail_closed.py:76-141`). **Not fixed:** deleting the ledger or truncating it at a still-valid prefix is not detectable without an external trusted head/checkpoint; v1 rows still lack v2 metadata authentication; file rotation/retention and multi-process locking are not added.
- **S4 — evidence manifest (fixed for v2, legacy caveat):** newly exported ZIP bundles use a canonical manifest hash and an HMAC signature from the configured audit key; verification checks the checksum, signature, record count, safe artifact paths, sizes and raw-artifact SHA-256. Tests reject artifact mutation and a manifest whose public checksum was recomputed without the HMAC key (`sentinel/storage/evidence/store.py:227-376`; `tests/unit/test_audit_remediations.py:120-190`). Legacy v1 ZIPs are still accepted after checksum verification but report `signature_verified=false`; an unkeyed v1 checksum cannot prove authenticity.
- **Dashboard/task wiring:** the API form now supplies required caller scope and displays 4xx detail; the local API-to-report exercise validates one scoped task path. This does not establish browser acceptance or an external authorization system.

[FACT] S2, S5-S11 remain open unless specifically superseded above. The scanner port-count/Python-fallback concurrency item in S10 is now partially mitigated; this does not add tenant identity, distributed task leases/cancellation, TLS verification, standalone research/inference consent enforcement, Nmap internals/load characterization, external audit anchoring, or production deployment validation. No live system was probed.

## Continued red-team-style regression pass (2026-10-07; local only)

[FACT] API cancellation edge tests reproduced a false success message after completion, duplicate `POST /tasks/{task_id}/cancel` registration, and uncaught missing-task errors on FRIDAY/Sentinel aliases. The message now reflects actual terminal/cancelled status, the duplicate route was removed, and aliases return 404. Tests also verify in-flight worker cancellation, task persistence, and local job-handle cleanup (`sentinel/apps/api/main.py:369-395,1088-1097`; `tests/integration/test_task_submission_e2e.py:173-292`).

[FACT] The local evidence artifact path issue was reproduced as seven red cases covering traversal, absolute paths, Windows path spellings and symlink escapes. Local storage now normalizes both separator styles, rejects unsafe components/drives, and checks `realpath` containment. Regression coverage runs each invalid key through store, read, exists and delete plus symlink tests (`sentinel/storage/artifacts/storage.py:48-76`; `tests/security/test_artifact_storage_paths.py:8-52`). **[HYPOTHESIS]** A concurrent filesystem race replacing symlinks after validation was not eliminated or tested.

[FACT] The loopback agent task now verifies its missing-header finding is low severity, has remediation, references evidence owned by the task, and appears in the report. This proves one controlled observation path, not detection accuracy across real systems. No public targets or external services were used.

[FACT] The scanner's formerly unbounded port parameter now rejects malformed/empty/out-of-range/over-256 requests and deduplicates repeats. Python fallback uses a 32-slot semaphore shared across concurrent scans on the same adapter instance. The red-first test observed peak fake concurrency of 32 before the fix and a cap of 3 afterwards; the full suite now passes 352 tests (`sentinel/integrations/scanners/network_adapter.py:18-127`; `tests/unit/test_network_scanner_bounds.py:24-107`). This is a guardrail/regression result, not an Nmap or multi-process load test.
