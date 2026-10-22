# SENTINEL PLATFORM LIMITATIONS AND ARCHITECTURAL GAPS (GAPS.md)

This document is the explicit **contract of honesty** for the Sentinel codebase. It enumerates all known hardware dependencies, software fallbacks, scaling thresholds, and unconfigured enterprise features.

---

## 1. External Security Tool Binaries & Pure-Python Fallbacks
- **Nmap, Nuclei, Amass, Trivy, Semgrep**:
  - The platform includes pure-Python network scanning, HTTP probing, and rule-based static analysis engines (`sentinel/integrations/scanners/`, `sentinel/modules/api_security/`, `sentinel/modules/web/`).
  - When external CLI binaries (`nmap`, `nuclei`, `amass`) are **not** present in the host `$PATH`, Sentinel operates in pure-Python degraded fallback mode. Full raw packet crafting (e.g. SYN stealth scanning, OS TCP/IP stack fingerprinting) is restricted to available Python socket primitives or mocked lab fixtures unless native root utilities are provisioned.

---

## 2. Wireless Hardware Driver & Kernel Interface Dependencies
- **802.11 Monitor Mode & RF Capture**:
  - `WirelessInventoryAdapter` and `WirelessTrafficAnalysisAdapter` rely on host CLI commands (`netsh wlan`, `iwlist`, `airport`) and raw PCAP readers (`dpkt`).
  - Active raw packet injection, WPA 4-way handshake cracking, and real-time deauthentication frame capture require physical Wi-Fi hardware adapters with monitor mode support (e.g., Atheros/Realtek chipsets with Linux `mac80211` / `aircrack-ng`). In virtualized or non-Linux testing environments, the module operates in interface-discovery or offline-PCAP analysis mode.

---

## 3. Cloud Provider Credentials & Live Multi-Account Role Assume
- **AWS / Azure / GCP Adapters**:
  - `AWSCloudAdapter`, `AzureCloudAdapter`, and `GCPCloudAdapter` enforce strict **READ-ONLY** posture assessment and credential scrubbing.
  - Automated dynamic cross-account STS AssumeRole chains and multi-tenant Azure Management Group traversal require pre-provisioned cloud credentials with appropriate IAM read permissions (`SecurityAudit` / `ViewOnlyAccess`). In offline or local test runs, assessments evaluate standardized JSON/YAML cloud inventory exports.

---

## 4. Single-Process Orchestration & Event Bus (Non-Distributed Mode)
- **Task Queue & Event Streaming**:
  - The runtime task engine currently runs via an in-memory `asyncio` event bus (`sentinel.core.events.bus`) and persistent database repositories (PostgreSQL / SQLite).
  - Distributed multi-worker fleets (e.g., Celery, Redis Streams, RabbitMQ) and multi-node leader election are not yet provisioned. A single Sentinel instance orchestrates tasks up to its local concurrency semaphore limit (`max_concurrent_actions`).

---

## 5. Dashboard Attack Surface Graph Scalability
- **Cytoscape / Canvas Graph Rendering**:
  - The Attack Surface visualization (`apps/dashboard/src/pages/AttackSurfacePage.tsx`) renders interactive topology graphs for enterprise assets, ports, and correlated findings.
  - In-browser DOM/Canvas graph layout performance is optimized for environments up to ~1,000 nodes and edges. Enterprise enterprise graphs exceeding 5,000+ assets require server-side clustering or WebGL-accelerated canvas renderers.

---

## 6. Authentication & SSO / OIDC Middleware
- **API Key & Bearer Token Authentication**:
  - The API Gateway enforces static API Key authentication via `APIKeyAuthMiddleware`.
  - Enterprise Single Sign-On (SSO) via SAML 2.0, Okta, Azure AD OIDC, or Keycloak OAuth2 is not configured out of the box and requires an external identity provider reverse proxy (e.g. Traefik, Kong, Cloudflare Access).

---

## 7. Distributed Rate Limiting & Sliding Windows
- **Local Sliding-Window Tracker**:
  - `PolicyEngine` enforces sliding-window requests-per-second (`rate_limit_rps`) using in-process millisecond timestamps.
  - API request admission has configurable per-process limits (`SENTINEL_MAX_HTTP_CONCURRENCY`, default 256, plus a separate health budget); the Uvicorn entrypoint applies the same normal-request cap and overload responses use HTTP 503. These controls are local to each process and do not form a shared global quota. A horizontally scaled deployment still needs a shared rate-limit/admission design (e.g., Redis token bucket) and real multi-worker testing.
- The existing `PolicyEngine` sliding-window rate limit is also in-process. In a horizontally scaled multi-container deployment, a global policy limit requires a shared Redis key-value store.

---

## 8. Supervised Multi-Agent Collaboration (Local and Sequential)
- `HeuristicPlanner` routes its web and network phases to the registered specialists. `AgentCoordinator` accepts only task-matched, capability-matched, in-scope proposals with task evidence, and suppresses duplicates/conflicting parameter variants under configured per-task budgets.
- Accepted follow-ups re-enter the normal policy/approval/executor path. Local tests exercise a recon-to-network handoff; this is not autonomous negotiation, peer-review/consensus, cross-process coordination, or a multi-node fleet. Behavior against live targets remains unverified.

---

## 9. Durable Memory and Conservative Recovery
- Versioned working-memory checkpoints and approval decisions persist through the task repository, with Alembic migrations `0003` and `0004`. Recovery resumes only valid checkpoint-safe tasks, leaves pending approvals paused, resumes finalized approval decisions only when the queued action matches, and fails closed on missing/corrupt checkpoints or ambiguous in-flight actions.
- SQLite/in-memory fixtures cover checkpoint rehydration and safe restart paths. Live PostgreSQL crash/restart, concurrent recovery, database/object-store outage, and multi-process lease behavior remain unverified. The configured Compose entrypoint currently uses one API worker.
- Executor retries and the heuristic intelligence fallback are bounded local resilience measures, not general self-healing or self-improving systems. Autonomous code modification is intentionally not enabled; future repair actions must remain narrowly scoped, reviewed, and auditable, with human approval where impact is ambiguous or destructive.

---

## 10. Production Validation Boundary
- Local tests, synthetic load, and loopback fixtures do not establish production readiness. The current workspace did not have Docker/Compose, Nginx, PostgreSQL, or MinIO executables, so the newly documented container topology remains **CONFIGURED-BUT-UNVERIFIED**.
- Live validation against a non-local security target requires explicit authorization and a controlled environment; no arbitrary external target should be scanned.