# SENTINEL — Autonomous Cybersecurity Platform

> **AUTHORIZED USE ONLY.** SENTINEL is designed exclusively for authorized security assessments on systems you own or have explicit written permission to test. Unauthorized use is illegal and unethical. All actions are audited.

---

## Quickstart (< 10 commands)

```bash
git clone https://github.com/surendra2304/Sentinel.git && cd Sentinel
cp .env.example .env          # Set DB/S3 passwords and a unique SENTINEL_AUDIT_SIGNING_KEY
docker compose up -d          # Starts: API (8000), Dashboard (3000), PostgreSQL, MinIO
docker compose ps             # Verify all services healthy
pip install -e ".[dev]"
sentinel task submit --objective "Passive recon" --target example.com --mode passive_recon --authorization-reference CHG-1234 --authorized-by operator@example.com
sentinel task list
sentinel report TASK_ID
# Dashboard: http://localhost:3000
```

Task submission requires an explicit owner, written authorization reference, target scope, impact ceiling, and bounded time window. The CLI builds a limited scope for the specified targets; it sends remote requests only when both `SENTINEL_API_URL` and `SENTINEL_API_KEY` are explicitly configured. Production Compose requires a unique API key and enables API-key authentication. Third-party OSINT enrichment is disabled by default; opt in with `--allow-third-party-enrichment` only when the task authorization permits target metadata to be shared with external enrichment services. GeoIP lookup is limited to globally routable IP addresses.


---

## Feature Overview

| Capability | Description |
|---|---|
| **10 Security Domains** | Recon/DNS, Network, Web, API, Device/Mobile, Cloud, Vulnerability, Threat Intel, DFIR, Compliance |
| **Autonomous Orchestrator** | Bounded multi-phase investigations, specialist routing, and evidence-backed policy-checked handoffs |
| **Governed Autonomy** | PolicyEngine + ScopeResolver on every action; approval workflow for elevated-impact operations |
| **Evidence Chain** | SHA-256 cryptographic artifacts; all findings anchored to raw evidence; audit-trail HMAC-signed |
| **4 Report Types** | Executive, Technical Pentest, SOC/IR, Machine JSON — each with evidence manifest |
| **FRIDAY Integration** | Typed delegation contract; SENTINEL secures, FRIDAY orchestrates, AI Universe reasons |
| **Intelligence Layer** | Model-agnostic IntelligenceProvider (HeuristicProvider offline, LLMProvider for OpenAI-compatible APIs) |
| **Security Operations** | Scheduled assessments, continuous monitoring, baseline diffs, alert deduplication |
| **Web Dashboard** | React 18 + TypeScript + Vite — real-time task progress, finding explorer, attack graph |
| **CLI + REST API** | Full programmatic access; same task/result model for all interfaces |

> **Current autonomy boundary:** The heuristic planner routes web/network phases to registered specialists, and the coordinator can accept bounded, evidence-backed follow-up proposals through the normal policy/approval path. Versioned checkpoints and conservative restart recovery are implemented. This remains sequential, single-process orchestration—not distributed agent collaboration, peer review/consensus, general self-healing, or production-certified autonomy. Ambiguous in-flight actions fail closed. See [`GAPS.md`](GAPS.md) and [`AUDIT_REPORT.md`](AUDIT_REPORT.md).

---

## Architecture Summary


FRIDAY (orchestrator)
    │  Delegation contract  (POST /api/v1/friday/delegate)
    ▼
┌─────────────────────────────────────────────────────────┐
│  SENTINEL                                               │
│  ┌──────────────┐  ┌─────────────┐  ┌───────────────┐  │
│  │  Task Gateway│  │PolicyEngine │  │ ScopeResolver │  │
│  └──────┬───────┘  └──────┬──────┘  └───────┬───────┘  │
│         │                 │                  │           │
│  ┌──────▼──────────────────▼──────────────────▼──────┐  │
│  │  AutonomousOrchestrator + HeuristicPlanner/LLM   │  │
│  └────────────────────┬──────────────────────────────┘  │
│    per-step:          │                                  │
│  ┌────────────────────▼─────────────────────────────┐   │
│  │  SecurityModules (10 domains × N adapters each)  │   │
│  └────────────────────┬─────────────────────────────┘   │
│                       │ evidence artifacts               │
│  ┌────────────────────▼─────────────────────────────┐   │
│  │  EvidenceStore (SHA-256) → FindingEngine          │   │
│  │  → RiskEngine → CrossDomainIntelligence           │   │
│  │  → AttackPathAnalyzer → ReportGenerator           │   │
│  └──────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
             │ IntelligenceRouter
             ├── HeuristicProvider (offline, default)
             └── LLMProvider (OpenAI-compatible, optional)


---

## Security Notice

- **Authorized assessments only.** SENTINEL enforces scope validation and mode-gated policies.
- **Evidence-First architecture.** No finding is published without a raw cryptographic evidence reference.
- **All actions audited.** HMAC-signed audit trail records every decision: authorized/denied/executed/result.
- **Secrets discipline.** No credentials, API keys, or secrets are logged, serialized to evidence, or included in reports.
- **Non-destructive by default.** Validation actions require explicit authorization and impact-level approval.

---

## Documentation

| Document | Description |
|---|---|
| [Architecture](docs/architecture.md) | Component diagrams and data flows |
| [Module Development](docs/module-development.md) | How to add new modules/adapters |
| [Contracts](docs/contracts.md) | All versioned schema documentation |
| [Authorization & Policy](docs/authorization-and-policy.md) | Scope, policy, approval, audit models |
| [Deployment](docs/deployment.md) | Docker Compose, env config, secrets |
| [FRIDAY Integration](docs/friday-integration.md) | Delegation contract, governance boundary |
| [Intelligence Providers](docs/intelligence-providers.md) | AI provider interface and configuration |

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All PRs must pass: `ruff check .`, `mypy sentinel`, `pytest`, and `python verify_diary.py`.