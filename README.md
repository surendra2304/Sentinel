# SENTINEL — Autonomous Cybersecurity Platform

> **AUTHORIZED USE ONLY.** SENTINEL is designed exclusively for authorized security assessments on systems you own or have explicit written permission to test. Unauthorized use is illegal and unethical. All actions are audited.

---

## Quickstart (< 10 commands)

ash
git clone https://github.com/surendra2304/Sentinel.git && cd Sentinel
cp .env.example .env          # Edit SENTINEL_DB_PASSWORD, SENTINEL_API_KEY, etc.
docker compose up -d          # Starts: API (8000), Dashboard (3000), PostgreSQL, MinIO
docker compose ps             # Verify all services healthy
# CLI (local dev)
pip install -e ".[dev]"
sentinel task submit --target https://example.com --mode passive_recon
sentinel task list
sentinel report generate --task-id TASK_ID --type executive
# Dashboard: http://localhost:3000


---

## Feature Overview

| Capability | Description |
|---|---|
| **10 Security Domains** | Recon/DNS, Network, Web, API, Device/Mobile, Cloud, Vulnerability, Threat Intel, DFIR, Compliance |
| **Autonomous Orchestrator** | HeuristicPlanner/LLMPlanner drives multi-phase investigations; evidence-first quality gate |
| **Governed Autonomy** | PolicyEngine + ScopeResolver on every action; approval workflow for elevated-impact operations |
| **Evidence Chain** | SHA-256 cryptographic artifacts; all findings anchored to raw evidence; audit-trail HMAC-signed |
| **4 Report Types** | Executive, Technical Pentest, SOC/IR, Machine JSON — each with evidence manifest |
| **FRIDAY Integration** | Typed delegation contract; SENTINEL secures, FRIDAY orchestrates, AI Universe reasons |
| **Intelligence Layer** | Model-agnostic IntelligenceProvider (HeuristicProvider offline, LLMProvider for OpenAI-compatible APIs) |
| **Security Operations** | Scheduled assessments, continuous monitoring, baseline diffs, alert deduplication |
| **Web Dashboard** | React 18 + TypeScript + Vite — real-time task progress, finding explorer, attack graph |
| **CLI + REST API** | Full programmatic access; same task/result model for all interfaces |

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

See [CONTRIBUTING.md](CONTRIBUTING.md). All PRs must pass: uff check . && mypy sentinel && pytest && python verify_diary.py.