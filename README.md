# 🛡️ SENTINEL — Unified Autonomous Cybersecurity Platform

> **"FRIDAY asks, SENTINEL secures, AI Universe reasons."**

SENTINEL is an independent, production-grade, modular cybersecurity platform covering the full lifecycle of modern offensive and defensive operations: reconnaissance, network auditing, wireless, web & API security, mobile, endpoint forensics, cloud posture, vulnerability intelligence, incident response, and security operations.

Unlike simple scanner wrappers, SENTINEL is an autonomous intelligence platform built around a unified target model, typed execution engine, cryptographic evidence store, policy engine, AI planner, and automated reporting pipeline.

---

## 🏛️ Layered Architecture

```
                  ┌────────────────────────────────────────────────────────┐
                  │                   Task Gateway (API / CLI)             │
                  └───────────────────────────┬────────────────────────────┘
                                              │
                                              ▼
                  ┌────────────────────────────────────────────────────────┐
                  │               AI Planner & Orchestrator                │
                  └───────────────────────────┬────────────────────────────┘
                                              │
                                              ▼
                  ┌────────────────────────────────────────────────────────┐
                  │              Scope & Policy Engine (Guardrails)        │
                  │  • Target Allow/Exclusions   • Approval Gates          │
                  │  • Rate & Intensity Limits   • Kill Switch Active      │
                  └───────────────────────────┬────────────────────────────┘
                                              │
                                              ▼
                  ┌────────────────────────────────────────────────────────┐
                  │             Execution & Tool Adapters Layer            │
                  │  • Nmap, Nuclei, ZAP, OpenVAS, Cloud/K8s/Endpoint      │
                  └───────────────────────────┬────────────────────────────┘
                                              │
                                              ▼
                  ┌────────────────────────────────────────────────────────┐
                  │             Evidence Store & Finding Pipeline          │
                  │  • SHA-256 Hashes  • Raw Artifacts  • Tamper Audit Log │
                  └───────────────────────────┬────────────────────────────┘
                                              │
                                              ▼
                  ┌────────────────────────────────────────────────────────┐
                  │             Reports, Threat Intel & Event Bus          │
                  └────────────────────────────────────────────────────────┘
```

---

## 🔑 Core Design Principles

1. **Evidence-First**: Every finding must trace back to raw artifacts, timestamps, source tool, target asset, and cryptographic integrity hashes.
2. **Governable Autonomy**: The AI planner dynamically chooses subsequent discovery steps, but **every single action** is a typed `ActionRequest` passing through the Scope & Policy Engine (allowlists, intensity gates, kill-switch, operator approval gates). Offensive capability exists only for owned and verified assets.
3. **Breadth Without Fragmentation**: A single common abstraction (`Task`, `Target`, `Scope`, `Action`, `Evidence`, `Finding`, `Risk`, `Agent`, `ToolAdapter`, `Policy`) with pluggable domain modules.
4. **Model-Agnostic Intelligence**: All reasoning leverages modular `IntelligenceProvider` interfaces without hard-coding any specific LLM provider.
5. **Standalone-First**: Fully functional standalone platform that natively interfaces with **FRIDAY** (agent delegation) and **AI Universe** (routing & reasoning layer).

---

## 📦 Directory Structure

```
sentinel/
├── apps/                 # Application Entry Points
│   ├── api/              # FastAPI Task Gateway & REST API
│   ├── dashboard/        # Web Dashboard & Visualizer
│   └── cli/              # Typer-powered CLI utility
├── core/                 # Execution & Governance Engine
│   ├── orchestrator/     # Task orchestration & tool coordinator
│   ├── agents/           # Domain agents (Recon, Web, Cloud, IR)
│   ├── planner/          # Model-agnostic AI planning & step selection
│   ├── policy/           # Scope boundaries & authorization rules
│   ├── scope/            # Subnet/domain allowlist matchers
│   ├── events/           # Asynchronous internal event bus
│   └── memory/           # Agent context memory & state
├── modules/              # Pluggable Domain Modules
│   ├── recon/            # Passive & active asset discovery
│   ├── dns/              # Subdomain, DNSSEC, zone auditing
│   ├── network/          # Port scanning, service fingerprinting
│   ├── wireless/         # 802.11, rogue AP, signal auditing
│   ├── web/              # Web app security, dynamic crawling
│   ├── api_security/     # REST/GraphQL/gRPC schema & auth audit
│   ├── mobile/           # iOS/Android static & dynamic analysis
│   ├── endpoint/         # Process inspection & host telemetry
│   ├── cloud/            # CSPM, IAM & Kubernetes security
│   ├── vulnerability/    # CVE intelligence & exploitability checks
│   ├── forensics/        # Artifact extraction & memory analysis
│   ├── threat_intel/     # MITRE ATT&CK & IOC correlation
│   └── incident_response/# Containment playbooks & triage
├── integrations/         # Tool Adapters & Connectors
│   ├── scanners/         # Nmap, Nuclei, ZAP, OpenVAS, Masscan
│   ├── browsers/         # Headless browser automation
│   ├── threat_feeds/     # MISP, AlienVault, OSINT feeds
│   └── external_apis/    # Shodan, Censys, SecurityTrails
├── intelligence/         # Correlation & Risk Modeling
│   ├── correlation/      # Multi-source deduplication & fusion
│   ├── attack_paths/     # Graph-based path modeling
│   ├── risk/             # Contextual CVSS & EPSS calculations
│   └── recommendations/  # Actionable remediation playbooks
├── storage/              # Persistence Layer
│   ├── database/         # PostgreSQL async models & migrations
│   ├── evidence/         # Cryptographically hashed evidence store
│   └── artifacts/        # MinIO/S3 object storage adapter
├── contracts/            # Typed Data Contracts & JSON Schemas
│   └── schemas/          # Task, Action, Evidence, Finding, Risk
├── audit/                # Append-only Tamper-Evident Audit Trail
└── config/               # Typed Pydantic Settings
```

---

## 🚀 Quick Start

### 1. Run with Docker Compose
```bash
docker compose up -d
```
Services started:
- **API Gateway**: `http://localhost:8000/api/v1/docs`
- **PostgreSQL**: `localhost:5432` (`sentinel_db`)
- **MinIO S3**: `http://localhost:9001` (Console) / `http://localhost:9000` (API)

### 2. Local CLI Usage
```bash
# View system status and module matrix
python -m sentinel.apps.cli.main status

# Verify tamper-evident audit log integrity
python -m sentinel.apps.cli.main verify-audit
```

---

## 📖 Engineering Diary
Sentinel enforces strict daily engineering logs:
- 📑 [Master Engineering Diary](SENTINEL_DIARY.md)
- 📁 [Daily Logs Directory](diary/)
