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

## 💻 CLI & API Usage Examples

### 1. Command Line Interface (Typer CLI)
```bash
# View platform status and module matrix
python -m sentinel.apps.cli.main status

# Verify cryptographic integrity of the audit hash chain
python -m sentinel.apps.cli.main verify-audit

# Submit a security task (Domain or IP Target)
python -m sentinel.apps.cli.main task submit --objective "Audit perimeter web application" --target "api.sentinel.security" --mode assessment

# Check task status and progress
python -m sentinel.apps.cli.main task status <task_id>

# Immediate Kill-Switch cancellation
python -m sentinel.apps.cli.main task cancel <task_id> --reason "Operator manual halt"

# View task findings & generated report
python -m sentinel.apps.cli.main task findings <task_id>
python -m sentinel.apps.cli.main report <task_id>
```

### 2. Task Gateway REST API (FastAPI)
```bash
# 1. Health and Readiness probes
curl http://localhost:8000/health
curl http://localhost:8000/ready

# 2. Submit Security Task
curl -X POST http://localhost:8000/api/v1/tasks \
  -H "Content-Type: application/json" \
  -d '{
    "objective": "Scan internal subnet for exposed management ports",
    "targets": [{"type": "cidr", "value": "10.0.0.0/24"}],
    "mode": "passive_recon",
    "requested_output": "comprehensive_report"
  }'

# 3. Stream Live Task Events via SSE
curl -N http://localhost:8000/api/v1/tasks/<task_id>/events

# 4. Immediate Task Kill-Switch
curl -X POST "http://localhost:8000/api/v1/tasks/<task_id>/cancel?reason=OperatorEmergencyHalt"
```

---

## 📦 Directory Structure

```
sentinel/
├── apps/                 # Application Entry Points
│   ├── api/              # FastAPI Task Gateway & REST API
│   ├── dashboard/        # Web Dashboard & Visualizer
│   └── cli/              # Typer-powered CLI utility
├── core/                 # Execution & Governance Engine
│   ├── orchestrator/     # Task lifecycle manager & tool coordinator
│   ├── agents/           # Domain agents (Recon, Web, Cloud, IR)
│   ├── planner/          # Model-agnostic AI planning & step selection
│   ├── policy/           # Scope boundaries & authorization rules
│   ├── scope/            # Subnet/domain allowlist matchers
│   ├── events/           # Asynchronous internal event bus (Pub/Sub)
│   └── memory/           # Agent context memory & state
├── modules/              # Pluggable Domain Modules (13 total)
├── integrations/         # Tool Adapters & Connectors
├── intelligence/         # Correlation & Risk Modeling
├── storage/              # Persistence Layer (SQLAlchemy 2.0 + MinIO)
├── contracts/            # Typed Data Contracts & JSON Schemas (v1.0.0)
├── audit/                # Append-only Tamper-Evident Audit Trail
└── config/               # Typed Pydantic Settings
```

---

## 📖 Engineering Diary
Sentinel enforces strict daily engineering logs:
- 📑 [Master Engineering Diary](SENTINEL_DIARY.md)
- 📁 [Daily Logs Directory](diary/)
