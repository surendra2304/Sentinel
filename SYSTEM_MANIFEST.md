# 🏛️ SYSTEM MANIFEST — Sentinel Cybersecurity & Cryptographic Gatekeeper

> **Official Subsystem Name:** Sentinel  
> **Role in Ecosystem:** Autonomous Security Watchdog, Cryptographic Signing Gatekeeper (HMAC-SHA256 & ECDSA), and Tamper-Detection Specialist  
> **Repository:** [surendra2304/Sentinel](https://github.com/surendra2304/Sentinel) (Branch: main)  
> **Workspace Path:** d:\FRIDAY Universe\Sentinel  

---

## ☁️ 1. Production Topology & Deployment Ground Truth

| Attribute | Modernized Production Infrastructure |
| :--- | :--- |
| **Host Environment** | Oracle Cloud Always Free (2 OCPUs, 12 GB RAM Ampere A1 ARM64 / AMD x86_64 host) |
| **Container Network** | `friday_mesh` (unified private container mesh) |
| **Public Gateway Domain** | `https://friday-universe.duckdns.org` (automated HTTPS via Caddy reverse proxy) |
| **Public Gateway Route** | `https://friday-universe.duckdns.org/sentinel/*` |
| **Internal Container Port** | `8000` |
| **Host Port Mapping** | `8007` (`8007:8000`) |
| **Direct Mesh URL** | `http://sentinel:8000` |
| **Health Check Endpoint** | `http://localhost:8000/health` or `https://friday-universe.duckdns.org/sentinel/health` |
| **API Authentication Key** | `SENTINEL_API_KEY` |
| **Cryptographic Signing Keys** | `SENTINEL_AUDIT_SIGNING_KEY`, `SENTINEL_AUDIT_HMAC_KEY`, `SENTINEL_CAPABILITY_SIGNING_KEY` |
| **Central Ecosystem Gateway** | FRIDAY Core at `http://friday:10000` |

---

## 🎯 2. Purpose & Responsibilities

### What Sentinel IS:
* The ecosystem-wide cybersecurity watchdog and cryptographic signing gatekeeper.
* Cryptographic signature authority providing HMAC-SHA256 and ECDSA signing, envelope verification, tamper-evident hash chaining, and scoped capability tokens.
* Real-time attack surface analyzer, CVE vulnerability scanner, and prompt injection defense shield.

### What Sentinel DOES:
* **Cryptographic Gatekeeping:** Signs inter-agent payloads and verifies cryptographic envelopes via `/sign` and `/verify`.
* **Tamper-Evident Ledger:** Maintains an append-only, SHA-256 HMAC-signed audit log ledger accessible via `/audit` and verified at `/health`.
* **Multi-Domain Intelligence:** Correlates vulnerability findings, recon graphs, and threat intelligence.
* **Bounded Autonomous Operations:** Enforces strict execution limits, policy gating, human approvals, and an instant kill-switch.

---

## 🌐 3. Ecosystem Endpoint Configuration (`friday_mesh`)

The 9 specialized agents communicate within the private Docker mesh `friday_mesh` with external ingress routed through Caddy:

```env
# ============================================================================== #
#               FRIDAY UNIVERSE MASTER ECOSYSTEM CONFIGURATION                  #
# ============================================================================== #

# 1. ⚡ Inference AI Multi-Model Gateway
INFERENCE_URL=http://inference:8000
INFERENCE_API_KEY=<configure in secret environment>

# 2. 🧠 Memora Cloud Persistent Memory
MEMORA_URL=http://memora:8000
MEMORA_API_KEY=<configure in secret environment>

# 3. 📈 Stratex Algorithmic Strategy Platform
STRATEX_URL=http://stratex:8000
STRATEX_API_KEY=<configure in secret environment>

# 4. 🧠 IntelX Evidence & Threat Intelligence
INTELX_URL=http://intelx:8000
INTELX_API_KEY=<configure in secret environment>

# 5. 🔮 Futuris Calibrated Predictive Forecasting
FUTURIS_URL=http://futuris:8000
FUTURIS_API_KEY=<configure in secret environment>

# 6. 🌐 Cortex Autonomous Web Operations & Intelligence
CORTEX_URL=http://cortex:8000
CORTEX_API_KEY=<configure in secret environment>

# 7. 🛠️ Forge Local Software Engineering Engine
FORGE_URL=http://forge:8000
FORGE_API_KEY=<configure in secret environment>

# 8. 🛡️ Sentinel Cybersecurity & Cryptographic Gatekeeper
SENTINEL_URL=http://sentinel:8000
SENTINEL_API_KEY=<configure in secret environment>
SENTINEL_AUDIT_SIGNING_KEY=<configure in secret environment>
SENTINEL_AUDIT_HMAC_KEY=<configure in secret environment>

# 9. 🤖 FRIDAY Central Desktop Operating System & Gateway
FRIDAY_URL=http://friday:10000
FRIDAY_API_KEY=<configure in secret environment>
```

---

## 🤖 4. Repository Guide

* **Identity:** You are working inside **Sentinel** (`d:\FRIDAY Universe\Sentinel`).
* **Deployment Target:** Oracle Cloud Always Free (`https://friday-universe.duckdns.org/sentinel/*`).
* **Authentication:** Incoming requests use `X-API-Key` or `Authorization: Bearer <SENTINEL_API_KEY>`.
* **Zero Trust & Tamper Evidence:** Every privileged action and signing request is recorded in the append-only HMAC audit chain.
