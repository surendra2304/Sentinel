# FRIDAY Integration & Delegation Architecture

This document specifies the technical and governance contract between **FRIDAY** (the general-purpose assistant/orchestrator) and **SENTINEL** (the specialized autonomous cybersecurity execution engine).

---

## 1. Core Architectural Boundary

> [!IMPORTANT]
> **Governed Autonomy Rule**: SENTINEL enforces its **OWN** internal scope resolution, policy verification, rate limits, and approval gates on all delegated tasks regardless of caller authority.
> 
> The `policy_context` passed by FRIDAY serves as **advisory input** (environment declarations, reference tickets), but **CANNOT** override Sentinel's zero-tolerance safety guardrails, kill-switch boundaries, or scope allowlists.

---

## 2. Delegation Endpoints

### 2.1 Submit Delegation
```http
POST /api/v1/friday/delegate
Content-Type: application/json
X-API-Key: <sentinel-api-key>

{
  "capability": "sentinel.security_assessment",
  "objective": "Assess staging API endpoint security and exposure",
  "targets": [
    { "type": "domain", "value": "staging-api.example.com" }
  ],
  "mode": "authorized_assessment",
  "requested_output": "technical_and_executive",
  "policy_context": {
    "environment": "staging",
    "authorization_reference": "SEC-ENG-901"
  }
}
```

### 2.2 Get Delegation Result & Summary
```http
GET /api/v1/friday/delegations/{delegation_id}
```
Returns a structured payload conforming to `contracts/friday_result.schema.json`, including:
- **`task_status`** and live progress percentage.
- **`findings`** with cryptographic evidence references.
- **`blocked_actions`** explaining what Sentinel refused to run and why.
- **`human_summary`** formatted deterministically for the user assistant without LLM dependencies.

### 2.3 Cancel Delegation (Kill Switch)
```http
POST /api/v1/friday/delegations/{delegation_id}/cancel?reason=OperatorHalt
```
