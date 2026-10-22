# FRIDAY Integration & Delegation Architecture

This document specifies the technical and governance contract between **FRIDAY** (the general-purpose assistant/orchestrator) and **SENTINEL** (the specialized autonomous cybersecurity execution engine).

---

## 1. Core Architectural Boundary

> [!IMPORTANT]
> **Governed Autonomy Rule**: SENTINEL enforces its **OWN** internal scope resolution, policy verification, rate limits, and approval gates on all delegated tasks regardless of caller authority.
> 
> The `policy_context` passed by FRIDAY is **advisory only**. It cannot create an authorization owner/reference, fill a time window, grant methods, or override Sentinel's scope allowlists. A complete caller-supplied `scope` is mandatory; missing or partial scope is rejected. The reference string is still a caller claim unless an external authorization authority is integrated.

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
  "scope": {
    "owner": "authorized asset owner",
    "written_authorization_reference": "SEC-ENG-901",
    "targets": ["staging-api.example.com"],
    "allowed_methods": ["discovery", "validation"],
    "time_window": {
      "start_time": "2030-01-01T09:00:00Z",
      "end_time": "2030-01-01T11:00:00Z"
    },
    "rate_limit": 25,
    "maximum_impact": "low",
    "authorization": { "allow_third_party_enrichment": false }
  },
  "policy_context": { "environment": "staging" }
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
