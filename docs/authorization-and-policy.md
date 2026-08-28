# Authorization & Policy Model

## Task Modes and Permissions

SENTINEL enforces a strict mode-based access model. Every task has a mode field that gates which action classes are available.

| Mode | Description | Active Testing | Destructive Actions |
|---|---|---|---|
| passive_recon | DNS, OSINT, passive fingerprinting only | No | No |
| ctive_recon | Port scans, HTTP probing, banner grabbing | Limited | No |
| uthorized_assessment | Full pentest scope including validation | Yes | No |
| incident_response | Forensics and IR — read-only on live systems | IR only | No |

---

## PolicyEngine Evaluation (6 Dimensions)

Every ActionRequest is evaluated against all six dimensions before execution:

1. **Scope validation** — ScopeResolver confirms the target is in the authorized target set (CIDR match, domain wildcard, URL path prefix)
2. **Mode check** — the action class must be permitted in the current task mode
3. **Action class authorization** — maps action types to required action classes (e.g., 
etwork.port_scan → ACTIVE_SCAN)
4. **Rate limiting** — per-target and per-module action rate limits enforced
5. **Credential verification** — actions requiring credentials (cloud, authenticated web) verify they are present
6. **Impact gate** — actions with ImpactLevel >= HIGH require an approval record before execution

**Default-deny principle:** any dimension failure results in immediate denial with an audit entry.

---

## Approval Workflow

For elevated-impact actions (ImpactLevel.HIGH or VERY_HIGH):

1. ExecutionEngine creates an ApprovalRecord with status PENDING_APPROVAL
2. SSE stream (GET /api/v1/tasks/{id}/stream) emits pproval_required event to the dashboard
3. Operator reviews and either approves or denies via POST /api/v1/approvals/{id}/approve|deny
4. AuditLogger records the decision with operator identity and timestamp
5. If approved, ExecutionEngine resumes execution; if denied, the action is recorded as SKIPPED

---

## Scope Model

json
{
  "targets": [
    {"type": "url", "value": "https://example.com"},
    {"type": "cidr", "value": "192.168.1.0/24"},
    {"type": "domain", "value": "*.example.com"},
    {"type": "ip", "value": "10.0.0.1"}
  ],
  "excluded_targets": ["10.0.0.50"],
  "wildcard_allowed": false
}


ScopeResolver rejects:
- IP addresses outside authorized CIDR ranges
- Domains not matching authorized domain patterns
- Any target that matches an exclusion entry
- Requests with IP smuggling (e.g., URL http://internal-host@external.com)

---

## Audit Model

All audit entries are stored in logs/audit.jsonl (configurable). Each entry contains:

| Field | Description |
|---|---|
| entry_id | UUID for the audit entry |
| event_type | ACTION_REQUESTED, ACTION_APPROVED, ACTION_DENIED, FINDING_CREATED, etc. |
| ctor | The agent or operator that initiated the action |
| 	arget | The target resource |
| ction_type | The specific action class |
| scope_policy | The task ID (links to scope + policy) |
| decision | APPROVED, DENIED, EXECUTED, SKIPPED, RECORDED |
| details | Structured dict with action-specific context |
| 	imestamp | ISO 8601 UTC |
| prev_hash | SHA-256 hash of the previous audit entry (HMAC chain) |

The HMAC chain allows independent verification: any tampering of historical entries breaks the chain.

---

## Authorization Requirements by Task Mode

| Action Class | passive_recon | active_recon | authorized_assessment | incident_response |
|---|---|---|---|---|
| DNS enumeration | ✅ | ✅ | ✅ | ✅ |
| OSINT | ✅ | ✅ | ✅ | ✅ |
| HTTP observation | ✅ | ✅ | ✅ | - |
| Port scanning | ❌ | ✅ | ✅ | - |
| Vulnerability probing | ❌ | ❌ | ✅ | - |
| Validation (proof-of-concept) | ❌ | ❌ | ✅ + approval | - |
| Cloud resource enumeration | ❌ | ✅ | ✅ | ✅ |
| Log/artifact collection | ❌ | ❌ | - | ✅ |
| Forensic timeline | ❌ | ❌ | - | ✅ |