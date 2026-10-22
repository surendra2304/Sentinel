# 🛡️ SENTINEL — Scope & Policy Governance Model

> **Governable Autonomy**: In SENTINEL, every executable action in the entire platform passes through the **ScopeResolver** and **PolicyEngine** before execution.

---

## 🏛️ Policy Dimensions

Every `ActionRequest` is systematically evaluated across six safety dimensions:

| Dimension | Rule & Verification Standard | Failure Behavior |
| :--- | :--- | :--- |
| **1. Kill Switch** | Checks task-level and global kill switches. | Immediate `DENY` — halts all running actions. |
| **2. Target Scope** | Evaluated via `ScopeResolver`. Validates against allowed subnets, wildcard domains (`*.example.com`), URL paths, and ports. | `DENY` — strictly forbids out-of-bounds scanning. |
| **3. Module / Action Classes** | Validates `action_type` against `allowed_action_classes` and `allowed_module_classes`. | `DENY` (Deny-by-default for unlisted actions). |
| **4. Rate & Intensity** | Enforces sliding-window rate limits (actions/min) and tool intensity constraints (1–10). | `DENY` with rate-limit / intensity breach message. |
| **5. Credential Boundaries** | Enforces redaction rules and restricts unauthorized stored credential usage. | `DENY` + redacts passwords/tokens in audit trail. |
| **6. Human Approval Gates** | Gating for high/critical impact, offensive payloads, or explicit approval flags. | `REQUIRE_APPROVAL` — triggers pending approval record. |

---

## 🔍 Scope Resolution & Adversarial Defense

The `ScopeResolver` handles normalization and robust boundary matching:
- **Wildcard Subdomains**: `*.target.com` matches `sub.target.com` but **never** matches the apex domain `target.com` (unless explicit) or `nottarget.com`.
- **CIDR Containment**: Evaluates IPv4/IPv6 address and subnet membership (e.g. `10.0.0.15` in `10.0.0.0/24`).
- **URL Path Scoping**: Enforces path prefixes and port matching (e.g. `https://target.corp:8443/api/v1`).
- **Target Smuggling & IDN Defenses**: Rejects ambiguous inputs, query string domain trickery (`evil.com?.target.com`), and punycode/IDN spoofing.

---

## ✍️ Human Approval Workflow

When an action requires human approval:
1. `PolicyEngine` generates an `ApprovalRecord` with a 24-hour expiration window.
2. Emits an asynchronous event `action.approval_requested`.
3. Operators can inspect and approve/deny via API or CLI:
   ```bash
   # CLI approval list & decide
   sentinel approval list
   sentinel approval decide <approval_id> --approve --operator "lead_sec_officer" --justification "Approved for pentest"
   ```
4. On decision, an `action.approved` or `action.denied` event is broadcast and logged to the tamper-evident audit trail.

---

## 🔒 Tamper-Evident Audit Logging

Every evaluation decision (`ALLOW`, `DENY`, `REQUIRE_APPROVAL`) generates an immutable entry in the SHA-256 HMAC-signed audit log recording:
- `entry_id` & `timestamp`
- `actor` & `target`
- `action_type` & `scope_policy`
- `decision` & `reason`
- Redacted parameters (passwords, tokens, private keys replaced with `[REDACTED]`)
