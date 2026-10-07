# Authorization and Policy Model

SENTINEL requires an explicit authorization contract for every submitted task. A target appearing in a request is not, by itself, evidence of permission. The owner, written authorization reference, target boundaries, permitted methods, impact ceiling, and active time window are validated before a task is accepted.

## Scope contract

A task request includes a `scope` object similar to:

```json
{
  "owner": "security-operator@example.org",
  "written_authorization_reference": "CHG-2026-1234",
  "allowed_targets": ["app.example.org", "192.0.2.10/32"],
  "excluded_targets": ["admin.example.org"],
  "allowed_methods": ["passive_recon"],
  "time_window": {
    "start_time": "2026-10-05T09:00:00Z",
    "end_time": "2026-10-05T17:00:00Z"
  },
  "rate_limit": 20,
  "maximum_impact": "low",
  "offensive_actions_enabled": false,
  "authorization": {
    "allow_third_party_enrichment": false
  }
}
```

The API validates the submitted targets against the scope. The policy engine repeats target and method checks for every planned action, so a task-level scope does not authorize an out-of-scope action or target.

## Third-party enrichment consent

Some optional passive enrichment sources receive target metadata. SENTINEL therefore defaults `authorization.allow_third_party_enrichment` to `false`:

- Certificate Transparency queries to `crt.sh` are not made unless the scope explicitly allows third-party enrichment.
- GeoIP requests to IP-API are not made unless the scope allows enrichment and the target is a globally routable IP address. Hostnames, private addresses, loopback, link-local, and other non-global addresses are not sent to that service.
- The CLI flag `--allow-third-party-enrichment` sets this explicit authorization field. Use it only when the engagement permits sharing target metadata with external services.

A policy decision denies an action that requests third-party enrichment when the task scope does not grant it. The adapter also defaults to skipping the external request, providing a second guard at the egress point.

## Action policy checks

Before an action executes, the policy engine evaluates the kill switch, time window, impact ceiling, passive-mode restrictions, target containment, policy action/module allowlists, scope-allowed methods, intensity and rate limits, credential rules, and approval requirements. A denied action is recorded in the audit trail and is not executed.

Passive reconnaissance is deliberately limited to the action allowlist in the policy engine. Mixed-mode adapters receive an explicit `passive_only` parameter; passive mode does not authorize active HTTP or port probing. Higher-impact or offensive actions remain subject to the explicit scope settings and configured human-approval gates.

## Audit trail

Task and action decisions are recorded by `AuditLogger`. Production requires a deployment-specific `SENTINEL_AUDIT_SIGNING_KEY`; there is no source-controlled signing-key fallback. Verify the local chain with:

```bash
sentinel verify-audit
```

Audit durability depends on the configured storage and mounted volume. Production readiness reports an in-memory backend as non-durable rather than claiming persistent protection.

## Authorization is not a blanket guarantee

Third-party services, network access, scanner binaries, and external credentials are deployment-dependent. Review [GAPS.md](../GAPS.md) and the deployment configuration before using Sentinel on any environment. Only assess assets covered by current written authorization.
