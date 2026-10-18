# VyralX YouTube Publish Policy

Sentinel exposes a dedicated endpoint for VyralX's pre-upload policy check:

- **Path:** `POST /api/v1/vyralx/publish-policy`
- **Authentication:** the configured Sentinel API key in `X-API-Key` or `Authorization: Bearer`, plus `X-Agent-Name: vyralx`. The endpoint enforces authentication even if the general API-auth toggle is off.
- **Response:** `allowed` and `decision` (`allow` or `deny`) with a bounded reason. A denial is an ordinary JSON policy result; transport/auth errors are non-2xx. VyralX must fail closed for either.
- **Audit:** decisions are appended to Sentinel's signed audit chain. If auditing fails, an otherwise allowed decision is downgraded to deny.

Request body:

```json
{
  "action": "youtube.publish",
  "job_id": 41,
  "asset_id": 17,
  "title": "How solar panels work",
  "privacy_status": "private",
  "scheduled_at": "",
  "operator_review_acknowledged": true,
  "rights_verified": true
}
```

The `rights_verified` and `operator_review_acknowledged` fields are assertions made by the authenticated VyralX service, after its own source-evidence checks and review flow; Sentinel does not independently fetch the media's licenses or reproduce a human operator's review. They are defense-in-depth input contract fields, not cryptographic proof.

## Default-deny configuration

All three switches default to `false` and are wired into both Compose files:

- `SENTINEL_YOUTUBE_PUBLISH_ENABLED=false`: no YouTube uploads are allowed until an operator explicitly enables the gate.
- `SENTINEL_YOUTUBE_PUBLISH_ALLOW_UNLISTED=false`: unlisted uploads require an additional opt-in.
- `SENTINEL_YOUTUBE_PUBLISH_ALLOW_PUBLIC=false`: public uploads require a separate additional opt-in.

The global Sentinel kill switch denies publication regardless of these flags. A scheduled job must use a valid timezone-aware future ISO-8601 timestamp and `private` privacy. The route never uploads media; VyralX remains responsible for revalidating source rights, requiring operator approval, and submitting the upload.

Do not set any switch to true until a deployed authenticated smoke test and a private test upload have passed. Never put credential values into source control.
