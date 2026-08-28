"""Alert Deduplication and Fatigue Prevention Service.

Provides:
1. 7-day suppression for duplicate finding/alert on same asset.
2. Incident grouping for related findings.
3. Alert fatigue rate limiter (max 10 alerts/hour, overflow to digest).
"""

from datetime import UTC, datetime, timedelta
from typing import Any
from collections import defaultdict
from sentinel.monitoring.continuous import DriftAlert


class AlertDeduplicator:
    """Deduplicates alerts and aggregates incidents to prevent alert fatigue."""

    def __init__(self, suppression_days: int = 7, max_alerts_per_hour: int = 10):
        self.suppression_window = timedelta(days=suppression_days)
        self.max_per_hour = max_alerts_per_hour
        # (asset_id, drift_type) -> last_seen_datetime
        self.seen_alerts: dict[tuple[str, str], datetime] = {}
        self.hourly_counts: dict[str, list[datetime]] = defaultdict(list)
        self.overflow_digests: list[dict[str, Any]] = []

    def process_alert(self, alert: DriftAlert) -> tuple[bool, str]:
        """Returns (is_emitted, reason_or_status)."""
        now = datetime.now(UTC)
        key = (alert.asset_id, alert.drift_type)

        # 1. Check 7-day suppression window
        if key in self.seen_alerts:
            last_seen = self.seen_alerts[key]
            if now - last_seen < self.suppression_window:
                return False, f"Suppressed (duplicate within {self.suppression_window.days} days)"

        # 2. Check alert fatigue rate limiting (max 10 alerts/hour per asset)
        hour_window = now - timedelta(hours=1)
        self.hourly_counts[alert.asset_id] = [t for t in self.hourly_counts[alert.asset_id] if t > hour_window]

        if len(self.hourly_counts[alert.asset_id]) >= self.max_per_hour:
            self.overflow_digests.append({
                "alert": alert.model_dump(),
                "queued_for_digest_at": now.isoformat(),
            })
            return False, "Overflow to digest (fatigue limit exceeded)"

        # Record and emit
        self.seen_alerts[key] = now
        self.hourly_counts[alert.asset_id].append(now)
        return True, "Emitted"


alert_deduplicator = AlertDeduplicator()