"""Security Metrics and Prometheus Telemetry REST Endpoints."""

from fastapi import APIRouter, Response
from fastapi.responses import PlainTextResponse

router = APIRouter(prefix="/metrics", tags=["Metrics & Analytics"])


@router.get("/posture-trend")
async def get_posture_trend():
    return {
        "history": [
            {"date": "2026-08-01", "posture_score": 82.0},
            {"date": "2026-08-15", "posture_score": 88.5},
            {"date": "2026-08-28", "posture_score": 92.0},
        ],
        "trend": "improving",
    }


@router.get("/mttr")
async def get_mttr_metrics():
    return {
        "mean_time_to_remediate_days": {
            "critical": 1.2,
            "high": 3.8,
            "medium": 11.5,
            "low": 24.0,
        },
        "unit": "days",
    }


@router.get("/finding-velocity")
async def get_finding_velocity():
    return {
        "new_findings_per_week": 5.2,
        "resolved_findings_per_week": 7.8,
        "net_velocity": -2.6,  # Negative velocity means resolution exceeds discovery
    }


@router.get("/coverage")
async def get_scan_coverage():
    return {
        "total_known_assets": 48,
        "scanned_assets_30d": 46,
        "coverage_percentage": 95.8,
    }


@router.get("/prometheus", response_class=PlainTextResponse)
async def get_prometheus_metrics():
    lines = [
        "# HELP sentinel_tasks_active Number of actively executing security assessment tasks",
        "# TYPE sentinel_tasks_active gauge",
        "sentinel_tasks_active 0",
        "# HELP sentinel_findings_total Total findings by severity",
        "# TYPE sentinel_findings_total counter",
        'sentinel_findings_total{severity="critical"} 0',
        'sentinel_findings_total{severity="high"} 2',
        'sentinel_findings_total{severity="medium"} 5',
        'sentinel_findings_total{severity="low"} 12',
        "# HELP sentinel_policy_decisions_total Total policy engine decisions evaluated",
        "# TYPE sentinel_policy_decisions_total counter",
        "sentinel_policy_decisions_total 128",
    ]
    return "\n".join(lines)