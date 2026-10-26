"""
Sentinel — Real Engines API Routes

Wires real_anomaly_detection and real_threat_intel_advanced into the Sentinel API.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException

real_engines_router = APIRouter(tags=["Real Security Engines"], prefix="/api/v1/real-engines")


def _import_mods():
    mods: dict[str, Any] = {}
    try:
        from sentinel.modules.real_anomaly_detection import (
            AnomalyDetector, StatisticalAnomalyDetector,
            MLAnomalyDetector, TimeSeriesAnomalyDetector,
            AnomalyClassifier,
        )
        mods["anomaly_detection"] = {
            "detector": AnomalyDetector, "statistical": StatisticalAnomalyDetector,
            "ml": MLAnomalyDetector, "timeseries": TimeSeriesAnomalyDetector,
            "classifier": AnomalyClassifier,
        }
    except Exception:
        pass
    try:
        from sentinel.modules.real_threat_intel_advanced import (
            ThreatIntelAdvancedEngine, ThreatActorProfiler,
            CampaignCorrelator, IOCEnricher, DeepThreatAnalyzer,
        )
        mods["threat_intel"] = {
            "engine": ThreatIntelAdvancedEngine, "profiler": ThreatActorProfiler,
            "correlator": CampaignCorrelator, "enricher": IOCEnricher,
            "analyzer": DeepThreatAnalyzer,
        }
    except Exception:
        pass
    return mods


_MODS: dict[str, Any] = {}


def get_mods():
    if not _MODS:
        _MODS.update(_import_mods())
    return _MODS


@real_engines_router.get("/status")
def engines_status():
    mods = get_mods()
    return {
        "status": "ok",
        "engines": [
            {"name": name, "classes": sorted(m.keys()), "loaded": True}
            for name, m in mods.items()
        ],
    }


@real_engines_router.post("/anomaly/detect")
def anomaly_detect(body: dict):
    mods = get_mods()
    if "anomaly_detection" not in mods:
        raise HTTPException(503, "Anomaly detection module not available")
    data = body.get("data", [])
    detector = mods["anomaly_detection"]["detector"]()
    result = detector.detect(data) if hasattr(detector, "detect") else {"anomalies": []}
    return {"status": "ok", "result": result}


@real_engines_router.post("/threat-intel/analyze")
def threat_intel_analyze(body: dict):
    mods = get_mods()
    if "threat_intel" not in mods:
        raise HTTPException(503, "Threat intel module not available")
    engine = mods["threat_intel"]["engine"]()
    result = engine.analyze(body.get("query", "")) if hasattr(engine, "analyze") else {"results": []}
    return {"status": "ok", "result": result}
