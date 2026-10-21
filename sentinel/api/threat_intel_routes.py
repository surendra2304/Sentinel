"""Threat Intelligence REST API Routes."""

from __future__ import annotations

import re
from contextlib import suppress
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from sentinel.modules.threat_intel import (
    IOCType,
    MitreMapper,
    ThreatIntelEngine,
    external_threat_enricher,
    extract_iocs,
)

threat_intel_router = APIRouter(tags=["Threat Intelligence"])
_engine = ThreatIntelEngine()
_mapper = MitreMapper()


class IOCExtractionRequest(BaseModel):
    text: str = Field(..., min_length=1, description="Raw text, log output, or report to parse")
    allowed_types: list[str] | None = None


class MitreMappingRequest(BaseModel):
    text: str = Field(..., min_length=1)
    title: str = ""
    related_cves: list[str] = Field(default_factory=list)


class ReputationCheckRequest(BaseModel):
    indicator: str = Field(..., min_length=1)
    ioc_type: str = "domain"


class ThreatAnalysisRequest(BaseModel):
    text: str = Field(..., min_length=1)


class ThreatEnrichmentRequest(BaseModel):
    indicator: str = Field(..., min_length=1, description="Target IP, File Hash (MD5/SHA256), or CVE identifier")
    indicator_type: str = Field(default="auto", description="ip | hash | cve | auto")


@threat_intel_router.post("/v1/intel/extract-iocs")
@threat_intel_router.post("/api/v1/intel/extract-iocs")
async def extract_indicators(req: IOCExtractionRequest) -> dict[str, Any]:
    """Extract, defang/refang, classify, and normalize all Indicators of Compromise from text."""
    allowed_enums: list[IOCType] | None = None
    if req.allowed_types:
        allowed_enums = []
        for t in req.allowed_types:
            with suppress(ValueError):
                allowed_enums.append(IOCType(t.lower()))

    items = extract_iocs(req.text, allowed_types=allowed_enums)
    return {
        "count": len(items),
        "iocs": [i.model_dump() for i in items],
    }


@threat_intel_router.post("/v1/intel/mitre-map")
@threat_intel_router.post("/api/v1/intel/mitre-map")
async def map_mitre_techniques(req: MitreMappingRequest) -> dict[str, Any]:
    """Map raw event logs, behavioral strings, or vulnerability findings to MITRE ATT&CK techniques."""
    if req.title or req.related_cves:
        techniques = _mapper.map_finding(req.title, req.text, req.related_cves)
    else:
        techniques = _mapper.map_text(req.text)

    return {
        "count": len(techniques),
        "techniques": [t.model_dump() for t in techniques],
    }


@threat_intel_router.post("/v1/intel/reputation")
@threat_intel_router.post("/api/v1/intel/reputation")
async def check_reputation(req: ReputationCheckRequest) -> dict[str, Any]:
    """Calculate reputation score, threat classification, and risk tier for an indicator."""
    try:
        ioc_type = IOCType(req.ioc_type.lower())
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid ioc_type '{req.ioc_type}'. Allowed: {[e.value for e in IOCType]}",
        ) from None

    score = _engine.score_indicator(req.indicator, ioc_type)
    return {"reputation": score.model_dump()}


@threat_intel_router.post("/v1/intel/analyze")
@threat_intel_router.post("/api/v1/intel/analyze")
async def analyze_threat(req: ThreatAnalysisRequest) -> dict[str, Any]:
    """Execute end-to-end threat intelligence assessment (IOC extraction, MITRE mapping, actor correlation)."""
    report = _engine.analyze_text(req.text)
    return {"report": report.model_dump()}


@threat_intel_router.post("/v1/intel/enrich")
@threat_intel_router.post("/api/v1/intel/enrich")
async def enrich_threat_indicator(req: ThreatEnrichmentRequest) -> dict[str, Any]:
    """Enrich an indicator via external intelligence providers (Shodan, VirusTotal, NVD)."""
    ind = req.indicator.strip()
    itype = req.indicator_type.lower()

    if itype == "auto":
        if ind.upper().startswith("CVE-"):
            itype = "cve"
        elif re.match(r"^[a-fA-F0-9]{32,64}$", ind):
            itype = "hash"
        elif re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", ind):
            itype = "ip"
        else:
            itype = "domain"

    if itype == "ip":
        result = await external_threat_enricher.enrich_ip_shodan(ind)
    elif itype in ("hash", "file_hash"):
        result = await external_threat_enricher.enrich_hash_virustotal(ind)
    elif itype == "cve":
        result = await external_threat_enricher.enrich_cve_nvd(ind)
    else:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported enrichment indicator_type '{itype}'. Supported: ip, hash, cve",
        )

    return {"enrichment": result.model_dump()}
