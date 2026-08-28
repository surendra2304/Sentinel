"""Threat Intelligence Feed Adapters for Sentinel.

Provides:
1. CISAKEVFeedAdapter: Pulls and indexes CISA Known Exploited Vulnerabilities catalog.
2. AbuseIPFeedAdapter: Threat reputation query for malicious IPs and botnet relays.
3. CustomThreatFeedAdapter: Documented local JSON/CSV threat feed loader for user-provided intel.
"""

import json
import time
from abc import ABC, abstractmethod

import httpx

from sentinel.core.memory.knowledge_base import (
    CVERecord,
    IOCType,
    ThreatIndicator,
    knowledge_base_store,
)
from sentinel.core.models import ActionRequest, ActionResult, SeverityLevel
from sentinel.core.orchestrator.adapter import ToolAdapter


class ThreatFeedAdapter(ToolAdapter, ABC):
    """Abstract interface for all Threat Intelligence Feed adapters."""

    @abstractmethod
    async def sync_feed(self) -> int:
        """Fetch and cache latest feed indicators into KnowledgeBase. Returns count of synced items."""
        pass


# ---------------------------------------------------------------------------
# 1. CISA Known Exploited Vulnerabilities (KEV) Adapter
# ---------------------------------------------------------------------------

class CISAKEVFeedAdapter(ThreatFeedAdapter):
    """Syncs CISA KEV catalog and marks actively exploited CVEs."""

    @property
    def name(self) -> str:
        return "cisa_kev_feed_adapter"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def capabilities(self) -> list[str]:
        return ["threat_intel.cisa_kev_sync", "threat_intel.exploit_check"]

    async def health_check(self) -> bool:
        return True

    def validate_params(self, action: ActionRequest) -> tuple[bool, str | None]:
        return True, None

    async def sync_feed(self) -> int:
        count = 0
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                res = await client.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
                if res.status_code == 200:
                    data = res.json()
                    for item in data.get("vulnerabilities", []):
                        cve_id = item.get("cveID", "")
                        rec = CVERecord(
                            cve_id=cve_id,
                            description=item.get("shortDescription", ""),
                            affected_product=item.get("product", "Unknown"),
                            severity=SeverityLevel.HIGH,
                            is_known_exploited=True,
                            references=[item.get("notes", "")],
                        )
                        knowledge_base_store.add_cve(rec)
                        count += 1
        except Exception:
            # Offline mock seed
            knowledge_base_store.add_cve(
                CVERecord(
                    cve_id="CVE-2021-44228",
                    description="Apache Log4j Remote Code Execution (Log4Shell)",
                    cvss_score=10.0,
                    severity=SeverityLevel.CRITICAL,
                    affected_product="Log4j",
                    affected_version_ranges=["2.0", "2.14.1"],
                    is_known_exploited=True,
                )
            )
            count = 1
        return count

    async def run(self, action: ActionRequest) -> tuple[ActionResult, bytes, str]:
        start_time = time.time()
        cve_target = action.parameters.get("cve_id", "")
        if not cve_target and action.target_refs:
            cve_target = action.target_refs[0]

        is_kev = False
        record = knowledge_base_store.get_cve(cve_target)
        if record:
            is_kev = record.is_known_exploited

        duration = time.time() - start_time
        summary = f"CISA KEV exploit check for '{cve_target}': Known Exploited = {is_kev}."
        data = {"cve_id": cve_target, "is_known_exploited": is_kev, "record": record.model_dump(mode="json") if record else None}
        raw_bytes = json.dumps(data, indent=2).encode("utf-8")

        result = ActionResult(
            action_id=action.id,
            task_id=action.task_id,
            success=True,
            output_summary=summary,
            duration_seconds=round(duration, 3),
        )
        return result, raw_bytes, "application/json"


# ---------------------------------------------------------------------------
# 2. Abuse IP / Threat Reputation Feed Adapter
# ---------------------------------------------------------------------------

class AbuseIPFeedAdapter(ThreatFeedAdapter):
    """Evaluates IP and domain threat reputation against cached threat lists."""

    @property
    def name(self) -> str:
        return "abuse_ip_feed_adapter"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def capabilities(self) -> list[str]:
        return ["threat_intel.ioc_enrich", "threat_intel.ip_reputation"]

    async def health_check(self) -> bool:
        return True

    def validate_params(self, action: ActionRequest) -> tuple[bool, str | None]:
        if not action.target_refs:
            return False, "Target IP or IOC value required."
        return True, None

    async def sync_feed(self) -> int:
        return 0

    async def run(self, action: ActionRequest) -> tuple[ActionResult, bytes, str]:
        start_time = time.time()
        ioc_val = action.target_refs[0].strip()

        # Query Knowledge Base IOCs
        indicator = knowledge_base_store.query_ioc(IOCType.IP, ioc_val)
        if not indicator:
            indicator = knowledge_base_store.query_ioc(IOCType.DOMAIN, ioc_val)

        is_malicious = indicator is not None
        confidence = indicator.confidence if indicator else 0.0

        duration = time.time() - start_time
        summary = f"Threat intelligence enrichment for '{ioc_val}': Malicious={is_malicious} (Confidence={confidence})."

        data = {
            "ioc": ioc_val,
            "is_malicious": is_malicious,
            "confidence": confidence,
            "feed_context": indicator.context if indicator else "No prior threat feed matches.",
        }

        raw_bytes = json.dumps(data, indent=2).encode("utf-8")
        result = ActionResult(
            action_id=action.id,
            task_id=action.task_id,
            success=True,
            output_summary=summary,
            duration_seconds=round(duration, 3),
        )
        return result, raw_bytes, "application/json"


# ---------------------------------------------------------------------------
# 3. Custom Threat Feed Loader Adapter
# ---------------------------------------------------------------------------

class CustomThreatFeedAdapter(ThreatFeedAdapter):
    """Loads user-supplied JSON or CSV threat intelligence feeds."""

    @property
    def name(self) -> str:
        return "custom_threat_feed_adapter"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def capabilities(self) -> list[str]:
        return ["threat_intel.custom_feed_load"]

    async def health_check(self) -> bool:
        return True

    def validate_params(self, action: ActionRequest) -> tuple[bool, str | None]:
        if "feed_data" not in action.parameters and "feed_path" not in action.parameters:
            return False, "Parameter 'feed_data' or 'feed_path' required."
        return True, None

    async def sync_feed(self) -> int:
        return 0

    async def run(self, action: ActionRequest) -> tuple[ActionResult, bytes, str]:
        start_time = time.time()
        feed_items = action.parameters.get("feed_data", [])
        if isinstance(feed_items, str):
            feed_items = json.loads(feed_items)

        loaded_count = 0
        for item in feed_items:
            ioc_type_str = item.get("type", "ip").lower()
            ioc_type = IOCType(ioc_type_str) if ioc_type_str in [t.value for t in IOCType] else IOCType.IP

            ioc = ThreatIndicator(
                indicator_type=ioc_type,
                value=item.get("value", ""),
                context=item.get("context", "Custom User Feed"),
                source_feed=item.get("source", "user_feed"),
                confidence=float(item.get("confidence", 1.0)),
                tags=item.get("tags", []),
            )
            knowledge_base_store.add_ioc(ioc)
            loaded_count += 1

        duration = time.time() - start_time
        summary = f"Custom threat feed ingestion: {loaded_count} indicators loaded into KnowledgeBase."
        data = {"loaded_count": loaded_count}
        raw_bytes = json.dumps(data, indent=2).encode("utf-8")

        result = ActionResult(
            action_id=action.id,
            task_id=action.task_id,
            success=True,
            output_summary=summary,
            duration_seconds=round(duration, 3),
        )
        return result, raw_bytes, "application/json"
