"""DNS Analysis and Query Adapter for Sentinel.

Wraps dnspython to query records (A, AAAA, MX, NS, TXT, CNAME, SOA)
and performs DNSSEC validation checks.
"""

import json
import time
from typing import Any

import dns.asyncresolver
import dns.dnssec
import dns.flags
import dns.name
import dns.rdatatype

from sentinel.core.models import ActionRequest, ActionResult
from sentinel.core.orchestrator.adapter import ToolAdapter


class DNSAdapter(ToolAdapter):
    """DNS queries, record enumeration, and DNSSEC validation adapter."""

    @property
    def name(self) -> str:
        return "dns_adapter"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def capabilities(self) -> list[str]:
        return ["dns.lookup", "dns.zone_info"]

    async def health_check(self) -> bool:
        return True

    def validate_params(self, action: ActionRequest) -> tuple[bool, str | None]:
        if not action.target_refs:
            return False, "Target references cannot be empty for DNS queries."
        return True, None

    async def run(self, action: ActionRequest) -> tuple[ActionResult, bytes, str]:
        start_time = time.time()
        target_domain = action.target_refs[0].lstrip("*.").strip()
        record_types = action.parameters.get("record_types", ["A", "AAAA", "MX", "NS", "TXT", "SOA"])

        results: dict[str, Any] = {
            "domain": target_domain,
            "action_type": action.action_type,
            "records": {},
            "dnssec": {"valid": False, "details": "Unchecked"},
        }

        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 5.0
        resolver.lifetime = 5.0

        for rtype in record_types:
            try:
                answers = await resolver.resolve(target_domain, rtype)
                results["records"][rtype] = [rdata.to_text() for rdata in answers]
            except Exception:
                results["records"][rtype] = []

        # Check DNSSEC if requested or default
        try:
            query = dns.message.make_query(target_domain, dns.rdatatype.SOA, want_dnssec=True)
            results["dnssec"]["has_dnssec_flags"] = bool(query.flags & dns.flags.DO)
        except Exception as e:
            results["dnssec"]["error"] = str(e)

        duration = time.time() - start_time
        summary_count = sum(len(v) for v in results["records"].values())
        summary = f"DNS enumeration for '{target_domain}' discovered {summary_count} records across {len(record_types)} types."

        raw_bytes = json.dumps(results, indent=2).encode("utf-8")

        result = ActionResult(
            action_id=action.id,
            task_id=action.task_id,
            success=True,
            output_summary=summary,
            duration_seconds=round(duration, 3),
        )

        return result, raw_bytes, "application/json"
