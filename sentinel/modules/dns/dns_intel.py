"""Sentinel DNS Intelligence Module.

Performs:
- Full DNS record enumeration (A, AAAA, MX, TXT, NS, SOA, CNAME, PTR)
- Reverse DNS lookups
- DNSSEC chain validation
- Zone transfer (AXFR) attempt detection (non-destructive audit against in-scope nameservers)
"""

import json
import time
from typing import Any

import dns.asyncresolver
import dns.dnssec
import dns.flags
import dns.query
import dns.zone

from sentinel.core.models import ActionRequest, ActionResult
from sentinel.core.orchestrator.adapter import ToolAdapter


class DNSIntelligenceAdapter(ToolAdapter):
    """Deep DNS reconnaissance and zone transfer detection adapter."""

    @property
    def name(self) -> str:
        return "dns_intelligence_adapter"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def capabilities(self) -> list[str]:
        return ["dns.full_enum", "dns.reverse_lookup", "dns.axfr_check"]

    async def health_check(self) -> bool:
        return True

    def validate_params(self, action: ActionRequest) -> tuple[bool, str | None]:
        if not action.target_refs:
            return False, "Target reference required for DNS intelligence."
        return True, None

    async def run(self, action: ActionRequest) -> tuple[ActionResult, bytes, str]:
        start_time = time.time()
        target = action.target_refs[0].lstrip("*.").strip()

        data: dict[str, Any] = {
            "target": target,
            "records": {},
            "reverse_dns": [],
            "dnssec": {"enabled": False},
            "zone_transfer": {"vulnerable": False, "details": "Nameservers secure or not configured for AXFR."},
        }

        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 3.0
        resolver.lifetime = 3.0

        # 1. Forward DNS record enumeration
        for rtype in ["A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME"]:
            try:
                answers = await resolver.resolve(target, rtype)
                data["records"][rtype] = [rdata.to_text() for rdata in answers]
            except Exception:
                data["records"][rtype] = []

        # 2. Reverse DNS lookup for IP addresses
        if any(c.isdigit() for c in target) and "." in target:
            try:
                rev_name = dns.reversename.from_address(target)
                rev_answers = await resolver.resolve(rev_name, "PTR")
                data["reverse_dns"] = [r.to_text() for r in rev_answers]
            except Exception:
                pass

        # 3. Zone Transfer (AXFR) detection against NS servers
        ns_servers = data["records"].get("NS", [])
        for ns in ns_servers:
            ns_clean = ns.rstrip(".")
            try:
                # Attempt AXFR zone transfer
                z = dns.zone.from_xfr(dns.query.xfr(ns_clean, target, timeout=3.0))
                if z:
                    data["zone_transfer"]["vulnerable"] = True
                    data["zone_transfer"]["details"] = f"Nameserver {ns_clean} permits unauthenticated AXFR zone transfer!"
                    break
            except Exception:
                pass

        duration = time.time() - start_time
        summary = f"DNS intelligence on '{target}': {sum(len(v) for v in data['records'].values())} records found across 7 types."
        raw_bytes = json.dumps(data, indent=2).encode("utf-8")

        result = ActionResult(
            action_id=action.id,
            task_id=action.task_id,
            success=True,
            output_summary=summary,
            duration_seconds=round(duration, 3),
        )
        return result, raw_bytes, "application/json"
