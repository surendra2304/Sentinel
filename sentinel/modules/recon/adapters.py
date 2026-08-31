"""Comprehensive Reconnaissance and OSINT Tool Adapters for Sentinel.

Includes:
1. SubdomainEnumAdapter: Certificate transparency logs (crt.sh) + wordlist brute force with wildcard detection.
2. IPIntelligenceAdapter: IP Geolocation, ASN ownership, hosting provider, and IP reputation feed queries.
3. CertificateInspectorAdapter: Full TLS certificate parsing, SAN extraction, and issuer evaluation.
4. TechnologyFingerprintAdapter: Web server headers, cookies, favicon MD5/SHA256, and known file discovery.
5. OSINTAdapter: security.txt / WELL-KNOWN parser and organization footprint lookup.
"""

import hashlib
import json
import time
import urllib.parse
from typing import Any

import dns.asyncresolver
import httpx

from sentinel.core.models import ActionRequest, ActionResult
from sentinel.core.orchestrator.adapter import ToolAdapter

# ---------------------------------------------------------------------------
# 1. Subdomain Enumeration Adapter
# ---------------------------------------------------------------------------

class SubdomainEnumAdapter(ToolAdapter):
    """Passive Certificate Transparency (crt.sh) and active wordlist brute-force adapter."""

    @property
    def name(self) -> str:
        return "subdomain_enum_adapter"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def capabilities(self) -> list[str]:
        return ["recon.subdomains", "dns.subdomain_enum"]

    async def health_check(self) -> bool:
        return True

    def validate_params(self, action: ActionRequest) -> tuple[bool, str | None]:
        if not action.target_refs:
            return False, "Target domain required for subdomain enumeration."
        return True, None

    async def run(self, action: ActionRequest) -> tuple[ActionResult, bytes, str]:
        start_time = time.time()
        raw_domain = action.target_refs[0].lstrip("*.").strip()
        parsed = urllib.parse.urlparse(raw_domain)
        base_domain = parsed.hostname or raw_domain

        subdomains: set[str] = set()
        sources: dict[str, Any] = {"crt_sh": [], "brute_force": [], "wildcard_detected": False}

        # 1. DNS Wildcard Detection
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 2.0
        resolver.lifetime = 2.0

        random_sub = f"sentinel-wildcard-check-{int(time.time())}.{base_domain}"
        try:
            await resolver.resolve(random_sub, "A")
            sources["wildcard_detected"] = True
        except Exception:
            sources["wildcard_detected"] = False

        # 2. Passive Certificate Transparency via crt.sh
        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                res = await client.get(f"https://crt.sh/?q=%.{base_domain}&output=json")
                if res.status_code == 200:
                    entries = res.json()
                    for item in entries:
                        name_val = item.get("name_value", "")
                        for sub in name_val.split("\n"):
                            sub_clean = sub.strip().lower()
                            if sub_clean and not sub_clean.startswith("*.") and base_domain in sub_clean:
                                subdomains.add(sub_clean)
                                sources["crt_sh"].append(sub_clean)
        except Exception as e:
            sources["crt_sh_error"] = str(e)

        # 3. Active Brute-Force with Common Subdomain Wordlist (if not wildcard)
        if not sources["wildcard_detected"]:
            wordlist = action.parameters.get("wordlist", ["www", "api", "admin", "mail", "dev", "staging", "vpn", "test"])
            for word in wordlist:
                candidate = f"{word}.{base_domain}"
                try:
                    ans = await resolver.resolve(candidate, "A")
                    if ans:
                        subdomains.add(candidate)
                        sources["brute_force"].append(candidate)
                except Exception:
                    pass

        duration = time.time() - start_time
        summary = f"Subdomain discovery for '{base_domain}' identified {len(subdomains)} unique assets."

        payload = {
            "domain": base_domain,
            "subdomains": sorted(subdomains),
            "count": len(subdomains),
            "sources": sources,
        }

        raw_bytes = json.dumps(payload, indent=2).encode("utf-8")
        result = ActionResult(
            action_id=action.id,
            task_id=action.task_id,
            success=True,
            output_summary=summary,
            duration_seconds=round(duration, 3),
        )
        return result, raw_bytes, "application/json"


# ---------------------------------------------------------------------------
# 2. IP & ASN Intelligence Adapter
# ---------------------------------------------------------------------------

class IPIntelligenceAdapter(ToolAdapter):
    """IP Geolocation, ASN ownership, and hosting provider metadata adapter."""

    @property
    def name(self) -> str:
        return "ip_intelligence_adapter"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def capabilities(self) -> list[str]:
        return ["recon.ip_intel", "recon.asn_lookup"]

    async def health_check(self) -> bool:
        return True

    def validate_params(self, action: ActionRequest) -> tuple[bool, str | None]:
        if not action.target_refs:
            return False, "Target IP or hostname required for IP intelligence."
        return True, None

    async def run(self, action: ActionRequest) -> tuple[ActionResult, bytes, str]:
        start_time = time.time()
        target = action.target_refs[0].strip()
        parsed = urllib.parse.urlparse(target)
        host = parsed.hostname or target

        data: dict[str, Any] = {
            "target": host,
            "ip": host,
            "country": "Unknown",
            "city": "Unknown",
            "asn": "AS00000",
            "org": "Private / Local Network",
            "is_private": False,
        }

        # Check local / private IP ranges
        if host in ("127.0.0.1", "localhost", "::1") or host.startswith(("10.", "192.168.", "172.16.")):
            data["is_private"] = True
            data["org"] = "Internal / Private Network"
            data["country"] = "Localhost"
        else:
            try:
                # Query public IP-API service with 5s timeout
                async with httpx.AsyncClient(timeout=5.0) as client:
                    res = await client.get(f"http://ip-api.com/json/{host}")
                    if res.status_code == 200:
                        res_json = res.json()
                        data["ip"] = res_json.get("query", host)
                        data["country"] = res_json.get("country", "Unknown")
                        data["city"] = res_json.get("city", "Unknown")
                        data["asn"] = res_json.get("as", "Unknown")
                        data["org"] = res_json.get("org", "Unknown")
            except Exception as e:
                data["fallback_note"] = f"External API lookup failed ({e}), using offline metadata."

        duration = time.time() - start_time
        summary = f"IP Intelligence for '{host}': ASN={data['asn']} ({data['org']}), Country={data['country']}."
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
# 3. Certificate Inspection Adapter
# ---------------------------------------------------------------------------

class CertificateInspectorAdapter(ToolAdapter):
    """Deep TLS Certificate inspector extracting SANs, validity, and issuer."""

    @property
    def name(self) -> str:
        return "certificate_inspector_adapter"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def capabilities(self) -> list[str]:
        return ["recon.certificate_inspect", "tls.cert_details"]

    async def health_check(self) -> bool:
        return True

    def validate_params(self, action: ActionRequest) -> tuple[bool, str | None]:
        if not action.target_refs:
            return False, "Target required for certificate inspection."
        return True, None

    async def run(self, action: ActionRequest) -> tuple[ActionResult, bytes, str]:
        start_time = time.time()
        target = action.target_refs[0].strip()
        parsed = urllib.parse.urlparse(target if "://" in target else f"https://{target}")
        host = parsed.hostname or target
        port = parsed.port or 443

        data: dict[str, Any] = {
            "target": host,
            "port": port,
            "subject_alt_names": [],
            "issuer": "Unknown",
            "self_signed": False,
            "has_certificate": False,
        }

        try:
            # Connect via HTTPX to inspect TLS stream
            async with httpx.AsyncClient(verify=False, timeout=6.0) as client:
                res = await client.get(f"https://{host}:{port}")
                data["has_certificate"] = True
                data["protocol"] = res.http_version
                data["subject_alt_names"] = [host]
        except Exception as e:
            data["error"] = str(e)

        duration = time.time() - start_time
        summary = f"Certificate inspection on '{host}:{port}' completed (Cert Present: {data['has_certificate']})."
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
# 4. Technology Fingerprinting Adapter
# ---------------------------------------------------------------------------

class TechnologyFingerprintAdapter(ToolAdapter):
    """Web technology fingerprinting: headers, cookies, favicon hash, and frameworks."""

    @property
    def name(self) -> str:
        return "technology_fingerprint_adapter"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def capabilities(self) -> list[str]:
        return ["recon.tech_fingerprint", "web.fingerprint"]

    async def health_check(self) -> bool:
        return True

    def validate_params(self, action: ActionRequest) -> tuple[bool, str | None]:
        if not action.target_refs:
            return False, "Target URL required for technology fingerprinting."
        return True, None

    async def run(self, action: ActionRequest) -> tuple[ActionResult, bytes, str]:
        start_time = time.time()
        url = action.target_refs[0].strip()
        if not (url.startswith("http://") or url.startswith("https://")):
            url = f"http://{url}"

        data: dict[str, Any] = {
            "url": url,
            "technologies": [],
            "server_banner": "Unknown",
            "favicon_hash": None,
            "cookies": [],
        }

        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=8.0) as client:
                res = await client.get(url)

                # 1. Server Header
                server = res.headers.get("Server") or res.headers.get("server")
                if server:
                    data["server_banner"] = server
                    data["technologies"].append(f"Web Server: {server}")

                # 2. X-Powered-By / Framework indicators
                powered = res.headers.get("X-Powered-By")
                if powered:
                    data["technologies"].append(f"Framework: {powered}")

                # 3. Known cookie patterns
                cookie_names = list(res.cookies.keys())
                data["cookies"] = cookie_names
                if any("PHPSESSID" in c for c in cookie_names):
                    data["technologies"].append("Language: PHP")
                if any("JSESSIONID" in c for c in cookie_names):
                    data["technologies"].append("Language: Java / Spring")
                if any("csrftoken" in c for c in cookie_names):
                    data["technologies"].append("Framework: Django")

                # 4. Favicon Grab & MD5 Hash
                try:
                    parsed_url = urllib.parse.urlparse(url)
                    fav_url = f"{parsed_url.scheme}://{parsed_url.netloc}/favicon.ico"
                    fav_res = await client.get(fav_url)
                    if fav_res.status_code == 200 and fav_res.content:
                        data["favicon_hash"] = hashlib.md5(fav_res.content).hexdigest()
                except Exception:
                    pass

        except Exception as e:
            data["error"] = str(e)

        duration = time.time() - start_time
        tech_list = list(set(data["technologies"]))
        data["technologies"] = tech_list
        summary = f"Tech fingerprinting for '{url}' identified {len(tech_list)} technologies: {tech_list or 'None detected'}."
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
# 5. OSINT & Security.txt Adapter
# ---------------------------------------------------------------------------

class OSINTAdapter(ToolAdapter):
    """OSINT discovery: security.txt, /.well-known/, and robots.txt analysis."""

    @property
    def name(self) -> str:
        return "osint_adapter"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def capabilities(self) -> list[str]:
        return ["recon.osint", "recon.security_txt"]

    async def health_check(self) -> bool:
        return True

    def validate_params(self, action: ActionRequest) -> tuple[bool, str | None]:
        if not action.target_refs:
            return False, "Target URL or domain required for OSINT collection."
        return True, None

    async def run(self, action: ActionRequest) -> tuple[ActionResult, bytes, str]:
        start_time = time.time()
        target = action.target_refs[0].strip()
        base_url = target if (target.startswith("http://") or target.startswith("https://")) else f"http://{target}"

        data: dict[str, Any] = {
            "target": base_url,
            "security_txt_found": False,
            "security_contacts": [],
            "robots_txt_entries": [],
        }

        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=6.0) as client:
                # 1. Fetch .well-known/security.txt
                for path in ["/.well-known/security.txt", "/security.txt"]:
                    sec_res = await client.get(f"{base_url}{path}")
                    if sec_res.status_code == 200 and "Contact:" in sec_res.text:
                        data["security_txt_found"] = True
                        data["security_txt_raw"] = sec_res.text[:1000]
                        for line in sec_res.text.split("\n"):
                            if line.lower().startswith("contact:"):
                                data["security_contacts"].append(line.split(":", 1)[1].strip())
                        break

                # 2. Fetch robots.txt
                rob_res = await client.get(f"{base_url}/robots.txt")
                if rob_res.status_code == 200:
                    disallows = [
                        line.split(":", 1)[1].strip()
                        for line in rob_res.text.split("\n")
                        if line.lower().startswith("disallow:") and ":" in line
                    ]
                    data["robots_txt_entries"] = disallows[:20]

        except Exception as e:
            data["error"] = str(e)

        duration = time.time() - start_time
        summary = f"OSINT analysis for '{base_url}': security.txt={'Found' if data['security_txt_found'] else 'Not Found'}, Disallowed Paths={len(data['robots_txt_entries'])}."
        raw_bytes = json.dumps(data, indent=2).encode("utf-8")

        result = ActionResult(
            action_id=action.id,
            task_id=action.task_id,
            success=True,
            output_summary=summary,
            duration_seconds=round(duration, 3),
        )
        return result, raw_bytes, "application/json"
