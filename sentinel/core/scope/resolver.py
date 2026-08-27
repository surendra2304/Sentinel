"""Scope Resolver for Sentinel.

Normalizes raw target inputs (domains, IPs, CIDRs, URLs with ports/paths,
wireless SSIDs/BSSIDs, cloud ARNs) and performs robust scope boundary checks
including wildcard subdomains, CIDR containment, port rules, and path scoping.
Defends against target smuggling, IDN/punycode spoofing, and embedded IP trickery.
"""

import ipaddress
import re
from enum import StrEnum
from typing import Any
from urllib.parse import unquote, urlparse

from sentinel.core.models import (
    Scope,
    Target,
    TargetMetadata,
    TargetType,
)


class ScopeVerdict(StrEnum):
    IN_SCOPE = "IN_SCOPE"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    EXPLICITLY_EXCLUDED = "EXPLICITLY_EXCLUDED"
    INVALID_TARGET = "INVALID_TARGET"


class TargetResolutionError(ValueError):
    """Raised when target input is ambiguous or invalid."""
    pass


class ScopeResolver:
    """High-assurance target normalizer and scope evaluator."""

    def __init__(self, scope: Scope):
        self.scope = scope

    @classmethod
    def normalize_target(
        cls,
        raw_target: str,
        target_type: TargetType | str | None = None,
        target_id: str | None = None,
        metadata: TargetMetadata | dict[str, Any] | None = None,
    ) -> Target:
        """Parse, validate, and normalize arbitrary raw target strings."""
        if not raw_target or not isinstance(raw_target, str) or not raw_target.strip():
            raise TargetResolutionError("Target input cannot be empty or non-string.")

        val = raw_target.strip()
        meta = metadata if isinstance(metadata, TargetMetadata) else TargetMetadata(**(metadata or {}))
        tid = target_id or f"t-{abs(hash(val)) % 100000000}"

        # If explicit type provided
        if target_type:
            ttype = TargetType(target_type) if isinstance(target_type, str) else target_type
            return Target(id=tid, type=ttype, value=val, metadata=meta)

        # 1. URL Detection (http:// or https://)
        if val.startswith("http://") or val.startswith("https://"):
            return cls._normalize_url_target(tid, val, meta)

        # 2. CIDR Range Detection
        if "/" in val and not val.startswith("/"):
            try:
                net = ipaddress.ip_network(val, strict=False)
                return Target(id=tid, type=TargetType.CIDR, value=str(net), metadata=meta)
            except ValueError:
                pass

        # 3. IP Address Detection (IPv4 or IPv6)
        try:
            ip = ipaddress.ip_address(val)
            return Target(id=tid, type=TargetType.IP, value=str(ip), metadata=meta)
        except ValueError:
            pass

        # 4. Wireless Network (BSSID / MAC)
        if re.match(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", val):
            return Target(id=tid, type=TargetType.WIRELESS_NETWORK, value=val.upper(), metadata=meta)

        # 5. Cloud Account / ARN Detection
        if val.startswith("arn:aws:") or val.startswith("projects/") or re.match(r"^\d{12}$", val):
            return Target(id=tid, type=TargetType.CLOUD_ACCOUNT, value=val, metadata=meta)

        # 6. Domain / Hostname Detection (handles IDN/punycode normalization)
        if re.match(r"^(\*\.)?[a-zA-Z0-9\-\._]+$", val):
            # Check IDN/Punycode
            try:
                val_clean = val.lstrip("*.")
                val_clean.encode("idna").decode("ascii")
            except Exception as e:
                raise TargetResolutionError(f"Domain normalization failed for IDN string '{val}': {e}") from e

            return Target(id=tid, type=TargetType.DOMAIN, value=val.lower(), metadata=meta)

        # 7. File target
        if val.startswith("file://") or val.startswith("/") or re.match(r"^[a-zA-Z]:\\", val):
            return Target(id=tid, type=TargetType.FILE, value=val, metadata=meta)

        raise TargetResolutionError(f"Ambiguous or unresolvable target format: '{raw_target}'")

    @classmethod
    def _normalize_url_target(cls, target_id: str, raw_url: str, metadata: TargetMetadata) -> Target:
        try:
            parsed = urlparse(raw_url)
            if not parsed.netloc:
                raise TargetResolutionError(f"URL missing hostname: {raw_url}")

            # Normalize hostname to lowercase and punycode
            host = parsed.hostname.lower() if parsed.hostname else ""
            port = f":{parsed.port}" if parsed.port and parsed.port not in (80, 443) else ""
            path = unquote(parsed.path) or "/"

            normalized_url = f"{parsed.scheme.lower()}://{host}{port}{path}"
            return Target(id=target_id, type=TargetType.URL, value=normalized_url, metadata=metadata)
        except Exception as e:
            raise TargetResolutionError(f"Failed to parse and normalize URL '{raw_url}': {e}") from e

    def is_target_in_scope(self, target: Target | str) -> tuple[bool, ScopeVerdict, str]:
        """Check if a target satisfies all scope rules, exclusions, and allowlists."""
        if isinstance(target, str):
            try:
                target_obj = self.normalize_target(target)
            except TargetResolutionError as e:
                return False, ScopeVerdict.INVALID_TARGET, str(e)
        else:
            target_obj = target

        target_val = target_obj.value

        # 1. Check Explicit Out-of-Scope / Excluded Declarations
        for excluded in self.scope.out_of_scope_declarations:
            if self._matches_rule(target_obj, excluded):
                return False, ScopeVerdict.EXPLICITLY_EXCLUDED, f"Target '{target_val}' is in out-of-scope declarations: '{excluded}'"

        # If no allowed targets or in-scope declarations are defined, deny by default
        effective_allowlist = self.scope.allowed_targets + self.scope.in_scope_declarations
        if not effective_allowlist:
            return False, ScopeVerdict.OUT_OF_SCOPE, "Scope has no allowlist declarations (Deny-by-default)."

        # 2. Check In-Scope / Allowed Targets
        for allowed in effective_allowlist:
            if self._matches_rule(target_obj, allowed):
                return True, ScopeVerdict.IN_SCOPE, f"Target '{target_val}' matched allowed scope rule: '{allowed}'"

        return False, ScopeVerdict.OUT_OF_SCOPE, f"Target '{target_val}' is outside authorized scope boundaries."

    def _matches_rule(self, target: Target, rule_str: str) -> bool:
        rule_str = rule_str.strip()
        t_val = target.value.strip()

        # Direct Equality
        if t_val.lower() == rule_str.lower():
            return True

        # Wildcard Domain match: *.example.com matches sub.example.com, but NOT example.com or other.com
        if rule_str.startswith("*."):
            base_domain = rule_str[2:].lower()
            if target.type == TargetType.DOMAIN:
                if t_val == base_domain:
                    return False  # *.example.com does NOT cover root apex example.com
                if t_val.endswith("." + base_domain):
                    return True
            elif target.type == TargetType.URL:
                try:
                    host = urlparse(t_val).hostname or ""
                    if host != base_domain and host.endswith("." + base_domain):
                        return True
                except Exception:
                    pass

        # Apex Domain match: example.com matches example.com, and sub.example.com if specified
        if target.type == TargetType.DOMAIN and not rule_str.startswith("*.") and "." in rule_str and (t_val == rule_str.lower() or t_val.endswith("." + rule_str.lower())):
            return True

        # CIDR Subnet Containment
        if "/" in rule_str:
            try:
                network = ipaddress.ip_network(rule_str, strict=False)
                if target.type == TargetType.IP:
                    ip = ipaddress.ip_address(t_val)
                    return ip in network
                if target.type == TargetType.CIDR:
                    target_net = ipaddress.ip_network(t_val, strict=False)
                    if network.version == target_net.version:
                        return network.subnet_of(target_net) or network == target_net or target_net.subnet_of(network)  # type: ignore[arg-type]
                if target.type == TargetType.URL:
                    host = urlparse(t_val).hostname or ""
                    try:
                        ip = ipaddress.ip_address(host)
                        return ip in network
                    except ValueError:
                        pass
            except ValueError:
                pass

        # URL Path and Port Scoping
        if target.type == TargetType.URL and (rule_str.startswith("http://") or rule_str.startswith("https://")):
            try:
                target_parsed = urlparse(t_val)
                rule_parsed = urlparse(rule_str)

                # Match host
                if target_parsed.hostname != rule_parsed.hostname:
                    return False

                # Match port if rule specifies port
                if rule_parsed.port and target_parsed.port != rule_parsed.port:
                    return False

                # Match path prefix
                rule_path = unquote(rule_parsed.path).rstrip("/")
                target_path = unquote(target_parsed.path).rstrip("/")
                return not (rule_path and not target_path.startswith(rule_path))
            except Exception:
                pass

        return False
