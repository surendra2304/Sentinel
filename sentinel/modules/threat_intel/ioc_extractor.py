"""High-performance Indicator of Compromise (IOC) extraction and normalization engine."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Sequence
from urllib.parse import urlparse

from sentinel.core.models import SeverityLevel
from sentinel.modules.threat_intel.models import IOCItem, IOCType

# Defanging and Refanging regex patterns
_REFANG_HTTP = re.compile(r"h[xX]{2}p([sS]?)://", re.IGNORECASE)
_REFANG_DOT = re.compile(r"\[\.\]|\(\.\)|\{\.\}")
_REFANG_COLON = re.compile(r"\[:\]|\(:\}")
_REFANG_AT = re.compile(r"\[@\]|\(@\)")

# Core IOC Extraction Patterns
_IPV4_PATTERN = re.compile(
    r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
)
_IPV6_PATTERN = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
    r"|\b(?:[0-9a-fA-F]{1,4}:){1,7}:"
    r"|\b:(?::[0-9a-fA-F]{1,4}){1,7}\b"
    r"|\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b"
)
_URL_PATTERN = re.compile(
    r"\b(?:https?|ftp|hxxps?|ws|wss)://[^\s<>\"'{}|\\^`]+"
    r"|\b[a-zA-Z0-9.-]+\[\.\][a-zA-Z]{2,}(?:/[^\s<>\"'{}|\\^`]*)?",
    re.IGNORECASE,
)
_EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+-]+(?:@|\[@\]|\(@\))[A-Za-z0-9.-]+(?:\.|\[\.\]|\(\.\))[A-Za-z]{2,}\b"
)
_DOMAIN_PATTERN = re.compile(
    r"\b(?!(?:https?|ftp)://)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\b"
)
_MD5_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA1_PATTERN = re.compile(r"\b[a-fA-F0-9]{40}\b")
_SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")
_CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

# Ignored domain extensions / common false positive words
_COMMON_EXTENSIONS = {
    "png", "jpg", "jpeg", "gif", "svg", "css", "js", "html", "htm",
    "json", "xml", "txt", "md", "py", "rs", "go", "ts", "tsx", "jsx",
    "pdf", "doc", "docx", "zip", "tar", "gz", "exe", "dll", "so",
}


def defang_ioc(value: str) -> str:
    """Defang an indicator to prevent accidental execution/clicking."""
    defanged = value.replace("http://", "hxxp://").replace("https://", "hxxps://")
    defanged = defanged.replace(".", "[.]").replace("@", "[@]")
    return defanged


def refang_ioc(value: str) -> str:
    """Normalize a defanged indicator back to standard form."""
    refanged = _REFANG_HTTP.sub(r"http\1://", value)
    refanged = _REFANG_DOT.sub(".", refanged)
    refanged = _REFANG_COLON.sub(":", refanged)
    refanged = _REFANG_AT.sub("@", refanged)
    return refanged


def is_valid_ipv4(value: str) -> bool:
    """Validate string is a true IPv4 address."""
    try:
        ip = ipaddress.IPv4Address(value)
        return not (ip.is_unspecified)
    except ValueError:
        return False


def is_valid_ipv6(value: str) -> bool:
    """Validate string is a true IPv6 address."""
    try:
        ipaddress.IPv6Address(value)
        return True
    except ValueError:
        return False


def extract_iocs(text: str, allowed_types: Sequence[IOCType] | None = None) -> list[IOCItem]:
    """Extract, refang, normalize, and classify all IOCs from free text."""
    if not text or not text.strip():
        return []

    types_set = set(allowed_types) if allowed_types else set(IOCType)
    items: list[IOCItem] = []
    seen: set[tuple[IOCType, str]] = set()

    # 1. Extract CVEs
    if IOCType.CVE in types_set:
        for match in _CVE_PATTERN.finditer(text):
            val = match.group(0).upper()
            if (IOCType.CVE, val) not in seen:
                seen.add((IOCType.CVE, val))
                items.append(
                    IOCItem(
                        value=val,
                        ioc_type=IOCType.CVE,
                        normalized_value=val,
                        severity=SeverityLevel.HIGH,
                        confidence=1.0,
                    )
                )

    # 2. Extract SHA256
    if IOCType.SHA256 in types_set:
        for match in _SHA256_PATTERN.finditer(text):
            val = match.group(0).lower()
            if (IOCType.SHA256, val) not in seen:
                seen.add((IOCType.SHA256, val))
                items.append(
                    IOCItem(
                        value=val,
                        ioc_type=IOCType.SHA256,
                        normalized_value=val,
                        confidence=1.0,
                    )
                )

    # 3. Extract SHA1 (must not be part of SHA256)
    if IOCType.SHA1 in types_set:
        for match in _SHA1_PATTERN.finditer(text):
            val = match.group(0).lower()
            # Verify boundary not part of longer hex
            start, end = match.span()
            if start > 0 and text[start - 1] in "0123456789abcdefABCDEF":
                continue
            if end < len(text) and text[end] in "0123456789abcdefABCDEF":
                continue
            if (IOCType.SHA1, val) not in seen:
                seen.add((IOCType.SHA1, val))
                items.append(
                    IOCItem(
                        value=val,
                        ioc_type=IOCType.SHA1,
                        normalized_value=val,
                        confidence=0.95,
                    )
                )

    # 4. Extract MD5 (must not be part of longer hex)
    if IOCType.MD5 in types_set:
        for match in _MD5_PATTERN.finditer(text):
            val = match.group(0).lower()
            start, end = match.span()
            if start > 0 and text[start - 1] in "0123456789abcdefABCDEF":
                continue
            if end < len(text) and text[end] in "0123456789abcdefABCDEF":
                continue
            if (IOCType.MD5, val) not in seen:
                seen.add((IOCType.MD5, val))
                items.append(
                    IOCItem(
                        value=val,
                        ioc_type=IOCType.MD5,
                        normalized_value=val,
                        confidence=0.9,
                    )
                )

    # 5. Extract URLs
    if IOCType.URL in types_set:
        for match in _URL_PATTERN.finditer(text):
            raw_val = match.group(0)
            norm_val = refang_ioc(raw_val).rstrip(".,;)>'\"")
            if not (norm_val.startswith("http://") or norm_val.startswith("https://") or norm_val.startswith("ftp://")):
                norm_val = f"http://{norm_val}"
            if (IOCType.URL, norm_val) not in seen:
                seen.add((IOCType.URL, norm_val))
                items.append(
                    IOCItem(
                        value=raw_val,
                        ioc_type=IOCType.URL,
                        normalized_value=norm_val,
                        is_defanged="[" in raw_val or "hxxp" in raw_val.lower(),
                        confidence=0.95,
                    )
                )

    # 6. Extract Emails
    if IOCType.EMAIL in types_set:
        for match in _EMAIL_PATTERN.finditer(text):
            raw_val = match.group(0)
            norm_val = refang_ioc(raw_val).lower().rstrip(".,;)>'\"")
            if (IOCType.EMAIL, norm_val) not in seen:
                seen.add((IOCType.EMAIL, norm_val))
                items.append(
                    IOCItem(
                        value=raw_val,
                        ioc_type=IOCType.EMAIL,
                        normalized_value=norm_val,
                        is_defanged="[@]" in raw_val or "[.]" in raw_val,
                        confidence=0.9,
                    )
                )

    # 7. Extract IPv4
    if IOCType.IPV4 in types_set:
        refanged_text = refang_ioc(text)
        for match in _IPV4_PATTERN.finditer(refanged_text):
            val = match.group(0)
            if is_valid_ipv4(val) and (IOCType.IPV4, val) not in seen:
                seen.add((IOCType.IPV4, val))
                items.append(
                    IOCItem(
                        value=val,
                        ioc_type=IOCType.IPV4,
                        normalized_value=val,
                        confidence=1.0,
                    )
                )

    # 8. Extract IPv6
    if IOCType.IPV6 in types_set:
        for match in _IPV6_PATTERN.finditer(text):
            val = match.group(0)
            if is_valid_ipv6(val):
                norm_val = str(ipaddress.IPv6Address(val))
                if (IOCType.IPV6, norm_val) not in seen:
                    seen.add((IOCType.IPV6, norm_val))
                    items.append(
                        IOCItem(
                            value=val,
                            ioc_type=IOCType.IPV6,
                            normalized_value=norm_val,
                            confidence=1.0,
                        )
                    )

    # Track hostnames of already extracted URLs/emails to avoid redundant duplicate domain IOCs
    existing_hosts: set[str] = set()
    for item in items:
        if item.ioc_type == IOCType.URL:
            try:
                parsed = urlparse(item.normalized_value)
                if parsed.hostname:
                    existing_hosts.add(parsed.hostname.lower())
            except Exception:
                pass
        elif item.ioc_type == IOCType.EMAIL and "@" in item.normalized_value:
            existing_hosts.add(item.normalized_value.split("@")[-1].lower())

    # 9. Extract Domains
    if IOCType.DOMAIN in types_set:
        refanged_text = refang_ioc(text)
        for match in _DOMAIN_PATTERN.finditer(refanged_text):
            val = match.group(0).lower().rstrip(".")
            tld = val.split(".")[-1]
            if tld in _COMMON_EXTENSIONS:
                continue
            if is_valid_ipv4(val):
                continue
            if val in existing_hosts:
                continue
            if (IOCType.DOMAIN, val) not in seen:
                seen.add((IOCType.DOMAIN, val))
                items.append(
                    IOCItem(
                        value=val,
                        ioc_type=IOCType.DOMAIN,
                        normalized_value=val,
                        confidence=0.85,
                    )
                )

    return items
