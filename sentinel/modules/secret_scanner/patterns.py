"""Secret detection regular expression patterns for Sentinel.

Includes comprehensive high-entropy patterns for Google Cloud, OpenAI, Anthropic,
GitHub PATs, AWS, Stripe, Slack, and PEM private keys.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

from sentinel.core.models import SeverityLevel


@dataclass(frozen=True)
class SecretPattern:
    rule_id: str
    name: str
    pattern: re.Pattern[str]
    severity: SeverityLevel
    description: str
    min_entropy: float = 0.0


SECRET_PATTERNS: Final[list[SecretPattern]] = [
    # 1. Private Cryptographic Keys
    SecretPattern(
        rule_id="SEC-PEM-KEY",
        name="Private PEM Key",
        pattern=re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY",
            re.MULTILINE,
        ),
        severity=SeverityLevel.CRITICAL,
        description="Hardcoded cryptographic private key header detected.",
        min_entropy=0.0,
    ),
    # 2. Google Cloud / Gemini API Keys (typically AIza followed by 35 alphanumeric characters)
    SecretPattern(
        rule_id="SEC-GOOGLE-API",
        name="Google API Key",
        pattern=re.compile(r"\bAIza[0-9A-Za-z\-_]{35,40}\b"),
        severity=SeverityLevel.CRITICAL,
        description="Google Cloud / Gemini API key detected.",
        min_entropy=3.0,
    ),
    # 3. OpenAI API Keys (legacy sk-, project sk-proj-, and fine-tuning)
    SecretPattern(
        rule_id="SEC-OPENAI-API",
        name="OpenAI API Key",
        pattern=re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b"),
        severity=SeverityLevel.CRITICAL,
        description="OpenAI API key or project token detected.",
        min_entropy=3.2,
    ),
    # 4. Anthropic / Claude API Keys
    SecretPattern(
        rule_id="SEC-ANTHROPIC-API",
        name="Anthropic API Key",
        pattern=re.compile(r"\bsk-ant-(?:api\d{2}-)?[A-Za-z0-9_-]{32,}\b"),
        severity=SeverityLevel.CRITICAL,
        description="Anthropic Claude API secret key detected.",
        min_entropy=3.2,
    ),
    # 5. GitHub Personal Access Tokens (Classic and Fine-Grained)
    SecretPattern(
        rule_id="SEC-GITHUB-PAT",
        name="GitHub Personal Access Token",
        pattern=re.compile(
            r"\b(?:ghp_[A-Za-z0-9]{36,40}|github_pat_[A-Za-z0-9_]{80,90}|gho_[A-Za-z0-9]{36,40}|ghu_[A-Za-z0-9]{36,40}|ghs_[A-Za-z0-9]{36,40}|ghr_[A-Za-z0-9]{36,40})\b"
        ),
        severity=SeverityLevel.CRITICAL,
        description="GitHub personal access token or OAuth secret detected.",
        min_entropy=3.0,
    ),
    # 6. AWS Credentials (Access Key & Secret Key)
    SecretPattern(
        rule_id="SEC-AWS-KEY",
        name="AWS Access Key ID",
        pattern=re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        severity=SeverityLevel.CRITICAL,
        description="AWS IAM Access Key ID detected.",
        min_entropy=2.8,
    ),
    SecretPattern(
        rule_id="SEC-AWS-SECRET",
        name="AWS Secret Access Key",
        pattern=re.compile(
            r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"
        ),
        severity=SeverityLevel.CRITICAL,
        description="AWS Secret Access Key detected.",
        min_entropy=3.5,
    ),
    # 7. Slack API Tokens
    SecretPattern(
        rule_id="SEC-SLACK-TOKEN",
        name="Slack API Token",
        pattern=re.compile(r"\bxox[baprs]-[0-9A-Za-z]{10,48}\b"),
        severity=SeverityLevel.HIGH,
        description="Slack OAuth or Bot token detected.",
        min_entropy=2.5,
    ),
    # 8. Stripe API Keys
    SecretPattern(
        rule_id="SEC-STRIPE-KEY",
        name="Stripe API Secret",
        pattern=re.compile(r"\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,}\b"),
        severity=SeverityLevel.CRITICAL,
        description="Stripe secret or restricted key detected.",
        min_entropy=3.0,
    ),
    # 9. Generic High-Entropy Token Assignment
    SecretPattern(
        rule_id="SEC-GENERIC-SECRET",
        name="Generic API Secret or Password",
        pattern=re.compile(
            r"(?i)(?:api_key|apikey|secret_key|secret|password|access_token|auth_token)\s*[:=]\s*['\"]([A-Za-z0-9_\-\.]{16,})['\"]"
        ),
        severity=SeverityLevel.HIGH,
        description="High-entropy secret assignment detected in source code.",
        min_entropy=3.3,
    ),
]
