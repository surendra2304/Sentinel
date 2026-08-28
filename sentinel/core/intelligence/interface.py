"""IntelligenceProvider - the model-agnostic reasoning contract for SENTINEL.

Every AI reasoning operation flows through this single typed interface.
Providers produce structured output validated against role schemas.
"""

from abc import ABC, abstractmethod
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class IntelligenceRole(StrEnum):
    PLANNING = "planning"
    CORRELATION = "correlation"
    VULNERABILITY_REASONING = "vulnerability_reasoning"
    THREAT_INTELLIGENCE = "threat_intelligence"
    FORENSICS_REASONING = "forensics_reasoning"
    REPORT_SYNTHESIS = "report_synthesis"
    QUALITY_REVIEW = "quality_review"


class TokenUsage(BaseModel):
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    cost_usd_stub: float = 0.0


class IntelligenceRequest(BaseModel):
    role: IntelligenceRole
    context: dict[str, Any] = Field(default_factory=dict)
    constraints: dict[str, Any] = Field(default_factory=dict)
    request_id: str = ""


class IntelligenceResult(BaseModel):
    role: IntelligenceRole
    provider_used: str
    structured_output: dict[str, Any] = Field(default_factory=dict)
    confidence: float = 1.0
    schema_valid: bool = True
    token_usage: TokenUsage = Field(default_factory=TokenUsage)
    latency_ms: float = 0.0
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and self.schema_valid


class IntelligenceProvider(ABC):
    @abstractmethod
    async def request(self, req: IntelligenceRequest) -> IntelligenceResult: ...

    @property
    @abstractmethod
    def provider_name(self) -> str: ...
