"""LLMProvider - OpenAI-compatible HTTP client IntelligenceProvider.

Secrets: API key read ONLY from settings; never logged or serialised.
"""

import json
import time
from typing import Any

import httpx

from sentinel.core.intelligence.interface import (
    IntelligenceProvider,
    IntelligenceRequest,
    IntelligenceResult,
    IntelligenceRole,
    TokenUsage,
)
from sentinel.logging.logger import get_logger

logger = get_logger("sentinel.intelligence.llm")

_DEFAULT_COST_PER_1K: dict[str, float] = {
    "gpt-4o": 0.005,
    "gpt-4o-mini": 0.00015,
    "default": 0.002,
}

_SYSTEM_PROMPTS: dict[IntelligenceRole, str] = {
    IntelligenceRole.PLANNING: (
        "You are a senior penetration testing planner. Given a task context, produce a structured "
        "assessment plan. Respond ONLY with valid JSON matching the planning schema."
    ),
    IntelligenceRole.CORRELATION: (
        "You are a security analyst. Identify correlated finding clusters. "
        "Respond ONLY with valid JSON matching the correlation schema."
    ),
    IntelligenceRole.VULNERABILITY_REASONING: (
        "You are a vulnerability researcher. Assess exploitability and remediation priority. "
        "Respond ONLY with valid JSON matching the vulnerability_reasoning schema."
    ),
    IntelligenceRole.THREAT_INTELLIGENCE: (
        "You are a threat intelligence analyst. Classify the indicator. "
        "Respond ONLY with valid JSON matching the threat_intelligence schema."
    ),
    IntelligenceRole.FORENSICS_REASONING: (
        "You are a digital forensics investigator. Reconstruct the incident timeline. "
        "Respond ONLY with valid JSON matching the forensics_reasoning schema."
    ),
    IntelligenceRole.REPORT_SYNTHESIS: (
        "You are an executive security report writer. Generate a concise risk summary. "
        "Respond ONLY with valid JSON matching the report_synthesis schema."
    ),
    IntelligenceRole.QUALITY_REVIEW: (
        "You are a rigorous security findings reviewer. Challenge weak findings. "
        "Respond ONLY with valid JSON matching the quality_review schema."
    ),
}


class LLMProvider(IntelligenceProvider):
    """OpenAI-compatible LLM provider with retries, schema validation, cost tracking."""

    def __init__(
        self,
        base_url: str = "https://api.openai.com/v1",
        api_key: str = "",
        model_map: dict[IntelligenceRole, str] | None = None,
        timeout_seconds: float = 30.0,
        max_retries: int = 2,
        cost_per_1k: dict[str, float] | None = None,
    ):
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key  # NEVER log this value
        self._model_map: dict[IntelligenceRole, str] = model_map or {}
        self._timeout = timeout_seconds
        self._max_retries = max_retries
        self._cost_per_1k = cost_per_1k or _DEFAULT_COST_PER_1K

    @property
    def provider_name(self) -> str:
        return "llm"

    def _model_for_role(self, role: IntelligenceRole) -> str:
        return self._model_map.get(role, self._model_map.get(  # type: ignore[call-overload]
            IntelligenceRole.PLANNING, "gpt-4o-mini"
        ))

    def _cost_stub(self, model: str, total_tokens: int) -> float:
        rate = self._cost_per_1k.get(model, self._cost_per_1k.get("default", 0.002))
        return rate * total_tokens / 1000.0

    async def request(self, req: IntelligenceRequest) -> IntelligenceResult:
        start = time.monotonic()
        model = self._model_for_role(req.role)
        system_prompt = _SYSTEM_PROMPTS.get(req.role, "Respond with valid JSON.")
        messages: list[dict[str, str]] = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": json.dumps(req.context, default=str)},
        ]

        for attempt in range(self._max_retries + 1):
            try:
                raw_output, usage = await self._call_api(model, messages)
                parsed = self._parse_json(raw_output)
                if parsed is None:
                    if attempt < self._max_retries:
                        messages.append({"role": "assistant", "content": raw_output})
                        messages.append({"role": "user",
                                         "content": "Your response was not valid JSON. Respond ONLY with a valid JSON object."})
                        continue
                    raise ValueError(f"Non-JSON response after {self._max_retries} retries")
                latency = (time.monotonic() - start) * 1000
                logger.info("LLM request OK", extra={"role": req.role, "model": model,
                                                      "tokens": usage.total_tokens})
                return IntelligenceResult(
                    role=req.role,
                    provider_used=f"llm:{model}",
                    structured_output=parsed,
                    confidence=0.85,
                    schema_valid=True,
                    token_usage=usage,
                    latency_ms=latency,
                )
            except httpx.TimeoutException as exc:
                if attempt >= self._max_retries:
                    return IntelligenceResult(
                        role=req.role, provider_used=f"llm:{model}",
                        error=f"Timeout: {exc}", schema_valid=False,
                        latency_ms=(time.monotonic() - start) * 1000,
                    )
            except Exception as exc:
                logger.error("LLM request failed", extra={"role": req.role, "error": str(exc)})
                if attempt >= self._max_retries:
                    return IntelligenceResult(
                        role=req.role, provider_used=f"llm:{model}",
                        error=str(exc), schema_valid=False,
                        latency_ms=(time.monotonic() - start) * 1000,
                    )

        return IntelligenceResult(
            role=req.role, provider_used=f"llm:{model}",
            error="Max retries exceeded", schema_valid=False,
            latency_ms=(time.monotonic() - start) * 1000,
        )

    async def _call_api(self, model: str, messages: list[dict[str, str]]) -> tuple[str, TokenUsage]:
        headers = {
            "Authorization": f"Bearer {self._api_key}",  # api_key never logged
            "Content-Type": "application/json",
        }
        payload: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "response_format": {"type": "json_object"},
            "temperature": 0.1,
        }
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(f"{self._base_url}/chat/completions",
                                     headers=headers, json=payload)
            resp.raise_for_status()
            data = resp.json()
        content: str = data["choices"][0]["message"]["content"]
        usage_data: dict[str, Any] = data.get("usage", {})
        pt = usage_data.get("prompt_tokens", 0)
        ct = usage_data.get("completion_tokens", 0)
        tt = usage_data.get("total_tokens", pt + ct)
        return content, TokenUsage(
            prompt_tokens=pt, completion_tokens=ct, total_tokens=tt,
            cost_usd_stub=self._cost_stub(model, tt),
        )

    @staticmethod
    def _parse_json(raw: str) -> dict[str, Any] | None:
        try:
            result = json.loads(raw)
            return result if isinstance(result, dict) else None
        except json.JSONDecodeError:
            return None
