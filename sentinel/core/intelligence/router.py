"""IntelligenceRouter - per-role provider selection with ordered fallback chains."""

from sentinel.core.intelligence.interface import (
    IntelligenceProvider,
    IntelligenceRequest,
    IntelligenceResult,
    IntelligenceRole,
)
from sentinel.logging.logger import get_logger

logger = get_logger("sentinel.intelligence.router")


class IntelligenceRouter(IntelligenceProvider):
    """Model-agnostic router: selects provider per role with fallback chains."""

    def __init__(
        self,
        providers: dict[str, IntelligenceProvider],
        role_provider_map: dict[IntelligenceRole, list[str]] | None = None,
        default_chain: list[str] | None = None,
    ):
        self._providers = providers
        self._role_map = role_provider_map or {}
        self._default_chain = default_chain or ["heuristic"]

    @property
    def provider_name(self) -> str:
        return "router"

    def register(self, name: str, provider: IntelligenceProvider) -> None:
        self._providers[name] = provider

    def has_llm_for_role(self, role: IntelligenceRole) -> bool:
        chain = self._role_map.get(role, self._default_chain)
        if not chain:
            return False
        first = self._providers.get(chain[0])
        return first is not None and first.provider_name == "llm"

    async def request(self, req: IntelligenceRequest) -> IntelligenceResult:
        chain = self._role_map.get(req.role, self._default_chain)
        last_result: IntelligenceResult | None = None

        for provider_name in chain:
            provider = self._providers.get(provider_name)
            if provider is None:
                logger.warning("Router: provider not found", extra={"provider": provider_name})
                continue
            logger.debug("Router: trying provider",
                         extra={"role": req.role, "provider": provider_name})
            result = await provider.request(req)
            if result.ok:
                if last_result is not None:
                    logger.info("Router: fallback succeeded",
                                extra={"role": req.role, "used": provider_name})
                return result
            logger.warning("Router: provider failed, trying fallback",
                           extra={"role": req.role, "provider": provider_name,
                                  "error": result.error or "schema invalid"})
            last_result = result

        logger.error("Router: all providers exhausted", extra={"role": req.role})
        return last_result or IntelligenceResult(
            role=req.role, provider_used="router",
            error="No providers available", schema_valid=False,
        )


def build_default_router() -> IntelligenceRouter:
    """Build the default router: heuristic-only, ready for LLM injection via config."""
    from sentinel.core.intelligence.heuristic_provider import heuristic_provider
    return IntelligenceRouter(
        providers={"heuristic": heuristic_provider},
        default_chain=["heuristic"],
    )


# Global singleton - wired at startup; LLMProvider injected when configured
intelligence_router: IntelligenceRouter = build_default_router()
