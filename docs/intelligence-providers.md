# Intelligence Providers

SENTINEL intelligence layer abstraction.

## Architecture

- IntelligenceRouter: routes per-role to provider chain
- HeuristicProvider: offline, deterministic, default
- LLMProvider: OpenAI-compatible, optional, with fallback

## Roles

planning, correlation, vulnerability_reasoning, threat_intelligence, forensics_reasoning, report_synthesis, quality_review

## Configuration

Offline (default): zero config needed.

With LLM, set in .env:
- SENTINEL_LLM_BASE_URL=https://api.openai.com/v1
- SENTINEL_LLM_API_KEY=sk-... (never commit)
- SENTINEL_LLM_MODEL=gpt-4o-mini

## Secrets Discipline

- API key read ONLY from environment/settings
- Never logged, serialised to evidence, or included in reports
- Authorization header built at HTTP call time only

## Adding a Provider

1. Implement IntelligenceProvider ABC
2. Override request() and provider_name
3. Register: intelligence_router.register('my_provider', MyProvider())

## Evaluation Harness

sentinel.intelligence.evaluation.harness.EvaluationHarness
- record(context) saves JSON fixture
- replay(path, provider, role) returns EvaluationResult with schema_valid + plan_sanity_score
