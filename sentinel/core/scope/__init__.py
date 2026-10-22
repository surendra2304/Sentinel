"""Target scope definitions, subnet/domain allowlists, and out-of-bounds boundary guards."""

from sentinel.core.scope.authoritative_scope import (
    FRIDAY_UNIVERSE_ALLOWED_TARGETS,
    FRIDAY_UNIVERSE_OUT_OF_SCOPE_DECLARATIONS,
    SOVEREIGN_PRODUCTION_SCOPE,
    create_sovereign_production_scope,
    seed_sovereign_scope_into_database,
)
from sentinel.core.scope.resolver import (
    ScopeConflictError,
    ScopeExpiredError,
    ScopeResolver,
    ScopeValidationError,
    ScopeVerdict,
    TargetResolutionError,
)

__version__ = "0.2.0"

__all__ = [
    "FRIDAY_UNIVERSE_ALLOWED_TARGETS",
    "FRIDAY_UNIVERSE_OUT_OF_SCOPE_DECLARATIONS",
    "SOVEREIGN_PRODUCTION_SCOPE",
    "ScopeConflictError",
    "ScopeExpiredError",
    "ScopeResolver",
    "ScopeValidationError",
    "ScopeVerdict",
    "TargetResolutionError",
    "create_sovereign_production_scope",
    "seed_sovereign_scope_into_database",
]
