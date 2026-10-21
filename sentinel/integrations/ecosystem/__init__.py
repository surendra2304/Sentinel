"""FRIDAY Universe Ecosystem Bridges for Sentinel."""

from sentinel.integrations.ecosystem.cortex_bridge import (
    CortexSecurityGate,
    CortexTargetValidationRequest,
    CortexValidationDecision,
)
from sentinel.integrations.ecosystem.forge_bridge import ForgeSentinelAdapter
from sentinel.integrations.ecosystem.friday_bridge import FridaySentinelAdapter
from sentinel.integrations.ecosystem.futuris_bridge import (
    FuturisForecastingBridge,
    FuturisThreatForecast,
    PostureAdjustment,
)
from sentinel.integrations.ecosystem.inference_bridge import InferenceSentinelAdapter
from sentinel.integrations.ecosystem.intelx_bridge import (
    IntelXCoordinationBridge,
    IntelXTargetRegistration,
    TargetDeconflictionStatus,
)
from sentinel.integrations.ecosystem.memora_bridge import MemoraSentinelAdapter
from sentinel.integrations.ecosystem.stratex_bridge import (
    StratexTradingGuard,
    TradeOrderIntent,
    TradeSecurityVerdict,
)
from sentinel.integrations.ecosystem.vyralx_bridge import (
    MediaAuditDecision,
    MediaPublicationRequest,
    VyralXMediaPolicyGate,
)

__all__ = [
    "CortexSecurityGate",
    "CortexTargetValidationRequest",
    "CortexValidationDecision",
    "ForgeSentinelAdapter",
    "FridaySentinelAdapter",
    "FuturisForecastingBridge",
    "FuturisThreatForecast",
    "InferenceSentinelAdapter",
    "IntelXCoordinationBridge",
    "IntelXTargetRegistration",
    "MediaAuditDecision",
    "MediaPublicationRequest",
    "MemoraSentinelAdapter",
    "PostureAdjustment",
    "StratexTradingGuard",
    "TargetDeconflictionStatus",
    "TradeOrderIntent",
    "TradeSecurityVerdict",
    "VyralXMediaPolicyGate",
]
