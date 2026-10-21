"""Stratex Trading Safety & Execution Invariant Bridge.

Provides pre-trade risk invariant verification, emergency kill-switch enforcement,
maximum drawdown threshold checks, and cryptographic trade order authorization.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

from sentinel.audit.audit_logger import audit_logger


class TradeOrderIntent(BaseModel):
    """Proposed trade execution submitted by Stratex."""

    order_id: str
    symbol: str
    side: str  # "BUY" | "SELL"
    order_type: str  # "LIMIT" | "MARKET"
    quantity: float
    price: float
    notional_value: float = 0.0
    current_daily_drawdown_pct: float = 0.0
    strategy_id: str
    account_id: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class TradeSecurityVerdict(BaseModel):
    """Cryptographically signed trade clearance verdict."""

    order_id: str
    symbol: str
    is_cleared: bool
    decision: str  # "CLEARED" | "VETOED"
    veto_reasons: list[str] = Field(default_factory=list)
    signature: str = ""
    kill_switch_active: bool = False
    timestamp: str = ""


class StratexTradingGuard:
    """Pre-Trade Gatekeeper and Kill-Switch Authority for Stratex."""

    def __init__(
        self,
        max_notional_per_order: float = 100_000.0,
        max_allowed_drawdown_pct: float = 5.0,
        signing_key: str | None = None,
    ) -> None:
        self.max_notional_per_order = max_notional_per_order
        self.max_allowed_drawdown_pct = max_allowed_drawdown_pct
        self.signing_key: str = str(
            signing_key or os.getenv("SENTINEL_AUDIT_SIGNING_KEY") or "sentinel-trade-key-not-for-prod"
        )
        self._kill_switch_active: bool = False
        self._kill_switch_reason: str = ""

    def engage_emergency_kill_switch(self, reason: str, operator: str = "sentinel-guardian") -> None:
        """Immediately lock down all trading operations across the universe."""
        self._kill_switch_active = True
        self._kill_switch_reason = reason

        audit_logger.log_event(
            event_type="STRATEX_KILL_SWITCH_ENGAGED",
            actor=operator,
            target="ALL_TRADING_STRATEGIES",
            action_type="emergency_kill_switch",
            scope_policy="trading_safety_invariants",
            decision="KILL_SWITCH_ACTIVE",
            details={"reason": reason, "timestamp": datetime.now(UTC).isoformat()},
        )

    def disengage_kill_switch(self, operator: str, justification: str) -> None:
        """Disengage emergency trading lock with mandatory operator justification."""
        self._kill_switch_active = False
        old_reason = self._kill_switch_reason
        self._kill_switch_reason = ""

        audit_logger.log_event(
            event_type="STRATEX_KILL_SWITCH_DISENGAGED",
            actor=operator,
            target="ALL_TRADING_STRATEGIES",
            action_type="disengage_kill_switch",
            scope_policy="trading_safety_invariants",
            decision="KILL_SWITCH_RESTORED",
            details={
                "justification": justification,
                "previous_reason": old_reason,
                "timestamp": datetime.now(UTC).isoformat(),
            },
        )

    @property
    def is_kill_switch_engaged(self) -> bool:
        return self._kill_switch_active

    def verify_trade_invariants(self, trade: TradeOrderIntent) -> TradeSecurityVerdict:
        """Evaluate pre-trade invariants and return signed clearance or veto."""
        veto_reasons: list[str] = []

        # 1. Kill Switch Check (Unconditional)
        if self._kill_switch_active:
            veto_reasons.append(
                f"Emergency Kill-Switch is ENGAGED across mesh. Reason: {self._kill_switch_reason}"
            )

        # 2. Daily Drawdown Threshold
        if trade.current_daily_drawdown_pct >= self.max_allowed_drawdown_pct:
            veto_reasons.append(
                f"Daily drawdown limit exceeded: current {trade.current_daily_drawdown_pct:.2f}% "
                f">= max allowed {self.max_allowed_drawdown_pct:.2f}%."
            )

        # 3. Notional Value Sanity Check
        computed_notional = trade.notional_value or (trade.quantity * trade.price)
        if computed_notional > self.max_notional_per_order:
            veto_reasons.append(
                f"Order notional ${computed_notional:,.2f} exceeds max order limit "
                f"${self.max_notional_per_order:,.2f}."
            )

        # 4. Quantity and Price Sign Integrity
        if trade.quantity <= 0 or trade.price <= 0:
            veto_reasons.append(f"Invalid quantity ({trade.quantity}) or price ({trade.price}); must be positive.")

        is_cleared = len(veto_reasons) == 0
        decision_str = "CLEARED" if is_cleared else "VETOED"

        # Cryptographic Signature
        payload_to_sign = f"{trade.order_id}:{trade.symbol}:{trade.quantity}:{trade.price}:{decision_str}"
        signature = hmac.new(
            self.signing_key.encode("utf-8"),
            payload_to_sign.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        audit_entry = audit_logger.log_event(
            event_type="STRATEX_TRADE_AUDIT",
            actor="sentinel-trade-guard",
            target=f"{trade.symbol}:{trade.order_id}",
            action_type="pre_trade_verification",
            scope_policy="stratex_risk_policy",
            decision=decision_str,
            details={
                "order_id": trade.order_id,
                "symbol": trade.symbol,
                "side": trade.side,
                "notional": computed_notional,
                "veto_reasons": veto_reasons,
                "is_cleared": is_cleared,
                "kill_switch_active": self._kill_switch_active,
            },
        )

        return TradeSecurityVerdict(
            order_id=trade.order_id,
            symbol=trade.symbol,
            is_cleared=is_cleared,
            decision=decision_str,
            veto_reasons=veto_reasons,
            signature=signature,
            kill_switch_active=self._kill_switch_active,
            timestamp=audit_entry.timestamp,
        )
