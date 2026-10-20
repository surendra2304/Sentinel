"""Sentinel Human-in-the-Loop Approval Dispatcher.

Dispatches actionable approval requests when agents trigger Guarded actions:
- Live trade execution (Stratex)
- System modifications / code deployments (Forge)
- Security overrides / killswitch triggers (Sentinel)
- Sensitive external operations (FRIDAY / Cortex)

Channels:
- Telegram Bot: Dispatches interactive approval messages with direct action links.
- Discord Webhook: Dispatches rich embed alerts.
- REST Endpoints: GET/POST one-click approval & denial routes.
- Offline Queue: Buffers pending requests if Telegram credentials are not yet linked.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
import time
import urllib.request
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

logger = logging.getLogger("approval_dispatcher")


class ApprovalStatus(StrEnum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    EXPIRED = "EXPIRED"


@dataclass
class PendingApproval:
    token: str
    request_id: str
    agent_name: str
    action: str
    risk_level: str
    details: dict[str, Any]
    created_at: float = field(default_factory=lambda: time.time())
    expires_at: float = field(default_factory=lambda: time.time() + 300.0)  # 5 min default
    status: ApprovalStatus = ApprovalStatus.PENDING
    decision_reason: str | None = None
    decided_at: float | None = None

    def is_expired(self) -> bool:
        return self.status == ApprovalStatus.PENDING and time.time() > self.expires_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "token": self.token,
            "request_id": self.request_id,
            "agent_name": self.agent_name,
            "action": self.action,
            "risk_level": self.risk_level,
            "details": self.details,
            "created_at": datetime.fromtimestamp(self.created_at, UTC).isoformat(),
            "expires_at": datetime.fromtimestamp(self.expires_at, UTC).isoformat(),
            "status": self.status.value,
            "decision_reason": self.decision_reason,
            "decided_at": datetime.fromtimestamp(self.decided_at, UTC).isoformat() if self.decided_at else None,
        }


class ApprovalDispatcher:
    """Singleton dispatcher managing pending approvals and multi-channel notifications."""
    _instance: ApprovalDispatcher | None = None
    _pending: dict[str, PendingApproval]
    _events: dict[str, asyncio.Event]

    def __new__(cls) -> ApprovalDispatcher:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._pending = {}
            cls._instance._events = {}
        return cls._instance

    @property
    def public_base_url(self) -> str:
        return os.getenv("FRIDAY_PUBLIC_URL", "http://friday-universe.duckdns.org/sentinel").rstrip("/")

    @property
    def telegram_bot_token(self) -> str | None:
        return os.getenv("TELEGRAM_BOT_TOKEN") or os.getenv("SENTINEL_TELEGRAM_BOT_TOKEN")

    @property
    def telegram_chat_id(self) -> str | None:
        return os.getenv("TELEGRAM_CHAT_ID") or os.getenv("SENTINEL_TELEGRAM_CHAT_ID")

    @property
    def discord_webhook_url(self) -> str | None:
        return os.getenv("DISCORD_WEBHOOK_URL")

    def submit_approval(
        self,
        agent_name: str,
        action: str,
        details: dict[str, Any] | None = None,
        risk_level: str = "GUARDED",
        timeout_sec: float = 300.0,
    ) -> PendingApproval:
        """Create and dispatch a new approval request."""
        token = secrets.token_hex(16)
        req_id = f"appr_{secrets.token_hex(6)}"
        pending = PendingApproval(
            token=token,
            request_id=req_id,
            agent_name=agent_name.upper(),
            action=action,
            risk_level=risk_level.upper(),
            details=details or {},
            created_at=time.time(),
            expires_at=time.time() + timeout_sec,
            status=ApprovalStatus.PENDING,
        )

        self._pending[token] = pending
        self._events[token] = asyncio.Event()

        # Dispatch async notification
        self._dispatch_notifications(pending)
        return pending

    async def wait_for_decision(self, token: str, timeout_sec: float | None = None) -> bool:
        """Asynchronously wait until the approval is decided by Surendra or expires."""
        pending = self._pending.get(token)
        if not pending:
            return False

        event = self._events.get(token)
        if not event:
            return False

        timeout = timeout_sec or max(0.1, pending.expires_at - time.time())
        try:
            await asyncio.wait_for(event.wait(), timeout=timeout)
            return pending.status == ApprovalStatus.APPROVED
        except TimeoutError:
            pending.status = ApprovalStatus.EXPIRED
            pending.decision_reason = "Approval request timed out without response"
            return False

    def decide(self, token: str, approve: bool, reason: str = "") -> PendingApproval | None:
        """Record decision (approve or deny) and awaken waiting agent."""
        pending = self._pending.get(token)
        if not pending:
            return None

        if pending.is_expired():
            pending.status = ApprovalStatus.EXPIRED
            return pending

        pending.status = ApprovalStatus.APPROVED if approve else ApprovalStatus.DENIED
        pending.decision_reason = reason or ("Approved by Sovereign Architect Surendra" if approve else "Denied by Surendra")
        pending.decided_at = time.time()

        event = self._events.get(token)
        if event:
            event.set()

        logger.info("Approval %s (%s) -> %s", pending.request_id, pending.action, pending.status.value)
        return pending

    def get_pending_list(self) -> list[dict[str, Any]]:
        """Return all non-expired pending approvals."""
        now = time.time()
        active = []
        for p in self._pending.values():
            if p.status == ApprovalStatus.PENDING and p.expires_at > now:
                active.append(p.to_dict())
        return active

    def _dispatch_notifications(self, pending: PendingApproval) -> None:
        """Dispatch notification to Telegram, Discord, and system log."""
        approve_url = f"{self.public_base_url}/api/v1/approvals/{pending.token}/approve"
        deny_url = f"{self.public_base_url}/api/v1/approvals/{pending.token}/deny"

        # 1. Telegram Dispatch
        if self.telegram_bot_token and self.telegram_chat_id:
            msg = (
                f"🛡️ <b>SENTINEL GUARDED ACTION APPROVAL</b>\n\n"
                f"<b>Agent:</b> <code>{pending.agent_name}</code>\n"
                f"<b>Action:</b> <code>{pending.action}</code>\n"
                f"<b>Risk Level:</b> {pending.risk_level}\n"
                f"<b>Details:</b> <pre>{json.dumps(pending.details, indent=2)}</pre>\n\n"
                f"✅ <a href=\"{approve_url}\"><b>APPROVE ACTION</b></a>\n"
                f"❌ <a href=\"{deny_url}\"><b>DENY ACTION</b></a>\n\n"
                f"<i>Expires in 5 minutes.</i>"
            )
            self._send_telegram(msg)
        else:
            logger.info(
                f"[SENTINEL APPROVAL QUEUED] Action '{pending.action}' by '{pending.agent_name}'. "
                f"Approve URL: {approve_url} | Deny URL: {deny_url} | "
                f"(Telegram alerts ready: Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID when desired)."
            )

        # 2. Discord Dispatch
        if self.discord_webhook_url:
            self._send_discord(pending, approve_url, deny_url)

    def _send_telegram(self, html_text: str) -> None:
        url = f"https://api.telegram.org/bot{self.telegram_bot_token}/sendMessage"
        payload = {
            "chat_id": self.telegram_chat_id,
            "text": html_text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=5.0)
        except Exception as e:
            logger.warning("Telegram notification dispatch error: %s", e)

    def _send_discord(self, pending: PendingApproval, approve_url: str, deny_url: str) -> None:
        payload = {
            "content": "🛡️ **SENTINEL GUARDED ACTION APPROVAL REQUIRED**",
            "embeds": [
                {
                    "title": f"Action: {pending.action} ({pending.agent_name})",
                    "description": f"Risk Level: **{pending.risk_level}**\n\n[✅ APPROVE]({approve_url}) | [❌ DENY]({deny_url})",
                    "fields": [
                        {"name": "Details", "value": f"```{json.dumps(pending.details)[:1000]}```"}
                    ],
                    "color": 16753920,
                }
            ]
        }
        if not self.discord_webhook_url:
            return
        try:
            req = urllib.request.Request(
                self.discord_webhook_url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=5.0)
        except Exception as e:
            logger.warning("Discord notification dispatch error: %s", e)


# Global singleton instance
approval_dispatcher = ApprovalDispatcher()
