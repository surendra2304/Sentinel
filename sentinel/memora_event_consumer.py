"""Consume Memora notices into Sentinel's idempotent, untrusted advisory memory."""

from __future__ import annotations

import logging
import math
import re
from typing import Any

logger = logging.getLogger(__name__)

CONSUMER_ID = "sentinel-security-advisories-v1"
_SECURITY_TERMS = (
    "cybersecurity",
    "security advisory",
    "malware",
    "ransomware",
    "vulnerability",
    "exploit",
    "zero-day",
    "zero day",
    "phishing",
    "data breach",
    "threat actor",
    "cve-",
)
_SECURITY_CATEGORIES = {
    "emerging_threat",
    "security_advisory",
    "cybersecurity",
    "vulnerability",
}


class MemoraDeliveryError(RuntimeError):
    """Raised when a Memora step fails so the event remains replayable."""


def _successful(result: Any) -> bool:
    return (
        isinstance(result, dict)
        and result.get("status") != "error"
        and result.get("cloud") is not False
    )


def _bounded_text(value: Any, limit: int) -> str:
    if not isinstance(value, str):
        return ""
    return " ".join(value.split())[:limit]


def _source_refs(value: Any) -> list[dict[str, str]]:
    """Copy only bounded source metadata; never fetch or execute a source URL."""
    if not isinstance(value, list):
        return []
    result: list[dict[str, str]] = []
    for source in value[:20]:
        if not isinstance(source, dict):
            continue
        url = _bounded_text(source.get("url"), 2048)
        if not url.startswith(("https://", "http://")):
            continue
        item = {"url": url}
        for key, max_length in (
            ("title", 300),
            ("domain", 255),
            ("publisher", 255),
            ("published_at", 64),
            ("trust_tier", 32),
        ):
            text = _bounded_text(source.get(key), max_length)
            if text:
                item[key] = text
        result.append(item)
    return result


def _is_security_notice(event: dict[str, Any]) -> bool:
    if event.get("event_type") != "intelx.news":
        return False
    event_id = event.get("event_id")
    if not isinstance(event_id, str) or not event_id.startswith("intelx-"):
        return False
    payload = event.get("payload")
    if not isinstance(payload, dict) or payload.get("source_agent") != "intelx":
        return False
    relevance = payload.get("relevance")
    relevance = relevance if isinstance(relevance, dict) else {}
    category = str(relevance.get("category", "")).strip().lower()
    domain = str(relevance.get("domain", "")).strip().lower()
    topics = payload.get("topics")
    topic_text = (
        " ".join(str(topic) for topic in topics[:20]).lower() if isinstance(topics, list) else ""
    )
    text = " ".join(str(payload.get(key, "")) for key in ("headline", "summary")).lower()
    if category in _SECURITY_CATEGORIES or domain in {"security", "cybersecurity", "vulnerability"}:
        return True
    if any(term in topic_text or term in text for term in _SECURITY_TERMS):
        return True
    return bool(re.search(r"\bcve-\d{4}-\d{3,}\b", text))


def _futuris_forecast(event: dict[str, Any]) -> dict[str, Any] | None:
    """Validate the narrow forecast envelope we retain as an advisory.

    Futuris probabilities and point forecasts are evidence for a human/Sentinel
    review, never authorization to scan, remediate, quarantine, or trade.
    """
    if event.get("event_type") != "futuris.forecast":
        return None
    event_id = event.get("event_id")
    payload = event.get("payload")
    if not isinstance(event_id, str) or not event_id.startswith("futuris-"):
        raise MemoraDeliveryError("Futuris forecast event has an invalid event_id")
    if not isinstance(payload, dict):
        raise MemoraDeliveryError("Futuris forecast payload is malformed")
    forecast_id = _bounded_text(payload.get("forecast_id"), 128)
    target = _bounded_text(payload.get("target"), 500)
    status = _bounded_text(payload.get("status"), 32).lower()
    if not forecast_id or not target or status not in {"active", "resolved", "expired", "invalidated"}:
        raise MemoraDeliveryError("Futuris forecast is missing required lifecycle fields")

    numbers: dict[str, float] = {}
    for key in ("prediction", "range_lower", "range_upper", "probability", "confidence"):
        value = payload.get(key)
        if value is None and key == "probability":
            continue
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            raise MemoraDeliveryError("Futuris forecast contains an invalid numeric value")
        number = float(value)
        if key in {"probability", "confidence"} and not 0.0 <= number <= 1.0:
            raise MemoraDeliveryError("Futuris forecast probability/confidence is out of range")
        numbers[key] = number
    if numbers["range_lower"] > numbers["prediction"] or numbers["prediction"] > numbers["range_upper"]:
        raise MemoraDeliveryError("Futuris forecast interval does not contain its prediction")
    if payload.get("prediction_is_not_authorization") is not True:
        raise MemoraDeliveryError("Futuris forecast is missing the no-authorization invariant")

    return {
        "forecast_id": forecast_id,
        "target": target,
        "status": status,
        "as_of": _bounded_text(payload.get("as_of"), 64),
        "expires_at": _bounded_text(payload.get("expires_at"), 64),
        "model_version": _bounded_text(payload.get("model_version"), 128),
        "prediction_is_not_authorization": True,
        **numbers,
    }


class MemoraEventConsumer:
    """Persist relevant IntelX notices before acknowledging their global event cursor."""

    def __init__(self, client: Any, *, consumer_id: str = CONSUMER_ID, limit: int = 50):
        self.client = client
        self.consumer_id = consumer_id
        self.limit = limit

    def consume_once(self) -> dict[str, int | bool]:
        cursor = self.client.read_event_cursor("sentinel", consumer_id=self.consumer_id)
        if not _successful(cursor) or not isinstance(cursor.get("after_id"), int):
            raise MemoraDeliveryError("Unable to read Sentinel's Memora event cursor")
        after_id = cursor["after_id"]

        # Do not filter by event_type: Memora acknowledgements are strictly ordered
        # across all events visible to this agent, including events we skip.
        feed = self.client.poll_events("sentinel", after_id=after_id, limit=self.limit)
        if not _successful(feed) or not isinstance(feed.get("events"), list):
            raise MemoraDeliveryError("Unable to poll Sentinel's Memora event feed")

        processed = 0
        skipped = 0
        previous_id = after_id
        for event in feed["events"]:
            if not isinstance(event, dict) or not isinstance(event.get("id"), int):
                raise MemoraDeliveryError("Memora returned a malformed event row")
            event_cursor = event["id"]
            if event_cursor <= previous_id:
                raise MemoraDeliveryError("Memora returned events out of cursor order")
            previous_id = event_cursor

            if event.get("event_type") == "futuris.forecast":
                forecast = _futuris_forecast(event)
                receipt = self.client.record_futuris_forecast_advisory(
                    event["event_id"], forecast=forecast
                )
                expected_key = self.client.futuris_forecast_idempotency_key(event["event_id"])
                if not _successful(receipt) or receipt.get("idempotency_key") != expected_key:
                    raise MemoraDeliveryError("Memora did not confirm the Futuris forecast advisory write")
                processed += 1
            elif _is_security_notice(event):
                payload = event["payload"]
                relevance = payload.get("relevance")
                relevance = relevance if isinstance(relevance, dict) else {}
                topics = payload.get("topics")
                safe_topics = (
                    [_bounded_text(topic, 100) for topic in topics[:20] if isinstance(topic, str)]
                    if isinstance(topics, list)
                    else []
                )
                persisted = self.client.record_intelx_security_notice(
                    event["event_id"],
                    headline=_bounded_text(payload.get("headline"), 500),
                    summary=_bounded_text(payload.get("summary"), 2000),
                    published_at=_bounded_text(payload.get("published_at"), 64),
                    relevance={
                        "category": _bounded_text(relevance.get("category"), 64),
                        "domain": _bounded_text(relevance.get("domain"), 128),
                        "confidence": relevance.get("confidence"),
                    },
                    topics=safe_topics,
                    sources=_source_refs(payload.get("sources")) or _source_refs(
                        [{"url": payload.get("source_url")}]
                    ),
                )
                expected_key = self.client.intelx_notice_idempotency_key(event["event_id"])
                if not _successful(persisted) or persisted.get("idempotency_key") != expected_key:
                    raise MemoraDeliveryError(
                        "Memora did not confirm the idempotent advisory write"
                    )
                processed += 1
            else:
                skipped += 1

            acknowledged = self.client.acknowledge_event(
                "sentinel", event_cursor, consumer_id=self.consumer_id
            )
            # The Memora endpoint returns an identity-bearing receipt only after
            # the per-consumer cursor is durably advanced. A 200 response or a
            # cursor-shaped object alone is not proof that this consumer acked it.
            if (
                not _successful(acknowledged)
                or acknowledged.get("status") != "acknowledged"
                or acknowledged.get("agent") != "sentinel"
                or acknowledged.get("consumer_id") != self.consumer_id
                or not isinstance(acknowledged.get("after_id"), int)
                or acknowledged["after_id"] < event_cursor
            ):
                raise MemoraDeliveryError("Memora did not confirm the event acknowledgement")

        return {
            "processed": processed,
            "skipped": skipped,
            "has_more": bool(feed.get("has_more")),
        }


async def run_memora_event_consumer(
    consumer: MemoraEventConsumer, poll_interval_seconds: float
) -> None:
    """Poll in a worker thread so synchronous HTTP does not block Sentinel's API loop."""
    import asyncio

    while True:
        try:
            result = await asyncio.to_thread(consumer.consume_once)
            if result["has_more"]:
                continue
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning("Memora event consumer will retry (%s)", type(exc).__name__)
        await asyncio.sleep(poll_interval_seconds)
