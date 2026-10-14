"""Structured, timestamped logging for Sentinel."""

import contextvars
import json
import logging
import os
import sys
import uuid
from datetime import UTC, datetime
from typing import Any

# Context variable to hold the correlation / task ID for the active async task/thread
correlation_id_ctx: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "correlation_id", default=None
)


def get_correlation_id() -> str:
    """Retrieve or generate a correlation ID for the current context."""
    cid = correlation_id_ctx.get()
    if not cid:
        cid = str(uuid.uuid4())
        correlation_id_ctx.set(cid)
    return cid


def set_correlation_id(cid: str) -> None:
    """Set correlation ID for current context."""
    correlation_id_ctx.set(cid)


class SentinelStructuredFormatter(logging.Formatter):
    """Structured, timestamped Python logging: [%(asctime)s] [%(levelname)s] [sentinel]: %(message)s"""

    def __init__(
        self,
        fmt: str = "[%(asctime)s] [%(levelname)s] [sentinel]: %(message)s",
        datefmt: str = "%Y-%m-%d %H:%M:%S",
    ):
        super().__init__(fmt=fmt, datefmt=datefmt)

    def format(self, record: logging.LogRecord) -> str:
        # Prepend correlation ID to message if present and not already formatted
        cid = correlation_id_ctx.get()
        if cid and not getattr(record, "_cid_applied", False):
            record.msg = f"[{cid}] {record.msg}"
            record._cid_applied = True  # type: ignore[attr-defined]
        return super().format(record)


class JSONFormatter(logging.Formatter):
    """Custom JSON log formatter including timestamp, level, correlation ID, and payload."""

    def format(self, record: logging.LogRecord) -> str:
        log_record: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "correlation_id": correlation_id_ctx.get(),
            "module": record.module,
            "func_name": record.funcName,
            "line_no": record.lineno,
        }

        # Include exception info if present
        if record.exc_info:
            log_record["exception"] = self.formatException(record.exc_info)

        # Include custom extra attributes
        for key, val in record.__dict__.items():
            if key not in {
                "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
                "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
                "created", "msecs", "relativeCreated", "thread", "threadName",
                "processName", "process", "message"
            } and not key.startswith("_"):
                log_record[key] = val

        return json.dumps(log_record)


def setup_logging(log_level: str = "INFO") -> None:
    """Configure root logger with structured, timestamped stream handler."""
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))

    # Clear existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    handler = logging.StreamHandler(sys.stdout)
    if os.getenv("SENTINEL_LOG_FORMAT", "").lower() == "json":
        handler.setFormatter(JSONFormatter())
    else:
        handler.setFormatter(SentinelStructuredFormatter())
    root_logger.addHandler(handler)


def get_logger(name: str) -> logging.Logger:
    """Get a named logger instance."""
    return logging.getLogger(name)
