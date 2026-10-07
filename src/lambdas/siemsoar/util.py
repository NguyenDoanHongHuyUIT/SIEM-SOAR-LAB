"""Small helpers: time, ids, structured logging, DynamoDB <-> JSON conversion."""

from __future__ import annotations

import json
import logging
import os
import secrets
import sys
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()


def now() -> datetime:
    return datetime.now(UTC)


def iso(dt: datetime | None = None) -> str:
    return (dt or now()).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def epoch(dt: datetime | None = None) -> int:
    return int((dt or now()).timestamp())


def parse_iso(value: str | None) -> datetime | None:
    """Parse ISO-8601 (with Z or offset). Returns None when value is falsy/invalid."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(UTC)
    except ValueError:
        return None


def new_case_id() -> str:
    """Sortable, human-friendly id: C-20261006T101500-ab12cd."""
    return f"C-{now().strftime('%Y%m%dT%H%M%S')}-{secrets.token_hex(3)}"


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {"level": record.levelname, "msg": record.getMessage(), "logger": record.name}
        extra = getattr(record, "ctx", None)
        if extra:
            payload.update(extra)
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def get_logger(name: str) -> logging.Logger:
    log = logging.getLogger(name)
    if not log.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JsonFormatter())
        log.addHandler(handler)
        log.propagate = False
    log.setLevel(_LEVEL)
    return log


def to_ddb(obj: Any) -> Any:
    """Recursively convert floats to Decimal and drop empty strings / None (DynamoDB-safe)."""
    if isinstance(obj, float):
        return Decimal(str(obj))
    if isinstance(obj, dict):
        return {k: to_ddb(v) for k, v in obj.items() if v is not None and v != ""}
    if isinstance(obj, (list, tuple)):
        return [to_ddb(v) for v in obj if v is not None]
    return obj


def from_ddb(obj: Any) -> Any:
    """Recursively convert Decimal to int/float and sets to sorted lists (JSON-safe)."""
    if isinstance(obj, Decimal):
        return int(obj) if obj == obj.to_integral_value() else float(obj)
    if isinstance(obj, dict):
        return {k: from_ddb(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [from_ddb(v) for v in obj]
    if isinstance(obj, (set, frozenset)):
        return sorted(from_ddb(v) for v in obj)
    return obj
