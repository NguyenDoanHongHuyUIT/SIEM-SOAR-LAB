"""Small helpers: time, ids, DynamoDB <-> JSON conversion.

Logging is plain `logging`: the Lambda runtime emits JSON itself (`logging_config` in infra/modules/serverless-core).
"""

from __future__ import annotations

import secrets
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any


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
