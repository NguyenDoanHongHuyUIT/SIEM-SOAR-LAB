"""Case lifecycle. Mirrors Figure 4 of the proposal (+ ACKNOWLEDGED for cases with no response plan)."""

from __future__ import annotations

from enum import StrEnum


class Status(StrEnum):
    NEW = "NEW"
    NOTIFIED = "NOTIFIED"
    APPROVED = "APPROVED"
    ISOLATING = "ISOLATING"
    ISOLATED = "ISOLATED"
    RESTORING = "RESTORING"
    RESTORED = "RESTORED"
    DISMISSED = "DISMISSED"
    EXPIRED = "EXPIRED"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    FAILED = "FAILED"


S = Status

TRANSITIONS: dict[Status, frozenset[Status]] = {
    S.NEW: frozenset({S.NOTIFIED, S.FAILED}),
    S.NOTIFIED: frozenset({S.APPROVED, S.DISMISSED, S.EXPIRED, S.ACKNOWLEDGED, S.FAILED}),
    S.APPROVED: frozenset({S.ISOLATING, S.FAILED}),
    S.ISOLATING: frozenset({S.ISOLATED, S.FAILED}),
    S.ISOLATED: frozenset({S.RESTORING, S.FAILED}),
    S.RESTORING: frozenset({S.RESTORED, S.FAILED}),
    S.RESTORED: frozenset(),
    S.DISMISSED: frozenset(),
    S.EXPIRED: frozenset(),
    S.ACKNOWLEDGED: frozenset(),
    S.FAILED: frozenset(),
}

TERMINAL = frozenset(s for s, nxt in TRANSITIONS.items() if not nxt)


def sources_for(target: Status) -> list[Status]:
    """All statuses from which `target` may be entered (used in DynamoDB condition expressions)."""
    return [src for src, nxt in TRANSITIONS.items() if target in nxt]


def is_terminal(status: str) -> bool:
    return Status(status) in TERMINAL
