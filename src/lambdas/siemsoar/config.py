"""Runtime configuration, read lazily from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def _int(name: str, default: int) -> int:
    try:
        return int(_env(name, str(default)))
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    table: str
    evidence_bucket: str
    topic_arn: str
    state_machine_arn: str
    name_prefix: str
    dedup_window: int
    approval_timeout: int
    restore_timeout: int
    breaker_limit: int
    breaker_window: int
    stop_risk_threshold: int
    dry_run: bool
    iam_target_prefix: str
    protected_tag: str
    zone_tag: str
    slack_channel: str

    def workflow_config(self) -> dict:
        """Config frozen into each execution input so a running case is not affected by later changes."""
        return {
            "approval_timeout": self.approval_timeout,
            "restore_timeout": self.restore_timeout,
            "stop_risk_threshold": self.stop_risk_threshold,
            "breaker_limit": self.breaker_limit,
            "breaker_window": self.breaker_window,
            "dry_run": self.dry_run,
        }


def settings() -> Settings:
    return Settings(
        table=_env("CASES_TABLE", "siemsoar-cases"),
        evidence_bucket=_env("EVIDENCE_BUCKET"),
        topic_arn=_env("NOTIFY_TOPIC_ARN"),
        state_machine_arn=_env("STATE_MACHINE_ARN"),
        name_prefix=_env("NAME_PREFIX", "siemsoar"),
        dedup_window=_int("DEDUP_WINDOW_SECONDS", 3600),
        approval_timeout=_int("APPROVAL_TIMEOUT_SECONDS", 3600),
        restore_timeout=_int("RESTORE_TIMEOUT_SECONDS", 86400),
        breaker_limit=_int("BREAKER_LIMIT", 3),
        breaker_window=_int("BREAKER_WINDOW_SECONDS", 3600),
        stop_risk_threshold=_int("STOP_RISK_THRESHOLD", 85),
        dry_run=_env("DRY_RUN", "false").lower() == "true",
        iam_target_prefix=_env("IAM_TARGET_PREFIX", "lab-"),
        protected_tag=_env("PROTECTED_TAG", "siemsoar:protected"),
        zone_tag=_env("ZONE_TAG", "siemsoar:zone"),
        slack_channel=_env("SLACK_CHANNEL", ""),
    )
