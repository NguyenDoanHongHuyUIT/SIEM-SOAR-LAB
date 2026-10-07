"""Ingest pipeline: dedup, create case, start the Step Functions workflow."""

from __future__ import annotations

import json
from collections.abc import Callable

from botocore.exceptions import ClientError

from . import aws
from .config import settings
from .states import Status, is_terminal
from .store import CaseStore
from .util import get_logger, new_case_id

log = get_logger("ingest")


def store_raw(alert: dict) -> str | None:
    """Persist the raw alert as evidence (best effort: never block case creation)."""
    bucket = settings().evidence_bucket
    if not bucket:
        return None
    key = f"raw/{alert['event_time'][:10]}/{alert['source']}-{alert['source_id']}.json"
    try:
        aws.client("s3").put_object(Bucket=bucket, Key=key, Body=json.dumps(alert["raw"], default=str).encode(),
                                    ContentType="application/json")
        return key
    except ClientError:
        log.warning("raw alert store failed", exc_info=True)
        return None


def _start(case_id: str) -> str:
    cfg = settings()
    res = aws.client("stepfunctions").start_execution(
        stateMachineArn=cfg.state_machine_arn, name=case_id,
        input=json.dumps({"case_id": case_id, "config": cfg.workflow_config()}))
    return res["executionArn"]


def ingest(alert: dict, store: CaseStore | None = None,
           start: Callable[[str], str] | None = None) -> dict:
    """Returns {"case_id", "action": created|deduplicated|duplicate_delivery}."""
    store, start, cfg = store or CaseStore(), start or _start, settings()
    if not store.first_delivery(f"{alert['source']}:{alert['source_id']}"):
        return {"action": "duplicate_delivery", "source_id": alert["source_id"]}

    case_id = new_case_id()
    for _ in range(2):  # second pass only if the dedup target is already closed
        existing = store.acquire_dedup(alert["dedup_key"], case_id, cfg.dedup_window)
        if existing is None:
            break
        status = store.get_case(existing)["status"]
        if is_terminal(status):
            store.release_dedup(alert["dedup_key"], existing)
            continue
        store.bump_alert(existing, alert["event_time"], alert["source_id"])
        return {"case_id": existing, "action": "deduplicated"}
    else:  # pragma: no cover - contention on a closed case twice in a row
        raise RuntimeError("could not acquire dedup lock")

    resource = alert["resource"]
    store.create_case({
        "case_id": case_id, "status": Status.NEW.value, "source": alert["source"],
        "source_id": alert["source_id"], "rule_id": alert["rule_id"], "title": alert["title"],
        "description": alert["description"], "severity": alert["severity"],
        "severity_label": alert["severity_label"], "event_time": alert["event_time"],
        "resource": resource, "resource_id": resource["id"], "mitre": alert["mitre"],
        "response_plan": alert["response_plan"], "dedup_key": alert["dedup_key"],
        "sample": alert.get("sample", False), "run_id": alert.get("run_id"),
        "extra": alert.get("extra"), "raw_ref": store_raw(alert),
    })
    try:
        execution_arn = start(case_id)
    except Exception as err:
        store.release_dedup(alert["dedup_key"], case_id)
        store.transition(case_id, Status.FAILED, detail={"reason": "start_execution_failed", "error": str(err)})
        raise
    store.update_case(case_id, execution_arn=execution_arn)
    log.info("case created", extra={"ctx": {"case_id": case_id, "source": alert["source"]}})
    return {"case_id": case_id, "action": "created", "execution_arn": execution_arn}
