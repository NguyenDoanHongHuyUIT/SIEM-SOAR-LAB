"""Small case lifecycle operations used by the workflow: expire, acknowledge, fail-safe."""

from __future__ import annotations

import logging

from botocore.exceptions import ClientError
from siemsoar.notifier import notify_case
from siemsoar.states import TERMINAL, Status
from siemsoar.store import InvalidTransition

from handlers._common import load, state_of

log = logging.getLogger("handlers.case_ops")


def _expire(store, case, event):
    store.transition(case["case_id"], Status.EXPIRED, detail={"reason": "approval_timeout"})
    return {"status": "EXPIRED"}


def _fail_safe(store, case, event):
    """Keep whatever safe state was reached; never roll back automatically. Alert the operator."""
    err = state_of(event).get("error", {})
    status = case["status"]
    if status in {Status.ISOLATING, Status.ISOLATED, Status.RESTORING}:
        safe = "resource left CONTAINED (isolation/disabled key retained); manual review required"
    else:
        safe = "no containment change was applied"
    try:
        store.transition(case["case_id"], Status.FAILED, detail={"error": err.get("Error"), "safe_state": safe},
                         failure_error=err.get("Error"), failure_cause=str(err.get("Cause", ""))[:500],
                         safe_state=safe)
    except InvalidTransition as exc:
        if exc.current not in TERMINAL:
            raise
    case = store.get_case(case["case_id"])
    try:
        sent = notify_case(case, "failed", extra=(f"Error: {err.get('Error', '?')} - {str(err.get('Cause', ''))[:300]}\n"
                                                  f"Safe state: {safe}"))
        store.audit(case["case_id"], "notified:failed", "system", sent)
    except (RuntimeError, ClientError):
        log.error("fail-safe notification failed", exc_info=True)
        store.audit(case["case_id"], "notify_failed", "system", {"kind": "failed"})
    return {"status": "FAILED", "safe_state": safe}


def _finalize_status(status: Status, reason: str):
    def run(store, case, event):
        if case["status"] != status:  # the human decision already moved the case; only converge if not
            store.transition(case["case_id"], status, detail={"reason": reason})
        return {"status": status.value}
    return run


OPS = {"expire": _expire, "fail_safe": _fail_safe,
       "acknowledged": _finalize_status(Status.ACKNOWLEDGED, "no_response_plan_ack")}


def handler(event, context=None):
    store, case = load(event)
    return OPS[event["op"]](store, case, event)
