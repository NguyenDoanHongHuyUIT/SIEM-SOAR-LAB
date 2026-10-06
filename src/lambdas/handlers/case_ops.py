"""Small case lifecycle operations used by the workflow: expire, acknowledge, dismiss feedback, fail-safe."""

from __future__ import annotations

from botocore.exceptions import ClientError
from siemsoar.notifier import notify_case
from siemsoar.states import TERMINAL, Status
from siemsoar.store import InvalidTransition
from siemsoar.util import epoch, get_logger, iso

from handlers._common import load, state_of

log = get_logger("handlers.case_ops")


def _expire(store, case, event):
    store.transition(case["case_id"], Status.EXPIRED, detail={"reason": "approval_timeout"})
    return {"status": "EXPIRED"}


def _record_feedback(store, case, event):
    """False-positive feedback loop: persisted per rule so `rulesctl tune-report` can propose tuning."""
    state = state_of(event)
    decision = (state.get("restore_decision") or state.get("approval") or {}).get("decision")
    store.table.put_item(Item={
        "pk": f"FEEDBACK#{case['rule_id']}", "sk": f"{iso()}#{case['case_id']}", "case_id": case["case_id"],
        "source": case["source"], "resource_id": case["resource_id"], "decision": decision,
        "run_id": case.get("run_id") or "", "ttl": epoch() + 180 * 86400})
    store.audit(case["case_id"], "fp_feedback_recorded", "system", {"rule_id": case["rule_id"]})
    return {"feedback": "recorded", "rule_id": case["rule_id"]}


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
        notify_case(case, "failed", extra=(f"Error: {err.get('Error', '?')} - {str(err.get('Cause', ''))[:300]}\n"
                                           f"Safe state: {safe}"))
    except (RuntimeError, ClientError):
        log.error("fail-safe notification failed", exc_info=True)
    return {"status": "FAILED", "safe_state": safe}


def _finalize_status(status: Status, reason: str):
    def run(store, case, event):
        if case["status"] != status:  # the human decision already moved the case; only converge if not
            store.transition(case["case_id"], status, detail={"reason": reason})
        return {"status": status.value}
    return run


OPS = {"expire": _expire, "feedback": _record_feedback, "fail_safe": _fail_safe,
       "acknowledged": _finalize_status(Status.ACKNOWLEDGED, "no_response_plan_ack")}


def handler(event, context=None):
    store, case = load(event)
    return OPS[event["op"]](store, case, event)
