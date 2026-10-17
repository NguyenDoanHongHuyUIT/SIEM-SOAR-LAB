"""Slack + SNS notifications.

op=request  (waitForTaskToken): store the task token server side, post the decision card.
op=info     : plain status notification.
"""

from __future__ import annotations

from siemsoar.notifier import notify_case
from siemsoar.states import Status
from siemsoar.store import InvalidTransition

from handlers._common import config_of, load, state_of


def _extra(kind: str, case: dict, state: dict) -> str:
    steps = state.get("steps", {})
    if kind == "isolated":
        v = steps.get("verify", {}).get("out", {})
        evidence_key = case.get("pre_action_state_ref", {}).get("key", "-")
        return f"Verified: {v.get('summary', 'containment verified')}. Evidence: {evidence_key}"
    if kind == "restored":
        return f"Verdict: {case.get('verdict', '?')}. Restore verified."
    if kind == "blocked":
        return "Reasons: " + "; ".join(steps.get("validate_restore", {}).get("out", {}).get("reasons", []))
    if kind == "failed":
        err = state.get("error", {})
        return f"Error: {err.get('Error', '?')} - {str(err.get('Cause', ''))[:300]}\nSafe state: {case.get('safe_state', '-')}"
    if kind == "expired":
        return "No decision before the approval timeout. No change was made."
    if kind in {"dismissed", "acknowledged"}:
        return f"By {case.get('approver', 'n/a')}"
    return ""


def handler(event, context=None):
    store, case = load(event)
    state = state_of(event)
    if event.get("op") == "request":
        gate = event["gate"]
        timeout = config_of(event).get("approval_timeout" if gate == "approval" else "restore_timeout", 3600)
        store.save_token(case["case_id"], gate, event["task_token"], timeout)
        if gate == "approval":
            try:
                store.transition(case["case_id"], Status.NOTIFIED, detail={"gate": gate})
            except InvalidTransition as err:  # Lambda retry after a partial success
                if err.current != Status.NOTIFIED:
                    raise
        case = store.get_case(case["case_id"])
        sent = notify_case(case, gate, gate=gate)
        store.audit(case["case_id"], f"notified:{gate}", "system", sent)
        return sent
    kind = event["kind"]
    sent = notify_case(case, kind, extra=_extra(kind, case, state))
    store.audit(case["case_id"], f"notified:{kind}", "system", sent)
    return sent

