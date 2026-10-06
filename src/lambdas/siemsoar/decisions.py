"""Human decisions: shared by the Slack callback Lambda and the soarctl CLI (same guards for both)."""

from __future__ import annotations

import json

from botocore.exceptions import ClientError

from . import aws
from .states import Status
from .store import CaseStore, InvalidTransition, TokenError
from .util import iso

APPROVAL_DECISIONS = {"approve": Status.APPROVED, "dismiss": Status.DISMISSED,
                      "acknowledge": Status.ACKNOWLEDGED}
RESTORE_DECISIONS = {"restore_tp", "restore_fp"}


class DecisionRejected(Exception):
    """Business-rule rejection (wrong state, double click, plan mismatch). Message is user-safe."""


def apply_decision(store: CaseStore, case_id: str, gate: str, decision: str, actor: str,
                   channel: str = "slack") -> dict:
    case = store.get_case(case_id)
    plan = case.get("response_plan", {}).get("type", "none")

    if not store.has_open_token(case_id, gate):
        raise DecisionRejected("no pending approval for this case (already decided or expired)")

    if gate == "approval":
        if decision not in APPROVAL_DECISIONS:
            raise DecisionRejected(f"unknown decision {decision!r}")
        if decision == "approve" and plan == "none":
            raise DecisionRejected("no response plan for this case; use acknowledge")
        if decision == "acknowledge" and plan != "none":
            raise DecisionRejected("this case has a response plan; use approve or dismiss")
        try:  # conditional on NOTIFIED: the first click wins, later clicks fail here
            store.transition(case_id, APPROVAL_DECISIONS[decision], actor=actor,
                             detail={"channel": channel, "decision": decision}, approver=actor)
        except InvalidTransition as err:
            raise DecisionRejected(f"already handled (status {err.current})") from err
    elif gate == "restore":
        if decision not in RESTORE_DECISIONS:
            raise DecisionRejected(f"unknown decision {decision!r}")
        if case["status"] != Status.ISOLATED:
            raise DecisionRejected(f"case is {case['status']}, restore needs ISOLATED")
    else:
        raise DecisionRejected(f"unknown gate {gate!r}")

    try:
        token = store.consume_token(case_id, gate)
    except TokenError as err:
        raise DecisionRejected(f"approval token unavailable: {type(err).__name__}") from err

    output = {"decision": decision, "actor": actor, "channel": channel, "decided_at": iso()}
    try:
        aws.client("stepfunctions").send_task_success(taskToken=token, output=json.dumps(output))
    except ClientError as err:
        code = err.response["Error"]["Code"]
        if code not in {"TaskTimedOut", "InvalidToken", "TaskDoesNotExist"}:
            store.release_token(case_id, gate)  # transient: allow a retry
        raise DecisionRejected(f"workflow no longer waiting ({code})") from err
    store.audit(case_id, f"decision:{gate}:{decision}", actor, {"channel": channel})
    return output
