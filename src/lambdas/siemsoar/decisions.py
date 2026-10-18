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
                   channel: str = "slack", detail: dict | None = None) -> dict:
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
        target = APPROVAL_DECISIONS[decision]
        try:  # conditional on NOTIFIED: the first click wins, later clicks fail here
            store.transition(case_id, target, actor=actor, detail={"channel": channel, "decision": decision},
                             approver=actor)
        except InvalidTransition as err:
            # Same decision, token still open: an earlier attempt moved the case but could not reach Step Functions
            # (token was released). Resume it; the single-use token below still lets exactly one delivery through.
            if err.current != target:
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
    store.audit(case_id, f"decision:{gate}:{decision}", actor, {"channel": channel, **(detail or {})})
    from .notifier import close_card  # late import: notifier pulls the Slack/SNS clients

    close_card(store.get_case(case_id), f"*{decision}* by `{actor}` via {channel}")
    return output
