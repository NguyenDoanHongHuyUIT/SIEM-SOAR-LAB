"""Generate statemachine/case_workflow.asl.json (DRY: every task state is built by one helper).

Usage:
  python -m tools.gen_asl            # rewrite the JSON file
  python -m tools.gen_asl --check    # exit 1 if the committed file is stale (used by CI and tests)

`${fn_*}` placeholders are substituted by Terraform templatefile() with the Lambda ARNs.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "statemachine" / "case_workflow.asl.json"
LAMBDA_RETRY = [{"ErrorEquals": ["Lambda.ServiceException", "Lambda.AWSLambdaException",
                                 "Lambda.SdkClientException", "Lambda.TooManyRequestsException"],
                 "IntervalSeconds": 2, "MaxAttempts": 4, "BackoffRate": 2.0}]
FAIL_CATCH = {"ErrorEquals": ["States.ALL"], "ResultPath": "$.error", "Next": "FailSafe"}


def task(fn: str, op: str, step: str, next_: str, *, catch=None, extra=None) -> dict:
    payload = {"op": op, "state.$": "$", **(extra or {})}
    return {
        "Type": "Task", "Resource": "arn:aws:states:::lambda:invoke",
        "Parameters": {"FunctionName": "${fn_" + fn + "}", "Payload": payload},
        "ResultSelector": {"out.$": "$.Payload"}, "ResultPath": f"$.steps.{step}",
        "Retry": LAMBDA_RETRY, "Catch": catch or [FAIL_CATCH], "Next": next_,
    }


def wait_for_decision(gate: str, timeout_path: str, result_path: str, next_: str, on_timeout: str) -> dict:
    return {
        "Type": "Task", "Resource": "arn:aws:states:::lambda:invoke.waitForTaskToken",
        "Parameters": {"FunctionName": "${fn_notify}", "Payload": {
            "op": "request", "gate": gate, "state.$": "$", "task_token.$": "$$.Task.Token"}},
        "TimeoutSecondsPath": timeout_path, "ResultPath": result_path, "Retry": LAMBDA_RETRY,
        "Catch": [{"ErrorEquals": ["States.Timeout"], "ResultPath": "$.error", "Next": on_timeout}, FAIL_CATCH],
        "Next": next_,
    }


def info(kind: str, step: str, next_: str, *, catch=None) -> dict:
    return task("notify", "info", step, next_, catch=catch, extra={"kind": kind})


def build() -> dict:
    s: dict[str, dict] = {}
    s["Enrich"] = task("enrich", "enrich", "enrich", "NotifyApproval")
    s["NotifyApproval"] = wait_for_decision("approval", "$.config.approval_timeout", "$.approval",
                                           "ApprovalChoice", "MarkExpired")
    s["ApprovalChoice"] = {"Type": "Choice", "Default": "FailSafe", "Choices": [
        {"Variable": "$.approval.decision", "StringEquals": "approve", "Next": "Preflight"},
        {"Variable": "$.approval.decision", "StringEquals": "acknowledge", "Next": "MarkAcknowledged"},
        {"Variable": "$.approval.decision", "StringEquals": "dismiss", "Next": "RecordFeedbackDismiss"}]}
    s["MarkAcknowledged"] = task("case_ops", "acknowledged", "ack", "DoneAcknowledged")
    s["DoneAcknowledged"] = {"Type": "Succeed"}
    s["RecordFeedbackDismiss"] = task("case_ops", "feedback", "feedback", "DoneDismissed")
    s["DoneDismissed"] = {"Type": "Succeed"}
    s["MarkExpired"] = task("case_ops", "expire", "expire", "NotifyExpired")
    s["NotifyExpired"] = info("expired", "notify_expired", "DoneExpired",
                              catch=[{"ErrorEquals": ["States.ALL"], "ResultPath": "$.notify_error", "Next": "DoneExpired"}])
    s["DoneExpired"] = {"Type": "Succeed"}

    # ---- containment
    s["Preflight"] = task("preflight", "preflight", "preflight", "SaveState")
    s["SaveState"] = task("save_state", "save_state", "save_state", "PlanChoice")
    s["PlanChoice"] = {"Type": "Choice", "Default": "FailSafe", "Choices": [
        {"Variable": "$.steps.enrich.out.plan_type", "StringEquals": "ec2_isolate", "Next": "SnapshotEvidence"},
        {"Variable": "$.steps.enrich.out.plan_type", "StringEquals": "iam_key_disable", "Next": "DisableKey"}]}
    s["SnapshotEvidence"] = task("contain", "snapshot", "snapshot", "IsolateNetwork")
    s["IsolateNetwork"] = task("contain", "isolate_network", "isolate", "RevokeSessions")
    s["RevokeSessions"] = task("contain", "revoke_sessions", "revoke", "StopInstance")
    s["StopInstance"] = task("contain", "stop_instance", "stop", "VerifyContainment")
    s["DisableKey"] = task("contain", "disable_key", "disable_key", "RevokeUserSessions")
    s["RevokeUserSessions"] = task("contain", "revoke_user_sessions", "revoke", "VerifyContainment")
    s["VerifyContainment"] = task("contain", "verify", "verify", "NotifyIsolated")
    s["NotifyIsolated"] = info("isolated", "notify_isolated", "WaitRestoreDecision",
                               catch=[{"ErrorEquals": ["States.ALL"], "ResultPath": "$.notify_error",
                                       "Next": "WaitRestoreDecision"}])

    # ---- restore (second human gate)
    s["WaitRestoreDecision"] = wait_for_decision("restore", "$.config.restore_timeout", "$.restore_decision",
                                                 "ValidateRestore", "FailSafe")
    s["ValidateRestore"] = task("restore", "validate", "validate_restore", "RestoreAllowed")
    s["RestoreAllowed"] = {"Type": "Choice", "Default": "NotifyBlocked", "Choices": [
        {"Variable": "$.steps.validate_restore.out.ok", "BooleanEquals": True, "Next": "ExecuteRestore"}]}
    s["NotifyBlocked"] = info("blocked", "notify_blocked", "BlockedTerminal",
                              catch=[{"ErrorEquals": ["States.ALL"], "ResultPath": "$.notify_error",
                                      "Next": "BlockedTerminal"}])
    s["BlockedTerminal"] = {"Type": "Choice", "Default": "WaitRestoreDecision", "Choices": [
        {"Variable": "$.steps.validate_restore.out.terminal", "BooleanEquals": True, "Next": "SetBlockedError"}]}
    s["SetBlockedError"] = {"Type": "Pass", "ResultPath": "$.error", "Next": "FailSafe", "Result": {
        "Error": "RestoreBlocked", "Cause": "restore validation failed after the maximum number of attempts"}}
    s["ExecuteRestore"] = task("restore", "execute", "execute_restore", "VerifyRestore")
    s["VerifyRestore"] = task("restore", "verify", "verify_restore", "WasFalsePositive")
    s["WasFalsePositive"] = {"Type": "Choice", "Default": "NotifyRestored", "Choices": [
        {"Variable": "$.restore_decision.decision", "StringEquals": "restore_fp", "Next": "RecordFeedbackFP"}]}
    s["RecordFeedbackFP"] = task("case_ops", "feedback", "feedback", "NotifyRestored")
    s["NotifyRestored"] = info("restored", "notify_restored", "DoneRestored",
                               catch=[{"ErrorEquals": ["States.ALL"], "ResultPath": "$.notify_error", "Next": "DoneRestored"}])
    s["DoneRestored"] = {"Type": "Succeed"}

    # ---- fail safe: keep the safe state reached, alert humans, fail the execution (CloudWatch alarm)
    s["FailSafe"] = task("case_ops", "fail_safe", "fail_safe", "CaseFailed",
                         catch=[{"ErrorEquals": ["States.ALL"], "ResultPath": "$.fail_safe_error", "Next": "CaseFailed"}])
    s["CaseFailed"] = {"Type": "Fail", "Error": "CaseFailedSafe",
                       "Cause": "Workflow failed; the last safe state was kept and operators were alerted"}
    return {"Comment": "SIEM/SOAR case workflow: enrich -> approve -> contain -> verify -> restore (generated by "
                       "tools/gen_asl.py)", "StartAt": "Enrich", "TimeoutSeconds": 1209600, "States": s}


def render() -> str:
    return json.dumps(build(), indent=2) + "\n"


def main(argv: list[str]) -> int:
    text = render()
    if "--check" in argv:
        if not OUT.exists() or OUT.read_text() != text:
            print(f"{OUT} is stale: run `python -m tools.gen_asl`", file=sys.stderr)
            return 1
        return 0
    OUT.write_text(text)
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
