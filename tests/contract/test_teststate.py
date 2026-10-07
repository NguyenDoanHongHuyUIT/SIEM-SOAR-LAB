"""Contract tests of the generated state machine against the REAL Step Functions service (TestState API).

tests/asl_runner.py is a fast offline harness written by hand; this file checks the same definition with AWS's own
interpreter, so JSONPath, intrinsics (States.Format/UUID/Array), Choice rules, Retry/Catch routing and the
`.waitForTaskToken` context are validated by the service instead of by our re-implementation.
(Step Functions Local is marked "unsupported" by AWS; TestState with mocks is the recommended replacement.)

  RUN_TESTSTATE=1 AWS_REGION=ap-southeast-1 pytest tests/contract      # needs credentials with states:TestState

Mocked task results are validated by the service against the API model of the integrated service (fieldValidationMode
STRICT), so a wrong mock fails instead of silently passing. Without RUN_TESTSTATE the requests are still validated
offline against the botocore model of the API (shape of every parameter), so typos in this file are caught anywhere.
"""

import json
import os
from pathlib import Path

import boto3
import pytest
from botocore.session import get_session
from botocore.validate import validate_parameters

ASL_PATH = Path(__file__).resolve().parents[2] / "statemachine" / "case_workflow.asl.json"
REGION = os.environ.get("AWS_REGION", "ap-southeast-1")

STOPPED = {"StoppingInstances": [{"InstanceId": "i-0abc", "CurrentState": {"Code": 64, "Name": "stopping"},
                                  "PreviousState": {"Code": 16, "Name": "running"}}]}
BASE = {"case_id": "C-1", "config": {"dry_run": False},
        "steps": {"enrich": {"out": {"stop_instance": True, "plan_type": "ec2_isolate",
                                     "plan_params": {"instance_id": "i-0abc", "user_name": "lab-alice",
                                                     "access_key_id": "AKIAEXAMPLE"}}}}}


def _state(**over):
    out = json.loads(json.dumps(BASE))
    for k, v in over.items():
        out.setdefault(k, {}).update(v) if isinstance(v, dict) else out.__setitem__(k, v)
    return out


ERR = {"errorOutput": {"error": "Ec2.Ec2Exception", "cause": "UnauthorizedOperation"}}

# (id, stateName, input, kwargs for test_state, expected status, expected nextState)
CASES = [
    ("stop-live", "ShouldStopInstance", BASE, {}, "SUCCEEDED", "StopInstance"),
    ("stop-dry-run", "ShouldStopInstance", _state(config={"dry_run": True}), {}, "SUCCEEDED", "AuditStopSkipped"),
    ("stop-low-risk", "ShouldStopInstance",
     _state(steps={"enrich": {"out": {"stop_instance": False}}}), {}, "SUCCEEDED", "AuditStopSkipped"),
    ("stop-sdk-ok", "StopInstance", BASE, {"mock": {"result": json.dumps(STOPPED)}}, "SUCCEEDED", "MarkInstanceStopped"),
    ("stop-sdk-retriable", "StopInstance", BASE, {"mock": ERR, "stateConfiguration": {"retrierRetryCount": 0}},
     "RETRIABLE", None),
    ("stop-sdk-exhausted-goes-to-failsafe", "StopInstance", BASE,
     {"mock": ERR, "stateConfiguration": {"retrierRetryCount": 3}}, "CAUGHT_ERROR", "FailSafe"),
    ("mark-stopped", "MarkInstanceStopped", BASE,
     {"mock": {"result": "{}"}, "context": json.dumps({"State": {"EnteredTime": "2026-10-07T10:00:00.000Z"}})},
     "SUCCEEDED", "AuditStopped"),
    ("audit-stopped", "AuditStopped", BASE,
     {"mock": {"result": "{}"}, "context": json.dumps({"State": {"EnteredTime": "2026-10-07T10:00:00.000Z"}})},
     "SUCCEEDED", "VerifyContainment"),
    ("key-live", "ShouldDisableKey", BASE, {}, "SUCCEEDED", "DisableKey"),
    ("key-dry-run", "ShouldDisableKey", _state(config={"dry_run": True}), {}, "SUCCEEDED", "AuditKeyDisableSkipped"),
    ("key-sdk-ok", "DisableKey", BASE, {"mock": {"result": "{}"}}, "SUCCEEDED", "AuditKeyDisabled"),
    ("plan-ec2", "PlanChoice", BASE, {}, "SUCCEEDED", "SnapshotEvidence"),
    ("plan-iam", "PlanChoice", _state(steps={"enrich": {"out": {"plan_type": "iam_key_disable"}}}), {},
     "SUCCEEDED", "ShouldDisableKey"),
    ("approve", "ApprovalChoice", _state(approval={"decision": "approve"}), {}, "SUCCEEDED", "Preflight"),
    ("dismiss", "ApprovalChoice", _state(approval={"decision": "dismiss"}), {}, "SUCCEEDED", "RecordFeedbackDismiss"),
    ("unknown-decision-fails-safe", "ApprovalChoice", _state(approval={"decision": "???"}), {}, "SUCCEEDED", "FailSafe"),
    ("human-gate-answer", "NotifyApproval", _state(config={"approval_timeout": 60}),
     {"mock": {"result": json.dumps({"decision": "approve"})}, "context": json.dumps({"Task": {"Token": "tok"}})},
     "SUCCEEDED", "ApprovalChoice"),
    ("human-gate-timeout-expires-case", "NotifyApproval", _state(config={"approval_timeout": 60}),
     {"mock": {"errorOutput": {"error": "States.Timeout", "cause": "no decision"}},
      "context": json.dumps({"Task": {"Token": "tok"}})}, "CAUGHT_ERROR", "MarkExpired"),
]


def _definition() -> str:
    text = ASL_PATH.read_text().replace("${table_name}", "siemsoar-cases")
    for fn in ("enrich", "notify", "preflight", "save_state", "contain", "restore", "case_ops"):
        text = text.replace("${fn_" + fn + "}", f"arn:aws:lambda:{REGION}:123456789012:function:siemsoar-{fn}")
    assert "${" not in text, "unsubstituted template placeholder"
    return text


def _request(state: str, payload: dict, extra: dict) -> dict:
    return {"definition": _definition(), "stateName": state, "input": json.dumps(payload), "inspectionLevel": "INFO", **extra}


@pytest.mark.parametrize("case", CASES, ids=[c[0] for c in CASES])
def test_requests_match_the_teststate_api_model(case):
    """Offline: every request is well formed for the TestState API and refers to a real state."""
    _, state, payload, extra, _, _ = case
    req = _request(state, payload, extra)
    validate_parameters(req, get_session().get_service_model("stepfunctions").operation_model("TestState").input_shape)
    assert state in json.loads(req["definition"])["States"]


@pytest.mark.skipif(not os.environ.get("RUN_TESTSTATE"), reason="set RUN_TESTSTATE=1 (needs AWS credentials with states:TestState)")
@pytest.mark.parametrize("case", CASES, ids=[c[0] for c in CASES])
def test_state_behaves_as_designed_on_the_real_service(case):
    _, state, payload, extra, status, next_state = case
    res = boto3.client("stepfunctions", region_name=REGION).test_state(**_request(state, payload, extra))
    assert res["status"] == status, res
    if next_state:
        assert res.get("nextState") == next_state, res
