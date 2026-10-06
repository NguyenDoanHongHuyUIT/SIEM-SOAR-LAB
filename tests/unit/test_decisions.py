import json

import pytest
from handlers import ingest as ingest_handler
from handlers import notify as notify_handler
from siemsoar.decisions import DecisionRejected, apply_decision
from siemsoar.states import Status

from tests.fixtures import events as ev


def _notified_case(store, event=None, token="TASK-TOKEN"):
    cid = ingest_handler.handler(event or ev.guardduty_instance())["case_id"]
    notify_handler.handler({"op": "request", "gate": "approval", "task_token": token,
                            "state": {"case_id": cid, "config": {"approval_timeout": 60}}})
    return cid


def test_request_stores_token_and_marks_notified(store, sfn):
    cid = _notified_case(store)
    assert store.get_case(cid)["status"] == "NOTIFIED"
    assert store.has_open_token(cid, "approval")


def test_approve_moves_state_and_resumes_workflow_once(store, sfn):
    cid = _notified_case(store)
    out = apply_decision(store, cid, "approval", "approve", "slack:U1")
    assert out["decision"] == "approve"
    assert store.get_case(cid)["status"] == "APPROVED" and store.get_case(cid)["approver"] == "slack:U1"
    assert sfn.success == [("TASK-TOKEN", {**out})]
    with pytest.raises(DecisionRejected):  # double click
        apply_decision(store, cid, "approval", "approve", "slack:U2")
    with pytest.raises(DecisionRejected):  # conflicting second click
        apply_decision(store, cid, "approval", "dismiss", "slack:U2")
    assert len(sfn.success) == 1


def test_dismiss(store, sfn):
    cid = _notified_case(store)
    apply_decision(store, cid, "approval", "dismiss", "slack:U1")
    assert store.get_case(cid)["status"] == "DISMISSED"
    assert json.dumps(sfn.success[0][1])  # JSON serialisable


def test_plan_mismatch_rejected_without_consuming_token(store, sfn):
    cid = _notified_case(store, ev.SURICATA)  # response plan none
    with pytest.raises(DecisionRejected):
        apply_decision(store, cid, "approval", "approve", "slack:U1")
    assert store.has_open_token(cid, "approval")
    apply_decision(store, cid, "approval", "acknowledge", "slack:U1")
    assert store.get_case(cid)["status"] == "ACKNOWLEDGED"


def test_unknown_values_and_missing_token(store, sfn):
    cid = ingest_handler.handler(ev.guardduty_instance())["case_id"]
    with pytest.raises(DecisionRejected):
        apply_decision(store, cid, "approval", "approve", "x")  # no token yet (not notified)
    cid2 = _notified_case(store, ev.guardduty_instance(fid="g2", instance_id="i-0bbb1234def567890"))
    with pytest.raises(DecisionRejected):
        apply_decision(store, cid2, "approval", "nuke", "x")
    with pytest.raises(DecisionRejected):
        apply_decision(store, cid2, "restore", "restore_tp", "x")
    with pytest.raises(DecisionRejected):
        apply_decision(store, cid2, "weird", "x", "x")


def test_expired_workflow_does_not_leave_case_approved(store, sfn):
    cid = _notified_case(store)
    store.transition(cid, Status.EXPIRED)
    with pytest.raises(DecisionRejected):
        apply_decision(store, cid, "approval", "approve", "slack:U1")
    assert store.get_case(cid)["status"] == "EXPIRED"
