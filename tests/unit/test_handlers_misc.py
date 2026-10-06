import base64
import hashlib
import hmac
import json
import os
import time
import urllib.parse

import boto3
import pytest
from handlers import ingest as ingest_handler
from handlers import lab_session, notify, slack_interact
from siemsoar import notifier, slack, ssm

from tests.fixtures import events as ev

R = "ap-southeast-1"


# ------------------------------------------------------------------ Slack HTTP entry point
def _put_params(secret="sign-secret", approvers="U1,U2"):
    c = boto3.client("ssm", region_name=R)
    c.put_parameter(Name="/siemsoar/slack/signing_secret", Value=secret, Type="SecureString")
    c.put_parameter(Name="/siemsoar/slack/approver_ids", Value=approvers, Type="String")


def _request(case_id, decision, user="U1", gate="approval", secret="sign-secret", ts=None, retry=False, b64=False):
    payload = {"type": "block_actions", "user": {"id": user}, "response_url": "https://hooks.slack.com/actions/x",
               "actions": [{"action_id": "decide", "value": f"{case_id}|{gate}|{decision}"}]}
    body = "payload=" + urllib.parse.quote(json.dumps(payload))
    ts = ts or str(int(time.time()))
    sig = "v0=" + hmac.new(secret.encode(), f"v0:{ts}:{body}".encode(), hashlib.sha256).hexdigest()
    headers = {"X-Slack-Request-Timestamp": ts, "X-Slack-Signature": sig}
    if retry:
        headers["X-Slack-Retry-Num"] = "1"
    return {"headers": headers, "body": base64.b64encode(body.encode()).decode() if b64 else body, "isBase64Encoded": b64}


@pytest.fixture
def notified(store, sfn, monkeypatch):
    _put_params()
    monkeypatch.setattr(slack, "respond", lambda *a, **k: None)
    cid = ingest_handler.handler(ev.guardduty_instance())["case_id"]
    notify.handler({"op": "request", "gate": "approval", "task_token": "TT", "state": {
        "case_id": cid, "config": {"approval_timeout": 60}}})
    return cid


def test_slack_endpoint_happy_path_and_double_click(store, sfn, notified):
    res = slack_interact.handler(_request(notified, "approve", b64=True))
    assert res["statusCode"] == 200 and not json.loads(res["body"]).get("text")
    assert store.get_case(notified)["status"] == "APPROVED"
    assert sfn.success[0][0] == "TT" and sfn.success[0][1]["actor"] == "slack:U1"
    again = json.loads(slack_interact.handler(_request(notified, "approve"))["body"])
    assert "already handled" in again["text"] or "no pending approval" in again["text"]
    assert len(sfn.success) == 1


def test_slack_endpoint_rejects_bad_signature_replay_and_unknown_user(store, sfn, notified):
    assert slack_interact.handler(_request(notified, "approve", secret="wrong"))["statusCode"] == 401
    old = str(int(time.time()) - 3600)
    assert slack_interact.handler(_request(notified, "approve", ts=old))["statusCode"] == 401
    denied = slack_interact.handler(_request(notified, "approve", user="UEVIL"))
    assert "not an authorised approver" in json.loads(denied["body"])["text"]
    assert store.get_case(notified)["status"] == "NOTIFIED" and not sfn.success
    assert "decision_denied" in [a["action"] for a in store.list_audit(notified)]
    assert slack_interact.handler(_request(notified, "approve", retry=True))["statusCode"] == 200
    assert store.get_case(notified)["status"] == "NOTIFIED"


def test_slack_endpoint_placeholder_secret_is_rejected(store, sfn):
    boto3.client("ssm", region_name=R).put_parameter(Name="/siemsoar/slack/signing_secret", Value="CHANGE_ME", Type="String")
    assert slack_interact.handler(_request("C-1", "approve", secret="CHANGE_ME"))["statusCode"] == 401


# ------------------------------------------------------------------ notifier
def test_notify_falls_back_to_sns_when_slack_down(store, sfn, monkeypatch):
    boto3.client("ssm", region_name=R).put_parameter(Name="/siemsoar/slack/bot_token", Value="xoxb-1", Type="SecureString")
    boto3.client("ssm", region_name=R).put_parameter(Name="/siemsoar/slack/channel", Value="C123", Type="String")
    ssm.clear()

    def boom(*a, **k):
        raise OSError("slack unreachable")

    monkeypatch.setattr(slack, "post_message", boom)
    cid = ingest_handler.handler(ev.guardduty_instance())["case_id"]
    out = notify.handler({"op": "request", "gate": "approval", "task_token": "T", "state": {"case_id": cid, "config": {}}})
    assert out == {"slack": False, "sns": True}
    assert store.get_case(cid)["status"] == "NOTIFIED"  # workflow keeps waiting: operators can use soarctl


def test_notify_uses_slack_when_available(store, sfn, monkeypatch):
    c = boto3.client("ssm", region_name=R)
    c.put_parameter(Name="/siemsoar/slack/bot_token", Value="xoxb-1", Type="SecureString")
    c.put_parameter(Name="/siemsoar/slack/channel", Value="C123", Type="String")
    ssm.clear()
    sent = []
    monkeypatch.setattr(slack, "post_message", lambda token, ch, text, blocks: sent.append((ch, blocks)) or {"ok": True})
    cid = ingest_handler.handler(ev.guardduty_instance())["case_id"]
    out = notify.handler({"op": "request", "gate": "approval", "task_token": "SECRET-TASK-TOKEN-XYZ",
                          "state": {"case_id": cid, "config": {}}})
    assert out["slack"] and sent[0][0] == "C123"
    assert "SECRET-TASK-TOKEN-XYZ" not in json.dumps(sent[0][1])  # token stays server side


def test_notify_raises_when_no_channel_at_all(store, sfn, monkeypatch):
    cid = ingest_handler.handler(ev.guardduty_instance())["case_id"]
    monkeypatch.setattr(notifier, "sns_publish", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("sns down")))
    with pytest.raises(RuntimeError):
        notify.handler({"op": "info", "kind": "isolated", "state": {"case_id": cid}})


# ------------------------------------------------------------------ lab session
@pytest.fixture
def lab_env(monkeypatch):
    monkeypatch.setenv("SCHEDULER_ROLE_ARN", "arn:aws:iam::123456789012:role/sched")
    monkeypatch.setenv("SELF_FUNCTION_ARN", "arn:aws:lambda:ap-southeast-1:123456789012:function:siemsoar-lab_session")
    monkeypatch.setenv("LAB_NAME_PREFIX", "siemsoar")
    ec2 = boto3.client("ec2", region_name=R)
    ids = []
    for role in ("wazuh-manager", "suricata-sensor"):
        r = ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1, TagSpecifications=[{
            "ResourceType": "instance", "Tags": [{"Key": "siemsoar:plane", "Value": "ondemand"},
                                                 {"Key": "siemsoar:role", "Value": role}]}])
        ids.append(r["Instances"][0]["InstanceId"])
    other = ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1)["Instances"][0]["InstanceId"]
    return ec2, ids, other


def _state(ec2, iid):
    return ec2.describe_instances(InstanceIds=[iid])["Reservations"][0]["Instances"][0]["State"]["Name"]


def test_lab_session_stop_start_and_timer(lab_env):
    ec2, ids, other = lab_env
    out = lab_session.handler({"action": "stop"})
    assert sorted(out["stopped"]) == sorted(ids)
    assert all(_state(ec2, i) == "stopped" for i in ids) and _state(ec2, other) == "running"  # untagged untouched
    out = lab_session.handler({"action": "start", "hours": 99})
    assert sorted(out["started"]) == sorted(ids) and out["auto_stop_at"].endswith("Z")
    assert all(_state(ec2, i) == "running" for i in ids)
    status = lab_session.handler({"action": "status"})
    assert status["auto_stop"].startswith("at(")
    lab_session.handler({"action": "stop", "reason": "auto-stop timer"})  # the timer firing keeps nothing armed
    assert all(_state(ec2, i) == "stopped" for i in ids)
    lab_session.handler({"action": "stop"})
    assert lab_session.handler({"action": "status"})["auto_stop"] is None


def test_lab_session_unknown_action(lab_env):
    with pytest.raises(ValueError):
        lab_session.handler({"action": "explode"})


def test_lab_session_caps_hours(lab_env):
    out = lab_session.handler({"action": "start", "hours": 500})
    sched = boto3.client("scheduler", region_name=R).get_schedule(Name="siemsoar-lab-autostop")
    assert sched["ScheduleExpression"].startswith("at(")
    assert out["auto_stop_at"][:10] >= time.strftime("%Y-%m-%d", time.gmtime())
    assert os.environ["LAB_NAME_PREFIX"] == "siemsoar"


def test_injected_slack_fault_uses_sns_fallback(store, sfn, monkeypatch):
    c = boto3.client("ssm", region_name=R)
    c.put_parameter(Name="/siemsoar/slack/bot_token", Value="xoxb-1", Type="SecureString")
    c.put_parameter(Name="/siemsoar/slack/channel", Value="C123", Type="String")
    ssm.clear()
    called = []
    monkeypatch.setattr(slack, "post_message", lambda *a, **k: called.append(1) or {"ok": True})
    monkeypatch.setenv("LAB_FAULTS_ENABLED", "true")
    monkeypatch.setenv("FAULT_INJECT", "notify.slack")
    cid = ingest_handler.handler(ev.guardduty_instance())["case_id"]
    out = notify.handler({"op": "request", "gate": "approval", "task_token": "T", "state": {"case_id": cid, "config": {}}})
    assert out == {"slack": False, "sns": True} and not called
