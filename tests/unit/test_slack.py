import hashlib
import hmac
import json
import time
import urllib.parse

from siemsoar import slack


def _sign(secret, ts, body):
    return "v0=" + hmac.new(secret.encode(), f"v0:{ts}:{body}".encode(), hashlib.sha256).hexdigest()


def test_signature_valid_replay_and_tamper():
    ts, body = str(int(time.time())), "payload=%7B%7D"
    sig = _sign("s3cret", ts, body)
    assert slack.verify_signature("s3cret", ts, body, sig)
    assert not slack.verify_signature("s3cret", ts, body + "x", sig)
    assert not slack.verify_signature("other", ts, body, sig)
    old = str(int(time.time()) - 301)
    assert not slack.verify_signature("s3cret", old, body, _sign("s3cret", old, body))
    assert not slack.verify_signature("s3cret", "abc", body, sig)
    assert not slack.verify_signature("s3cret", ts, body, "")


def test_parse_interaction():
    payload = {"type": "block_actions", "actions": [{"value": "C-1|approval|approve"}]}
    body = "payload=" + urllib.parse.quote(json.dumps(payload))
    assert slack.parse_interaction(body) == payload


CASE = {"case_id": "C-1", "title": "T", "source": "guardduty", "rule_id": "r", "severity_label": "high",
        "resource": {"type": "ec2_instance", "id": "i-1"}, "response_plan": {"type": "ec2_isolate"},
        "mitre": ["T1110"], "risk_score": 77}


def test_cards_hold_only_case_id_gate_decision_never_token():
    blocks = slack.card_blocks({**CASE, "task_token": "SECRET-TOKEN"}, "approval")
    blob = json.dumps(blocks)
    assert "SECRET-TOKEN" not in blob
    values = [b["value"] for blk in blocks if blk["type"] == "actions" for b in blk["elements"]]
    assert values == ["C-1|approval|approve", "C-1|approval|dismiss"]
    restore = [b["value"] for blk in slack.card_blocks(CASE, "restore") if blk["type"] == "actions"
               for b in blk["elements"]]
    assert restore == ["C-1|restore|restore_tp", "C-1|restore|restore_fp"]


def test_no_plan_card_offers_acknowledge():
    case = {**CASE, "response_plan": {"type": "none"}}
    values = [b["value"] for blk in slack.card_blocks(case, "approval") if blk["type"] == "actions"
              for b in blk["elements"]]
    assert values == ["C-1|approval|acknowledge", "C-1|approval|dismiss"]


def test_respond_ignores_non_slack_hosts(monkeypatch):
    called = []
    monkeypatch.setattr(slack, "_request", lambda *a, **k: called.append(a))
    slack.respond("https://evil.example/x", "t", [])
    assert not called
