import pytest
from siemsoar import schema

from tests.fixtures import events as ev


def test_guardduty_instance_maps_to_ec2_plan():
    a = schema.normalize_event(ev.guardduty_instance())
    assert a["source"] == "guardduty"
    assert a["resource"] == {"type": "ec2_instance", "id": "i-0abc1234def567890",
                             "region": "ap-southeast-1", "account": "123456789012"}
    assert a["response_plan"] == {"type": "ec2_isolate", "params": {"instance_id": "i-0abc1234def567890"}}
    assert a["severity"] == pytest.approx(89.9, abs=0.1)
    assert a["severity_label"] == "critical"
    assert a["mitre"] == ["T1110.001"]
    assert a["event_time"] == "2026-10-06T09:59:00.000Z"


def test_guardduty_access_key_maps_to_iam_plan():
    a = schema.normalize_event(ev.guardduty_key())
    assert a["response_plan"]["type"] == "iam_key_disable"
    assert a["response_plan"]["params"] == {"user_name": "lab-alice", "access_key_id": "AKIAIOSFODNN7EXAMPLE"}
    assert a["resource"]["id"] == "lab-alice/AKIAIOSFODNN7EXAMPLE"


def test_guardduty_sample_flag_and_fake_instance_id():
    a = schema.normalize_event(ev.guardduty_instance("i-99999999", sample=True))
    assert a["sample"] is True
    assert a["response_plan"]["type"] == "ec2_isolate"  # downgraded later by enrichment if missing


def test_guardduty_unknown_resource_has_no_plan():
    e = ev.clone(ev.guardduty_instance())
    e["detail"]["resource"] = {"resourceType": "S3Bucket"}
    assert schema.normalize_event(e)["response_plan"]["type"] == "none"


def test_wazuh_alert_uses_agent_instance_and_run_id():
    a = schema.normalize_event(ev.WAZUH_FIM)
    assert a["source"] == "wazuh" and a["rule_id"] == "100100"
    assert a["run_id"] == "run-20261006-01"
    assert a["response_plan"]["params"]["instance_id"] == "i-0abc1234def567890"
    assert a["mitre"] == ["T1136.001"]
    assert a["severity"] == 80.0


def test_wazuh_plan_requires_instance_id_agent_name():
    e = ev.clone(ev.WAZUH_FIM)
    e["detail"]["agent"]["name"] = "ubuntu-box"
    assert schema.normalize_event(e)["response_plan"]["type"] == "none"


def test_suricata_alert_detected_via_group_and_no_response_plan():
    a = schema.normalize_event(ev.SURICATA)
    assert a["source"] == "suricata"
    assert a["title"] == "SIEMSOAR-LAB path traversal"
    assert a["response_plan"]["type"] == "none"


def test_dedup_key_stable_and_distinguishes_src_ip():
    a, b = schema.normalize_event(ev.SURICATA), schema.normalize_event(ev.SURICATA)
    assert a["dedup_key"] == b["dedup_key"]
    e = ev.clone(ev.SURICATA)
    e["detail"]["data"]["src_ip"] = "10.0.1.100"
    assert schema.normalize_event(e)["dedup_key"] != a["dedup_key"]


def test_unsupported_events_rejected():
    with pytest.raises(schema.UnsupportedEvent):
        schema.normalize_event({"source": "aws.ec2", "detail": {}})
    with pytest.raises(schema.UnsupportedEvent):
        schema.normalize_event({"source": "aws.guardduty"})


def test_risk_score_bounds_and_monotonic():
    low = schema.compute_risk(20, "low")
    assert 0 <= low < schema.compute_risk(20, "high") < schema.compute_risk(90, "high", 5, True) <= 100
    assert schema.compute_risk(100, "critical", 50, True) == 100
