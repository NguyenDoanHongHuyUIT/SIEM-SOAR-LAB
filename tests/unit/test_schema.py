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
    assert a["mitre"] == ["T1110"]
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
    assert a["title"] == "ET MALWARE Sality - Fake Opera User-Agent"
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


def test_invalid_event_time_and_severity_are_rejected():
    bad_time = ev.clone(ev.guardduty_instance())
    bad_time["detail"]["createdAt"] = "not-a-timestamp"
    bad_time["detail"]["service"].pop("eventFirstSeen")
    bad_time["detail"]["service"].pop("eventLastSeen", None)
    with pytest.raises(schema.InvalidEvent, match="event time"):
        schema.normalize_event(bad_time)

    for severity in (-1, 9, float("nan"), "unknown", True):
        bad_severity = ev.clone(ev.guardduty_instance())
        bad_severity["detail"]["severity"] = severity
        with pytest.raises(schema.InvalidEvent, match="severity"):
            schema.normalize_event(bad_severity)

    bad_wazuh = ev.clone(ev.WAZUH_FIM)
    bad_wazuh["detail"]["timestamp"] = "2026-10-06T10:00:00"
    with pytest.raises(schema.InvalidEvent, match="timezone offset"):
        schema.normalize_event(bad_wazuh)


def test_risk_score_bounds_and_monotonic():
    low = schema.compute_risk(20, "low")
    assert 0 <= low < schema.compute_risk(20, "high") < schema.compute_risk(90, "high", 5, True) <= 100
    assert schema.compute_risk(100, "critical", 50, True) == 100


def test_a_recurring_finding_is_timed_from_its_latest_activity():
    """Lab 2026-10-19: RootCredentialUsage first seen 04:06:41, count 241, last seen 09:12:29, case at 09:30:16."""
    e = ev.clone(ev.guardduty_key())
    e["detail"]["service"].update(eventFirstSeen="2026-10-19T04:06:41.000Z", eventLastSeen="2026-10-19T09:12:29.000Z",
                                  count=241)
    a = schema.normalize_event(e)
    assert a["event_time"] == "2026-10-19T09:12:29.000Z" and a["extra"]["first_seen"] == "2026-10-19T04:06:41.000Z"


def test_temporary_credentials_are_one_identity_and_never_a_key_to_disable():
    """ASIA keys are STS session credentials: a new one per console session. Same user -> same resource (one case),
    and UpdateAccessKey cannot disable them, so no iam_key_disable plan."""
    def finding(key):
        e = ev.clone(ev.guardduty_key(user="lab-alice", key=key))
        return schema.normalize_event(e)
    a, b = finding("ASIAEXAMPLE000000001"), finding("ASIAEXAMPLE000000002")
    assert a["resource"]["id"] == b["resource"]["id"] == "lab-alice/temporary-credentials"
    assert a["dedup_key"] == b["dedup_key"] and a["response_plan"]["type"] == "none"
    long_term = finding("AKIAIOSFODNN7EXAMPLE")
    assert long_term["response_plan"]["type"] == "iam_key_disable" and long_term["resource"]["id"].endswith("EXAMPLE")
