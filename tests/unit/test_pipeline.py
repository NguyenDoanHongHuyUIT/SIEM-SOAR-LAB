import pytest
from handlers import ingest as ingest_handler
from siemsoar import pipeline, schema
from siemsoar.states import Status

from tests.fixtures import events as ev


def test_ingest_creates_case_and_starts_workflow(store, sfn):
    out = ingest_handler.handler(ev.guardduty_instance())
    assert out["action"] == "created"
    case = store.get_case(out["case_id"])
    assert case["status"] == "NEW" and case["response_plan"]["type"] == "ec2_isolate"
    assert case["execution_arn"].endswith(out["case_id"])
    assert sfn.started[0]["name"] == out["case_id"]
    assert '"approval_timeout"' in sfn.started[0]["input"]
    assert case["raw_ref"].startswith("raw/2026-10-06/guardduty-")


def test_duplicate_delivery_is_ignored(store, sfn):
    first = ingest_handler.handler(ev.guardduty_instance())
    again = ingest_handler.handler(ev.guardduty_instance())  # same finding id (EventBridge retry)
    assert again["action"] == "duplicate_delivery"
    assert store.get_case(first["case_id"])["alert_count"] == 1
    assert len(sfn.started) == 1


def test_new_finding_same_resource_is_deduplicated(store, sfn):
    first = ingest_handler.handler(ev.guardduty_instance(fid="f1"))
    second = ingest_handler.handler(ev.guardduty_instance(fid="f2"))
    assert second == {"case_id": first["case_id"], "action": "deduplicated"}
    assert store.get_case(first["case_id"])["alert_count"] == 2
    assert len(sfn.started) == 1
    assert "alert_deduplicated" in [a["action"] for a in store.list_audit(first["case_id"])]


def test_dedup_target_closed_opens_new_case(store, sfn):
    first = ingest_handler.handler(ev.guardduty_instance(fid="f1"))
    store.transition(first["case_id"], Status.NOTIFIED)
    store.transition(first["case_id"], Status.DISMISSED)
    second = ingest_handler.handler(ev.guardduty_instance(fid="f2"))
    assert second["action"] == "created" and second["case_id"] != first["case_id"]


def test_start_failure_releases_lock_and_marks_failed(store, sfn):
    sfn.fail_start = True
    alert = schema.normalize_event(ev.guardduty_instance(fid="f9"))
    with pytest.raises(RuntimeError):
        pipeline.ingest(alert)
    sfn.fail_start = False
    retry = pipeline.ingest(schema.normalize_event(ev.guardduty_instance(fid="f10")))
    assert retry["action"] == "created"  # lock was released, no lost alert
    failed = store.list_cases("FAILED")
    assert len(failed) == 1


def test_unsupported_event_ignored(sfn):
    assert ingest_handler.handler({"source": "aws.s3", "detail": {}})["action"] == "ignored"


def test_wazuh_and_suricata_cases(store, sfn):
    a = ingest_handler.handler(ev.WAZUH_FIM)
    b = ingest_handler.handler(ev.SURICATA)
    assert store.get_case(a["case_id"])["run_id"] == "run-20261006-01"
    assert store.get_case(b["case_id"])["source"] == "suricata"
