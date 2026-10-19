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
    third = ingest_handler.handler(ev.guardduty_instance(fid="f3"))
    case = store.get_case(third["case_id"])
    assert len(case["merged_at"]) == 2 and all(t >= case["created_at"] for t in case["merged_at"])


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
    # EventBridge retries the SAME finding: it must open a case, not be swallowed as a duplicate delivery
    retry = pipeline.ingest(alert)
    assert retry["action"] == "created"
    assert len(store.list_cases("FAILED")) == 1


def test_orphaned_dedup_lock_does_not_block_new_alerts(store, sfn):
    """A crash between acquire_dedup and create_case leaves a lock pointing at a case that does not exist."""
    alert = schema.normalize_event(ev.guardduty_instance(fid="f1"))
    store.acquire_dedup(alert["dedup_key"], "C-never-created", 3600)
    out = pipeline.ingest(alert)
    assert out["action"] == "created" and out["case_id"] != "C-never-created"


def test_unsupported_event_ignored(sfn):
    assert ingest_handler.handler({"source": "aws.s3", "detail": {}})["action"] == "ignored"


def test_wazuh_and_suricata_cases(store, sfn):
    a = ingest_handler.handler(ev.WAZUH_FIM)
    b = ingest_handler.handler(ev.SURICATA)
    assert store.get_case(a["case_id"])["run_id"] == "run-20261006-01"
    assert store.get_case(b["case_id"])["source"] == "suricata"


def test_a_recurring_guardduty_finding_is_not_mistaken_for_a_redelivery(store):
    """GuardDuty re-publishes a recurring finding with the SAME id and a new updatedAt/service.count. Only an
    identical event (EventBridge at-least-once delivery) is a duplicate; observed on AWS with sample findings."""
    first = ev.clone(ev.guardduty_instance())
    first["detail"]["updatedAt"] = "2026-10-17T15:52:00.000Z"
    a = pipeline.ingest(schema.normalize_event(first), store, start=lambda cid: "arn:exec")
    assert pipeline.ingest(schema.normalize_event(ev.clone(first)), store,
                           start=lambda cid: "arn:exec")["action"] == "duplicate_delivery"
    again = ev.clone(first)
    again["detail"]["updatedAt"] = "2026-10-17T16:01:00.000Z"
    again["detail"]["service"]["count"] = 4
    b = pipeline.ingest(schema.normalize_event(again), store, start=lambda cid: "arn:exec")
    assert b["action"] == "deduplicated" and b["case_id"] == a["case_id"]
    assert store.get_case(a["case_id"])["alert_count"] == 2
