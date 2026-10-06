import pytest
from siemsoar.states import Status
from siemsoar.store import CaseNotFound, InvalidTransition, TokenMissing, TokenUsed


def _case(cid="C-1", **kw):
    return {"case_id": cid, "status": "NEW", "source": "guardduty", "rule_id": "r", "title": "t",
            "dedup_key": "dk", "resource_id": "i-1", **kw}


def test_create_and_get(store):
    store.create_case(_case(severity=88.5))
    c = store.get_case("C-1")
    assert c["status"] == "NEW" and c["severity"] == 88.5 and c["alert_count"] == 1
    assert [a["action"] for a in store.list_audit("C-1")] == ["case_created"]
    with pytest.raises(CaseNotFound):
        store.get_case("nope")


def test_transition_guard_and_audit(store):
    store.create_case(_case())
    store.transition("C-1", Status.NOTIFIED)
    store.transition("C-1", Status.APPROVED, actor="slack:U1", approver="slack:U1")
    with pytest.raises(InvalidTransition) as e:  # double click
        store.transition("C-1", Status.APPROVED)
    assert e.value.current == "APPROVED"
    with pytest.raises(InvalidTransition):
        store.transition("C-1", Status.RESTORED)  # cannot skip states
    c = store.get_case("C-1")
    assert c["status"] == "APPROVED" and c["approver"] == "slack:U1" and "approved_at" in c
    assert [a["action"] for a in store.list_audit("C-1")][-2:] == ["status:NOTIFIED", "status:APPROVED"]


def test_transition_missing_case(store):
    with pytest.raises(InvalidTransition) as e:
        store.transition("ghost", Status.NOTIFIED)
    assert e.value.current is None


def test_dedup_lock_single_winner_and_expiry(store):
    assert store.acquire_dedup("k", "C-A", 3600) is None
    assert store.acquire_dedup("k", "C-B", 3600) == "C-A"
    store.release_dedup("k", "C-B")  # not the owner: no-op
    assert store.acquire_dedup("k", "C-C", 3600) == "C-A"
    store.release_dedup("k", "C-A")
    assert store.acquire_dedup("k", "C-D", 3600) is None
    assert store.acquire_dedup("k2", "C-E", -10) is None
    assert store.acquire_dedup("k2", "C-F", 3600) is None  # expired lock is replaceable


def test_first_delivery_idempotent(store):
    assert store.first_delivery("guardduty:abc") is True
    assert store.first_delivery("guardduty:abc") is False


def test_token_single_use(store):
    with pytest.raises(TokenMissing):
        store.consume_token("C-1", "approval")
    store.save_token("C-1", "approval", "tok", 60)
    assert store.has_open_token("C-1", "approval")
    assert store.consume_token("C-1", "approval") == "tok"
    with pytest.raises(TokenUsed):
        store.consume_token("C-1", "approval")
    store.release_token("C-1", "approval")
    assert store.consume_token("C-1", "approval") == "tok"


def test_breaker_is_idempotent_per_case_and_trips(store):
    assert store.breaker_register("C-1", 2, 3600) == (1, False)
    assert store.breaker_register("C-1", 2, 3600) == (1, False)  # retry of same case does not double count
    assert store.breaker_register("C-2", 2, 3600) == (2, False)
    assert store.breaker_register("C-3", 2, 3600) == (3, True)


def test_resource_and_status_indexes(store):
    store.create_case(_case("C-1"))
    store.create_case(_case("C-2", resource_id="i-2"))
    store.transition("C-2", Status.NOTIFIED)
    assert [c["case_id"] for c in store.cases_for_resource("i-1")] == ["C-1"]
    assert [c["case_id"] for c in store.list_cases("NOTIFIED")] == ["C-2"]
    assert {c["case_id"] for c in store.list_cases()} == {"C-1", "C-2"}
