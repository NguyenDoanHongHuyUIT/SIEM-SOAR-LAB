"""Capture the pre-action state to immutable evidence, then enter ISOLATING."""

from __future__ import annotations

from siemsoar import evidence, response
from siemsoar.schema import PLAN_EC2, PLAN_IAM
from siemsoar.states import Status
from siemsoar.store import InvalidTransition
from siemsoar.util import iso, parse_iso

from handlers._common import load


def _capture(case: dict) -> dict:
    plan = case["response_plan"]
    if plan["type"] == PLAN_EC2:
        info = response.describe_instance(plan["params"]["instance_id"])
        role = response.instance_role_name(info["instance_profile_arn"])
        iac = info["tags"].get("iac:security_groups")
        return {"kind": PLAN_EC2, **info, "role_name": role,
                "iac_security_groups": sorted(iac.split(",")) if iac else None}
    if plan["type"] == PLAN_IAM:
        user = plan["params"]["user_name"]
        return {"kind": PLAN_IAM, "user_name": user, "access_key_id": plan["params"]["access_key_id"],
                "keys": response.list_keys(user)}
    raise ValueError("no plan")


def handler(event, context=None):
    store, case = load(event)
    cid = case["case_id"]
    state = _capture(case)
    state["captured_at"] = iso()
    try:
        ref = evidence.put_json(cid, "pre_action_state", {"case_id": cid, **state})
    except evidence.EvidenceExists:  # retry: keep the first capture, it is the truth
        _, digest = evidence.get_json(cid, "pre_action_state")
        ref = {"key": f"cases/{cid}/pre_action_state.json", "sha256": digest}
    approved = parse_iso(case.get("approved_at"))
    evidence_seconds = round((parse_iso(state["captured_at"]) - approved).total_seconds(), 2) if approved else None
    store.update_case(cid, pre_action_state_ref=ref, evidence_saved_at=state["captured_at"],
                      evidence_seconds=evidence_seconds)
    try:
        store.transition(cid, Status.ISOLATING, detail={"evidence": ref["key"]})
    except InvalidTransition as err:
        if err.current != Status.ISOLATING:
            raise
    return {"evidence": ref, "evidence_seconds": evidence_seconds}
