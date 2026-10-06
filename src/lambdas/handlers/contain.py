"""Containment steps (each op is idempotent so Step Functions retries are safe)."""

from __future__ import annotations

from siemsoar import evidence, faults, response
from siemsoar.config import settings
from siemsoar.errors import VerificationFailed
from siemsoar.schema import PLAN_EC2
from siemsoar.states import Status
from siemsoar.util import iso, parse_iso

from handlers._common import config_of, dry_run_of, load


def _pre(cid: str) -> dict:
    return evidence.get_json(cid, "pre_action_state")[0]


def _snapshot(case, event, store):
    pre = _pre(case["case_id"])
    ids = response.snapshot_volumes(pre["instance_id"], case["case_id"], pre["volumes"], dry_run_of(event))
    store.update_case(case["case_id"], evidence_snapshots=ids)
    return {"snapshots": ids}


def _isolate(case, event, store):
    out = response.isolate_instance(case["response_plan"]["params"]["instance_id"], case["case_id"],
                                    dry_run_of(event))
    store.update_case(case["case_id"], isolation=out)
    return out


def _revoke_ec2_sessions(case, event, store):
    faults.maybe_fail("contain.revoke_sessions")
    pre = _pre(case["case_id"])
    if not pre.get("role_name"):
        return {"skipped": "no instance role"}
    return response.revoke_role_sessions(pre["role_name"], dry_run_of(event))


def _stop(case, event, store):
    threshold = config_of(event).get("stop_risk_threshold", settings().stop_risk_threshold)
    if case.get("risk_score", 0) < threshold:
        return {"stopped": False, "reason": f"risk {case.get('risk_score')} < {threshold}"}
    out = response.set_instance_running(case["response_plan"]["params"]["instance_id"], False, dry_run_of(event))
    store.update_case(case["case_id"], instance_stopped=out["changed"])
    return {"stopped": out["changed"], **out}


def _disable_key(case, event, store):
    p = case["response_plan"]["params"]
    return response.set_key_status(p["user_name"], p["access_key_id"], active=False, dry_run=dry_run_of(event))


def _revoke_user_sessions(case, event, store):
    return response.revoke_user_sessions(case["response_plan"]["params"]["user_name"], dry_run_of(event))


def _verify(case, event, store):
    plan, cid, dry = case["response_plan"], case["case_id"], dry_run_of(event)
    if plan["type"] == PLAN_EC2:
        info = response.describe_instance(plan["params"]["instance_id"])
        sg = (case.get("isolation") or {}).get("isolation_sg")
        ok = dry or info["security_groups"] == [sg]
        summary = f"security groups now {info['security_groups']}, instance {info['state']}"
    else:
        keys = response.list_keys(plan["params"]["user_name"])
        ok = dry or keys.get(plan["params"]["access_key_id"]) == "Inactive"
        summary = f"access key {plan['params']['access_key_id']} is {keys.get(plan['params']['access_key_id'])}"
    if not ok:
        raise VerificationFailed(summary)
    now = iso()
    approved = parse_iso(case.get("approved_at"))
    seconds = round((parse_iso(now) - approved).total_seconds(), 2) if approved else None
    store.transition(cid, Status.ISOLATED, detail={"summary": summary, "dry_run": dry},
                     containment_seconds=seconds, alert_count_at_isolation=case.get("alert_count", 1))
    return {"verified": True, "summary": summary, "containment_seconds": seconds}


OPS = {"snapshot": _snapshot, "isolate_network": _isolate, "revoke_sessions": _revoke_ec2_sessions,
       "stop_instance": _stop, "disable_key": _disable_key, "revoke_user_sessions": _revoke_user_sessions,
       "verify": _verify}


def handler(event, context=None):
    store, case = load(event)
    op = event["op"]
    out = OPS[op](case, event, store)
    if op != "verify":
        store.audit(case["case_id"], f"contain:{op}", "system", {k: v for k, v in out.items() if k != "secret"})
    return out

