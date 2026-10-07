"""Controlled restore: validate (no new alerts, no drift) -> execute -> verify.

Compares three views before touching anything: the saved pre-action state (S3 evidence), the current
state (AWS API) and the IaC desired state (tag iac:security_groups written by Terraform).
"""

from __future__ import annotations

from siemsoar import evidence, response
from siemsoar.config import settings
from siemsoar.errors import VerificationFailed
from siemsoar.schema import PLAN_EC2
from siemsoar.states import TERMINAL, Status
from siemsoar.util import iso, parse_iso

from handlers._common import dry_run_of, load, state_of

MAX_ATTEMPTS = 3


def _validate(case, event, store):
    cid, plan, reasons = case["case_id"], case["response_plan"], []
    attempts = int(case.get("restore_attempts", 0)) + 1
    store.update_case(cid, restore_attempts=attempts)

    try:
        pre, digest = evidence.get_json(cid, "pre_action_state")
        if digest != case.get("pre_action_state_ref", {}).get("sha256"):
            reasons.append("evidence hash mismatch (pre_action_state was modified)")
    except Exception as err:  # noqa: BLE001
        pre = None
        reasons.append(f"pre-action state unreadable: {type(err).__name__}")

    since = case.get("isolated_at")
    new_alerts = int(case.get("alert_count", 1)) - int(case.get("alert_count_at_isolation", 1))
    if new_alerts > 0:
        reasons.append(f"{new_alerts} new alert(s) merged into this case after isolation")
    later = [c["case_id"] for c in store.cases_for_resource(case["resource_id"], since=since)
             if c["case_id"] != cid and c["status"] not in TERMINAL] if since else []
    if later:
        reasons.append(f"open related case(s) on same resource: {', '.join(later)}")

    if pre and plan["type"] == PLAN_EC2:
        cur = response.describe_instance(plan["params"]["instance_id"])
        iso_sg = (case.get("isolation") or {}).get("isolation_sg")
        if not dry_run_of(event) and cur["security_groups"] != [iso_sg]:
            reasons.append(f"drift: current security groups {cur['security_groups']} != isolation SG [{iso_sg}]")
        iac = pre.get("iac_security_groups")
        if iac and iac != pre["security_groups"]:
            reasons.append(f"drift: saved SGs {pre['security_groups']} differ from IaC desired {iac}")

    ok = not reasons
    if ok:
        store.transition(cid, Status.RESTORING, detail={"attempt": attempts, "verdict": state_of(event).get(
            "restore_decision", {}).get("decision")})
    else:
        store.audit(cid, "restore_blocked", "system", {"reasons": reasons, "attempt": attempts})
    return {"ok": ok, "reasons": reasons, "attempt": attempts, "terminal": (not ok) and attempts >= MAX_ATTEMPTS}


def _verdict(event) -> str:
    decision = state_of(event).get("restore_decision", {}).get("decision")
    return "false_positive" if decision == "restore_fp" else "true_positive"


def _execute(case, event, store):
    cid, plan, dry = case["case_id"], case["response_plan"], dry_run_of(event)
    pre, _ = evidence.get_json(cid, "pre_action_state")
    verdict = _verdict(event)
    out: dict = {"verdict": verdict}
    if plan["type"] == PLAN_EC2:
        iid = plan["params"]["instance_id"]
        out["security_groups"] = response.restore_instance_sgs(iid, pre["security_groups"], dry)
        if pre.get("role_name"):
            out["sessions"] = response.restore_role_sessions(pre["role_name"], dry)
        if case.get("instance_stopped") and pre.get("state") == "running":
            out["start"] = response.set_instance_running(iid, True, dry)
    else:
        user, key = pre["user_name"], pre["access_key_id"]
        out["sessions"] = response.restore_user_sessions(user, dry)
        if verdict == "false_positive":
            out["key"] = response.set_key_status(user, key, active=pre["keys"].get(key) == "Active", dry_run=dry)
        else:  # confirmed compromise: never re-enable the exposed key, rotate it
            out["rotation"] = response.rotate_key(user, key, f"/{settings().name_prefix}", dry)
    store.update_case(cid, verdict=verdict, restore_actions=out)
    return out


def _verify(case, event, store):
    cid, plan, dry = case["case_id"], case["response_plan"], dry_run_of(event)
    pre, _ = evidence.get_json(cid, "pre_action_state")
    if plan["type"] == PLAN_EC2:
        cur = response.describe_instance(plan["params"]["instance_id"])
        ok = dry or (cur["security_groups"] == pre["security_groups"]
                     and not (pre.get("role_name") and response.has_revoke_policy(pre["role_name"])))
        summary = f"security groups {cur['security_groups']} (expected {pre['security_groups']})"
    else:
        keys = response.list_keys(pre["user_name"])
        want_fp = _verdict(event) == "false_positive"
        ok = dry or (keys.get(pre["access_key_id"]) == pre["keys"].get(pre["access_key_id"]) if want_fp
                     else pre["access_key_id"] not in keys)
        summary = f"keys now {keys}"
    if not ok:
        raise VerificationFailed(summary)
    now = iso()
    isolated = parse_iso(case.get("isolated_at"))
    store.transition(cid, Status.RESTORED, detail={"summary": summary, "dry_run": dry},
                     verdict=_verdict(event),
                     restore_seconds=round((parse_iso(now) - isolated).total_seconds(), 2) if isolated else None)
    return {"verified": True, "summary": summary}


OPS = {"validate": _validate, "execute": _execute, "verify": _verify}


def handler(event, context=None):
    store, case = load(event)
    out = OPS[event["op"]](case, event, store)
    if event["op"] != "validate":
        store.audit(case["case_id"], f"restore:{event['op']}", "system",
                    {k: v for k, v in out.items() if k != "secret_access_key"})
    return out

