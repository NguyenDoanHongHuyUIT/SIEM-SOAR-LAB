"""Containment steps (each op is idempotent so Step Functions retries are safe)."""

from __future__ import annotations

from siemsoar import evidence, faults, response
from siemsoar.errors import VerificationFailed
from siemsoar.schema import PLAN_EC2
from siemsoar.states import Status
from siemsoar.util import iso, parse_iso

from handlers._common import dry_run_of, load, state_of

SNAPSHOT_OK = {"pending", "completed"}


def _pre(cid: str) -> dict:
    return evidence.get_json(cid, "pre_action_state")[0]


def _snapshot(case, event, store):
    faults.maybe_fail("contain.snapshot")
    pre = _pre(case["case_id"])
    ids = response.snapshot_volumes(pre["instance_id"], case["case_id"], pre["volumes"], dry_run_of(event))
    store.update_case(case["case_id"], evidence_snapshots=ids)
    return {"snapshots": ids}


def _isolate(case, event, store):
    faults.maybe_fail("contain.isolate_network")
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


def _revoke_user_sessions(case, event, store):
    return response.revoke_user_sessions(case["response_plan"]["params"]["user_name"], dry_run_of(event))


def _stop_decided(case, event) -> bool:
    """True when this execution stopped the instance (enrich decided it, MarkInstanceStopped recorded it)."""
    decided = state_of(event).get("steps", {}).get("enrich", {}).get("out", {}).get("stop_instance")
    return bool(case.get("instance_stopped") or decided)


def _checks_ec2(case, event, info) -> dict:
    """Every containment action the plan took, re-read from the API rather than taken from the steps' own results."""
    cid, pre = case["case_id"], _pre(case["case_id"])
    sg = (case.get("isolation") or {}).get("isolation_sg")
    checks = {"network_isolated": response.is_isolated(info, sg)}  # every interface, not just the primary one
    snaps = case.get("evidence_snapshots") or []
    found = response.describe_snapshots(snaps)
    checks["evidence_snapshots"] = (len(snaps) == len(pre["volumes"]) and set(found) == set(snaps) and all(
        s["state"] in SNAPSHOT_OK and s["case"] == cid for s in found.values()))
    if pre.get("role_name"):
        checks["role_sessions_revoked"] = response.has_revoke_policy(pre["role_name"])
    if _stop_decided(case, event):
        checks["instance_stopped"] = info["state"] in {"stopping", "stopped"}
    return checks


def _verify(case, event, store):
    plan, cid, dry = case["response_plan"], case["case_id"], dry_run_of(event)
    if plan["type"] == PLAN_EC2:
        info = response.describe_instance(plan["params"]["instance_id"])
        summary = (f"security groups now {info['security_groups']} (interfaces {response.eni_groups(info)}), "
                   f"instance {info['state']}")
        checks = {} if dry else _checks_ec2(case, event, info)
    else:
        user, key = plan["params"]["user_name"], plan["params"]["access_key_id"]
        keys = response.list_keys(user)
        summary = f"access key {key} is {keys.get(key)}"
        checks = {} if dry else {"key_disabled": keys.get(key) == "Inactive",
                                 "user_sessions_revoked": response.has_user_revoke_policy(user)}
    failed = [name for name, ok in checks.items() if not ok]
    if failed:
        raise VerificationFailed(f"not confirmed: {', '.join(failed)}; {summary}")
    # a dry run changed nothing, so it verifies nothing: recorded as such, never as a verified containment
    verification = "dry_run" if dry else "ok"
    now = iso()
    approved = parse_iso(case.get("approved_at"))
    seconds = round((parse_iso(now) - approved).total_seconds(), 2) if approved else None
    store.transition(cid, Status.ISOLATED, detail={"summary": summary, "dry_run": dry, "verification": verification,
                                                   "checks": checks},
                     containment_seconds=seconds, alert_count_at_isolation=case.get("alert_count", 1),
                     containment_verification=verification)
    return {"verified": verification == "ok", "verification": verification, "checks": checks, "summary": summary,
            "containment_seconds": seconds}


# `stop_instance` (ec2:StopInstances) and `disable_key` (iam:UpdateAccessKey) are single API calls: they run as
# Step Functions AWS SDK integrations (see tools/gen_asl.py), not here.
OPS = {"snapshot": _snapshot, "isolate_network": _isolate, "revoke_sessions": _revoke_ec2_sessions,
       "revoke_user_sessions": _revoke_user_sessions, "verify": _verify}


def handler(event, context=None):
    store, case = load(event)
    op = event["op"]
    out = OPS[op](case, event, store)
    if op != "verify":
        store.audit(case["case_id"], f"contain:{op}", "system", {k: v for k, v in out.items() if k != "secret"})
    return out
