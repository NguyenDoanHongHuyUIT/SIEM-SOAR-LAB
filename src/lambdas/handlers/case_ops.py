"""Small case lifecycle operations used by the workflow: expire, acknowledge, fail-safe."""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError
from siemsoar import evidence, response
from siemsoar.notifier import notify_case
from siemsoar.schema import PLAN_EC2
from siemsoar.states import TERMINAL, Status
from siemsoar.store import InvalidTransition

from handlers._common import dry_run_of, load, state_of

log = logging.getLogger("handlers.case_ops")

# ISOLATING is entered before the first containment step and RESTORING before the first restore step: in these states
# (and ISOLATED) what is actually in place has to be looked up, it cannot be inferred from the status
CONTAINMENT_STATUSES = {Status.ISOLATING, Status.ISOLATED, Status.RESTORING}
# Operator choice: the look-up may take this long of the function's 60 s, the rest is for the FAILED transition and the
# alert. With a hung API one read outlasts the whole timeout (retries of the default client), which would lose both.
OBSERVE_SECONDS = 20


def _expire(store, case, event):
    store.transition(case["case_id"], Status.EXPIRED, detail={"reason": "approval_timeout"})
    return {"status": "EXPIRED"}


def _observe_ec2(case: dict) -> dict:
    info = response.describe_instance(case["response_plan"]["params"]["instance_id"])
    # the step that swaps the groups records the SG only once it succeeded: a failure halfway leaves it unrecorded
    sg = (case.get("isolation") or {}).get("isolation_sg") or response.ensure_isolation_sg(info["vpc_id"], dry_run=True)
    held = [n["id"] for n in info["network_interfaces"] if sg and n["groups"] == [sg]]
    seen = {"network": "isolated" if response.is_isolated(info, sg) else "partial" if held else "open",
            "isolated_interfaces": held, "interfaces": len(info["network_interfaces"]),
            "instance_state": info["state"], "evidence_snapshots": case.get("evidence_snapshots") or []}
    role = evidence.get_json(case["case_id"], "pre_action_state")[0].get("role_name")
    if role:
        seen["role_sessions_revoked"] = response.has_revoke_policy(role)
    return seen


def _observe_iam(case: dict) -> dict:
    user, key = case["response_plan"]["params"]["user_name"], case["response_plan"]["params"]["access_key_id"]
    return {"key_status": response.list_keys(user).get(key, "deleted"),
            "user_sessions_revoked": response.has_user_revoke_policy(user)}


def _observe(plan_type: str, case: dict) -> dict:
    """What is in place now, or TimeoutError after OBSERVE_SECONDS. A worker thread, abandoned on timeout: a read stuck
    inside botocore cannot be interrupted, and it only reads."""
    pool = ThreadPoolExecutor(max_workers=1)
    try:
        return pool.submit(_observe_ec2 if plan_type == PLAN_EC2 else _observe_iam, case).result(timeout=OBSERVE_SECONDS)
    finally:
        pool.shutdown(wait=False)


def _describe(plan_type: str, seen: dict) -> tuple[str, str, list[str]]:
    """(level: full | partial | none, headline, facts) from what the API shows now."""
    if plan_type == PLAN_EC2:
        network = {"isolated": "network isolated on every interface",
                   "partial": f"network isolated on {len(seen['isolated_interfaces'])} of {seen['interfaces']} "
                              f"interfaces only",
                   "open": "network NOT isolated (no interface carries the isolation SG)"}[seen["network"]]
        facts = [network]
        if "role_sessions_revoked" in seen:
            facts.append("instance role sessions " + ("revoked" if seen["role_sessions_revoked"] else "NOT revoked"))
        facts.append(f"instance {seen['instance_state']}")
        facts.append(f"{len(seen['evidence_snapshots'])} evidence snapshot(s) recorded")
        if seen["network"] == "isolated":
            if seen.get("role_sessions_revoked", True):
                return "full", "resource left CONTAINED", facts
            return "partial", "resource network CONTAINED only", facts  # credentials already issued to the role still work
        partly = seen["network"] == "partial" or seen.get("role_sessions_revoked") or \
            seen["instance_state"] in {"stopping", "stopped"}
        return ("partial", "resource only PARTIALLY contained", facts) if partly else \
            ("none", "resource NOT contained", facts)
    facts = [f"access key {seen['key_status']}",
             "user sessions " + ("revoked" if seen["user_sessions_revoked"] else "NOT revoked")]
    if seen["key_status"] in {"Inactive", "deleted"}:
        if seen["user_sessions_revoked"]:
            return "full", "resource left CONTAINED", facts
        return "partial", "access key CONTAINED only", facts  # temporary credentials already issued still work
    return ("partial", "resource only PARTIALLY contained", facts) if seen["user_sessions_revoked"] else \
        ("none", "resource NOT contained", facts)


def _completed_steps(store, case_id: str) -> list[str]:
    """Containment/restore steps the audit trail shows as done (a step that decided to skip is audited too)."""
    return [a["action"] for a in store.list_audit(case_id) if a["action"].startswith(("contain:", "restore:"))
            and a["detail"].get("stopped") is not False and not a["detail"].get("skipped")]


def _reached(store, case: dict, dry_run: bool) -> tuple[str, dict]:
    """(safe-state text, observed state). The status alone does not say what is in place: a failure at the snapshot,
    the SG swap or DisableKey happens in ISOLATING with nothing contained, and one in RESTORING may come after the
    original groups were put back. So the resource is checked through the API; if that fails, the audit trail says
    which steps completed."""
    if case.get("safe_state"):  # Lambda retry: the first attempt already moved the case to FAILED and looked it up
        return case["safe_state"], case.get("containment_reached") or {"level": "unknown"}
    if case["status"] not in CONTAINMENT_STATUSES:
        return "no containment change was applied", {"level": "none"}
    if dry_run:
        return "dry run: no containment change was applied", {"level": "none", "dry_run": True}
    plan_type = case["response_plan"]["type"]
    try:
        seen = _observe(plan_type, case)
    except Exception as err:  # noqa: BLE001 - the operator must still be alerted, with what is known
        log.error("fail-safe could not read the resource state", exc_info=True)
        steps = _completed_steps(store, case["case_id"])
        return (f"containment state UNKNOWN (API check failed: {type(err).__name__}); completed steps per audit: "
                f"{', '.join(steps) or 'none'}; manual review required"), {"level": "unknown", "steps": steps}
    level, head, facts = _describe(plan_type, seen)
    return f"{head} ({'; '.join(facts)}); manual review required", {"level": level, **seen}


def _fail_safe(store, case, event):
    """Keep whatever safe state was reached; never roll back automatically. Alert the operator with what is in place."""
    err = state_of(event).get("error", {})
    dry_run = bool(case.get("dry_run")) or dry_run_of(event)  # the config also covers a failure before enrich stored it
    safe, reached = _reached(store, case, dry_run)
    try:
        store.transition(case["case_id"], Status.FAILED,
                         detail={"error": err.get("Error"), "safe_state": safe, "reached": reached},
                         failure_error=err.get("Error"), failure_cause=str(err.get("Cause", ""))[:500],
                         safe_state=safe, containment_reached=reached, dry_run=dry_run)
    except InvalidTransition as exc:
        if exc.current not in TERMINAL:
            raise
    case = store.get_case(case["case_id"])
    try:
        sent = notify_case(case, "failed", extra=(f"Error: {err.get('Error', '?')} - {str(err.get('Cause', ''))[:300]}\n"
                                                  f"Safe state: {safe}"))
        store.audit(case["case_id"], "notified:failed", "system", sent)
    except (RuntimeError, ClientError):
        log.error("fail-safe notification failed", exc_info=True)
        store.audit(case["case_id"], "notify_failed", "system", {"kind": "failed"})
    return {"status": "FAILED", "safe_state": safe, "containment": reached["level"]}


def _finalize_status(status: Status, reason: str):
    def run(store, case, event):
        if case["status"] != status:  # the human decision already moved the case; only converge if not
            store.transition(case["case_id"], status, detail={"reason": reason})
        return {"status": status.value}
    return run


OPS = {"expire": _expire, "fail_safe": _fail_safe,
       "acknowledged": _finalize_status(Status.ACKNOWLEDGED, "no_response_plan_ack")}


def handler(event, context=None):
    store, case = load(event)
    return OPS[event["op"]](store, case, event)
