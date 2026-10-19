"""soarctl: operator CLI for the SOAR lab (uses your AWS credentials; no secrets of its own).

  python -m tools.soarctl list [--status NOTIFIED]
  python -m tools.soarctl show <case_id>
  python -m tools.soarctl decide <case_id> --gate approval --decision approve     # Slack-less fallback channel
  python -m tools.soarctl recover <case_id> --approver U012 --reason "..."         # FAILED case, host contained
  python -m tools.soarctl feedback > feedback.json                                  # feed `rulesctl tune`
  python -m tools.soarctl lab status|up --hours 4|down

Resource names default to the Terraform module defaults (prefix `siemsoar`); override with --prefix or
CASES_TABLE / EVIDENCE_BUCKET / NAME_PREFIX.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import defaultdict

SRC = os.path.join(os.path.dirname(__file__), "..", "src", "lambdas")
if SRC not in sys.path:
    sys.path.insert(0, SRC)


def _env(prefix: str) -> None:
    os.environ.setdefault("NAME_PREFIX", prefix)
    os.environ.setdefault("CASES_TABLE", f"{prefix}-cases")


def _principal() -> str:
    from siemsoar import aws
    return aws.client("sts").get_caller_identity()["Arn"]


def _approvers(prefix: str) -> set[str]:
    from siemsoar.ssm import get_param
    raw = get_param(f"/{prefix}/slack/approver_ids", "") or ""
    return {a.strip() for a in raw.split(",") if a.strip() and a.strip() != "CHANGE_ME"}


def confirm_human_decision(case_id: str, approver: str, approvers: set[str], tty: bool, typed: str | None) -> str | None:
    """The CLI is the fallback of a HUMAN gate: the approver must be on the same list Slack enforces, and the decision
    is only taken from an interactive terminal where that person retypes the case id. AWS credentials alone (a script,
    an automation, an AI assistant) are not an approval. Returns the refusal reason, or None."""
    if approver not in approvers:
        return f"{approver!r} is not an authorised approver (/<prefix>/slack/approver_ids)"
    if not tty:
        return "decisions need an interactive terminal (a human retyping the case id); refusing a non-interactive call"
    if (typed or "").strip() != case_id:
        return "case id not confirmed"
    return None


def recover(store, case_id: str, actor: str, reason: str, principal: str) -> dict:
    """Runbook recovery of a FAILED EC2 case whose host was left contained: restore from the hashed pre-action state
    (the same procedure as the workflow's restore), verify, and audit who decided and why. A key disabled by an IAM case
    is not re-enabled here: whether to reactivate or rotate it is an IAM decision taken in the console."""
    from siemsoar import evidence, response
    from siemsoar.schema import PLAN_EC2
    case = store.get_case(case_id)
    if case["status"] != "FAILED":
        raise ValueError(f"case is {case['status']}: only a FAILED case is recovered by hand (otherwise use decide)")
    if case.get("response_plan", {}).get("type") != PLAN_EC2:
        raise ValueError("not an EC2 containment: review the IAM key in the console")
    iid = case["response_plan"]["params"]["instance_id"]
    holder = response.describe_instance(iid)["tags"].get(response.CASE_TAG)
    if holder != case_id:
        raise ValueError(f"{iid} is not held by this case (isolation tag: {holder})")
    pre, digest = evidence.get_json(case_id, "pre_action_state")
    if digest != (case.get("pre_action_state_ref") or {}).get("sha256"):
        raise ValueError("pre_action_state does not match the hash recorded when it was saved: do not restore from it")
    out = response.restore_ec2_from_state(iid, pre)
    restored, summary = response.ec2_matches_state(iid, pre)
    detail = {"reason": reason, "aws_principal": principal, "evidence_sha256": digest, "restored": out,
              "verified": restored, "summary": summary}
    store.audit(case_id, "manual_recovery", actor, detail)
    from siemsoar.util import iso
    store.update_case(case_id, manual_recovery_at=iso())
    return detail


def feedback_stats(store) -> dict:
    """Per rule: closed cases and how many were false positives (dismissed by a human or restored as FP)."""
    stats: dict[str, dict[str, int]] = defaultdict(lambda: {"cases": 0, "false_positive": 0})
    for case in store.list_cases():
        if case["status"] in {"NEW", "NOTIFIED", "APPROVED", "ISOLATING"}:
            continue
        s = stats[str(case["rule_id"])]
        s["cases"] += 1
        if case["status"] == "DISMISSED" or case.get("verdict") == "false_positive":
            s["false_positive"] += 1
    return dict(stats)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="soarctl")
    ap.add_argument("--prefix", default=os.environ.get("NAME_PREFIX", "siemsoar"))
    sub = ap.add_subparsers(dest="cmd", required=True)
    ls = sub.add_parser("list")
    ls.add_argument("--status")
    sh = sub.add_parser("show")
    sh.add_argument("case_id")
    dc = sub.add_parser("decide")
    dc.add_argument("case_id")
    dc.add_argument("--gate", choices=["approval", "restore"], required=True)
    dc.add_argument("--decision", required=True)
    dc.add_argument("--approver", required=True, help="your Slack member id (must be in /<prefix>/slack/approver_ids)")
    rc = sub.add_parser("recover")
    rc.add_argument("case_id")
    rc.add_argument("--approver", required=True, help="your Slack member id (must be in /<prefix>/slack/approver_ids)")
    rc.add_argument("--reason", required=True, help="why the containment can be lifted (kept in the audit)")
    sub.add_parser("feedback")
    lab = sub.add_parser("lab")
    lab.add_argument("action", choices=["status", "up", "extend", "down"])
    lab.add_argument("--hours", type=float, default=4)
    args = ap.parse_args(argv)
    _env(args.prefix)

    from siemsoar.decisions import DecisionRejected, apply_decision
    from siemsoar.store import CaseNotFound, CaseStore

    if args.cmd == "lab":
        from tools import labctl
        timed = {"up": labctl.up, "extend": labctl.extend}.get(args.action)
        out = timed(args.prefix, args.hours) if timed else getattr(labctl, args.action)(args.prefix)
        print(json.dumps(out, indent=2))
        return 0

    store = CaseStore()
    if args.cmd == "list":
        for c in sorted(store.list_cases(args.status), key=lambda c: c["created_at"]):
            print(f"{c['case_id']}  {c['status']:<10} {c['source']:<9} {c['rule_id'][:38]:<38} "
                  f"risk={c.get('risk_score', '?'):<4} {c['resource_id']}")
        return 0
    if args.cmd == "show":
        try:
            case = store.get_case(args.case_id)
        except CaseNotFound:
            print("case not found", file=sys.stderr)
            return 1
        case.pop("raw", None)
        print(json.dumps({"case": case, "audit": store.list_audit(args.case_id)}, indent=2, default=str))
        return 0
    if args.cmd == "decide":
        tty = sys.stdin.isatty()
        typed = input(f"{args.decision} on gate {args.gate} as {args.approver}. Type the case id to confirm: ") \
            if tty else None
        refusal = confirm_human_decision(args.case_id, args.approver, _approvers(args.prefix), tty, typed)
        if refusal:
            print(f"rejected: {refusal}", file=sys.stderr)
            return 1
        try:
            out = apply_decision(store, args.case_id, args.gate, args.decision, actor=f"cli:{args.approver}",
                                 channel="cli", detail={"aws_principal": _principal()})
        except (DecisionRejected, CaseNotFound) as err:
            print(f"rejected: {err}", file=sys.stderr)
            return 1
        print(json.dumps(out))
        return 0
    if args.cmd == "recover":
        tty = sys.stdin.isatty()
        typed = input(f"lift the containment of {args.case_id} as {args.approver}. Type the case id to confirm: ") \
            if tty else None
        refusal = confirm_human_decision(args.case_id, args.approver, _approvers(args.prefix), tty, typed)
        if refusal:
            print(f"rejected: {refusal}", file=sys.stderr)
            return 1
        os.environ.setdefault("EVIDENCE_BUCKET", f"{args.prefix}-evidence-{_principal().split(':')[4]}")
        try:
            out = recover(store, args.case_id, f"cli:{args.approver}", args.reason, _principal())
        except (ValueError, CaseNotFound) as err:
            print(f"rejected: {err}", file=sys.stderr)
            return 1
        print(json.dumps(out, indent=2, default=str))
        return 0 if out["verified"] else 1
    if args.cmd == "feedback":
        print(json.dumps(feedback_stats(store), indent=2))
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
