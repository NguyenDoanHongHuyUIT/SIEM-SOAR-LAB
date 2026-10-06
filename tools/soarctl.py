"""soarctl: operator CLI for the SOAR lab (uses your AWS credentials; no secrets of its own).

  python -m tools.soarctl list [--status NOTIFIED]
  python -m tools.soarctl show <case_id>
  python -m tools.soarctl decide <case_id> --gate approval --decision approve     # Slack-less fallback channel
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


def _actor() -> str:
    from siemsoar import aws
    arn = aws.client("sts").get_caller_identity()["Arn"]
    return f"cli:{arn}"


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
    sub.add_parser("feedback")
    lab = sub.add_parser("lab")
    lab.add_argument("action", choices=["status", "up", "extend", "down"])
    lab.add_argument("--hours", type=float, default=4)
    args = ap.parse_args(argv)
    _env(args.prefix)

    from siemsoar import aws
    from siemsoar.decisions import DecisionRejected, apply_decision
    from siemsoar.store import CaseNotFound, CaseStore

    if args.cmd == "lab":
        action = {"up": "start", "down": "stop"}.get(args.action, args.action)
        res = aws.client("lambda").invoke(FunctionName=f"{args.prefix}-lab_session",
                                          Payload=json.dumps({"action": action, "hours": args.hours}))
        print(res["Payload"].read().decode())
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
        try:
            out = apply_decision(store, args.case_id, args.gate, args.decision, actor=_actor(), channel="cli")
        except (DecisionRejected, CaseNotFound) as err:
            print(f"rejected: {err}", file=sys.stderr)
            return 1
        print(json.dumps(out))
        return 0
    if args.cmd == "feedback":
        print(json.dumps(feedback_stats(store), indent=2))
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
