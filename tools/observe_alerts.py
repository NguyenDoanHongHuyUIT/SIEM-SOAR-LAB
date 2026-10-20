"""observe_alerts: every Wazuh alert (official rules included) that a recorded run raised on its target, read-only.

  python -m tools.observe_alerts <run_id> [<run_id> ...]

The runner only keeps SIEMSOAR alerts (the rules it scores). Before a new SIEMSOAR rule is written for a technique, the
evidence is what the real procedure produced on the lab: which official rules fired (audit 80792, FIM 550/554, ...)
and with which fields. Per run: each rule id with its level, description, count and the distinct values of the
fields a rule could key on. The filtering and grouping run on the manager (jq), so only the summary crosses SSM
(whose output is capped at 24 000 characters). Nothing is changed on the manager.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import timedelta

from simulation.runner import INSTANCE_RE, Runner, parse_iso

# path in the alert -> short name in the summary
FIELDS = {"exe": ".data.audit.exe", "command": ".data.audit.command", "key": ".data.audit.key",
          "file": ".data.audit.file.name", "path": ".syscheck.path", "event": ".syscheck.event"}


def _ts(dt) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S")  # same leading format as Wazuh's alert timestamp: compares as text


def summary_command(agent: str, start, end) -> str:
    if not INSTANCE_RE.fullmatch(agent):
        raise ValueError(f"not an EC2 instance id: {agent!r}")
    lo, hi = _ts(start - timedelta(seconds=5)), _ts(end)
    pick = ", ".join(f"{k}: {v}" for k, v in FIELDS.items())
    uniq = ", ".join(f'{k}: ([.[].{k}] | map(select(. != null)) | unique | .[0:8] | map(tostring | .[0:160]))'
                     for k in FIELDS)
    # -R + fromjson?: the last line of alerts.json can be half-written while analysisd appends to it
    return ("tail -n 300000 /var/ossec/logs/alerts/alerts.json | "
            f"jq -R -c 'fromjson? | select(.agent.name==\"{agent}\" and .timestamp >= \"{lo}\" and .timestamp <= \"{hi}\") | "
            f"{{id: .rule.id, level: .rule.level, d: .rule.description, mitre: .rule.mitre.id, {pick}}}' | "
            f"jq -s -c 'group_by(.id) | map({{rule_id: .[0].id, level: .[0].level, description: .[0].d, "
            f"mitre: .[0].mitre, count: length, {uniq}}}) | sort_by(-.level)'")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="tools.observe_alerts")
    ap.add_argument("run_ids", nargs="+")
    ap.add_argument("--prefix", default=os.environ.get("NAME_PREFIX", "siemsoar"))
    args = ap.parse_args(argv)
    runner = Runner(args.prefix)
    runs = {r["run_id"]: r for r in runner.store.list_runs()}
    manager = runner.instance("wazuh-manager")
    for run_id in args.run_ids:
        run = runs.get(run_id)
        if not run or not run.get("target") or not INSTANCE_RE.fullmatch(str(run["target"])):
            print(json.dumps({"run_id": run_id, "error": "unknown run or run without a host target"}))
            continue
        end = parse_iso(run["ended_at"]) + timedelta(seconds=int(run.get("settle_seconds", 120)))
        out = runner.ssm_run(manager, [summary_command(run["target"], parse_iso(run["started_at"]), end)], timeout=300)
        print(json.dumps({"run_id": run_id, "scenario": run["scenario"], "target": run["target"],
                          "alerts": json.loads(out.strip() or "[]")}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
