"""Scenario runner with ground truth (paper chapter 5.4 / 6.1).

  python -m simulation.runner list
  python -m simulation.runner run host-useradd [--dry-run] [--no-wait]
  python -m simulation.runner run-all [--kind ssm_shell --kind pcap_replay]
  python -m simulation.runner upload-pcaps

Every run gets a run_id, is written to DynamoDB (RUN#<id>) with its expectations, and is verified after a settle
period against the cases the system produced. `evaluation/evaluate.py` later turns the stored runs into metrics.
Host scenarios stamp `run_id=<id>` into syslog so Wazuh alerts (and thus cases) carry the label; cloud and network
scenarios are joined to cases by time window and expected rule/finding type.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src" / "lambdas"))
sys.path.insert(0, str(ROOT))

SCENARIO_DIR = Path(__file__).resolve().parent / "scenarios"


def load_scenarios(directory: Path = SCENARIO_DIR) -> dict[str, dict]:
    out = {}
    for p in sorted(directory.glob("*.yml")):
        s = yaml.safe_load(p.read_text())
        s["_file"] = p.name
        out[s["id"]] = s
    return out


def new_run_id(scenario_id: str) -> str:
    return f"run-{datetime.now(UTC):%Y%m%d%H%M}-{scenario_id}-{secrets.token_hex(2)}"[:64]


def render(command: str, run_id: str) -> str:
    return command.replace("{run_id}", run_id).replace("{short}", run_id.rsplit("-", 1)[-1])


def match_expectations(expect: list[dict], cases: list[dict]) -> list[dict]:
    """Compare expectations with observed cases. A `case: false` expectation fails when a case exists."""
    checks = []
    for e in expect:
        hits = [c for c in cases if str(c["rule_id"]) == str(e["rule_id"]) and c["source"] == e["source"]]
        want = e.get("case", True)
        ok = bool(hits) == want
        if not ok and e.get("optional"):
            ok = True
        checks.append({"name": f"{e['source']}:{e['rule_id']} case={want}", "ok": ok,
                       "detail": [c["case_id"] for c in hits]})
    return checks


class Runner:
    def __init__(self, prefix: str = "siemsoar", dry_run: bool = False, wait: bool = True):
        os.environ.setdefault("NAME_PREFIX", prefix)
        os.environ.setdefault("CASES_TABLE", f"{prefix}-cases")
        from siemsoar import aws
        from siemsoar.store import CaseStore
        self.aws, self.prefix, self.dry_run, self.wait = aws, prefix, dry_run, wait
        self.store = CaseStore()
        account = aws.client("sts").get_caller_identity()["Account"]
        self.rules_bucket = f"{prefix}-rules-{account}"
        self.log = lambda msg: print(f"[{datetime.now(UTC):%H:%M:%S}] {msg}", flush=True)

    # ---- discovery ----------------------------------------------------------------
    def instance(self, role: str) -> str:
        res = self.aws.client("ec2").describe_instances(Filters=[
            {"Name": "tag:siemsoar:role", "Values": [role]}, {"Name": "instance-state-name", "Values": ["running"]}])
        ids = [i["InstanceId"] for r in res["Reservations"] for i in r["Instances"]]
        if not ids:
            raise SystemExit(f"no running instance with siemsoar:role={role}; start the lab: soarctl lab up")
        return ids[0]

    # ---- executors ----------------------------------------------------------------
    def ssm_run(self, instance_id: str, commands: list[str], timeout: int = 120) -> str:
        ssm = self.aws.client("ssm")
        cmd = ssm.send_command(InstanceIds=[instance_id], DocumentName="AWS-RunShellScript",
                               Parameters={"commands": commands, "executionTimeout": [str(timeout)]},
                               TimeoutSeconds=max(30, timeout))["Command"]["CommandId"]
        end = time.time() + timeout + 30
        while time.time() < end:
            time.sleep(2)
            inv = ssm.get_command_invocation(CommandId=cmd, InstanceId=instance_id)
            if inv["Status"] in {"Success", "Failed", "Cancelled", "TimedOut"}:
                if inv["Status"] != "Success":
                    raise RuntimeError(f"ssm command {inv['Status']}: {inv.get('StandardErrorContent', '')[:300]}")
                return inv.get("StandardOutputContent", "")
        raise TimeoutError("ssm command did not finish")

    def exec_ssm_shell(self, s: dict, run_id: str) -> dict:
        iid = self.instance("suricata-sensor" if s.get("target", "sensor") == "sensor" else "wazuh-manager")
        cmds = [render(c, run_id) for c in s["commands"]]
        try:
            out = self.ssm_run(iid, cmds)
        finally:
            if s.get("cleanup"):
                self.ssm_run(iid, [render(c, run_id) for c in s["cleanup"]])
        return {"instance": iid, "output": out[-500:]}

    def exec_guardduty_sample(self, s: dict, run_id: str) -> dict:
        gd = self.aws.client("guardduty")
        det = gd.list_detectors()["DetectorIds"][0]
        gd.create_sample_findings(DetectorId=det, FindingTypes=s["finding_types"])
        return {"detector": det, "types": s["finding_types"]}

    def exec_stratus(self, s: dict, run_id: str) -> dict:
        tech = s["stratus_technique"]
        try:
            subprocess.run(["stratus", "detonate", tech], check=True, timeout=600)
        finally:
            subprocess.run(["stratus", "cleanup", tech], check=False, timeout=600)
        return {"technique": tech}

    def upload_pcaps(self) -> list[str]:
        from tools import make_pcaps
        s3, names = self.aws.client("s3"), []
        with tempfile.TemporaryDirectory() as tmp:
            for name, make in make_pcaps.PCAPS.items():
                path = Path(tmp) / name
                make_pcaps.write_pcap(path, make())
                s3.upload_file(str(path), self.rules_bucket, f"sim/pcaps/{name}")
                names.append(name)
        return names

    def exec_pcap_replay(self, s: dict, run_id: str) -> dict:
        iid = self.instance("suricata-sensor")
        self.upload_pcaps()
        name = s["pcap"]
        out = self.ssm_run(iid, [
            f"aws s3 cp s3://{self.rules_bucket}/sim/pcaps/{name} /tmp/{name} --region {self.aws.region()}",
            "IFACE=$(ip -o -4 route show to default | awk '{print $5}' | head -1)",
            f"tcpreplay --intf1=$IFACE --pps=20 /tmp/{name}",
            f"logger -t siemsoar-sim 'pcap={name} run_id={run_id}'"])
        return {"instance": iid, "pcap": name, "output": out[-300:]}

    # ---- robustness ----------------------------------------------------------------
    def _set_fault(self, function: str, point: str) -> None:
        lam = self.aws.client("lambda")
        name = f"{self.prefix}-{function}"
        env = lam.get_function_configuration(FunctionName=name)["Environment"]["Variables"]
        env["FAULT_INJECT"] = point
        lam.update_function_configuration(FunctionName=name, Environment={"Variables": env})
        lam.get_waiter("function_updated_v2").wait(FunctionName=name)

    def _inject_finding(self, run_id: str, instance_id: str, severity: float = 5.0) -> str:
        """Replay a GuardDuty-shaped finding through the real ingest Lambda (same path as EventBridge)."""
        now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        event = {"source": "aws.guardduty", "detail-type": "GuardDuty Finding", "detail": {
            "id": f"sim-{run_id}", "type": "UnauthorizedAccess:EC2/SSHBruteForce", "severity": severity,
            "accountId": "000000000000", "region": self.aws.region(), "title": f"[SIMULATION] {run_id}",
            "description": "synthetic finding injected by simulation.runner", "createdAt": now,
            "resource": {"resourceType": "Instance", "instanceDetails": {"instanceId": instance_id}},
            "service": {"eventFirstSeen": now, "additionalInfo": {"sample": False}}}}
        out = self.aws.client("lambda").invoke(FunctionName=f"{self.prefix}-ingest", Payload=json.dumps(event))
        return json.loads(out["Payload"].read())["case_id"]

    def _wait_status(self, case_id: str, statuses: set[str], timeout: int = 180) -> dict:
        end = time.time() + timeout
        while time.time() < end:
            case = self.store.get_case(case_id)
            if case["status"] in statuses:
                return case
            time.sleep(3)
        raise TimeoutError(f"{case_id} never reached {statuses}")

    def check_double_click(self, s: dict, run_id: str) -> list[dict]:
        from siemsoar.decisions import DecisionRejected, apply_decision
        iid = self.instance("suricata-sensor")
        case_id = self._inject_finding(run_id, iid)
        self._wait_status(case_id, {"NOTIFIED"})

        def click(_):
            try:
                apply_decision(self.store, case_id, "approval", "dismiss", actor=f"sim:{run_id}", channel="cli")
                return "ok"
            except DecisionRejected as err:
                return f"rejected: {err}"

        with ThreadPoolExecutor(8) as pool:
            results = list(pool.map(click, range(8)))
        case = self._wait_status(case_id, {"DISMISSED"})
        return [{"name": "exactly one click accepted", "ok": results.count("ok") == 1, "detail": results},
                {"name": "case DISMISSED once", "ok": case["status"] == "DISMISSED", "detail": case_id}]

    def check_mid_failure(self, s: dict, run_id: str) -> list[dict]:
        from handlers._common import config_of  # noqa: F401  (import check: handlers on path)
        from siemsoar import evidence, response
        from siemsoar.decisions import apply_decision
        iid = self.instance("suricata-sensor")
        original = response.describe_instance(iid)["security_groups"]
        self._set_fault("contain", s["fault"])
        try:
            case_id = self._inject_finding(run_id, iid)
            self._wait_status(case_id, {"NOTIFIED"})
            apply_decision(self.store, case_id, "approval", "approve", actor=f"sim:{run_id}", channel="cli")
            case = self._wait_status(case_id, {"FAILED"}, timeout=300)
            isolated = response.describe_instance(iid)["security_groups"] != original
            checks = [{"name": "case FAILED (fail-safe)", "ok": case["status"] == "FAILED", "detail": case_id},
                      {"name": "resource left contained", "ok": isolated, "detail": case.get("safe_state")},
                      {"name": "operator alerted", "ok": "notified:failed" in
                       [a["action"] for a in self.store.list_audit(case_id)], "detail": ""}]
        finally:
            self._set_fault("contain", "")
        pre, _ = evidence.get_json(case_id, "pre_action_state")  # manual recovery a human would do
        response.restore_instance_sgs(iid, pre["security_groups"])
        return checks

    def check_slack_down(self, s: dict, run_id: str) -> list[dict]:
        from siemsoar.decisions import apply_decision
        iid = self.instance("suricata-sensor")
        self._set_fault("notify", s["fault"])
        try:
            case_id = self._inject_finding(run_id, iid)
            self._wait_status(case_id, {"NOTIFIED"})
            notified = [a for a in self.store.list_audit(case_id) if a["action"] == "notified:approval"][0]["detail"]
            apply_decision(self.store, case_id, "approval", "dismiss", actor=f"sim:{run_id}", channel="cli")
            case = self._wait_status(case_id, {"DISMISSED"})
        finally:
            self._set_fault("notify", "")
        return [{"name": "Slack failed, SNS fallback used", "ok": notified == {"slack": False, "sns": True},
                 "detail": notified},
                {"name": "decision via CLI channel completed the workflow", "ok": case["status"] == "DISMISSED",
                 "detail": case_id}]

    # ---- orchestration ----------------------------------------------------------------
    def run(self, scenario_id: str) -> dict:
        scenarios = load_scenarios()
        s = scenarios[scenario_id]
        run_id = new_run_id(scenario_id)
        started = datetime.now(UTC)
        self.log(f"{run_id}: {s['title']}")
        run = {"run_id": run_id, "scenario": scenario_id, "kind": s["kind"], "malicious": bool(s.get("malicious")),
               "techniques": s.get("techniques", []), "expect": s.get("expect", []),
               "started_at": started.strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z"}
        if self.dry_run:
            plan = {k: v for k, v in s.items() if k != "_file"}
            self.log(f"dry run, would execute kind={s['kind']}: {json.dumps(plan)}")
            return run
        kind = s["kind"]
        details: dict = {}
        try:
            if kind == "robustness":
                checks = getattr(self, f"check_{s['check']}")(s, run_id)
                run["result"] = {"pass": all(c["ok"] for c in checks), "checks": checks}
            else:
                details = getattr(self, f"exec_{kind}")(s, run_id)
        except Exception as err:  # noqa: BLE001
            run["result"] = {"pass": False, "checks": [{"name": "execution", "ok": False, "detail": str(err)}]}
            self.log(f"scenario error: {err}")
        run["ended_at"] = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z"
        run["details"] = details
        self.store.put_run(run)
        if kind != "robustness" and self.wait and "result" not in run:
            settle = int(s.get("settle_seconds", 120))
            self.log(f"waiting {settle}s for detections")
            time.sleep(settle)
            window_start = (started - timedelta(seconds=5)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
            cases = [c for c in self.store.list_cases() if c["created_at"] >= window_start]
            checks = match_expectations(s.get("expect", []), cases)
            run["result"] = {"pass": all(c["ok"] for c in checks), "checks": checks,
                             "observed_cases": [c["case_id"] for c in cases]}
            self.store.put_run(run)
        res = run.get("result", {})
        self.log(f"{run_id}: {'PASS' if res.get('pass') else 'FAIL' if res else 'recorded'}")
        for c in res.get("checks", []):
            self.log(f"   {'ok ' if c['ok'] else 'BAD'} {c['name']} {c.get('detail', '')}")
        return run


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="simulation.runner")
    ap.add_argument("--prefix", default=os.environ.get("NAME_PREFIX", "siemsoar"))
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    r = sub.add_parser("run")
    r.add_argument("scenario")
    r.add_argument("--dry-run", action="store_true")
    r.add_argument("--no-wait", action="store_true")
    ra = sub.add_parser("run-all")
    ra.add_argument("--kind", action="append")
    ra.add_argument("--repeat", type=int, default=1)
    sub.add_parser("upload-pcaps")
    args = ap.parse_args(argv)

    if args.cmd == "list":
        for sid, s in load_scenarios().items():
            print(f"{sid:<24} {s['kind']:<16} {s['title']}")
        return 0
    runner = Runner(args.prefix, dry_run=getattr(args, "dry_run", False), wait=not getattr(args, "no_wait", False))
    if args.cmd == "upload-pcaps":
        print(runner.upload_pcaps())
        return 0
    if args.cmd == "run":
        res = runner.run(args.scenario).get("result", {})
        return 0 if res.get("pass", True) else 1
    failed = 0
    for _ in range(args.repeat):
        for sid, s in load_scenarios().items():
            if args.kind and s["kind"] not in args.kind:
                continue
            failed += not runner.run(sid).get("result", {}).get("pass", True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
