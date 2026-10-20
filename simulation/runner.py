"""Scenario runner with ground truth (paper chapter 5.4 / 6.1).

  python -m simulation.runner list
  python -m simulation.runner run host-useradd [--dry-run] [--no-wait]
  python -m simulation.runner run-all [--kind atomic --kind stratus] [--repeat 3]
  python -m simulation.runner upload-pcaps

What a scenario claims (technique, malicious or benign, which rule should fire) is validated by simulation/catalog.py
against pinned public sources before anything runs. Every run gets a run_id and is stored in DynamoDB (RUN#<id>) with:

  * `target`       the instance the procedure ran on (cases are joined to runs by target + time window, or by run_id
                   when the procedure could stamp it into a log line),
  * `siem_alerts`  every SIEMSOAR alert Wazuh raised on that target during the run window, whatever the rule's
                   lifecycle state: this is how shadow rules, false positives of benign runs and missed detections are
                   measured at the SIEM layer, independently of the case pipeline,
  * `observed`     per expectation, whether its rule alerted in the window.

After a benign run, cases opened on the target are closed with the simulation's ground truth (actor
`sim:ground-truth`) so they do not block later restores; the evaluation never counts those as human feedback.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import shlex
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

from botocore.exceptions import WaiterError

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src" / "lambdas"))
sys.path.insert(0, str(ROOT))

from siemsoar.util import parse_iso  # noqa: E402

from simulation.catalog import SCENARIO_DIR, case_in_run, load_scenarios, merged_in_run  # noqa: E402,F401

PCAP_DIR = ROOT / "rules" / "pcaps"
GROUND_TRUTH_ACTOR = "sim:ground-truth"
INSTANCE_RE = re.compile(r"^i-[0-9a-f]{8,17}$")


def new_run_id(scenario_id: str) -> str:
    return f"run-{datetime.now(UTC):%Y%m%d%H%M}-{scenario_id}-{secrets.token_hex(2)}"[:64]


def render(command: str, run_id: str, context: dict[str, str] | None = None) -> str:
    """Fill the catalogue's placeholders: {run_id}, {short} and host facts such as {manager_ip}."""
    values = {"run_id": run_id, "short": run_id.rsplit("-", 1)[-1], **(context or {})}
    return re.sub(r"\{(\w+)\}", lambda m: values.get(m.group(1), m.group(0)), command)


def match_expectations(expect: list[dict], cases: list[dict], run: dict) -> list[dict]:
    """Compare expectations with observed cases. A `case: false` expectation fails when a case exists.

    Cases are attributed exactly as the evaluation does (catalog.case_in_run: run_id, scripted actor, target + window):
    a same-rule case on another resource (e.g. the operator's key in Stratus' cleanup) is not this run's detection."""
    if parse_iso(run.get("started_at")) is None or parse_iso(run.get("ended_at")) is None \
            or int(run.get("settle_seconds", 120)) < 0:
        raise ValueError("scenario run has invalid time bounds")

    checks = []
    for e in expect:
        same = [case for case in cases if str(case["rule_id"]) == str(e["rule_id"]) and case["source"] == e["source"]]
        hits = [case for case in same if case_in_run(case, run)] or [case for case in same if merged_in_run(case, run)]
        want = e.get("case", True)
        ok = bool(hits) == want
        if not ok and e.get("optional"):
            ok = True
        checks.append({"name": f"{e['source']}:{e['rule_id']} case={want}", "ok": ok,
                       "detail": [c["case_id"] for c in hits]})
    return checks


def siem_alerts_command(agent: str, day: str | None = None) -> str:
    """Shell snippet for the Wazuh manager: "<rule id> <timestamp>" of every SIEMSOAR alert of `agent`.

    alerts.json is where Wazuh records an alert whatever the rule's lifecycle state is, so this sees shadow rules too.
    With `day` (YYYY-MM-DD, a run re-observed later), that day's rotated archive is read as well: Wazuh moves the
    alerts of each day to logs/alerts/<year>/<Mon>/ossec-alerts-<dd>.json, gzipped by monitord at day change when it
    runs then (monitord.compress). Lab 2026-10-20: the manager was stopped at midnight and the archives stayed plain
    .json, so both names are read. Today's archive is a hard link to alerts.json (`-ef`): read once, not twice.

    analysisd appends to alerts.json while it is read, so its last line can be half-written. Lines are parsed one by one
    (`jq -R 'fromjson?'`): an incomplete line is skipped instead of failing the whole read, and alerts.json comes last
    so that line cannot be glued to an archive's first line (lab 2026-10-20: "parse error: Invalid literal at line
    14981, column 2189", the junction of alerts.json and ossec-alerts-19.json).
    The agent name (= EC2 instance id) is validated because it ends up inside a shell command.
    """
    if not INSTANCE_RE.fullmatch(agent):
        raise ValueError(f"not an EC2 instance id: {agent!r}")
    source = "tail -n 50000 /var/ossec/logs/alerts/alerts.json"
    if day is not None:
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", day):
            raise ValueError(f"not a date: {day!r}")
        when = datetime.strptime(day, "%Y-%m-%d")
        archive = f"/var/ossec/logs/alerts/{when:%Y}/{when:%b}/ossec-alerts-{when:%d}.json"
        current = "/var/ossec/logs/alerts/alerts.json"
        source = (f"(for f in {archive} {archive}.gz; do "
                  f"if [ -e \"$f\" ] && ! [ \"$f\" -ef {current} ]; then zcat -f \"$f\"; echo; fi; done; "
                  f"cat {current}) 2>/dev/null")
    return (f"{source} | jq -R -r 'fromjson? | select(.agent.name==\"{agent}\") | "
            f"select((.rule.groups // []) | index(\"siemsoar\")) | \"\\(.rule.id) \\(.timestamp)\"'")


def parse_siem_alerts(output: str) -> list[dict]:
    out = []
    for line in output.splitlines():
        rule_id, _, ts = line.strip().partition(" ")
        when = parse_iso(ts)
        if rule_id.isdigit() and when is not None:
            out.append({"rule_id": rule_id, "timestamp": when.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"})
    return out


def in_window(alerts: list[dict], started_at: str, ended_at: str, settle_seconds: int) -> list[dict]:
    start, end = parse_iso(started_at), parse_iso(ended_at)
    if start is None or end is None:
        raise ValueError("scenario run has invalid time bounds")
    lo, hi = start - timedelta(seconds=5), end + timedelta(seconds=settle_seconds)
    return [a for a in alerts if lo <= parse_iso(a["timestamp"]) <= hi]


def observe_expectations(expect: list[dict], alerts: list[dict]) -> dict[str, bool]:
    """{"<source>:<rule>": the rule alerted in the SIEM during the run} for every host/network expectation.

    For a shadow rule (`case: false`) this is the only proof it fired; for an active rule it separates a detection
    miss (no alert) from a pipeline miss (alert but no case).
    """
    fired = {a["rule_id"] for a in alerts}
    return {f"{e['source']}:{e['rule_id']}": str(e["rule_id"]) in fired
            for e in expect if e["source"] in ("wazuh", "suricata") and e.get("siem_alert", True)}


OBSERVE_ROLES = {"sensor": "suricata-sensor", "lab-target": "lab-target"}  # catalog.OBSERVE_HOSTS -> siemsoar:role
EXEC_ROLES = {"sensor": "suricata-sensor", "manager": "wazuh-manager", "lab-target": "lab-target"}  # catalog.EXEC_HOSTS


def resource_env(prefix: str, account: str) -> dict[str, str]:
    """Names the Lambdas get from Terraform and the runner needs too (it reads evidence after a robustness test).
    Without EVIDENCE_BUCKET the mid-failure recovery could not read pre_action_state and left the host isolated."""
    return {"NAME_PREFIX": prefix, "CASES_TABLE": f"{prefix}-cases", "EVIDENCE_BUCKET": f"{prefix}-evidence-{account}"}


class Runner:
    def __init__(self, prefix: str = "siemsoar", dry_run: bool = False, wait: bool = True):
        os.environ.setdefault("NAME_PREFIX", prefix)
        os.environ.setdefault("CASES_TABLE", f"{prefix}-cases")
        from siemsoar import aws
        from siemsoar.store import CaseStore
        self.aws, self.prefix, self.dry_run, self.wait = aws, prefix, dry_run, wait
        self.store = CaseStore()
        account = aws.client("sts").get_caller_identity()["Account"]
        for key, value in resource_env(prefix, account).items():
            os.environ.setdefault(key, value)
        self.rules_bucket = f"{prefix}-rules-{account}"
        self.log = lambda msg: print(f"[{datetime.now(UTC):%H:%M:%S}] {msg}", flush=True)

    # ---- discovery ----------------------------------------------------------------
    def instance(self, role: str) -> str:
        from siemsoar import response
        found = response.find_instances({"siemsoar:role": role, "siemsoar:plane": "ondemand"})
        ids = [i["id"] for i in sorted(found, key=lambda i: i["tags"].get("Name", ""))]  # lab-target-1 before -2
        if not ids:  # an error, not SystemExit: inside a run it must be recorded, not end the process unrecorded
            raise RuntimeError(f"no running instance with siemsoar:role={role}; start the lab: soarctl lab up")
        return ids[0]

    def attack_target(self, role: str) -> str:
        """The instance a scenario acts on, refused while a case holds it contained.

        Lab 2026-10-19: a second host-useradd ran on the sensor 80 s after a case had isolated it (SSM still reached the
        host). Its alert merged into the open case and, correctly, blocked the analyst's restore three times: the
        system cannot tell a test from an intruder still active. A contained host is decided on first."""
        from siemsoar import response
        iid = self.instance(role)
        info = response.describe_instance(iid)
        holder = info["tags"].get(response.CASE_TAG)  # set by the containment step, removed by a verified restore
        if holder:
            raise RuntimeError(f"{iid} is contained by case {holder}: decide/restore that case before running "
                               f"another scenario on it")
        return iid

    def await_detections(self, expect: list[dict], run: dict, poll: int = 30) -> list[dict]:
        """Wait up to the settle window for the expected cases. Stops early only when every expectation wants a case
        and all are there: a `case: false` expectation (shadow rule, benign run) needs the whole window to be proven."""
        settle = run["settle_seconds"]
        self.log(f"waiting up to {settle}s for detections")
        deadline = time.time() + settle
        early = bool(expect) and all(e.get("case", True) for e in expect)
        while True:
            cases = self.store.list_cases()
            if early and all(c["ok"] for c in match_expectations(expect, cases, run)):
                self.log(f"all expected cases present after {settle - max(0, int(deadline - time.time()))}s")
                return cases
            if time.time() >= deadline:
                return cases
            time.sleep(min(poll, max(1, deadline - time.time())))

    def conclude(self, run: dict, s: dict, cases: list[dict], day: str | None = None) -> dict:
        """Verdict of a run: expected cases, the SIEM alerts on its target in its window, the benign-noise check.
        A SIEM read that fails (manager stopped, SSM error) is recorded as an observation error and leaves the run
        unobserved, instead of ending the process with the run half-written (lab 2026-10-19: the manager was being
        resized while a run waited)."""
        checks = match_expectations(s.get("expect", []), cases, run)
        try:
            run["siem_alerts"] = self.siem_alerts(run, day)
        except Exception as err:  # noqa: BLE001 - recorded on the run
            run["observation_error"] = str(err)[:300]
            run.pop("siem_alerts", None)
            checks.append({"name": "SIEM read", "ok": False, "detail": run["observation_error"]})
        mine = [c for c in cases if case_in_run(c, run)]
        if "siem_alerts" in run:
            run["observed"] = observe_expectations(s.get("expect", []), run["siem_alerts"])
            checks += [{"name": f"{key} alert observed in the SIEM", "ok": ok, "detail": ""}
                       for key, ok in run["observed"].items() if ok or not _optional(s, key)]
            if not run["malicious"]:
                expected = {str(e["rule_id"]) for e in s.get("expect", [])}  # incl. declared false positives
                noise = sorted({a["rule_id"] for a in run["siem_alerts"]} - expected)
                checks.append({"name": "benign activity raised no unexpected SIEMSOAR alert", "ok": not noise,
                               "detail": noise})
                run["ground_truth_closed"] = self.close_benign_cases(run, mine)
        run["result"] = {"pass": all(c["ok"] for c in checks), "checks": checks,
                         "observed_cases": [c["case_id"] for c in mine]}
        self.store.put_run(run)
        return run

    def reobserve(self, run_id: str) -> dict:
        """Conclude a run whose process stopped during its wait (the session ended, the operator's machine slept):
        the attack ran and its alerts are in the manager's alert log, so the verdict is read from there, with the same
        window and attribution as a live run. Marked `reobserved_at`; a run with a live verdict is refused.

        The expectations are the ones the run recorded when it executed, not today's scenario file: an observation
        run (`expect: []`) stays an observation run after rules were written from it (2026-10-20: a run made before
        100141 existed was judged against 100141). A verdict that itself came from a re-observation can be read
        again (the reader was wrong: archive name, 2026-10-20); the previous one is kept in `superseded_results`."""
        run = next((r for r in self.store.list_runs() if r["run_id"] == run_id), None)
        if run is None:
            raise ValueError(f"unknown run {run_id}")
        if ("result" in run and not run.get("reobserved_at")) or run.get("execution_error") or not run.get("ended_at"):
            raise ValueError(f"{run_id} already has a live verdict or never finished its execution")
        if "result" in run:
            run["superseded_results"] = [*run.get("superseded_results", []),
                                         {"reobserved_at": run["reobserved_at"], "result": run.pop("result"),
                                          "siem_alerts": run.pop("siem_alerts", None),
                                          "observed": run.pop("observed", None),
                                          "observation_error": run.pop("observation_error", None)}]
        s = {**load_scenarios().get(run["scenario"], {}), "expect": run.get("expect", [])}
        run["reobserved_at"] = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z"
        return self.conclude(run, s, self.store.list_cases(), day=run["started_at"][:10])

    def rules_release(self) -> str | None:
        """The rule release deployed on the lab (releases/current.json): every run is measured against one version."""
        try:
            body = self.aws.client("s3").get_object(Bucket=self.rules_bucket, Key="releases/current.json")["Body"]
            return json.loads(body.read()).get("sha")
        except Exception:  # noqa: BLE001 - informative only
            return None

    def private_ip(self, role: str) -> str:
        from siemsoar import response
        return response.describe_instance(self.instance(role))["private_ip"]

    def context(self, s: dict) -> dict[str, str]:
        """Host facts a scenario's commands/args refer to (resolved only when used)."""
        text = json.dumps({k: s.get(k) for k in ("commands", "prepare", "verify", "cleanup", "atomic")})
        ctx = {}
        if "{manager_ip}" in text:
            ctx["manager_ip"] = self.private_ip("wazuh-manager")
        if "{sensor_ip}" in text:
            ctx["sensor_ip"] = self.private_ip("suricata-sensor")
        if "{target_ip}" in text:
            ctx["target_ip"] = self.private_ip("lab-target")
        return ctx

    # ---- executors ----------------------------------------------------------------
    def ssm_run(self, instance_id: str, commands: list[str], timeout: int = 120) -> str:
        ssm = self.aws.client("ssm")
        cmd = ssm.send_command(InstanceIds=[instance_id], DocumentName="AWS-RunShellScript",
                               Parameters={"commands": commands, "executionTimeout": [str(timeout)]},
                               TimeoutSeconds=max(30, timeout))["Command"]["CommandId"]
        try:  # the waiter also tolerates InvocationDoesNotExist right after send_command
            ssm.get_waiter("command_executed").wait(CommandId=cmd, InstanceId=instance_id,
                                                    WaiterConfig={"Delay": 2, "MaxAttempts": (timeout + 30) // 2})
        except WaiterError:
            pass  # Failed / Cancelled / TimedOut: the invocation below carries the real status
        inv = ssm.get_command_invocation(CommandId=cmd, InstanceId=instance_id)
        if inv["Status"] != "Success":
            raise RuntimeError(f"ssm command {inv['Status']}: {inv.get('StandardErrorContent', '')[:300]}")
        return inv.get("StandardOutputContent", "")

    def exec_ssm_shell(self, s: dict, run_id: str) -> dict:
        iid = self.attack_target(EXEC_ROLES[s.get("target", "sensor")])
        ctx = self.context(s)
        cmds = [render(c, run_id, ctx) for c in s["commands"]]
        try:
            out = self.ssm_run(iid, cmds)
        finally:
            if s.get("cleanup"):
                self.ssm_run(iid, [render(c, run_id, ctx) for c in s["cleanup"]])
        return {"instance": iid, "output": out[-500:]}

    def exec_atomic(self, s: dict, run_id: str) -> dict:
        """Atomic Red Team test (unmodified upstream YAML) executed on the sensor by scripts/run_atomic.py.

        Order: `prepare` (e.g. back up a file the atomic changes), the atomic, `verify` (proves the behaviour really
        happened: a run whose atomic did nothing is an execution error, never a false negative), then, whatever
        happened, the test's own `cleanup_command` (run_atomic.py --cleanup, the Atomic Red Team convention) followed by
        the scenario's `cleanup`. Lab 2026-10-19: without the upstream cleanup the cron and systemd persistence of
        T1053.003/T1543.002 stayed installed on the sensor after their runs.
        A missing prerequisite makes run_atomic exit 3, which fails the SSM command: also an execution error.
        """
        iid = self.attack_target(EXEC_ROLES[s.get("target", "sensor")])
        art = s["atomic"]
        ctx = self.context(s)
        timeout = int(art.get("timeout", 120))
        args = " ".join(f"--arg {shlex.quote(str(key) + '=' + render(str(value), run_id, ctx))}"
                        for key, value in (art.get("args") or {}).items())
        cmd = (f"HOME=/root ART_REF={shlex.quote(art['ref'])} python3 /opt/siemsoar/bootstrap/scripts/run_atomic.py "
               f"{shlex.quote(art['technique'])} {shlex.quote(art['test_guid'])} {args} --timeout {timeout}").rstrip()
        report: dict = {}
        cleanup: dict = {}
        try:
            if s.get("prepare"):
                self.ssm_run(iid, [render(c, run_id, ctx) for c in s["prepare"]])
            out = self.ssm_run(iid, [cmd], timeout=timeout + 60)
            try:
                report = json.loads(out.strip().splitlines()[-1])
            except (ValueError, IndexError):
                report = {"output": out[-500:]}
            for check in s.get("verify", []):
                self.ssm_run(iid, [render(check, run_id, ctx)])
        finally:
            try:
                out = self.ssm_run(iid, [f"{cmd} --cleanup"], timeout=timeout + 60)
                cleanup = json.loads(out.strip().splitlines()[-1])
            except Exception as err:  # noqa: BLE001 - reported, and the scenario cleanup must still run
                cleanup = {"error": str(err)[:300]}
                self.log(f"atomic cleanup failed on {iid}: {err}")
            if s.get("cleanup"):
                self.ssm_run(iid, [render(c, run_id, ctx) for c in s["cleanup"]])
        return {"instance": iid, "atomic": {k: art[k] for k in ("technique", "test_guid")}, "report": report,
                "cleanup": {k: cleanup.get(k) for k in ("exit_code", "timed_out", "error") if k in cleanup}}

    def exec_guardduty_sample(self, s: dict, run_id: str) -> dict:
        gd = self.aws.client("guardduty")
        det = gd.list_detectors()["DetectorIds"][0]
        gd.create_sample_findings(DetectorId=det, FindingTypes=s["finding_types"])
        return {"detector": det, "types": s["finding_types"]}

    def victim_credentials(self) -> dict[str, str]:
        """A fresh access key of the simulation-zone IAM user. Older keys (from earlier runs, possibly disabled by the
        SOAR) are deleted first: IAM allows two keys per user."""
        iam, user = self.aws.client("iam"), os.environ.get("SIEMSOAR_SIM_USER", "lab-victim")
        for key in iam.list_access_keys(UserName=user)["AccessKeyMetadata"]:
            iam.delete_access_key(UserName=user, AccessKeyId=key["AccessKeyId"])
        key = iam.create_access_key(UserName=user)["AccessKey"]
        time.sleep(10)  # IAM is eventually consistent: a brand-new key is not usable immediately
        return {"AWS_ACCESS_KEY_ID": key["AccessKeyId"], "AWS_SECRET_ACCESS_KEY": key["SecretAccessKey"],
                "user": user}

    def exec_stratus(self, s: dict, run_id: str) -> dict:
        tech = s["stratus_technique"]
        allowed_account = os.environ.get("SIEMSOAR_LAB_ACCOUNT_ID", "")
        if not re.fullmatch(r"\d{12}", allowed_account):
            raise RuntimeError("set SIEMSOAR_LAB_ACCOUNT_ID to the approved 12-digit lab account before Stratus")
        account = self.aws.client("sts").get_caller_identity()["Account"]
        if account != allowed_account:
            raise RuntimeError(f"refusing Stratus in AWS account {account}; expected approved lab account")
        details = {"technique": tech, "account_id": account}
        try:
            env = None
            if s.get("detonate_as") == "victim":
                subprocess.run(["stratus", "warmup", tech], check=True, timeout=600)  # operator builds the infra
                creds = self.victim_credentials()
                details.update(detonated_by=creds["user"], access_key_id=creds["AWS_ACCESS_KEY_ID"],
                               target=f'{creds["user"]}/{creds["AWS_ACCESS_KEY_ID"]}',  # the case's resource id
                               target_unique=True)  # a key created for this run only: no late-arrival cut-off
                env = {k: v for k, v in os.environ.items() if not k.startswith("AWS_") or k == "AWS_REGION"}
                env.update({k: creds[k] for k in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY")},
                           AWS_REGION=self.aws.region())
            subprocess.run(["stratus", "detonate", tech], check=True, timeout=600, env=env)
        finally:
            cleanup = subprocess.run(["stratus", "cleanup", tech], check=False, timeout=600)
            if cleanup.returncode != 0:
                raise RuntimeError(f"Stratus cleanup failed for {tech} (exit {cleanup.returncode})")
        return details

    def upload_pcaps(self) -> list[str]:
        """The committed captures (rules/pcaps, provenance.json) for pcap_replay scenarios."""
        s3, names = self.aws.client("s3"), []
        for path in sorted(PCAP_DIR.glob("*.pcap")):
            s3.upload_file(str(path), self.rules_bucket, f"sim/pcaps/{path.name}")
            names.append(path.name)
        return names

    def exec_pcap_replay(self, s: dict, run_id: str) -> dict:
        iid = self.attack_target("suricata-sensor")
        self.upload_pcaps()
        name = s["pcap"]
        out = self.ssm_run(iid, [
            f"aws s3 cp s3://{self.rules_bucket}/sim/pcaps/{name} /tmp/{name} --region {self.aws.region()}",
            "IFACE=$(ip -o -4 route show to default | awk '{print $5}' | head -1)",
            f"tcpreplay --intf1=$IFACE --pps=20 /tmp/{name}",
            f"logger -t siemsoar-sim 'pcap={name} run_id={run_id}'"])
        return {"instance": iid, "pcap": name, "output": out[-300:]}

    def siem_alerts(self, run: dict, day: str | None = None) -> list[dict]:
        """Every SIEMSOAR alert Wazuh raised on the run's target inside the run window (any lifecycle state).

        Only hosts run a Wazuh agent: a cloud target (the IAM key of a Stratus run) has no SIEM layer, GuardDuty is
        its only detector, so there is nothing to read (lab session 3 crashed here on 'lab-victim/AKIA...')."""
        if not run.get("target") or not INSTANCE_RE.fullmatch(str(run["target"])):
            return []
        output = self.ssm_run(self.instance("wazuh-manager"), [siem_alerts_command(run["target"], day)])
        return in_window(parse_siem_alerts(output), run["started_at"], run["ended_at"], run["settle_seconds"])

    def close_benign_cases(self, run: dict, cases: list[dict]) -> list[str]:
        """Dismiss cases opened on the target during a benign run, as the simulation's ground truth (not a human)."""
        from siemsoar.decisions import DecisionRejected, apply_decision
        closed = []
        for case in cases:
            if case["status"] == "NOTIFIED" and case_in_run(case, run):
                try:
                    apply_decision(self.store, case["case_id"], "approval", "dismiss",
                                   actor=f"{GROUND_TRUTH_ACTOR}:{run['run_id']}", channel="cli")
                    closed.append(case["case_id"])
                except DecisionRejected as err:
                    self.log(f"could not close {case['case_id']}: {err}")
        return closed

    # ---- robustness ----------------------------------------------------------------
    def _set_fault(self, function: str, point: str) -> None:
        lam = self.aws.client("lambda")
        name = f"{self.prefix}-{function}"
        env = lam.get_function_configuration(FunctionName=name)["Environment"]["Variables"]
        env["FAULT_INJECT"] = point
        lam.update_function_configuration(FunctionName=name, Environment={"Variables": env})
        lam.get_waiter("function_updated_v2").wait(FunctionName=name)

    def _open_case_via(self, trigger: str, run_id: str) -> str:
        """Run the real trigger scenario (e.g. Atomic Red Team T1136.001) and return the case Wazuh opened for it.

        Nothing is injected: the case exists because the genuine detection chain fired. Cases are matched on rule,
        source and the creation window, like evaluation.attribute does for scenarios without a run_id.
        """
        scenario = load_scenarios()[trigger]
        wanted = [e for e in scenario.get("expect", []) if e.get("case", True) and not e.get("optional")]
        if not wanted:  # e.g. its rules are still in shadow: robustness needs an active rule (promote it first)
            raise RuntimeError(f"trigger scenario {trigger} expects no case: promote its rule to active first "
                               f"(python -m tools.rulesctl promote wazuh-100110 active)")
        since = datetime.now(UTC) - timedelta(seconds=5)
        getattr(self, f"exec_{scenario['kind']}")(scenario, run_id)
        deadline = time.time() + int(scenario.get("settle_seconds", 120)) + 120
        while time.time() < deadline:
            for case in self.store.list_cases():
                created = parse_iso(case.get("created_at"))
                if (created and created >= since and case["source"] == wanted[0]["source"]
                        and str(case["rule_id"]) == str(wanted[0]["rule_id"])):
                    return case["case_id"]
            time.sleep(5)
        raise TimeoutError(f"no case for {wanted[0]['source']}:{wanted[0]['rule_id']} after running {trigger}")

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
        case_id = self._open_case_via(s["trigger"], run_id)
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
        from siemsoar import evidence, response
        from siemsoar.decisions import apply_decision
        iid = self.attack_target("suricata-sensor")
        original = response.eni_groups(response.describe_instance(iid))
        self._set_fault("contain", s["fault"])
        try:
            case_id = self._open_case_via(s["trigger"], run_id)
            self._wait_status(case_id, {"NOTIFIED"})
            apply_decision(self.store, case_id, "approval", "approve", actor=f"sim:{run_id}", channel="cli")
            case = self._wait_status(case_id, {"FAILED"}, timeout=300)
            isolated = response.eni_groups(response.describe_instance(iid)) != original
            checks = [{"name": "case FAILED (fail-safe)", "ok": case["status"] == "FAILED", "detail": case_id},
                      {"name": "resource left contained", "ok": isolated, "detail": case.get("safe_state")},
                      {"name": "operator alerted", "ok": "notified:failed" in
                       [a["action"] for a in self.store.list_audit(case_id)], "detail": ""}]
        finally:
            self._set_fault("contain", "")
        pre, _ = evidence.get_json(case_id, "pre_action_state")  # the recovery `soarctl recover` performs
        response.restore_ec2_from_state(iid, pre)
        restored, summary = response.ec2_matches_state(iid, pre)
        checks.append({"name": "recovered after the test", "ok": restored, "detail": summary})
        return checks

    def check_slack_down(self, s: dict, run_id: str) -> list[dict]:
        from siemsoar.decisions import apply_decision
        self._set_fault("notify", s["fault"])
        try:
            case_id = self._open_case_via(s["trigger"], run_id)
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
               "canary": bool(s.get("canary")), "evaluation_scope": s.get("evaluation_scope", "detection"),
               "techniques": s.get("techniques") or [], "technique_source": s.get("technique_source"),
               "evidence": bool(s.get("evidence")), "expect": s.get("expect", []),
               "rules_release": None if self.dry_run else self.rules_release(),
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
                # cross-host test: it runs on the sensor, the detection is expected on `observe_on`'s agent. That host
                # must not be contained either (its new alerts would block the restore of its case).
                observed = self.attack_target(OBSERVE_ROLES[s["observe_on"]]) if s.get("observe_on") else None
                details = getattr(self, f"exec_{kind}")(s, run_id)
                if observed:
                    details["executed_on"], details["instance"] = details.get("instance"), observed
        except Exception as err:  # noqa: BLE001
            run["result"] = {"pass": False, "checks": [{"name": "execution", "ok": False, "detail": str(err)}]}
            run["execution_error"] = str(err)  # evaluation must not count this run's expectations as false negatives
            self.log(f"scenario error: {err}")
        ended = datetime.now(UTC)
        run["ended_at"] = ended.strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z"
        run["settle_seconds"] = int(s.get("settle_seconds", 120))
        run["details"] = {k: v for k, v in details.items() if k != "instance"}
        run["target"] = details.get("instance") or details.get("target")
        run["target_unique"] = bool(details.get("target_unique"))
        self.store.put_run(run)
        if kind != "robustness" and self.wait and "result" not in run:
            self.conclude(run, s, self.await_detections(s.get("expect", []), run))
        res = run.get("result", {})
        self.log(f"{run_id}: {'PASS' if res.get('pass') else 'FAIL' if res else 'recorded'}")
        for c in res.get("checks", []):
            self.log(f"   {'ok ' if c['ok'] else 'BAD'} {c['name']} {c.get('detail', '')}")
        return run


def _optional(s: dict, key: str) -> bool:
    return any(f"{e['source']}:{e['rule_id']}" == key and e.get("optional") for e in s.get("expect", []))


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
    ro = sub.add_parser("reobserve", help="conclude runs whose process stopped during the wait, from the alert log")
    ro.add_argument("run_ids", nargs="+")
    args = ap.parse_args(argv)

    if args.cmd == "list":
        for sid, s in load_scenarios().items():
            print(f"{sid:<24} {s['kind']:<16} {s['title']}")
        return 0
    runner = Runner(args.prefix, dry_run=getattr(args, "dry_run", False), wait=not getattr(args, "no_wait", False))
    if args.cmd == "reobserve":
        for run_id in args.run_ids:
            res = runner.reobserve(run_id).get("result", {})
            runner.log(f"{run_id}: {'PASS' if res.get('pass') else 'FAIL'} (re-observed)")
            for c in res.get("checks", []):
                runner.log(f"   {'ok ' if c['ok'] else 'BAD'} {c['name']} {c.get('detail', '')}")
        return 0
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
