"""labctl: switch the on-demand plane (Wazuh manager + lab hosts) on/off with a hard auto-stop timer.

  python -m tools.labctl up --hours 4      # start stopped lab instances, arm the auto-stop timer
  python -m tools.labctl extend --hours 2  # re-arm the timer from now
  python -m tools.labctl down              # stop instances and cancel the timer
  python -m tools.labctl status

Replaces the former `lab_session` Lambda. The auto-stop itself is now native: a one-time EventBridge Scheduler
schedule whose *universal target* is `arn:aws:scheduler:::aws-sdk:ec2:stopInstances`, so no code runs when it fires
(and no Lambda, role or `iam:PassRole` is needed for it). Instances are selected by tag siemsoar:plane=ondemand;
the scheduler role can only stop instances carrying that tag (infra/modules/serverless-core/lab_scheduler.tf).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src" / "lambdas"))

from botocore.exceptions import ClientError  # noqa: E402
from siemsoar import aws  # noqa: E402

MAX_HOURS = 12
STOP_TARGET = "arn:aws:scheduler:::aws-sdk:ec2:stopInstances"
LIVE_STATES = ["pending", "running", "stopping", "stopped"]


def instances() -> list[dict]:
    res = aws.client("ec2").describe_instances(Filters=[
        {"Name": "tag:siemsoar:plane", "Values": ["ondemand"]}, {"Name": "instance-state-name", "Values": LIVE_STATES}])
    out = []
    for r in res["Reservations"]:
        for i in r["Instances"]:
            tags = {t["Key"]: t["Value"] for t in i.get("Tags", [])}
            out.append({"id": i["InstanceId"], "state": i["State"]["Name"], "role": tags.get("siemsoar:role")})
    return out


def schedule_name(prefix: str) -> str:
    return f"{prefix}-lab-autostop"


def scheduler_role_arn(prefix: str) -> str:
    return os.environ.get("SCHEDULER_ROLE_ARN") or (
        f"arn:aws:iam::{aws.client('sts').get_caller_identity()['Account']}:role/{prefix}-lab-scheduler")


def disarm_timer(prefix: str) -> None:
    try:
        aws.client("scheduler").delete_schedule(Name=schedule_name(prefix))
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def arm_timer(prefix: str, hours: float, ids: list[str]) -> str:
    if not ids:
        raise SystemExit("no lab instances found (is the on-demand plane applied? tag siemsoar:plane=ondemand)")
    when = (datetime.now(UTC) + timedelta(hours=min(hours, MAX_HOURS))).strftime("%Y-%m-%dT%H:%M:%S")
    disarm_timer(prefix)
    aws.client("scheduler").create_schedule(
        Name=schedule_name(prefix), ScheduleExpression=f"at({when})", ScheduleExpressionTimezone="UTC",
        FlexibleTimeWindow={"Mode": "OFF"}, ActionAfterCompletion="DELETE",
        Target={"Arn": STOP_TARGET, "RoleArn": scheduler_role_arn(prefix), "Input": json.dumps({"InstanceIds": ids})})
    return when + "Z"


def up(prefix: str, hours: float = 4) -> dict:
    insts = instances()
    stopped = [i["id"] for i in insts if i["state"] in {"stopped", "stopping"}]
    if stopped:
        aws.client("ec2").start_instances(InstanceIds=stopped)
    return {"started": stopped, "auto_stop_at": arm_timer(prefix, hours, [i["id"] for i in insts]), "instances": insts}


def extend(prefix: str, hours: float = 2) -> dict:
    insts = instances()
    return {"auto_stop_at": arm_timer(prefix, hours, [i["id"] for i in insts]), "instances": insts}


def down(prefix: str) -> dict:
    running = [i["id"] for i in instances() if i["state"] in {"pending", "running"}]
    if running:
        aws.client("ec2").stop_instances(InstanceIds=running)
    disarm_timer(prefix)
    return {"stopped": running}


def status(prefix: str) -> dict:
    try:
        timer = aws.client("scheduler").get_schedule(Name=schedule_name(prefix))["ScheduleExpression"]
    except ClientError:
        timer = None
    return {"instances": instances(), "auto_stop": timer}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="tools.labctl")
    ap.add_argument("--prefix", default=os.environ.get("NAME_PREFIX", "siemsoar"))
    ap.add_argument("action", choices=["up", "extend", "down", "status"])
    ap.add_argument("--hours", type=float, default=4)
    args = ap.parse_args(argv)
    fn = {"up": lambda: up(args.prefix, args.hours), "extend": lambda: extend(args.prefix, args.hours),
          "down": lambda: down(args.prefix), "status": lambda: status(args.prefix)}[args.action]
    print(json.dumps(fn(), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
