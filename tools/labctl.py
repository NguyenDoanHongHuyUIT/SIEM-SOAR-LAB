"""labctl: switch the on-demand plane (Wazuh manager + lab hosts) on/off with a hard auto-stop timer.

  python -m tools.labctl up --hours 4      # start stopped lab instances, arm the auto-stop timer
  python -m tools.labctl extend --hours 2  # re-arm the timer from now
  python -m tools.labctl down              # stop instances and cancel the timer
  python -m tools.labctl ensure-timer      # after a Terraform apply: no running lab instance without a timer
  python -m tools.labctl status

Replaces the former `lab_session` Lambda. The auto-stop itself is now native: a one-time EventBridge Scheduler
schedule whose *universal target* is `arn:aws:scheduler:::aws-sdk:ec2:stopInstances`, so no code runs when it fires
(and no Lambda, role or `iam:PassRole` is needed for it). Instances are selected by tag siemsoar:plane=ondemand;
the scheduler role can only stop instances carrying that tag (infra/modules/serverless-core/lab_scheduler.tf).
"""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src" / "lambdas"))

from botocore.exceptions import ClientError  # noqa: E402
from siemsoar import aws, response  # noqa: E402

MAX_HOURS = 12
GUARD_HOURS = 1  # timer armed by ensure-timer when instances run and no session timer exists
STOP_TARGET = "arn:aws:scheduler:::aws-sdk:ec2:stopInstances"
LIVE_STATES = ["pending", "running", "stopping", "stopped"]


def instances() -> list[dict]:
    found = response.find_instances({"siemsoar:plane": "ondemand"}, tuple(LIVE_STATES))
    return [{"id": i["id"], "state": i["state"], "role": i["tags"].get("siemsoar:role")} for i in found]


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


def arm_timer(prefix: str, hours: float, ids: list[str], at: datetime | None = None) -> str:
    """One-time schedule stopping `ids` in `hours` (capped at MAX_HOURS), or at `at` (re-arming an existing session)."""
    if at is None and (not math.isfinite(hours) or hours <= 0):
        raise ValueError("hours must be a finite number greater than zero")
    if not ids:
        raise SystemExit("no lab instances found (is the on-demand plane applied? tag siemsoar:plane=ondemand)")
    moment = at or datetime.now(UTC) + timedelta(hours=min(hours, MAX_HOURS))
    when = moment.strftime("%Y-%m-%dT%H:%M:%S")
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


def _timer_at(prefix: str) -> datetime | None:
    """When the session timer fires (its `at(...)` expression, UTC), or None when there is no timer."""
    try:
        expr = aws.client("scheduler").get_schedule(Name=schedule_name(prefix))["ScheduleExpression"]
    except ClientError as err:
        if err.response["Error"]["Code"] == "ResourceNotFoundException":
            return None
        raise
    return datetime.strptime(expr[3:-1], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=UTC)


def ensure_timer(prefix: str, guard_hours: float = GUARD_HOURS) -> dict:
    """Run after every apply of the on-demand plane. The timer stops the instance ids it was given when it was armed,
    so an instance Terraform creates later (lab 2026-10-19: two new targets kept running after the 08:39 stop) is not
    covered. An existing timer is re-armed at the SAME time with every current lab instance; if there is none (or it is
    already past) while something runs, a GUARD_HOURS timer is armed. Nothing running and no timer: nothing to do."""
    insts = instances()
    ids = [i["id"] for i in insts]
    running = [i["id"] for i in insts if i["state"] in {"pending", "running"}]
    at = _timer_at(prefix)
    if at and at > datetime.now(UTC) + timedelta(minutes=1):
        return {"auto_stop_at": arm_timer(prefix, 0, ids, at=at), "rearmed_for": ids, "instances": insts}
    if running:
        return {"auto_stop_at": arm_timer(prefix, guard_hours, ids), "guard": True, "instances": insts}
    return {"auto_stop_at": None, "instances": insts}


def status(prefix: str) -> dict:
    try:
        timer = aws.client("scheduler").get_schedule(Name=schedule_name(prefix))["ScheduleExpression"]
    except ClientError:
        timer = None
    return {"instances": instances(), "auto_stop": timer}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="tools.labctl")
    ap.add_argument("--prefix", default=os.environ.get("NAME_PREFIX", "siemsoar"))
    ap.add_argument("action", choices=["up", "extend", "down", "status", "ensure-timer"])
    ap.add_argument("--hours", type=float, default=4)
    args = ap.parse_args(argv)
    fn = {"up": lambda: up(args.prefix, args.hours), "extend": lambda: extend(args.prefix, args.hours),
          "down": lambda: down(args.prefix), "status": lambda: status(args.prefix),
          "ensure-timer": lambda: ensure_timer(args.prefix)}[args.action]
    print(json.dumps(fn(), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
