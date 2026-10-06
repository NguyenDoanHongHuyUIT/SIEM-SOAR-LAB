"""On-demand plane switch: start/stop/extend/status of the Wazuh manager + lab hosts, with a hard auto-stop timer.

Invocation (aws lambda invoke / GitHub workflow / soarctl):
  {"action": "start",  "hours": 4}    start tagged instances and arm a one-off stop timer
  {"action": "extend", "hours": 2}    re-arm the timer from now
  {"action": "stop"}                  stop instances and cancel the timer (also what the timer itself sends)
  {"action": "status"}
Instances are selected by tag siemsoar:plane=ondemand; IAM additionally enforces that tag on start/stop.
"""

from __future__ import annotations

import json
import os
from datetime import timedelta

from botocore.exceptions import ClientError

from siemsoar import aws
from siemsoar.util import get_logger, now

log = get_logger("handlers.lab_session")
MAX_HOURS = 12


def _instances() -> list[dict]:
    res = aws.client("ec2").describe_instances(Filters=[
        {"Name": "tag:siemsoar:plane", "Values": ["ondemand"]},
        {"Name": "instance-state-name", "Values": ["pending", "running", "stopping", "stopped"]}])
    out = []
    for r in res["Reservations"]:
        for i in r["Instances"]:
            tags = {t["Key"]: t["Value"] for t in i.get("Tags", [])}
            out.append({"id": i["InstanceId"], "state": i["State"]["Name"], "role": tags.get("siemsoar:role")})
    return out


def _schedule_name() -> str:
    return f"{os.environ.get('LAB_NAME_PREFIX', 'siemsoar')}-lab-autostop"


def _arm_timer(hours: float) -> str:
    sched = aws.client("scheduler")
    when = (now() + timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S")
    _disarm_timer()
    sched.create_schedule(
        Name=_schedule_name(), ScheduleExpression=f"at({when})", ScheduleExpressionTimezone="UTC",
        FlexibleTimeWindow={"Mode": "OFF"}, ActionAfterCompletion="DELETE",
        Target={"Arn": os.environ["SELF_FUNCTION_ARN"], "RoleArn": os.environ["SCHEDULER_ROLE_ARN"],
                "Input": json.dumps({"action": "stop", "reason": "auto-stop timer"})})
    return when + "Z"


def _disarm_timer() -> None:
    try:
        aws.client("scheduler").delete_schedule(Name=_schedule_name())
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def handler(event, context=None):
    action = event.get("action", "status")
    insts = _instances()
    ec2 = aws.client("ec2")
    if action in {"start", "extend"}:
        hours = min(float(event.get("hours", 4)), MAX_HOURS)
        ids = [i["id"] for i in insts if i["state"] in {"stopped", "stopping"}] if action == "start" else []
        if ids:
            ec2.start_instances(InstanceIds=ids)
        return {"action": action, "started": ids, "auto_stop_at": _arm_timer(hours), "instances": insts}
    if action == "stop":
        ids = [i["id"] for i in insts if i["state"] in {"pending", "running"}]
        if ids:
            ec2.stop_instances(InstanceIds=ids)
        if event.get("reason") != "auto-stop timer":
            _disarm_timer()
        log.info("lab stopped", extra={"ctx": {"stopped": ids, "reason": event.get("reason")}})
        return {"action": "stop", "stopped": ids}
    if action == "status":
        try:
            sched = aws.client("scheduler").get_schedule(Name=_schedule_name())["ScheduleExpression"]
        except ClientError:
            sched = None
        return {"instances": insts, "auto_stop": sched}
    raise ValueError(f"unknown action {action!r}")
