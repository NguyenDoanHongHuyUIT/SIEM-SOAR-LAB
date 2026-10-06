"""Pre-flight checks before any containment: scope, protection tag, permission dry run, circuit breaker."""

from __future__ import annotations

from botocore.exceptions import ClientError
from siemsoar import aws, response
from siemsoar.config import settings
from siemsoar.errors import BreakerOpen, PreflightFailed
from siemsoar.schema import PLAN_EC2, PLAN_IAM

from handlers._common import config_of, dry_run_of, load


def _tags_iam(user: str) -> dict:
    return {t["Key"]: t["Value"] for t in aws.client("iam").list_user_tags(UserName=user)["Tags"]}


def handler(event, context=None):
    store, case = load(event)
    cfg, plan = settings(), case["response_plan"]
    dry_run = dry_run_of(event)
    checks: dict = {}

    if plan["type"] == PLAN_EC2:
        iid = plan["params"]["instance_id"]
        try:
            info = response.describe_instance(iid)
        except response.NotFound as err:
            raise PreflightFailed(f"instance {iid} not found") from err
        if info["state"] in {"terminated", "shutting-down"}:
            raise PreflightFailed(f"instance {iid} is {info['state']}")
        if info["tags"].get(cfg.protected_tag, "").lower() == "true":
            raise PreflightFailed(f"instance {iid} carries {cfg.protected_tag}=true")
        if info["tags"].get(cfg.zone_tag) != "workload":
            raise PreflightFailed(f"instance {iid} is not in zone=workload (tag {cfg.zone_tag})")
        holder = info["tags"].get(response.CASE_TAG)
        if holder and holder != case["case_id"]:
            # a second alert on a host that is already contained: its "pre-action state" would be the isolation SG
            raise PreflightFailed(f"instance {iid} is already isolated by case {holder}; decide on that case")
        if not response.check_modify_permission(iid):
            raise PreflightFailed("EC2 DryRun: SOAR role lacks ModifyInstanceAttribute on target")
        checks = {"target": iid, "zone": "workload", "ec2_dry_run": "ok"}
    elif plan["type"] == PLAN_IAM:
        user, key = plan["params"]["user_name"], plan["params"]["access_key_id"]
        if not user.startswith(cfg.iam_target_prefix):
            raise PreflightFailed(f"IAM user {user} outside allowed prefix {cfg.iam_target_prefix!r}")
        try:
            tags = _tags_iam(user)
            keys = response.list_keys(user)
        except ClientError as err:
            raise PreflightFailed(f"cannot read IAM user {user}: {err.response['Error']['Code']}") from err
        if tags.get(cfg.protected_tag, "").lower() == "true":
            raise PreflightFailed(f"IAM user {user} carries {cfg.protected_tag}=true")
        if key not in keys:
            raise PreflightFailed(f"access key {key} not found for {user}")
        checks = {"target": f"{user}/{key}", "key_status": keys[key]}
    else:
        raise PreflightFailed("case has no containment plan")

    limit, window = config_of(event).get("breaker_limit", cfg.breaker_limit), config_of(event).get(
        "breaker_window", cfg.breaker_window)
    count, tripped = store.breaker_register(case["case_id"], limit, window)
    if tripped:
        store.audit(case["case_id"], "circuit_breaker_open", "system", {"count": count, "limit": limit})
        raise BreakerOpen(f"{count} isolations in {window}s exceeds limit {limit}")
    store.audit(case["case_id"], "preflight_ok", "system", {**checks, "breaker": count, "dry_run": dry_run})
    return {"plan_type": plan["type"], "checks": checks, "breaker_count": count}
