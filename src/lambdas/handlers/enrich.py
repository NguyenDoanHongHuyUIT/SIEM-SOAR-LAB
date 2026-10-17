"""Enrichment + risk scoring. Also downgrades the plan when the target does not exist (e.g. GuardDuty samples)."""

from __future__ import annotations

from botocore.exceptions import ClientError
from siemsoar import aws, response
from siemsoar.config import settings
from siemsoar.schema import PLAN_EC2, PLAN_IAM, PLAN_NONE, compute_risk

from handlers._common import config_of, load


def _enrich_ec2(case: dict, plan: dict) -> tuple[dict, dict, bool, str]:
    try:
        info = response.describe_instance(plan["params"]["instance_id"])
    except response.NotFound:
        return {}, {"type": PLAN_NONE, "params": {}}, False, "target instance not found"
    tags = info["tags"]
    enrichment = {"name": info["name"], "state": info["state"], "vpc_id": info["vpc_id"],
                  "criticality": tags.get("criticality", "medium"), "owner": tags.get("owner"),
                  "zone": tags.get(settings().zone_tag), "internet_exposed": bool(info["public_ip"]),
                  "security_groups": info["security_groups"]}
    return enrichment, plan, True, ""


def _enrich_iam(case: dict, plan: dict) -> tuple[dict, dict, bool, str]:
    user = plan["params"]["user_name"]
    try:
        keys = response.list_keys(user)
        tags = {t["Key"]: t["Value"] for t in aws.client("iam").list_user_tags(UserName=user)["Tags"]}
    except ClientError as err:
        if err.response["Error"]["Code"] == "NoSuchEntity":
            return {}, {"type": PLAN_NONE, "params": {}}, False, "target IAM user not found"
        raise
    return ({"criticality": tags.get("criticality", "medium"), "owner": tags.get("owner"),
             "key_status": keys.get(plan["params"]["access_key_id"], "missing")}, plan, True, "")


LOOKUP_STATES = ("pending", "running", "stopping", "stopped")


def resolve_agent(plan: dict) -> tuple[str | None, str]:
    """Map a Wazuh agent that is not named after an instance id to exactly one EC2 instance.

    Strategies and their order come from policy `resolution.wazuh_agent`. A strategy that matches several instances
    (overlapping private ranges, reused names) is an ambiguity, not a guess: the plan stays `none`.
    Returns (instance id or None, how it was resolved / why not).
    """
    info = plan.get("unresolved") or {}
    reasons = []
    for how in plan.get("resolve_via", []):
        if how == "private_ip" and info.get("agent_ip"):
            filters = [{"Name": "private-ip-address", "Values": [str(info["agent_ip"])]}]
        elif how == "name_tag" and info.get("agent_name"):
            filters = [{"Name": "tag:Name", "Values": [str(info["agent_name"])]}]
        else:
            continue
        hits = response.find_instances_where(filters, LOOKUP_STATES)
        if len(hits) == 1:
            return hits[0]["id"], how
        reasons.append(f"{how}: {len(hits)} instances matched")
    return None, "agent could not be mapped to one EC2 instance (" + ("; ".join(reasons) or "no usable identifier") + ")"


def handler(event, context=None):
    store, case = load(event)
    plan = case.get("response_plan", {"type": PLAN_NONE, "params": {}})
    resolution_note = ""
    if plan["type"] == PLAN_NONE and plan.get("requested") == PLAN_EC2 and plan.get("unresolved"):
        instance_id, how = resolve_agent(plan)
        if instance_id:
            plan = {"type": PLAN_EC2, "params": {"instance_id": instance_id}, "resolved_via": how}
            old = case.get("resource", {})
            store.update_case(case["case_id"], resource={**old, "type": "ec2_instance", "id": instance_id,
                                                         "agent_name": old.get("id")}, resource_id=instance_id)
            store.audit(case["case_id"], "agent_resolved", "system", {"instance_id": instance_id, "via": how})
        else:
            resolution_note = how
    enrichment, note, exists = {}, resolution_note, True
    if plan["type"] == PLAN_EC2:
        enrichment, plan, exists, note = _enrich_ec2(case, plan)
    elif plan["type"] == PLAN_IAM:
        enrichment, plan, exists, note = _enrich_iam(case, plan)

    risk = compute_risk(case["severity"], enrichment.get("criticality", "medium"), case.get("alert_count", 1),
                        enrichment.get("internet_exposed", False))
    updates = {"enrichment": enrichment, "risk_score": risk, "response_plan": plan, "resource_exists": exists}
    if note:
        updates["plan_note"] = note + (" (sample finding)" if case.get("sample") else "")
    store.update_case(case["case_id"], **updates)
    store.audit(case["case_id"], "enriched", "system", {"risk_score": risk, "plan": plan["type"], "note": note})
    threshold = config_of(event).get("stop_risk_threshold", settings().stop_risk_threshold)
    return {"risk_score": risk, "plan_type": plan["type"], "plan_params": plan["params"], "resource_exists": exists,
            "stop_instance": plan["type"] == PLAN_EC2 and risk >= threshold}
