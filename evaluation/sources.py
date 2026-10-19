"""Evaluation inputs measured from AWS itself instead of typed in or assumed.

  * sessions   - when the on-demand lab really ran: CloudTrail RunInstances/StartInstances/StopInstances of the instances
                 tagged siemsoar:plane=ondemand (also catches the auto-stop timer, which is just another StopInstances).
  * cost       - what AWS actually billed for those days: Cost Explorer filtered by the cost-allocation tag
                 Project=siem-soar-lab (needs the tag activated in Billing; data lags up to ~24 h; ~$0.01 per request).
                 Or, as an estimate, list prices from the AWS Pricing API (never a constant in the code).
  * baseline   - the manual alternative: for each GuardDuty finding, the first containment API call a *human* made on the
                 same resource from the AWS Management Console (CloudTrail), minus the finding time, plus how many
                 state-changing console calls they needed. Scripts with the same credentials (the simulation runner
                 deletes the previous victim key before each Stratus run) are not a person reacting to an alert.

Every function takes the boto3 client as a parameter and has a pure core, so tests run without AWS. CloudTrail event
fields follow https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.html .
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

LAB_TAG = ("siemsoar:plane", "ondemand")
CONTAINMENT_EVENTS = {"ModifyInstanceAttribute", "ModifyNetworkInterfaceAttribute", "StopInstances", "UpdateAccessKey",
                      "DeleteAccessKey", "DeactivateMFADevice", "PutUserPolicy", "PutRolePolicy"}
SOAR_PRINCIPAL_MARKERS = ("-fn-", "-sfn-role", "-lab-scheduler")  # roles created by infra/modules/serverless-core
BASELINE_WINDOW = timedelta(hours=6)


def _time(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(UTC)
    except ValueError:
        return None


def _dig(obj: Any, *path: str) -> Any:
    for key in path:
        obj = obj.get(key) if isinstance(obj, dict) else None
    return obj


def _detail(event: dict) -> dict:
    """CloudTrail LookupEvents wraps the full record as a JSON string in `CloudTrailEvent`."""
    raw = event.get("CloudTrailEvent")
    return json.loads(raw) if isinstance(raw, str) else (raw or event)


def lookup(ct, event_name: str, start: datetime, end: datetime) -> list[dict]:
    """All CloudTrail management events called `event_name` in [start, end] (LookupEvents covers the last 90 days)."""
    out: list[dict] = []
    paginator = ct.get_paginator("lookup_events")
    for page in paginator.paginate(LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": event_name}],
                                   StartTime=start, EndTime=end):
        out += [_detail(e) for e in page.get("Events", [])]
    return out


# --------------------------------------------------------------------------- lab sessions
def _instance_ids(record: dict) -> list[str]:
    for container in ("requestParameters", "responseElements"):
        items = _dig(record, container, "instancesSet", "items") or []
        ids = [i.get("instanceId") for i in items if isinstance(i, dict) and i.get("instanceId")]
        if ids:
            return ids
    return []


def lab_instances(run_events: list[dict]) -> dict[str, str]:
    """{instance id: instance type} for instances whose RunInstances call carried the tag siemsoar:plane=ondemand."""
    out: dict[str, str] = {}
    for rec in run_events:
        tags = [t for spec in (_dig(rec, "requestParameters", "tagSpecificationSet", "items") or [])
                if isinstance(spec, dict) and spec.get("resourceType") == "instance"
                for t in (spec.get("tags") or [])]
        if any(t.get("key") == LAB_TAG[0] and t.get("value") == LAB_TAG[1] for t in tags):
            for iid in _instance_ids({"responseElements": rec.get("responseElements")}):
                out[iid] = _dig(rec, "requestParameters", "instanceType") or "unknown"
    return out


def _type_changes(modify_events: list[dict], lab: set[str]) -> dict[str, list[tuple[datetime, str]]]:
    """{instance id: [(time, new type)]} from ModifyInstanceAttribute calls that changed instanceType (what Terraform
    does to resize a stopped instance in place; no RunInstances is recorded for it)."""
    out: dict[str, list[tuple[datetime, str]]] = {}
    for rec in modify_events:
        iid = _dig(rec, "requestParameters", "instanceId")
        new = _dig(rec, "requestParameters", "instanceType", "value")
        if iid in lab and new and (t := _time(rec.get("eventTime"))):
            out.setdefault(iid, []).append((t, new))
    return {k: sorted(v) for k, v in out.items()}


def build_sessions(run_events: list[dict], start_events: list[dict], stop_events: list[dict],
                   now: datetime | None = None, modify_events: list[dict] | None = None) -> list[dict]:
    """Lab sessions: from the first instance start to the last instance stop that follows it.

    The creation (RunInstances) counts as the first start. Overlapping instance runs are merged, because the manager and
    the sensor start and stop together and only wall-clock time is billable once. `types` lists every lab instance type.
    A session still running at `now` is reported up to `now` with `open: true` (it used to be dropped: the first real
    report showed 0 lab hours while the lab was up). `types` has one entry per instance that ran in the session, with
    the type it had then (resizes from ModifyInstanceAttribute applied), so two instances of one type count twice.
    """
    types = lab_instances(run_events)
    changes = _type_changes(modify_events or [], set(types))

    def type_at(iid: str, when: datetime) -> str:
        current = types[iid]
        for t, new in changes.get(iid, []):
            if t <= when:
                current = new
        return current
    points: list[tuple[datetime, str, str]] = []
    for rec in run_events:
        for iid in _instance_ids({"responseElements": rec.get("responseElements")}):
            if iid in types and (t := _time(rec.get("eventTime"))):
                points.append((t, "up", iid))
    for rec, kind in [(r, "up") for r in start_events] + [(r, "down") for r in stop_events]:
        t = _time(rec.get("eventTime"))
        points += [(t, kind, iid) for iid in _instance_ids(rec) if iid in types and t]
    points.sort()
    running: set[str] = set()
    seen: dict[str, str] = {}  # instances started in the current session -> type at their start
    sessions: list[dict] = []
    opened: datetime | None = None
    for when, kind, iid in points:
        if kind == "up":
            if not running:
                opened, seen = when, {}
            running.add(iid)
            seen.setdefault(iid, type_at(iid, when))
        else:
            running.discard(iid)
            if not running and opened is not None:
                sessions.append({"start": opened, "end": when, "hours": round((when - opened).total_seconds() / 3600, 3),
                                 "types": sorted(seen.values()), "open": False})
                opened = None
    if opened is not None and now is not None and now > opened:
        sessions.append({"start": opened, "end": now, "hours": round((now - opened).total_seconds() / 3600, 3),
                         "types": sorted(seen.values()), "open": True})
    return sessions


def sessions_from_cloudtrail(ct, start: datetime, end: datetime) -> list[dict]:
    return build_sessions(lookup(ct, "RunInstances", start, end), lookup(ct, "StartInstances", start, end),
                          lookup(ct, "StopInstances", start, end), now=end,
                          modify_events=lookup(ct, "ModifyInstanceAttribute", start, end))


# --------------------------------------------------------------------------- cost
def region_location(region: str) -> str:
    """Pricing API location name of a region ("ap-southeast-1" -> "Asia Pacific (Singapore)"), from botocore's data."""
    from botocore.loaders import create_loader
    partitions = create_loader().load_data("endpoints")["partitions"]
    for part in partitions:
        if region in part["regions"]:
            return part["regions"][region]["description"]
    raise ValueError(f"unknown region {region!r}")


def parse_ec2_price(price_list: list[str]) -> float:
    """Hourly on-demand USD out of Pricing API `PriceList` entries; refuses ambiguous answers."""
    prices = set()
    for item in price_list:
        doc = json.loads(item) if isinstance(item, str) else item
        for term in (doc.get("terms", {}).get("OnDemand") or {}).values():
            for dim in term["priceDimensions"].values():
                if dim.get("unit") == "Hrs":
                    prices.add(float(dim["pricePerUnit"]["USD"]))
    if len(prices) != 1:
        raise ValueError(f"expected one on-demand hourly price, found {sorted(prices)}")
    return prices.pop()


def ec2_hourly_price(pricing, instance_type: str, region: str) -> float:
    """List price of one Linux, shared-tenancy EC2 instance hour from the AWS Pricing API (us-east-1 endpoint)."""
    flt = [("instanceType", instance_type), ("location", region_location(region)), ("operatingSystem", "Linux"),
           ("tenancy", "Shared"), ("preInstalledSw", "NA"), ("capacitystatus", "Used")]
    res = pricing.get_products(ServiceCode="AmazonEC2", MaxResults=10, Filters=[
        {"Type": "TERM_MATCH", "Field": f, "Value": v} for f, v in flt])
    return parse_ec2_price(res["PriceList"])


def estimate_session_cost(sessions: list[dict], prices: dict[str, float]) -> dict:
    """EC2 compute only, from list prices: sum(hours x price of every lab instance type). Storage/IPv4 are not included."""
    rows, total = [], 0.0
    for s in sessions:
        missing = [t for t in s["types"] if t not in prices]
        if missing:
            raise ValueError(f"no price for instance type(s) {missing}")
        usd = round(s["hours"] * sum(prices[t] for t in s["types"]), 3)
        rows.append({"start": s["start"].isoformat(), "hours": s["hours"], "usd_compute_estimate": usd})
        total += usd
    return {"sessions": rows, "total_usd_compute_estimate": round(total, 2),
            "avg_usd_per_session": round(total / len(rows), 2) if rows else None,
            "note": "EC2 compute at AWS list prices; excludes EBS, public IPv4 and data transfer"}


def actual_cost(ce, start: datetime, end: datetime, tag_key: str = "Project", tag_value: str = "siem-soar-lab") -> dict:
    """What AWS billed, per service, for resources carrying the cost-allocation tag (Cost Explorer, daily).

    An empty answer for an inactive tag means "unknown", not "$0": Cost Explorer only filters by user-defined tags
    that are activated as cost-allocation tags. That case raises, so the report says why there is no figure."""
    tags = ce.list_cost_allocation_tags(TagKeys=[tag_key]).get("CostAllocationTags", [])
    tag = next((t for t in tags if t.get("TagKey") == tag_key), {})
    if tag.get("Status") != "Active":
        raise RuntimeError(f"cost-allocation tag {tag_key!r} is {tag.get('Status') or 'unknown to Billing'}: activate "
                           f"it in Billing > Cost allocation tags; until then the billed cost is unknown, not $0")
    # Cost Explorer attributes tagged cost from the activation on, and the data lags (up to ~24 h): a period that starts
    # before the activation is only partly covered, and an empty answer right after it is "not yet known".
    activated = _time(tag.get("LastUpdatedDate"))
    res = ce.get_cost_and_usage(
        TimePeriod={"Start": start.date().isoformat(), "End": end.date().isoformat()}, Granularity="DAILY",
        Metrics=["UnblendedCost"], Filter={"Tags": {"Key": tag_key, "Values": [tag_value]}},
        GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}])
    by_service: dict[str, float] = {}
    for day in res["ResultsByTime"]:
        for group in day.get("Groups", []):
            by_service[group["Keys"][0]] = by_service.get(group["Keys"][0], 0.0) + float(
                group["Metrics"]["UnblendedCost"]["Amount"])
    since = activated.date().isoformat() if activated else "?"
    if not by_service:
        raise RuntimeError(f"no billed cost carries {tag_key}={tag_value} yet (tag active since {since}; Cost Explorer "
                           f"only attributes costs incurred after activation, with up to ~24 h delay): unknown, not $0")
    partial = bool(activated and activated > start)
    return {"period": [start.date().isoformat(), end.date().isoformat()], "tag": f"{tag_key}={tag_value}",
            "by_service_usd": {k: round(v, 4) for k, v in sorted(by_service.items())},
            "total_usd": round(sum(by_service.values()), 4), "covers_from": since if partial else start.date().isoformat(),
            "note": "billed amounts (Cost Explorer, UnblendedCost)" + (
                f"; only costs since the tag activation ({since}) carry the tag: earlier sessions are not included"
                if partial else "")}


# --------------------------------------------------------------------------- baseline (manual containment)
def from_console(record: dict) -> bool:
    """CloudTrail `sessionCredentialFromConsole`: "Shows whether or not an event originated from an AWS Management
    Console session" (https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html).
    Absent for SDK/CLI/Terraform calls, observed "true" for console clicks in the lab account."""
    return str(record.get("sessionCredentialFromConsole", "")).lower() == "true"


def is_soar_principal(record: dict) -> bool:
    arn = _dig(record, "userIdentity", "arn") or ""
    return any(marker in arn for marker in SOAR_PRINCIPAL_MARKERS)


def _resource_of(record: dict) -> set[str]:
    """Instance id(s) or user/key a containment call touched."""
    ids = set(_instance_ids(record))
    for key in ("instanceId", "userName", "accessKeyId"):
        value = _dig(record, "requestParameters", key)
        if value:
            ids.add(value)
    return ids


def baseline_rows(findings: list[dict], events: list[dict]) -> list[dict]:
    """One row per finding that a human contained by hand.

    findings: [{"id", "type", "created_at", "resources": {instance ids / user names / key ids}}]
    events:   CloudTrail records of the looked-up API names. A human containment call is the first CONTAINMENT_EVENTS
    call made from the console by a non-SOAR principal, on one of the finding's resources, within BASELINE_WINDOW after
    the finding. manual_steps = the state-changing (readOnly=false) console calls among those API names that the same
    principal made in between, i.e. what the person clicked to contain.
    """
    humans = sorted((e for e in events if from_console(e) and not is_soar_principal(e) and _time(e.get("eventTime"))),
                    key=lambda e: _time(e["eventTime"]))
    rows = []
    for f in findings:
        created = _time(f["created_at"])
        if created is None:
            continue
        window_end = created + BASELINE_WINDOW
        hit = next((e for e in humans
                    if e.get("eventName") in CONTAINMENT_EVENTS and created <= _time(e["eventTime"]) <= window_end
                    and _resource_of(e) & set(f["resources"])), None)
        if hit is None:
            continue
        who = _dig(hit, "userIdentity", "arn")
        done = _time(hit["eventTime"])
        steps = [e for e in humans if _dig(e, "userIdentity", "arn") == who and e.get("readOnly") is False
                 and created <= _time(e["eventTime"]) <= done]
        rows.append({"scenario": f["type"], "run": f["id"], "seconds_to_contain": round((done - created).total_seconds(), 1),
                     "manual_steps": len(steps), "seconds_to_notice": "", "errors": 0,
                     "notes": f"{hit['eventName']} by {who} (CloudTrail, console)"})
    return rows


def guardduty_findings(gd, start: datetime) -> list[dict]:
    """Real GuardDuty findings (not samples) created since `start`, with the resources a responder would touch."""
    out = []
    for detector in gd.list_detectors()["DetectorIds"]:
        ids: list[str] = []
        for page in gd.get_paginator("list_findings").paginate(DetectorId=detector, FindingCriteria={"Criterion": {
                "updatedAt": {"GreaterThanOrEqual": int(start.timestamp() * 1000)}}}):
            ids += page["FindingIds"]
        for i in range(0, len(ids), 50):
            for f in gd.get_findings(DetectorId=detector, FindingIds=ids[i:i + 50])["Findings"]:
                if _dig(f, "Service", "AdditionalInfo", "Value") and "sample" in str(f["Service"]["AdditionalInfo"]).lower():
                    continue  # GuardDuty sample findings are demo data, never a baseline
                res = f.get("Resource", {})
                resources = {_dig(res, "InstanceDetails", "InstanceId"), _dig(res, "AccessKeyDetails", "UserName"),
                             _dig(res, "AccessKeyDetails", "AccessKeyId")} - {None}
                out.append({"id": f["Id"], "type": f["Type"], "created_at": f["CreatedAt"], "resources": resources})
    return out


def baseline_from_cloudtrail(ct, gd, start: datetime, end: datetime) -> list[dict]:
    events: list[dict] = []
    for name in sorted(CONTAINMENT_EVENTS) + ["AuthorizeSecurityGroupIngress", "RevokeSecurityGroupIngress"]:
        events += lookup(ct, name, start, end)
    return baseline_rows(guardduty_findings(gd, start), events)
