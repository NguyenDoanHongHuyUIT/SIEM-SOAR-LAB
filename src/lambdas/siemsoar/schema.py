"""Normalise GuardDuty / Wazuh (incl. Suricata) alerts into one common alert schema.

What is decided here is parsing and validation. Everything that is a *judgement* (severity scales, which finding may
trigger which response, ATT&CK mapping, which raw fields become context, the de-duplication key, risk weights) is read
from policy.toml, so changing an input source or a policy does not need a code change.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import UTC, datetime
from typing import Any

from .policy import finding_techniques, policy
from .util import iso

INSTANCE_ID_RE = re.compile(r"^i-[0-9a-f]{8,17}$")
RUN_ID_RE = re.compile(r"run_id=([A-Za-z0-9_-]{4,64})")
INTEGRAL_RE = re.compile(r"-?[0-9]+(?:[.]0+)?")
MAX_RAW_BYTES = 200_000

PLAN_EC2 = "ec2_isolate"
PLAN_IAM = "iam_key_disable"
PLAN_NONE = "none"


class UnsupportedEvent(ValueError):
    """Raised when an EventBridge event is not a supported alert source."""


class InvalidEvent(ValueError):
    """Raised when a supported source sends fields that cannot support reliable processing or measurement."""


# --------------------------------------------------------------------------- generic field access
def dig(obj: Any, path: str) -> Any:
    """Value at a dotted path ("a.b.0.c": digits index lists); None when any step is missing or not traversable."""
    cur = obj
    for part in path.split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        elif isinstance(cur, list) and part.isdigit() and int(part) < len(cur):
            cur = cur[int(part)]
        else:
            return None
        if cur is None:
            return None
    return cur


def _scalar(value: Any) -> str | int | float | bool | None:
    """Only scalars are context; containers and empty strings are not (they would bloat DynamoDB and the cards)."""
    if isinstance(value, bool) or (isinstance(value, (int, float)) and math.isfinite(value)):
        return value
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def extract_entities(family: str, detail: dict) -> dict[str, Any]:
    """Context named by policy `entities.<family>`: first path that holds a scalar wins; integers are coerced."""
    pol = policy()["entities"]
    integers = set(pol["integers"]["names"])
    out: dict[str, Any] = {}
    for name, paths in pol[family].items():
        for path in paths:
            value = _scalar(dig(detail, path))
            if value is None:
                continue
            if name in integers and isinstance(value, str):
                # Wazuh stores JSON numbers as doubles and prints some as "80.000000": accept integral decimals only
                if not INTEGRAL_RE.fullmatch(value):
                    continue  # a non-numeric "port" is noise, try the next path
                value = int(value.split(".", 1)[0])
            out[name] = value
            break
    return out


# --------------------------------------------------------------------------- time, severity, hashing
def _event_time(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise InvalidEvent(f"missing {field}")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as err:
        raise InvalidEvent(f"invalid {field}: expected ISO-8601 timestamp") from err
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise InvalidEvent(f"invalid {field}: timezone offset is required")
    return iso(parsed.astimezone(UTC))


def severity_label(score: float) -> str:
    for floor, label in policy()["severity"]["bands"]:
        if score >= floor:
            return label
    return "info"


def _scale(value: float, maximum: float) -> float:
    return min(100.0, round(value / maximum * 100, 1))


def _hash(*parts: str) -> str:
    return hashlib.sha1("|".join(parts).encode(), usedforsecurity=False).hexdigest()[:20]


def _dedup_key(source: str, family_prefix: str, values: dict[str, Any]) -> str:
    fields = policy()["dedup"][source]
    return _hash(family_prefix, *(str(values.get(f, "")) for f in fields))


def _trim_raw(obj: dict) -> dict:
    """Keep the stored raw alert below the EventBridge/DynamoDB-friendly size bound."""
    blob = json.dumps(obj, default=str)
    if len(blob) <= MAX_RAW_BYTES:
        return obj
    slim = dict(obj)
    slim.pop("full_log", None)
    return {"_truncated": True, **{k: slim[k] for k in list(slim)[:12]}}


def gd_mitre(finding_type: str) -> list[str]:
    """ATT&CK techniques for a GuardDuty finding type: a local override (longest prefix) first, otherwise the CTID
    mapping for exactly this type (names already normalised to AWS's current ones). No entry -> no technique."""
    mitre = policy()["guardduty"]["mitre"]
    override = max((m for m in mitre.get("overrides", []) if finding_type.startswith(m["prefix"])),
                   key=lambda m: len(m["prefix"]), default=None)
    if override:
        return list(override["techniques"])
    return list(finding_techniques().get(finding_type, []))


def _plan(plan_type: str = PLAN_NONE, params: dict | None = None, **notes: Any) -> dict:
    return {"type": plan_type, "params": params or {}, **notes}


# --------------------------------------------------------------------------- GuardDuty
def _gd_resource(rtype: str, res: dict) -> tuple[str, str, dict]:
    """(resource kind, resource id, identifying facts) for the resource types SIEMSOAR understands."""
    if rtype == "Instance":
        details = res.get("instanceDetails", {})
        if not isinstance(details, dict):
            raise InvalidEvent("GuardDuty instanceDetails must be an object")
        iid = details.get("instanceId", "unknown")
        return "ec2_instance", iid, {"instance_id": iid}
    if rtype == "AccessKey":
        ak = res.get("accessKeyDetails", {})
        if not isinstance(ak, dict):
            raise InvalidEvent("GuardDuty accessKeyDetails must be an object")
        user, key = ak.get("userName", ""), ak.get("accessKeyId", "")
        # IAM unique-id prefixes: AKIA = long-term access key, ASIA = temporary STS credentials
        # (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-unique-ids).
        # A temporary key changes with every session (each console login of the root user is a new ASIA key), so the
        # principal is the resource: one case per identity, not per session. It cannot be disabled by UpdateAccessKey.
        temporary = key.startswith("ASIA")
        rid = f"{user}/temporary-credentials" if temporary and user else (f"{user}/{key}" if user else key or "unknown")
        return "iam_access_key", rid, {"user_name": user, "access_key_id": key, "user_type": ak.get("userType"),
                                       "temporary": temporary}
    return rtype, "unknown", {}


def _gd_plan(rtype: str, facts: dict, sample: bool) -> dict:
    """First policy entry for this resource type whose preconditions hold; otherwise no plan."""
    for entry in policy()["guardduty"]["plans"]:
        if entry["resource_type"] != rtype:
            continue
        if entry["plan"] == PLAN_EC2 and (INSTANCE_ID_RE.match(facts["instance_id"]) or sample):
            return _plan(PLAN_EC2, {"instance_id": facts["instance_id"]})
        if entry["plan"] == PLAN_IAM:
            if (facts["user_name"] and facts["access_key_id"] and not facts.get("temporary")
                    and facts["user_type"] in entry.get("user_types", [facts["user_type"]])):
                return _plan(PLAN_IAM, {"user_name": facts["user_name"], "access_key_id": facts["access_key_id"]})
    return _plan()


def normalize_guardduty(detail: dict) -> dict:
    """GuardDuty severity is 0-8.9 (float); scaled linearly to 0-100 by policy."""
    ftype = detail.get("type", "Unknown")
    res = detail.get("resource", {})
    service = detail.get("service", {})
    if not isinstance(res, dict) or not isinstance(service, dict):
        raise InvalidEvent("GuardDuty resource and service fields must be objects")
    if not isinstance(ftype, str) or not ftype.strip():
        raise InvalidEvent("GuardDuty finding type must be a non-empty string")
    rtype = res.get("resourceType", "Unknown")
    if not isinstance(rtype, str) or not rtype:
        raise InvalidEvent("GuardDuty resourceType must be a non-empty string")
    finding_id, account, region = detail.get("id"), detail.get("accountId"), detail.get("region")
    if not isinstance(finding_id, str) or not finding_id:
        raise InvalidEvent("GuardDuty finding id is required")
    if not isinstance(account, str) or not re.fullmatch(r"\d{12}", account):
        raise InvalidEvent("GuardDuty accountId must contain 12 digits")
    if not isinstance(region, str) or not region:
        raise InvalidEvent("GuardDuty region is required")
    additional = service.get("additionalInfo", {})
    if not isinstance(additional, dict):
        raise InvalidEvent("GuardDuty service.additionalInfo must be an object")
    sample_value = additional.get("sample", False)
    sample = sample_value is True or (isinstance(sample_value, str) and sample_value.lower() == "true")

    maximum = float(policy()["guardduty"]["severity_max"])
    raw_severity = detail.get("severity")
    try:
        severity = float(raw_severity)
    except (TypeError, ValueError) as err:
        raise InvalidEvent(f"GuardDuty severity must be a number from 0 to {maximum}") from err
    if isinstance(raw_severity, bool) or not math.isfinite(severity) or not 0 <= severity <= maximum:
        raise InvalidEvent(f"GuardDuty severity must be a number from 0 to {maximum}")

    kind, resource_id, facts = _gd_resource(rtype, res)
    resource: dict[str, Any] = {"type": kind, "id": resource_id, "region": region, "account": account}
    sev = _scale(severity, maximum)
    # the activity that produced THIS delivery: for a recurring finding (service.count > 1) it is eventLastSeen, not the
    # first occurrence hours earlier (lab 2026-10-19: root usage first seen 04:06, cases at 07:30-09:30 measured 4.4 h)
    event_time = _event_time(service.get("eventLastSeen") or service.get("eventFirstSeen") or detail.get("createdAt"),
                             "GuardDuty event time")
    entities = extract_entities("guardduty", detail)
    # GuardDuty keeps the finding id when the activity recurs and only bumps service.count / updatedAt, so the id alone
    # would make every recurrence look like an EventBridge re-delivery and drop it. One delivery = one finding version.
    version = detail.get("updatedAt") or service.get("count") or ""
    return {
        "source": "guardduty",
        "source_id": finding_id,
        "delivery_id": f"{finding_id}@{version}",
        "rule_id": ftype,
        "title": detail.get("title", ftype),
        "description": detail.get("description", ""),
        "severity": sev,
        "severity_label": severity_label(sev),
        "event_time": event_time,
        "resource": resource,
        "mitre": gd_mitre(ftype),
        "response_plan": _gd_plan(rtype, facts, sample),
        "dedup_key": _dedup_key("guardduty", "gd", {"rule_id": ftype, "resource_id": resource_id,
                                                    "resource_type": kind, "source": "guardduty"}),
        "sample": sample,
        "run_id": None,
        "extra": entities or None,
        "raw": _trim_raw(detail),
    }


# --------------------------------------------------------------------------- Wazuh / Suricata
def _wazuh_plan(groups: list[str], agent_name: str, agent_ip: str | None) -> dict:
    """The rule asks for a response through its `resp_<plan>` group; the agent decides whether it can be honoured."""
    pol = policy()
    prefix = pol["wazuh"]["response_group_prefix"]
    requested = next((g[len(prefix):] for g in groups if g.startswith(prefix)), PLAN_NONE)
    if requested != PLAN_EC2:
        return _plan()
    order = pol["resolution"]["wazuh_agent"]
    if "instance_id" in order and INSTANCE_ID_RE.match(agent_name):
        return _plan(PLAN_EC2, {"instance_id": agent_name})
    resolvers = [r for r in order if r != "instance_id"]
    if resolvers:  # enrichment looks the instance up; with no unique match the plan stays `none`
        return _plan(requested=PLAN_EC2, resolve_via=resolvers,
                     unresolved={"agent_name": agent_name, "agent_ip": agent_ip})
    return _plan(requested=PLAN_EC2)


def normalize_wazuh(detail: dict) -> dict:
    """Wazuh level is 0-15; scaled by policy. Suricata EVE alerts arrive through Wazuh."""
    rule = detail.get("rule", {})
    agent = detail.get("agent", {})
    if not isinstance(rule, dict) or not isinstance(agent, dict):
        raise InvalidEvent("Wazuh rule and agent fields must be objects")
    data = detail.get("data", {})
    raw_groups = rule.get("groups", [])
    if not isinstance(data, dict) or not isinstance(raw_groups, list) or any(not isinstance(g, str) for g in raw_groups):
        raise InvalidEvent("Wazuh data must be an object and rule.groups a list of strings")
    groups = raw_groups
    pol = policy()["wazuh"]
    is_suricata = pol["suricata_group"] in groups or (data.get("event_type") == "alert"
                                                      and isinstance(data.get("alert"), dict))
    source = "suricata" if is_suricata else "wazuh"

    rule_id = str(rule.get("id", "unknown"))
    agent_name = agent.get("name", "unknown")
    if rule_id == "unknown" or not isinstance(agent_name, str) or not agent_name:
        raise InvalidEvent("Wazuh rule.id and agent.name are required")
    entities = extract_entities("wazuh", detail)
    try:
        level = int(rule.get("level", 0))
    except (TypeError, ValueError) as err:
        raise InvalidEvent(f"Wazuh rule.level must be an integer from 0 to {pol['level_max']}") from err
    if isinstance(rule.get("level", 0), bool) or not 0 <= level <= pol["level_max"]:
        raise InvalidEvent(f"Wazuh rule.level must be an integer from 0 to {pol['level_max']}")
    sev = _scale(level, pol["level_max"])

    full_log = detail.get("full_log", "") or ""
    if not isinstance(full_log, str):
        raise InvalidEvent("Wazuh full_log must be a string")
    m = RUN_ID_RE.search(full_log) or RUN_ID_RE.search(json.dumps(data, default=str))
    signature = entities.get("signature_id") and dig(detail, "data.alert.signature")
    raw_mitre = rule.get("mitre", {}) or {}
    if not isinstance(raw_mitre, dict) or not isinstance(raw_mitre.get("id", []), list):
        raise InvalidEvent("Wazuh rule.mitre.id must be a list")
    mitre = [t for t in raw_mitre.get("id", []) if isinstance(t, str)]
    event_time = _event_time(detail.get("timestamp"), "Wazuh timestamp")

    resource_type = "ec2_instance" if INSTANCE_ID_RE.match(agent_name) else "agent"
    values = {"rule_id": rule_id, "resource_id": agent_name, "src_ip": entities.get("src_ip", ""),
              "dest_ip": entities.get("dest_ip", ""), "resource_type": resource_type, "source": source}
    return {
        "source": source,
        "source_id": detail.get("id") or _hash(json.dumps(detail, default=str, sort_keys=True)),
        "rule_id": rule_id,
        "title": signature if isinstance(signature, str) and signature else rule.get("description", f"Wazuh rule {rule_id}"),
        "description": rule.get("description", ""),
        "severity": sev,
        "severity_label": severity_label(sev),
        "event_time": event_time,
        "resource": {"type": resource_type, "id": agent_name, "region": None, "account": None},
        "mitre": mitre,
        "response_plan": _wazuh_plan(groups, agent_name, entities.get("agent_ip")),
        "dedup_key": _dedup_key(source, "wz", values),
        "sample": False,
        "run_id": m.group(1) if m else None,
        "raw": _trim_raw(detail),
        "extra": {**entities, "groups": groups, "location": detail.get("location")},
    }


def normalize_event(event: dict) -> dict:
    """Dispatch on the EventBridge envelope."""
    if not isinstance(event, dict):
        raise InvalidEvent("EventBridge event must be an object")
    source, detail = event.get("source"), event.get("detail")
    if source == "aws.guardduty" and event.get("detail-type") == "GuardDuty Finding":
        if not isinstance(detail, dict):
            raise InvalidEvent("GuardDuty detail must be an object")
        return normalize_guardduty(detail)
    if source == "siemsoar.wazuh":
        if not isinstance(detail, dict):
            raise InvalidEvent("Wazuh detail must be an object")
        return normalize_wazuh(detail)
    raise UnsupportedEvent(f"unsupported source {source!r}")


def compute_risk(severity: float, criticality: str = "medium", alert_count: int = 1,
                 internet_exposed: bool = False) -> int:
    """Risk score 0-100 from policy: share of source severity + asset criticality + repetition + exposure."""
    risk = policy()["risk"]
    crit = risk["criticality"].get(criticality, risk["criticality"][risk["default_criticality"]])
    repeat = min(risk["repeat_cap"], risk["repeat_step"] * max(0, alert_count - 1))
    score = risk["severity_weight"] * severity + crit + repeat + (risk["internet_exposed"] if internet_exposed else 0)
    return int(max(0, min(100, round(score))))
