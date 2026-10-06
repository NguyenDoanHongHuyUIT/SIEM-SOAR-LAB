"""Normalise GuardDuty / Wazuh (incl. Suricata) alerts into one common alert schema."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from .util import iso, parse_iso

INSTANCE_ID_RE = re.compile(r"^i-[0-9a-f]{8,17}$")
RUN_ID_RE = re.compile(r"run_id=([A-Za-z0-9_-]{4,64})")
MAX_RAW_BYTES = 200_000

PLAN_EC2 = "ec2_isolate"
PLAN_IAM = "iam_key_disable"
PLAN_NONE = "none"

# GuardDuty finding type prefix -> MITRE ATT&CK technique ids (coarse, lab-scope mapping)
GD_MITRE: list[tuple[str, list[str]]] = [
    ("Recon:EC2/Portscan", ["T1046"]),
    ("Recon:EC2/PortProbe", ["T1046"]),
    ("Recon:IAMUser", ["T1087.004"]),
    ("UnauthorizedAccess:EC2/SSHBruteForce", ["T1110.001"]),
    ("UnauthorizedAccess:EC2/RDPBruteForce", ["T1110.001"]),
    ("UnauthorizedAccess:IAMUser", ["T1078.004"]),
    ("CredentialAccess:IAMUser", ["T1552"]),
    ("Persistence:IAMUser", ["T1098"]),
    ("PrivilegeEscalation:IAMUser", ["T1098"]),
    ("Backdoor:EC2", ["T1071"]),
    ("CryptoCurrency:EC2", ["T1496"]),
    ("Trojan:EC2", ["T1071"]),
    ("Impact:EC2", ["T1496"]),
    ("Exfiltration:S3", ["T1530"]),
    ("Discovery:S3", ["T1619"]),
    ("Stealth:IAMUser", ["T1562.008"]),
    ("DefenseEvasion:IAMUser", ["T1562.008"]),
]

SEVERITY_BANDS = [(80, "critical"), (60, "high"), (40, "medium"), (20, "low")]


class UnsupportedEvent(ValueError):
    """Raised when an EventBridge event is not a supported alert source."""


def severity_label(score: float) -> str:
    for floor, label in SEVERITY_BANDS:
        if score >= floor:
            return label
    return "info"


def _hash(*parts: str) -> str:
    return hashlib.sha1("|".join(parts).encode(), usedforsecurity=False).hexdigest()[:20]


def _trim_raw(obj: dict) -> dict:
    """Keep the stored raw alert below the EventBridge/DynamoDB-friendly size bound."""
    blob = json.dumps(obj, default=str)
    if len(blob) <= MAX_RAW_BYTES:
        return obj
    slim = dict(obj)
    slim.pop("full_log", None)
    return {"_truncated": True, **{k: slim[k] for k in list(slim)[:12]}}


def gd_mitre(finding_type: str) -> list[str]:
    for prefix, techniques in GD_MITRE:
        if finding_type.startswith(prefix):
            return techniques
    return []


def normalize_guardduty(detail: dict) -> dict:
    """GuardDuty severity is 0-8.9 (float); map linearly to 0-100."""
    ftype = detail.get("type", "Unknown")
    res = detail.get("resource", {})
    rtype = res.get("resourceType", "Unknown")
    service = detail.get("service", {})
    sample = bool(service.get("additionalInfo", {}).get("sample")) or str(
        service.get("additionalInfo", {}).get("sample", "")
    ).lower() == "true"

    resource: dict[str, Any] = {
        "type": rtype,
        "id": "unknown",
        "region": detail.get("region"),
        "account": detail.get("accountId"),
    }
    plan_type, plan_params = PLAN_NONE, {}
    if rtype == "Instance":
        iid = res.get("instanceDetails", {}).get("instanceId", "unknown")
        resource.update(id=iid, type="ec2_instance")
        if INSTANCE_ID_RE.match(iid) or sample:
            plan_type, plan_params = PLAN_EC2, {"instance_id": iid}
    elif rtype == "AccessKey":
        ak = res.get("accessKeyDetails", {})
        user, key = ak.get("userName", ""), ak.get("accessKeyId", "")
        resource.update(id=f"{user}/{key}" if user else key or "unknown", type="iam_access_key")
        if ak.get("userType") == "IAMUser" and user and key:
            plan_type, plan_params = PLAN_IAM, {"user_name": user, "access_key_id": key}

    sev = min(100.0, round(float(detail.get("severity", 0)) / 8.9 * 100, 1))
    event_time = service.get("eventFirstSeen") or detail.get("createdAt")
    return {
        "source": "guardduty",
        "source_id": detail.get("id", _hash(json.dumps(detail, default=str))),
        "rule_id": ftype,
        "title": detail.get("title", ftype),
        "description": detail.get("description", ""),
        "severity": sev,
        "severity_label": severity_label(sev),
        "event_time": iso(parse_iso(event_time)) if parse_iso(event_time) else iso(),
        "resource": resource,
        "mitre": gd_mitre(ftype),
        "response_plan": {"type": plan_type, "params": plan_params},
        "dedup_key": _hash("gd", ftype, resource["id"]),
        "sample": sample,
        "run_id": None,
        "raw": _trim_raw(detail),
    }


def normalize_wazuh(detail: dict) -> dict:
    """Wazuh level is 0-15; map linearly to 0-100. Suricata EVE alerts arrive through Wazuh."""
    rule = detail.get("rule", {})
    agent = detail.get("agent", {})
    data = detail.get("data", {}) if isinstance(detail.get("data"), dict) else {}
    groups = [g for g in rule.get("groups", []) if isinstance(g, str)]
    is_suricata = "suricata" in groups or data.get("event_type") == "alert" and "alert" in data
    source = "suricata" if is_suricata else "wazuh"

    rule_id = str(rule.get("id", "unknown"))
    agent_name = agent.get("name", "unknown")
    src_ip = data.get("src_ip") or data.get("srcip") or ""
    level = int(rule.get("level", 0))
    sev = min(100.0, round(level / 15 * 100, 1))

    requested = next((g[len("resp_") :] for g in groups if g.startswith("resp_")), PLAN_NONE)
    plan_type, plan_params = PLAN_NONE, {}
    if requested == PLAN_EC2 and INSTANCE_ID_RE.match(agent_name):
        plan_type, plan_params = PLAN_EC2, {"instance_id": agent_name}

    full_log = detail.get("full_log", "") or ""
    m = RUN_ID_RE.search(full_log) or RUN_ID_RE.search(json.dumps(data, default=str))
    sig = data.get("alert", {}).get("signature") if is_suricata else None
    mitre = [t for t in (rule.get("mitre", {}) or {}).get("id", []) if isinstance(t, str)]
    event_time = parse_iso(detail.get("timestamp"))

    return {
        "source": source,
        "source_id": detail.get("id") or _hash(json.dumps(detail, default=str, sort_keys=True)),
        "rule_id": rule_id,
        "title": sig or rule.get("description", f"Wazuh rule {rule_id}"),
        "description": rule.get("description", ""),
        "severity": sev,
        "severity_label": severity_label(sev),
        "event_time": iso(event_time) if event_time else iso(),
        "resource": {"type": "ec2_instance" if INSTANCE_ID_RE.match(agent_name) else "agent",
                     "id": agent_name, "region": None, "account": None},
        "mitre": mitre,
        "response_plan": {"type": plan_type, "params": plan_params},
        "dedup_key": _hash("wz", rule_id, agent_name, src_ip),
        "sample": False,
        "run_id": m.group(1) if m else None,
        "raw": _trim_raw(detail),
        "extra": {"src_ip": src_ip, "groups": groups, "location": detail.get("location")},
    }


def normalize_event(event: dict) -> dict:
    """Dispatch on the EventBridge envelope."""
    source, detail = event.get("source"), event.get("detail")
    if not isinstance(detail, dict):
        raise UnsupportedEvent("missing detail")
    if source == "aws.guardduty" and event.get("detail-type") == "GuardDuty Finding":
        return normalize_guardduty(detail)
    if source == "siemsoar.wazuh":
        return normalize_wazuh(detail)
    raise UnsupportedEvent(f"unsupported source {source!r}")


def compute_risk(severity: float, criticality: str = "medium", alert_count: int = 1,
                 internet_exposed: bool = False) -> int:
    """Risk score 0-100: 60% source severity + asset criticality + repetition + exposure."""
    crit = {"critical": 20, "high": 15, "medium": 8, "low": 0}.get(criticality, 8)
    repeat = min(10, 2 * max(0, alert_count - 1))
    score = 0.6 * severity + crit + repeat + (10 if internet_exposed else 0)
    return int(max(0, min(100, round(score))))
