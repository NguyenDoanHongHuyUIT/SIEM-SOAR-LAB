"""Load and validate policy.toml (stdlib `tomllib`, so the Lambda package needs no extra dependency).

The policy is data, not code: a mistake in it must fail loudly at import/cold start, never turn into a silently wrong
severity or a response plan on the wrong resource. `validate` is also what the unit tests call on edited copies.
"""

from __future__ import annotations

import json
import tomllib
from functools import cache
from pathlib import Path
from typing import Any

POLICY_PATH = Path(__file__).with_name("policy.toml")
PLANS = {"ec2_isolate", "iam_key_disable"}
RESOLVERS = {"instance_id", "private_ip", "name_tag"}
DEDUP_FIELDS = {"rule_id", "resource_id", "src_ip", "dest_ip", "resource_type", "source"}


class PolicyError(ValueError):
    """policy.toml is malformed or inconsistent."""


def _need(cond: bool, message: str) -> None:
    if not cond:
        raise PolicyError(message)


def _number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def validate(doc: dict) -> dict:
    """Return `doc` if it is usable, otherwise raise PolicyError naming the first problem."""
    _need(doc.get("version") == 1, "policy version must be 1")

    risk = doc.get("risk", {})
    for key in ("severity_weight", "repeat_step", "repeat_cap", "internet_exposed"):
        _need(_number(risk.get(key)) and risk[key] >= 0, f"risk.{key} must be a non-negative number")
    _need(0 < risk["severity_weight"] <= 1, "risk.severity_weight must be in (0, 1]")
    crit = risk.get("criticality", {})
    _need(bool(crit) and all(_number(v) and v >= 0 for v in crit.values()), "risk.criticality needs numeric weights")
    _need(risk.get("default_criticality") in crit, "risk.default_criticality must be one of risk.criticality")

    bands = doc.get("severity", {}).get("bands", [])
    _need(bool(bands) and all(len(b) == 2 and _number(b[0]) and isinstance(b[1], str) for b in bands),
          "severity.bands must be [[lower bound, label], ...]")
    _need([b[0] for b in bands] == sorted((b[0] for b in bands), reverse=True), "severity.bands must descend")

    gd = doc.get("guardduty", {})
    _need(_number(gd.get("severity_max")) and gd["severity_max"] > 0, "guardduty.severity_max must be positive")
    for plan in gd.get("plans", []):
        _need(plan.get("plan") in PLANS, f"guardduty.plans: unknown plan {plan.get('plan')!r}")
        _need(isinstance(plan.get("resource_type"), str) and plan.get("resource_kind"),
              "guardduty.plans entries need resource_type and resource_kind")
    mitre = gd.get("mitre", {})
    _need(isinstance(mitre, dict) and bool(mitre.get("mapping_file")), "guardduty.mitre.mapping_file is required")
    seen = set()
    for m in mitre.get("overrides", []):
        _need(isinstance(m.get("prefix"), str) and m["prefix"] and m["prefix"] not in seen,
              f"guardduty.mitre.overrides: bad or duplicate prefix {m.get('prefix')!r}")
        seen.add(m["prefix"])
        _need(bool(m.get("techniques")) and all(isinstance(t, str) for t in m["techniques"]),
              f"guardduty.mitre.overrides {m['prefix']}: techniques must be a non-empty list")
        _need(m.get("basis") in {"analyst", "vendor"} and bool(m.get("reason")),
              f"guardduty.mitre.overrides {m['prefix']}: state its basis and reason")

    wz = doc.get("wazuh", {})
    _need(_number(wz.get("level_max")) and wz["level_max"] > 0, "wazuh.level_max must be positive")
    _need(bool(wz.get("response_group_prefix")) and bool(wz.get("suricata_group")), "wazuh group names missing")
    order = doc.get("resolution", {}).get("wazuh_agent", [])
    _need(bool(order) and set(order) <= RESOLVERS, f"resolution.wazuh_agent must be a subset of {sorted(RESOLVERS)}")

    for source in ("guardduty", "wazuh", "suricata"):
        fields = doc.get("dedup", {}).get(source)
        _need(bool(fields) and set(fields) <= DEDUP_FIELDS, f"dedup.{source} must be a subset of {sorted(DEDUP_FIELDS)}")
    for family in ("wazuh", "guardduty"):
        for name, paths in doc.get("entities", {}).get(family, {}).items():
            _need(bool(paths) and all(isinstance(p, str) and p for p in paths), f"entities.{family}.{name}: paths needed")
    return doc


@cache
def policy() -> dict:
    return validate(tomllib.loads(POLICY_PATH.read_text(encoding="utf-8")))


@cache
def finding_techniques() -> dict[str, list[str]]:
    """{GuardDuty finding type: ATT&CK ids} from the generated mapping file named by the policy."""
    path = POLICY_PATH.with_name(policy()["guardduty"]["mitre"]["mapping_file"])
    doc = json.loads(path.read_text(encoding="utf-8"))
    _need(doc.get("kind") == "guardduty-attack-mapping" and bool(doc.get("finding_types")),
          f"{path.name} is not a guardduty-attack-mapping snapshot")
    return doc["finding_types"]


def reload_for_tests(text: str | None = None) -> dict:
    """Drop the cache; with `text`, validate that document instead (returns it, does not replace the cache)."""
    policy.cache_clear()
    finding_techniques.cache_clear()
    return validate(tomllib.loads(text)) if text is not None else policy()
