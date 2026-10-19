"""Scenario catalogue: what each simulation does and the ground truth it claims, checked against pinned sources.

Pure YAML + the snapshots in rules/reference (no AWS), so `rulesctl lint` and the unit tests use the same code as the
runner. Where a scenario's ATT&CK technique comes from (the scenario author never types it for these kinds):

  * `atomic`      the technique Atomic Red Team files the test GUID under (rules/reference/atomic-red-team-linux.json,
                  same commit the run executes). `techniques:` may be omitted; if written it must agree.
  * `stratus`     the GuardDuty finding Stratus Red Team documents for that technique (`documented_detection`), which
                  must be an active type in AWS's catalogue; techniques = the CTID mapping of that finding.
  * `pcap_replay` the procedure recorded in rules/pcaps/provenance.json for the capture.
  * `ssm_shell`   a lab procedure: techniques are declared by hand, reported as such, and never used as evidence for a
                  rule's ATT&CK mapping.

Expectations name the rule that should fire; in a benign scenario `false_positive: true` declares a known false
positive (still counted as one). `check_against_rules` rejects an expectation on an unknown rule, a `case`
flag that contradicts the rule's lifecycle state, and a malicious scenario whose techniques do not relate to the ATT&CK
ids of the rule it expects (the "mapping is wrong" case).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
SCENARIO_DIR = Path(__file__).resolve().parent / "scenarios"
REF_DIR = ROOT / "rules" / "reference"
PCAP_DIR = ROOT / "rules" / "pcaps"
GD_MAPPING = ROOT / "src" / "lambdas" / "siemsoar" / "guardduty_attack.json"

SCENARIO_KINDS = {"ssm_shell", "atomic", "guardduty_sample", "stratus", "pcap_replay", "robustness"}
EVIDENCE_KINDS = {"atomic", "stratus", "pcap_replay"}  # their technique comes from a public source, not from us
SCENARIO_SOURCES = {"guardduty", "wazuh", "suricata"}
PLACEHOLDERS = {"run_id", "short", "manager_ip", "sensor_ip"}
MITRE_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
# the runner decides some cases itself (robustness scripts, ground-truth closures) as "sim:[ground-truth:]<run_id>"
SIM_ACTOR_RE = re.compile(r"^sim:(?:ground-truth:)?(run-[\w-]+)$")
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")
STRATUS_DOC = "https://stratus-red-team.cloud/attack-techniques/AWS/{technique}/"


def _json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


@dataclass
class References:
    atomic: dict = field(default_factory=dict)          # refdata atomic-red-team-index
    finding_types: dict = field(default_factory=dict)   # refdata guardduty-finding-types
    gd_mapping: dict = field(default_factory=dict)      # guardduty_attack.json
    pcaps: dict = field(default_factory=dict)           # rules/pcaps/provenance.json

    @classmethod
    def load(cls) -> References:
        return cls(_json(REF_DIR / "atomic-red-team-linux.json"), _json(REF_DIR / "guardduty-finding-types.json"),
                   _json(GD_MAPPING), _json(PCAP_DIR / "provenance.json"))


def related(a: str, b: str) -> bool:
    """Same ATT&CK technique, or one is a sub-technique of the other (T1110 ~ T1110.004)."""
    return a == b or a.startswith(b + ".") or b.startswith(a + ".")


def pcap_technique(provenance: dict) -> str | None:
    return ((provenance.get("procedure") or {}).get("atomic_red_team") or {}).get("technique")


def _need(cond: bool, filename: str, message: str) -> None:
    if not cond:
        raise ValueError(f"{filename}: {message}")


def _placeholders_ok(text: str) -> bool:
    return set(re.findall(r"\{(\w+)\}", text)) <= PLACEHOLDERS


def _validate_common(s: object, filename: str) -> dict:
    _need(isinstance(s, dict), filename, "scenario must be a YAML mapping")
    _need(s.get("id") == Path(filename).stem, filename, "id must match the filename")
    _need(isinstance(s.get("title"), str) and bool(s["title"].strip()), filename, "title must be a non-empty string")
    _need(s.get("kind") in SCENARIO_KINDS, filename, "unsupported scenario kind")
    _need(isinstance(s.get("malicious"), bool), filename, "malicious must be a boolean")
    _need(s.get("evaluation_scope", "detection") in {"detection", "pipeline_only"}, filename,
          "evaluation_scope must be detection|pipeline_only")
    if s.get("evaluation_scope") == "pipeline_only":
        _need(not s["malicious"] and not s.get("techniques"), filename,
              "pipeline_only scenarios cannot claim malicious activity or techniques")
    techniques = s.get("techniques", [])
    _need(isinstance(techniques, list) and all(isinstance(t, str) and MITRE_ID_RE.fullmatch(t) for t in techniques),
          filename, "techniques must contain valid ATT&CK IDs")
    expect = s.get("expect", [])
    _need(isinstance(expect, list), filename, "expect must be a list")
    for item in expect:
        _need(isinstance(item, dict) and item.get("source") in SCENARIO_SOURCES, filename,
              "every expectation needs a supported source")
        rid = item.get("rule_id")
        _need(not isinstance(rid, bool) and isinstance(rid, (str, int)) and bool(str(rid)), filename,
              "every expectation needs a string or integer rule_id")
        _need(all(isinstance(item.get(k, d), bool) for k, d in (("case", True), ("optional", False),
                                                                  ("siem_alert", True), ("false_positive", False))),
              filename, "expectation case/optional/siem_alert/false_positive values must be booleans")
        # `false_positive: true` = "this benign activity is known to trigger the rule": it documents the rule's limit;
        # the evaluation still counts every such alert/case as a false positive
        _need(not (item.get("false_positive") and s.get("malicious")), filename,
              "false_positive expectations only make sense in benign (malicious: false) scenarios")
    settle = s.get("settle_seconds", 120)
    _need(not isinstance(settle, bool) and isinstance(settle, int) and 1 <= settle <= 3600, filename,
          "settle_seconds must be an integer from 1 to 3600")
    for key in ("prepare", "verify", "cleanup", "commands"):
        cmds = s.get(key, [])
        _need(isinstance(cmds, list) and all(isinstance(c, str) and c and _placeholders_ok(c) for c in cmds),
              filename, f"{key} must be a list of commands using only {sorted(PLACEHOLDERS)} placeholders")
    return s


def _derive(s: dict, filename: str, derived: list[str], source: str) -> None:
    """Set the scenario's techniques from their source; a hand-written list must agree with it."""
    declared = s.get("techniques")
    _need(declared is None or sorted(declared) == sorted(derived), filename,
          f"techniques {declared} contradict {source} {derived}: remove them, they are derived")
    s["techniques"] = sorted(derived)
    s["technique_source"] = source


def validate(s: object, filename: str, refs: References | None = None) -> dict:
    refs = refs or References()
    s = _validate_common(s, filename)
    kind = s["kind"]
    s["evidence"] = kind in EVIDENCE_KINDS and s["malicious"]
    if kind == "atomic":
        a = s.get("atomic")
        _need(isinstance(a, dict) and isinstance(a.get("technique"), str) and MITRE_ID_RE.fullmatch(a["technique"])
              and isinstance(a.get("test_guid"), str) and UUID_RE.fullmatch(a["test_guid"])
              and isinstance(a.get("ref"), str) and COMMIT_RE.fullmatch(a["ref"]), filename,
              "atomic needs a valid technique, test GUID and pinned commit SHA")
        args = a.get("args") or {}
        _need(isinstance(args, dict) and all(isinstance(v, (str, int)) and _placeholders_ok(str(v))
                                             for v in args.values()), filename, "atomic args must be scalars")
        if refs.atomic:
            _need(a["ref"] == refs.atomic.get("ref"), filename,
                  f"atomic ref {a['ref'][:12]} differs from the pinned index {refs.atomic.get('ref', '')[:12]}")
            test = refs.atomic["tests"].get(a["test_guid"])
            _need(test is not None, filename, f"test GUID {a['test_guid']} is not a Linux atomic at that commit")
            _need(test["technique"] == a["technique"], filename,
                  f"test {a['test_guid']} belongs to {test['technique']}, not {a['technique']}")
            s["atomic"]["test_name"] = test["name"]
        _derive(s, filename, [a["technique"]], "Atomic Red Team index")
    elif kind == "guardduty_sample":
        types = s.get("finding_types")
        _need(isinstance(types, list) and bool(types) and all(isinstance(t, str) and t for t in types), filename,
              "finding_types must be a non-empty list of strings")
        if refs.finding_types:
            unknown = [t for t in types if t not in refs.finding_types["active"]]
            _need(not unknown, filename, f"not active GuardDuty finding types: {unknown}")
    elif kind == "stratus":
        tech = s.get("stratus_technique")
        _need(isinstance(tech, str) and bool(re.fullmatch(r"aws\.[a-z0-9][a-z0-9.-]*", tech)), filename,
              "invalid Stratus AWS technique name")
        doc = s.get("documented_detection") or {}
        _need(doc.get("url") == STRATUS_DOC.format(technique=tech), filename,
              f"documented_detection.url must be the Stratus page {STRATUS_DOC.format(technique=tech)}")
        finding = doc.get("finding_type")
        _need(any(e["source"] == "guardduty" and e["rule_id"] == finding and not e.get("optional")
                  for e in s.get("expect", [])), filename,
              "expect must contain the documented GuardDuty finding (not optional)")
        if refs.finding_types:
            _need(finding in refs.finding_types["active"], filename, f"{finding} is not an active GuardDuty type")
        _need(s.get("detonate_as") in (None, "victim"), filename, "detonate_as must be `victim` when given")
        if refs.gd_mapping:
            _derive(s, filename, refs.gd_mapping["finding_types"].get(finding, []), f"CTID mapping of {finding}")
    elif kind == "pcap_replay":
        name = s.get("pcap")
        _need(isinstance(name, str) and name.endswith(".pcap"), filename, "pcap_replay needs a .pcap filename")
        if refs.pcaps:
            _need(name in refs.pcaps, filename, f"{name} is not a captured pcap (rules/pcaps/provenance.json)")
            tech = pcap_technique(refs.pcaps[name])
            _need(bool(tech) == s["malicious"], filename, "malicious must match the capture's procedure (atomic/benign)")
            _derive(s, filename, [tech] if tech else [], f"capture provenance of {name}")
    elif kind == "ssm_shell":
        _need(bool(s.get("commands")), filename, "ssm_shell needs a non-empty list of commands")
        s["technique_source"] = "declared (lab procedure, not mapping evidence)"
    elif kind == "robustness":
        _need(s.get("check") in {"double_click", "mid_failure", "slack_down"}, filename, "unsupported robustness check")
        _need(isinstance(s.get("trigger"), str) and bool(s["trigger"]), filename,
              "robustness needs `trigger`: the id of a real scenario that opens the case")
    return s


def load_scenarios(directory: Path = SCENARIO_DIR, refs: References | None = None) -> dict[str, dict]:
    refs = refs if refs is not None else References.load()
    out = {}
    for p in sorted(directory.glob("*.yml")):
        s = validate(yaml.safe_load(p.read_text(encoding="utf-8")), p.name, refs)
        _need(s["id"] not in out, p.name, f"duplicate scenario id {s['id']}")
        s["_file"] = p.name
        out[s["id"]] = s
    for s in out.values():
        if s["kind"] == "robustness":
            _need(s["trigger"] in out, s["_file"], f"trigger {s['trigger']} is not a scenario")
    return out


# --------------------------------------------------------------------------- runs <-> cases
def _iso(value):
    from datetime import datetime
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def case_in_run(case: dict, run: dict) -> bool:
    """A case belongs to a run when it carries the run's run_id, or was created on the run's target (resource id or
    the Wazuh agent name it was resolved from) inside [start - 5 s, end + settle]. Runs without a target (cloud
    procedures) match on the window only. A case the runner decided itself names its run in the actor: that is exact,
    whereas back-to-back runs on one host have overlapping windows.

    A run whose target exists only for that run (`target_unique`, e.g. the access key created for one Stratus
    detonation) needs no end bound: whatever names that target belongs to the run, however late the detector reports
    it. The settle window then only says how long the runner waits before its live verdict."""
    from datetime import timedelta
    if case.get("run_id"):
        return case["run_id"] == run.get("run_id")
    if m := SIM_ACTOR_RE.match(str(case.get("approver") or "")):
        return m.group(1) == run.get("run_id")
    start, end, created = _iso(run.get("started_at")), _iso(run.get("ended_at")), _iso(case.get("created_at"))
    if not (start and end and created):
        return False
    target = run.get("target")
    on_target = target is None or target in (case.get("resource_id"), (case.get("resource") or {}).get("agent_name"))
    if not on_target or created < start - timedelta(seconds=5):
        return False
    if target is not None and run.get("target_unique"):
        return True
    return created <= end + timedelta(seconds=int(run.get("settle_seconds", 120)))


def merged_in_run(case: dict, run: dict) -> bool:
    """The run's detection was merged into a case opened earlier (dedup keeps one open case per key and records each
    merge in `merged_at`): on the run's target, an alert merged inside the run's window. The case still belongs to the
    run that created it (case_in_run); this only says the later run was detected, not missed."""
    from datetime import timedelta
    start, end = _iso(run.get("started_at")), _iso(run.get("ended_at"))
    target = run.get("target")
    if not (start and end and target) or case.get("run_id") or case_in_run(case, run):
        return False
    if target not in (case.get("resource_id"), (case.get("resource") or {}).get("agent_name")):
        return False
    hi = None if run.get("target_unique") else end + timedelta(seconds=int(run.get("settle_seconds", 120)))
    return any(t and t >= start - timedelta(seconds=5) and (hi is None or t <= hi)
               for t in (_iso(x) for x in case.get("merged_at") or []))


# --------------------------------------------------------------------------- scenarios <-> rules
def metadata_id(expectation: dict, meta: dict[str, dict]) -> str | None:
    """The rules/metadata id an expectation points at (Suricata expectations name the generated Wazuh rule)."""
    rid = str(expectation["rule_id"])
    if expectation["source"] == "wazuh":
        return f"wazuh-{rid}" if f"wazuh-{rid}" in meta else None
    if expectation["source"] == "suricata":
        return next((k for k, m in meta.items() if m.get("engine") == "suricata"
                     and str(m.get("wazuh_rule_id")) == rid), None)
    return None


def check_against_rules(scenarios: dict[str, dict], meta: dict[str, dict]) -> list[str]:
    errors = []
    for sid, s in scenarios.items():
        for e in s.get("expect", []):
            if e["source"] == "guardduty":
                continue
            key = metadata_id(e, meta)
            if key is None:
                errors.append(f"scenario {sid}: expects {e['source']} rule {e['rule_id']} that has no metadata")
                continue
            m = meta[key]
            if m.get("state") == "deprecated":
                errors.append(f"scenario {sid}: expects {key}, which is deprecated (not deployed)")
                continue
            live = m.get("state") in ("active", "enforce")
            if e.get("case", True) != live:
                errors.append(f"scenario {sid}: expects case={e.get('case', True)} but {key} is {m.get('state')}")
            if s["malicious"] and s.get("techniques") and m.get("mitre") and not e.get("optional"):
                if not any(related(t, x) for t in s["techniques"] for x in m["mitre"]):
                    errors.append(f"scenario {sid} executes {s['techniques']} ({s.get('technique_source')}) but "
                                  f"expects {key} labelled {m['mitre']}: the rule's ATT&CK mapping or the "
                                  f"expectation is wrong")
    return errors


def evidence(scenarios: dict[str, dict], meta: dict[str, dict], pcaps: dict | None = None) -> dict[str, set[str]]:
    """{metadata id: techniques of public procedures shown to trigger the rule}.

    Sources: malicious atomic/stratus/pcap_replay scenarios expecting the rule (non-optional), and Suricata metadata
    tests whose positive pcap was captured from an Atomic Red Team procedure (replayed on the real engine in CI).
    """
    out: dict[str, set[str]] = {}
    for s in scenarios.values():
        if not s.get("evidence"):
            continue
        for e in s.get("expect", []):
            key = metadata_id(e, meta)
            if key and not e.get("optional"):
                out.setdefault(key, set()).update(s.get("techniques", []))
    for key, m in meta.items():
        if m.get("engine") != "suricata":
            continue
        for t in m.get("tests") or []:
            tech = pcap_technique((pcaps or {}).get(t.get("pcap"), {}))
            if t.get("expect") == "match" and tech:
                out.setdefault(key, set()).add(tech)
    return out
