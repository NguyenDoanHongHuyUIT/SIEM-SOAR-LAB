"""rulesctl: detection-as-code toolbelt (lint, lifecycle gate, build, promote, coverage, tune).

Behavioural tests of the rules run on the real engines, not here: `tools.wazuh_logtest` (Wazuh logtest API + analysisd)
and `tools.suricata_pcap_test` (Suricata + replay of pcaps captured from real tools). `lint` checks the metadata, the rule
files and where every ATT&CK label comes from:

  * a technique on a rule must be justified by a source: the ATT&CK ids Wazuh itself puts on the official rules it
    wraps, or a public attack procedure (Atomic Red Team / Stratus Red Team scenario, or an Atomic Red Team pcap) shown
    to trigger the rule (same technique or parent/sub-technique). A label nobody can back is a lint error;
  * every scenario expectation must point at an existing rule, agree with its lifecycle state and relate to its
    ATT&CK labels (simulation/catalog.py).

Suricata detection is either LOCAL (rules/suricata/*.rules, sids 9000000-9099999) or MANAGED Emerging Threats Open rules
(`source: et-open`, pinned text in rules/reference/et-open-managed.json). Both get a generated Wazuh rule whose id is
the metadata field `wazuh_rule_id`.

  python -m tools.rulesctl lint
  python -m tools.rulesctl lifecycle --base origin/main [--allow-revert]
  python -m tools.rulesctl build --out dist [--sha <git sha>] [--allow-drop]
  python -m tools.rulesctl promote wazuh-100101 active
  python -m tools.rulesctl coverage
  python -m tools.rulesctl tune feedback.json [--min-cases 3]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse

import yaml
from suricata.update import rule as suricata_rule  # OISF's own rule parser (what suricata-update uses)

from simulation import catalog
from tools import refdata

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "rules"
STATES = ("shadow", "active", "enforce", "deprecated")
RESPONSES = ("none", "ec2_isolate", "iam_key_disable")
WAZUH_RANGE = range(100000, 120000)
SURICATA_RANGE = range(9000000, 9100000)        # local sids
MAPPING_RANGE = range(110000, 120000)           # generated Wazuh rules for Suricata sids (metadata wazuh_rule_id)
SURICATA_SOURCES = ("local", "et-open")
MITRE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
FREEZE = {  # allowed lifecycle moves (paper Figure 2: shadow -> active -> enforce, deprecate, rollback)
    "shadow": {"active", "deprecated"},
    "active": {"enforce", "shadow", "deprecated"},
    "enforce": {"active", "deprecated"},
    "deprecated": {"shadow"},
}
# keys that make a metadata test executable: `logs`/`log` through the Wazuh logtest API, `fim` through the analysisd
# queue (syscheck events never go through logtest), `pcap` replayed on Suricata
RUNNABLE_TEST_KEYS = {"wazuh": ("log", "logs", "fim"), "suricata": ("pcap",)}
FORBIDDEN_GROUP = re.compile(r"(^|,)\s*(siemsoar_(shadow|active|enforce|deprecated)|resp_\w+)\s*(,|$)")


@dataclass
class WazuhRule:
    id: int
    level: int
    description: str
    mitre: list[str]
    groups: list[str]  # <group name=> of the container + the rule's own <group>
    element: ET.Element = field(repr=False)
    container: ET.Element = field(repr=False)
    parents: list[int] = field(default_factory=list)  # <if_sid>/<if_matched_sid> ids this rule hangs under


def _split_groups(text: str | None) -> list[str]:
    return [g.strip() for g in (text or "").split(",") if g.strip()]


def parse_wazuh_xml(text: str) -> dict[int, WazuhRule]:
    """Rule files are XML fragments with several top level <group> elements: wrap them in a root."""
    root = ET.fromstring(f"<root>{text}</root>")  # noqa: S314 - rule files are repo-owned, reviewed in PRs
    rules: dict[int, WazuhRule] = {}
    for container in root.findall("group"):
        for el in container.findall("rule"):
            rid = int(el.get("id"))
            if rid in rules:
                raise ValueError(f"duplicate Wazuh rule id {rid}")
            rules[rid] = WazuhRule(
                id=rid, level=int(el.get("level", "0")), description=(el.findtext("description") or "").strip(),
                mitre=[(i.text or "").strip() for i in el.findall("mitre/id")],
                groups=_split_groups(container.get("name")) + _split_groups(el.findtext("group")),
                parents=sorted({int(p) for tag in ("if_sid", "if_matched_sid") for e in el.findall(tag)
                                for p in _split_groups(e.text) if p.isdigit()}),
                element=el, container=container)
    return rules


def parse_suricata_rules(text: str) -> dict[int, suricata_rule.Rule]:
    rules: dict[int, suricata_rule.Rule] = {}
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        try:
            rule = suricata_rule.parse(line)
        except ValueError as err:
            raise ValueError(f"cannot parse suricata rule {line[:60]!r}: {err}") from err
        if rule is None:
            raise ValueError(f"cannot parse suricata rule {line[:60]!r}")
        if rule.sid in rules:
            raise ValueError(f"duplicate suricata sid {rule.sid}")
        rules[rule.sid] = rule
    return rules


def wazuh_rule_of(meta: dict) -> int:
    """Id of the Wazuh rule generated for a Suricata metadata entry (declared, never computed)."""
    return int(meta["wazuh_rule_id"])


def suricata_meta_by_wazuh_rule(meta: dict[str, dict]) -> dict[int, dict]:
    return {wazuh_rule_of(m): m for m in meta.values() if m.get("engine") == "suricata" and m.get("wazuh_rule_id")}


# --------------------------------------------------------------------------- loading
def load_metadata(root: Path | None = None) -> dict[str, dict]:
    root = root or RULES
    meta: dict[str, dict] = {}
    for path in sorted((root / "metadata").glob("*.yml")):
        data = yaml.safe_load(path.read_text()) or {}
        data["_path"] = str(path)
        meta[data.get("id", path.stem)] = data
    return meta


def load_wazuh(root: Path | None = None) -> dict[int, WazuhRule]:
    root = root or RULES
    rules: dict[int, WazuhRule] = {}
    for path in sorted((root / "wazuh").glob("*.xml")):
        for rid, rule in parse_wazuh_xml(path.read_text()).items():
            if rid in rules:
                raise ValueError(f"duplicate Wazuh rule id {rid}")
            rules[rid] = rule
    return rules


def load_suricata(root: Path | None = None) -> dict[int, suricata_rule.Rule]:
    """LOCAL rules written in this repository."""
    root = root or RULES
    rules: dict[int, suricata_rule.Rule] = {}
    for path in sorted((root / "suricata").glob("*.rules")):
        for sid, rule in parse_suricata_rules(path.read_text()).items():
            if sid in rules:
                raise ValueError(f"duplicate suricata sid {sid}")
            rules[sid] = rule
    return rules


def load_et(root: Path | None = None) -> tuple[dict[int, suricata_rule.Rule], dict]:
    """MANAGED Emerging Threats Open rules: the pinned text of the sids the metadata selects (+ snapshot header)."""
    snap = refdata.load_et_open((root or RULES) / "reference") or {}
    return {int(sid): suricata_rule.parse(r["raw"]) for sid, r in (snap.get("rules") or {}).items()}, snap


def suricata_text(meta: dict, local: dict[int, suricata_rule.Rule], et: dict[int, suricata_rule.Rule]) -> str:
    return (et if meta.get("source") == "et-open" else local)[int(meta["rule_id"])].raw


# --------------------------------------------------------------------------- lint
def _technique_problems(where: str, technique: str, techniques: dict) -> list[str]:
    """ATT&CK id must exist in the pinned snapshot and must not be revoked or deprecated."""
    if not techniques:
        return []
    entry = techniques.get(technique)
    if entry is None:
        return [f"{where}: ATT&CK id {technique} does not exist in the pinned ATT&CK snapshot"]
    if entry["revoked"]:
        return [f"{where}: ATT&CK id {technique} ({entry['name']}) is revoked; use {entry['revoked_by'] or 'its successor'}"]
    if entry["deprecated"]:
        return [f"{where}: ATT&CK id {technique} ({entry['name']}) is deprecated"]
    return []


def lint(root: Path | None = None) -> list[str]:
    root = root or RULES
    errors: list[str] = []
    meta = load_metadata(root)
    try:
        wz, su = load_wazuh(root), load_suricata(root)
    except (ValueError, ET.ParseError) as err:
        return [f"rule files do not parse: {err}"]

    attack, wazuh_ref = refdata.load_attack(root / "reference"), refdata.load_wazuh_reference(root / "reference")
    if attack is None:
        errors.append("rules/reference has no ATT&CK snapshot: run `python -m tools.refdata attack`")
    if wazuh_ref is None:
        errors.append("rules/reference has no Wazuh ruleset snapshot: run `python -m tools.refdata wazuh`")
    techniques = (attack or {}).get("techniques", {})
    official = (wazuh_ref or {}).get("rules", {})

    et, _ = load_et(root)
    try:
        scenarios = catalog.load_scenarios(catalog.SCENARIO_DIR)
    except ValueError as err:
        errors.append(f"simulation scenarios invalid: {err}")
        scenarios = {}
    errors += catalog.check_against_rules(scenarios, meta)
    proven = catalog.evidence(scenarios, meta, catalog.References.load().pcaps)
    mapping_ids: dict[int, str] = {}

    seen_ids = set()
    for mid, m in meta.items():
        where = m["_path"]
        if mid in seen_ids:
            errors.append(f"{where}: duplicate metadata id {mid}")
        seen_ids.add(mid)
        for key in ("id", "engine", "rule_id", "name", "state", "response", "owner", "description",
                    "expected_fp", "references", "tests"):
            if not m.get(key):
                errors.append(f"{where}: missing required field `{key}`")
        if not isinstance(m.get("mitre"), list):
            errors.append(f"{where}: `mitre` must be a list (empty when the rule claims no technique)")
        elif m["mitre"] and not m.get("tactic"):
            errors.append(f"{where}: missing required field `tactic`")
        if m.get("engine") not in ("wazuh", "suricata"):
            errors.append(f"{where}: engine must be wazuh|suricata")
            continue
        if mid != f"{m['engine']}-{m.get('rule_id')}":
            errors.append(f"{where}: id must be '<engine>-<rule_id>' (got {mid})")
        if m.get("state") not in STATES:
            errors.append(f"{where}: state must be one of {STATES}")
        if m.get("response", "none") not in RESPONSES:
            errors.append(f"{where}: response must be one of {RESPONSES}")
        mitre_refs = set()
        for technique in m.get("mitre", []) or []:
            if not MITRE_RE.match(str(technique)):
                errors.append(f"{where}: bad ATT&CK id {technique!r}")
                continue
            errors += _technique_problems(where, str(technique), techniques)
            base, _, sub = str(technique).partition(".")
            mitre_refs.add(f"https://attack.mitre.org/techniques/{base}/{sub}/" if sub else
                           f"https://attack.mitre.org/techniques/{base}/")
        references = m.get("references") or []
        valid_references = set()
        if not isinstance(references, list):
            errors.append(f"{where}: references must be a list of HTTPS URLs")
        else:
            for reference in references:
                parsed = urlparse(reference) if isinstance(reference, str) else None
                if not parsed or parsed.scheme != "https" or not parsed.netloc:
                    errors.append(f"{where}: invalid reference {reference!r}; use an HTTPS URL")
                else:
                    valid_references.add(reference.rstrip("/") + "/")
        if not mitre_refs.issubset(valid_references):
            errors.append(f"{where}: references must include the canonical ATT&CK URL for every MITRE id")
        tests = m.get("tests") or []
        runnable = RUNNABLE_TEST_KEYS.get(m["engine"], ())
        for t in tests:
            if t.get("expect") not in ("match", "no_match"):
                errors.append(f"{where}: test {t.get('name', '?')!r} needs expect: match|no_match")
            if not any(k in t for k in runnable):
                errors.append(f"{where}: test {t.get('name', '?')!r} must define one of {runnable} "
                              f"(tests run on the real {m['engine']} engine)")
        if m.get("state") != "deprecated":
            if not any(t.get("expect") == "match" for t in tests):
                errors.append(f"{where}: needs at least one positive test (expect: match)")
            if not any(t.get("expect") == "no_match" for t in tests):
                errors.append(f"{where}: needs at least one negative test (expect: no_match)")
        if m["engine"] == "wazuh":
            rule = wz.get(m.get("rule_id"))
            if rule is None:
                errors.append(f"{where}: no <rule id={m.get('rule_id')}> in rules/wazuh")
            else:
                if sorted(rule.mitre) != sorted(m.get("mitre", [])):
                    errors.append(f"{where}: mitre {m.get('mitre')} != XML {rule.mitre}")
                official_parents = sorted(p for p in rule.parents if p not in wz and str(p) in official)
                if official and sorted(m.get("wraps") or []) != official_parents:
                    errors.append(f"{where}: `wraps` {sorted(m.get('wraps') or [])} must list exactly the official "
                                  f"Wazuh rules this rule hangs under: {official_parents}")
        else:
            source = m.get("source", "local")
            if source not in SURICATA_SOURCES:
                errors.append(f"{where}: source must be one of {SURICATA_SOURCES}")
            elif source == "local" and su.get(m.get("rule_id")) is None:
                errors.append(f"{where}: no sid {m.get('rule_id')} in rules/suricata")
            elif source == "et-open" and et.get(m.get("rule_id")) is None:
                errors.append(f"{where}: sid {m.get('rule_id')} is not in rules/reference/et-open-managed.json "
                              f"(run `python -m tools.refdata et-open`)")
            if not isinstance(m.get("level"), int) or not 1 <= m["level"] <= 15:
                errors.append(f"{where}: suricata metadata needs integer `level` 1-15 (used by the mapping rule)")
            wid = m.get("wazuh_rule_id")
            if not isinstance(wid, int) or wid not in MAPPING_RANGE:
                errors.append(f"{where}: `wazuh_rule_id` must be an integer in "
                              f"{MAPPING_RANGE.start}-{MAPPING_RANGE.stop - 1}")
            elif wid in mapping_ids or wid in wz or (official and str(wid) in official):
                errors.append(f"{where}: wazuh_rule_id {wid} is already used ({mapping_ids.get(wid, 'a Wazuh rule')})")
            else:
                mapping_ids[wid] = mid
        errors += _provenance_problems(where, m, official, proven.get(mid, set()))

    for rid, rule in wz.items():
        for tid in rule.mitre:
            errors += _technique_problems(f"wazuh rule {rid}", tid, techniques)
        if official and str(rid) in official:
            errors.append(f"wazuh rule {rid}: id is already used by the official ruleset ({official[str(rid)]['file']})")
        for parent in rule.parents:
            if official and parent not in wz and str(parent) not in official:
                errors.append(f"wazuh rule {rid}: parent rule {parent} exists neither here nor in Wazuh "
                              f"{wazuh_ref['wazuh_version']} (rule would never fire)")
        if rid not in WAZUH_RANGE:
            errors.append(f"wazuh rule {rid}: id outside custom range {WAZUH_RANGE.start}-{WAZUH_RANGE.stop - 1}")
        if f"wazuh-{rid}" not in meta:
            errors.append(f"wazuh rule {rid}: no metadata file rules/metadata/wazuh-{rid}.yml")
        if not rule.description:
            errors.append(f"wazuh rule {rid}: missing <description>")
        if not 0 <= rule.level <= 15:
            errors.append(f"wazuh rule {rid}: level must be 0-15")
        if any(FORBIDDEN_GROUP.search(g) for g in rule.groups):
            errors.append(f"wazuh rule {rid}: lifecycle/response groups are injected by the build, remove them")
        if rule.element is not None and rule.element.find("options") is not None:
            if "alert_by_email" in (rule.element.findtext("options") or ""):
                errors.append(f"wazuh rule {rid}: alert_by_email bypasses the SOAR case flow")
    for sid, rule in su.items():
        if sid in et:
            errors.append(f"suricata sid {sid}: local rule reuses the sid of a managed ET Open rule")
        if sid not in SURICATA_RANGE:
            errors.append(f"suricata sid {sid}: outside {SURICATA_RANGE.start}-{SURICATA_RANGE.stop - 1}")
        if f"suricata-{sid}" not in meta:
            errors.append(f"suricata sid {sid}: no metadata file")
        if not rule.msg.startswith("SIEMSOAR"):
            errors.append(f"suricata sid {sid}: msg must start with 'SIEMSOAR' (namespacing)")
        if not rule.classtype:
            errors.append(f"suricata sid {sid}: missing classtype")
        if not rule.rev:
            errors.append(f"suricata sid {sid}: missing rev")
        if rule.action not in ("alert", "drop"):
            errors.append(f"suricata sid {sid}: action must be alert|drop (build converts enforce)")
        if rule.action == "drop":
            errors.append(f"suricata sid {sid}: write rules as `alert`; the build produces drop for enforce state")
    return errors


def _provenance_problems(where: str, m: dict, official: dict, proven: set[str]) -> list[str]:
    """Every ATT&CK id on a rule needs a source: the official parent rules' own MITRE ids, or a public procedure."""
    vendor = {t for parent in (m.get("wraps") or []) for t in (official.get(str(parent)) or {}).get("mitre", [])}
    problems = []
    for technique in m.get("mitre") or []:
        if not any(catalog.related(technique, s) for s in vendor | proven):
            problems.append(
                f"{where}: ATT&CK {technique} has no source: not on the wrapped official Wazuh rules "
                f"({sorted(vendor) or 'none'}) and no Atomic/Stratus procedure shown to trigger this rule "
                f"({sorted(proven) or 'none'}). Add such a scenario/pcap or remove the label")
    return problems


# --------------------------------------------------------------------------- lifecycle gate
def _git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, check=True, capture_output=True, text=True).stdout


def lifecycle_check(base: str, allow_revert: bool = False) -> list[str]:
    """Compare metadata states with the base ref. New rules must start in shadow; moves must follow FREEZE."""
    errors = []
    current = load_metadata()
    for mid, m in current.items():
        rel = Path(m["_path"]).relative_to(ROOT).as_posix()
        try:
            old = yaml.safe_load(_git("show", f"{base}:{rel}"))
        except subprocess.CalledProcessError:
            old = None
        if old is None:
            if m["state"] != "shadow" and not allow_revert:
                errors.append(f"{mid}: new rules must be introduced as `shadow` (found `{m['state']}`)")
            continue
        a, b = old["state"], m["state"]
        if a != b and b not in FREEZE.get(a, set()) and not allow_revert:
            errors.append(f"{mid}: illegal lifecycle move {a} -> {b} (allowed: {sorted(FREEZE.get(a, []))})")
    return errors


# --------------------------------------------------------------------------- build
def _inject_groups(rule: WazuhRule, state: str, response: str) -> None:
    el = rule.element
    extra = f"siemsoar_{state},resp_{response},"
    group = el.find("group")
    if group is None:
        group = ET.SubElement(el, "group")
        group.text = extra
    else:
        group.text = (group.text or "").rstrip(",") + "," + extra


def _mapping_rule_xml(sid: int, m: dict, rule: suricata_rule.Rule) -> ET.Element:
    container = ET.Element("group", name="siemsoar,suricata,")
    el = ET.SubElement(container, "rule", id=str(wazuh_rule_of(m)), level=str(m["level"]))
    ET.SubElement(el, "if_sid").text = "86601"  # built-in: Suricata alert event
    f = ET.SubElement(el, "field", name="alert.signature_id")
    f.text = f"^{sid}$"
    ET.SubElement(el, "description").text = f"Suricata: {rule.msg}"
    if m["mitre"]:  # an empty <mitre/> is a warning in wazuh-analysisd
        mitre = ET.SubElement(el, "mitre")
        for t in m["mitre"]:
            ET.SubElement(mitre, "id").text = t
    ET.SubElement(el, "group").text = f"siemsoar_{m['state']},resp_{m['response']},"
    return container


def build(out: Path, sha: str, allow_drop: bool = False, commit_time: str | None = None) -> dict:
    errors = lint()
    if errors:
        raise SystemExit("lint failed:\n  " + "\n  ".join(errors))
    meta, wz, su = load_metadata(), load_wazuh(), load_suricata()
    et, et_snap = load_et()
    out = out / sha
    (out / "wazuh").mkdir(parents=True, exist_ok=True)
    (out / "suricata").mkdir(parents=True, exist_ok=True)

    containers: list[ET.Element] = []
    seen_container = set()
    for rid, rule in wz.items():
        m = meta[f"wazuh-{rid}"]
        if m["state"] == "deprecated":
            rule.container.remove(rule.element)
            continue
        _inject_groups(rule, m["state"], m["response"])
        if id(rule.container) not in seen_container:
            seen_container.add(id(rule.container))
            containers.append(rule.container)
    containers = [c for c in containers if c.findall("rule")]
    suri = {int(m["rule_id"]): m for m in meta.values() if m["engine"] == "suricata"}
    for sid, m in sorted(suri.items()):
        if m["state"] != "deprecated":
            containers.append(_mapping_rule_xml(sid, m, (et if m.get("source") == "et-open" else su)[sid]))
    xml_lines = ["<!-- GENERATED by tools/rulesctl.py build. Do not edit on the host. -->"]
    for c in containers:
        ET.indent(c, space="  ")
        xml_lines.append(ET.tostring(c, encoding="unicode"))
    (out / "wazuh" / "siemsoar_rules.xml").write_text("\n".join(xml_lines) + "\n")

    lines = ["# GENERATED by tools/rulesctl.py build. Do not edit on the host.",
             f"# Managed rules: Emerging Threats Open {et_snap.get('version', '-')} ({refdata.ET_LICENSE})."]
    for sid, m in sorted(suri.items()):
        state = m["state"]
        if state == "deprecated":
            continue
        line = suricata_text(m, su, et)
        if state == "enforce":
            if allow_drop:
                line = re.sub(r"^alert\b", "drop", line)
            else:
                print(f"warning: sid {sid} is `enforce` but --allow-drop not set; staying `alert`", file=sys.stderr)
        lines.append(line)
    (out / "suricata" / "siemsoar.rules").write_text("\n".join(lines) + "\n")
    # suricata-update must drop its own copy of the managed sids, otherwise Suricata loads them twice
    managed = sorted(sid for sid, m in suri.items() if m.get("source") == "et-open")
    (out / "suricata" / "disable.conf").write_text(
        "# GENERATED by tools/rulesctl.py build: managed ET Open sids are deployed from siemsoar.rules\n"
        + "".join(f"1:{sid}\n" for sid in managed))

    files = []
    for p in sorted(out.rglob("*")):
        if p.is_file() and p.name != "manifest.json":
            files.append({"path": p.relative_to(out).as_posix(), "sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
                          "bytes": p.stat().st_size})
    summary = {s: sum(1 for m in meta.values() if m["state"] == s) for s in STATES}
    manifest = {
        "sha": sha, "commit_time": commit_time, "built_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "files": files, "summary": summary, "et_open_version": et_snap.get("version"),
        "rules": [{"id": mid, "state": m["state"], "response": m["response"], "mitre": m["mitre"]}
                  for mid, m in meta.items()],
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


# --------------------------------------------------------------------------- promote / coverage / tune
def promote(rule_id: str, state: str) -> str:
    """Rewrite only the `state:` line so diffs stay one line and comments are preserved."""
    meta = load_metadata()
    if rule_id not in meta:
        raise SystemExit(f"unknown rule {rule_id}")
    old = meta[rule_id]["state"]
    if state not in FREEZE.get(old, set()):
        raise SystemExit(f"illegal move {old} -> {state}; allowed: {sorted(FREEZE.get(old, []))}")
    path = Path(meta[rule_id]["_path"])
    path.write_text(re.sub(r"(?m)^state:\s*\S+", f"state: {state}", path.read_text(), count=1))
    changed = sync_scenarios(meta[rule_id], state)
    return f"{rule_id}: {old} -> {state}" + (f" (scenario expectations updated: {', '.join(changed)})" if changed else "")


def sync_scenarios(m: dict, state: str, directory: Path | None = None) -> list[str]:
    """After a state change, a scenario expecting this rule must expect a case exactly when the rule is active/enforce.
    Only the `case:` flag on that rule's expectation lines is rewritten (comments and layout are kept)."""
    rid = str(m["wazuh_rule_id"] if m["engine"] == "suricata" else m["rule_id"])
    source = m["engine"]
    want = "true" if state in ("active", "enforce") else "false"
    line_re = re.compile(rf'^(\s*-\s*\{{[^}}]*source:\s*{source}\b[^}}]*rule_id:\s*"?{rid}"?[^}}]*case:\s*)(true|false)',
                         re.M)
    changed = []
    for path in sorted((directory or catalog.SCENARIO_DIR).glob("*.yml")):
        text = path.read_text(encoding="utf-8")
        new = line_re.sub(lambda mt: mt.group(1) + want, text)
        if new != text:
            path.write_text(new, encoding="utf-8", newline="\n")
            changed.append(path.stem)
    return changed


def coverage(states=("active", "enforce")) -> dict:
    meta = load_metadata()
    by_tech: dict[str, list[str]] = {}
    for mid, m in meta.items():
        if m["state"] in states:
            for t in m["mitre"]:
                by_tech.setdefault(t, []).append(mid)
    return {"states_counted": list(states), "techniques": by_tech, "technique_count": len(by_tech)}


def tune(feedback: dict, min_cases: int = 3) -> list[str]:
    """feedback: {"<rule_id>": {"cases": N, "false_positive": M}} (from `soarctl feedback`)."""
    meta = load_metadata()
    suggestions = []
    for rid, stats in feedback.items():
        n, fp = stats.get("cases", 0), stats.get("false_positive", 0)
        if n < min_cases:
            continue
        rate = fp / n
        candidates = [f"wazuh-{rid}"]
        mapped = suricata_meta_by_wazuh_rule(meta).get(int(rid)) if str(rid).isdigit() else None
        if mapped:  # generated Suricata mapping rule -> its metadata
            candidates.append(mapped["id"])
        key = next((c for c in candidates if c in meta), None)
        state = meta.get(key, {}).get("state", "?")
        if rate >= 0.5 and state in ("active", "enforce"):
            suggestions.append(f"{key or rid}: FP rate {rate:.0%} over {n} cases -> demote to shadow "
                               f"(`rulesctl promote {key} shadow`) or tighten the rule")
        elif rate == 0 and state == "shadow":
            suggestions.append(f"{key or rid}: no FP in {n} cases -> candidate for promotion to active")
    return suggestions


# --------------------------------------------------------------------------- CLI
def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="rulesctl")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("lint")
    lc = sub.add_parser("lifecycle")
    lc.add_argument("--base", required=True)
    lc.add_argument("--allow-revert", action="store_true")
    b = sub.add_parser("build")
    b.add_argument("--out", default="dist")
    b.add_argument("--sha", default=None)
    b.add_argument("--allow-drop", action="store_true")
    pr = sub.add_parser("promote")
    pr.add_argument("rule_id")
    pr.add_argument("state", choices=STATES)
    sub.add_parser("coverage")
    t = sub.add_parser("tune")
    t.add_argument("feedback")
    t.add_argument("--min-cases", type=int, default=3)
    args = p.parse_args(argv)

    if args.cmd == "lint":
        errs = lint()
        print("\n".join(errs) if errs else "lint ok")
        return 1 if errs else 0
    if args.cmd == "lifecycle":
        errs = lifecycle_check(args.base, args.allow_revert)
        print("\n".join(errs) if errs else "lifecycle ok")
        return 1 if errs else 0
    if args.cmd == "build":
        sha = args.sha or _git("rev-parse", "HEAD").strip()
        try:
            ct = _git("show", "-s", "--format=%cI", sha).strip()
        except subprocess.CalledProcessError:
            ct = None
        m = build(Path(args.out), sha, args.allow_drop, ct)
        print(json.dumps({"sha": sha, "summary": m["summary"], "files": [f["path"] for f in m["files"]]}))
        return 0
    if args.cmd == "promote":
        print(promote(args.rule_id, args.state))
        return 0
    if args.cmd == "coverage":
        print(json.dumps(coverage(), indent=2))
        return 0
    if args.cmd == "tune":
        out = tune(json.loads(Path(args.feedback).read_text()), args.min_cases)
        print("\n".join(out) if out else "no tuning suggestions")
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
