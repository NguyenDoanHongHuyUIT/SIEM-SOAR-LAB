"""rulesctl: detection-as-code toolbelt (lint, test, lifecycle gate, build, promote, coverage, tune).

  python -m tools.rulesctl lint
  python -m tools.rulesctl test
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
from datetime import UTC, datetime
from pathlib import Path

import yaml

from tools import rule_engine as eng

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "rules"
STATES = ("shadow", "active", "enforce", "deprecated")
RESPONSES = ("none", "ec2_isolate", "iam_key_disable")
WAZUH_RANGE = range(100000, 120000)
SURICATA_RANGE = range(9000000, 9100000)
MITRE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
FREEZE = {  # allowed lifecycle moves (paper Figure 2: shadow -> active -> enforce, deprecate, rollback)
    "shadow": {"active", "deprecated"},
    "active": {"enforce", "shadow", "deprecated"},
    "enforce": {"active", "deprecated"},
    "deprecated": {"shadow"},
}
FORBIDDEN_GROUP = re.compile(r"(^|,)\s*(siemsoar_(shadow|active|enforce|deprecated)|resp_\w+)\s*(,|$)")


def mapped_wazuh_id(sid: int) -> int:
    """Suricata sid 9000001 -> Wazuh mapping rule 110001."""
    return 110000 + (sid - 9000000)


# --------------------------------------------------------------------------- loading
def load_metadata(root: Path | None = None) -> dict[str, dict]:
    root = root or RULES
    meta: dict[str, dict] = {}
    for path in sorted((root / "metadata").glob("*.yml")):
        data = yaml.safe_load(path.read_text()) or {}
        data["_path"] = str(path)
        meta[data.get("id", path.stem)] = data
    return meta


def load_wazuh(root: Path | None = None) -> dict[int, eng.WazuhRule]:
    root = root or RULES
    rules: dict[int, eng.WazuhRule] = {}
    for path in sorted((root / "wazuh").glob("*.xml")):
        for rid, rule in eng.parse_wazuh_xml(path.read_text()).items():
            if rid in rules:
                raise ValueError(f"duplicate Wazuh rule id {rid}")
            rules[rid] = rule
    return rules


def load_suricata(root: Path | None = None) -> dict[int, eng.SuricataRule]:
    root = root or RULES
    rules: dict[int, eng.SuricataRule] = {}
    for path in sorted((root / "suricata").glob("*.rules")):
        for sid, rule in eng.parse_suricata_rules(path.read_text()).items():
            if sid in rules:
                raise ValueError(f"duplicate suricata sid {sid}")
            rules[sid] = rule
    return rules


# --------------------------------------------------------------------------- lint
def lint(root: Path | None = None) -> list[str]:
    root = root or RULES
    errors: list[str] = []
    meta = load_metadata(root)
    try:
        wz, su = load_wazuh(root), load_suricata(root)
    except (ValueError, ET.ParseError) as err:
        return [f"rule files do not parse: {err}"]

    seen_ids = set()
    for mid, m in meta.items():
        where = m["_path"]
        if mid in seen_ids:
            errors.append(f"{where}: duplicate metadata id {mid}")
        seen_ids.add(mid)
        for key in ("id", "engine", "rule_id", "name", "state", "response", "mitre", "tactic", "owner", "description",
                    "expected_fp", "tests"):
            if not m.get(key):
                errors.append(f"{where}: missing required field `{key}`")
        if m.get("engine") not in ("wazuh", "suricata"):
            errors.append(f"{where}: engine must be wazuh|suricata")
            continue
        if mid != f"{m['engine']}-{m.get('rule_id')}":
            errors.append(f"{where}: id must be '<engine>-<rule_id>' (got {mid})")
        if m.get("state") not in STATES:
            errors.append(f"{where}: state must be one of {STATES}")
        if m.get("response", "none") not in RESPONSES:
            errors.append(f"{where}: response must be one of {RESPONSES}")
        for t in m.get("mitre", []) or []:
            if not MITRE_RE.match(str(t)):
                errors.append(f"{where}: bad ATT&CK id {t!r}")
        tests = m.get("tests") or []
        if m.get("state") != "deprecated":
            if not any(t.get("expect") == "match" for t in tests):
                errors.append(f"{where}: needs at least one positive test (expect: match)")
            if not any(t.get("expect") == "no_match" for t in tests):
                errors.append(f"{where}: needs at least one negative test (expect: no_match)")
        if m["engine"] == "wazuh":
            rule = wz.get(m.get("rule_id"))
            if rule is None:
                errors.append(f"{where}: no <rule id={m.get('rule_id')}> in rules/wazuh")
            elif sorted(rule.mitre) != sorted(m.get("mitre", [])):
                errors.append(f"{where}: mitre {m.get('mitre')} != XML {rule.mitre}")
        else:
            if su.get(m.get("rule_id")) is None:
                errors.append(f"{where}: no sid {m.get('rule_id')} in rules/suricata")
            if not isinstance(m.get("level"), int) or not 1 <= m["level"] <= 15:
                errors.append(f"{where}: suricata metadata needs integer `level` 1-15 (used by the mapping rule)")
            pcap = m.get("pcap")
            if pcap and (not pcap.get("file") or sid_not_listed(pcap, m["rule_id"])):
                errors.append(f"{where}: pcap needs `file` and `expect_sids` containing {m['rule_id']}")

    for rid, rule in wz.items():
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
        if sid not in SURICATA_RANGE:
            errors.append(f"suricata sid {sid}: outside {SURICATA_RANGE.start}-{SURICATA_RANGE.stop - 1}")
        if f"suricata-{sid}" not in meta:
            errors.append(f"suricata sid {sid}: no metadata file")
        if not rule.msg.startswith("SIEMSOAR"):
            errors.append(f"suricata sid {sid}: msg must start with 'SIEMSOAR' (namespacing)")
        for need in ("classtype", "rev"):
            if not any(k == need for k, _ in rule.options):
                errors.append(f"suricata sid {sid}: missing {need}")
        if rule.action not in ("alert", "drop"):
            errors.append(f"suricata sid {sid}: action must be alert|drop (build converts enforce)")
        if rule.action == "drop":
            errors.append(f"suricata sid {sid}: write rules as `alert`; the build produces drop for enforce state")
    return errors


def sid_not_listed(pcap: dict, sid: int) -> bool:
    return sid not in (pcap.get("expect_sids") or [])


# --------------------------------------------------------------------------- test
def run_tests(root: Path | None = None) -> list[tuple[str, str, bool, str]]:
    meta, wz, su = load_metadata(root), load_wazuh(root), load_suricata(root)
    results = []
    for mid, m in meta.items():
        for t in m.get("tests", []) or []:
            if m["engine"] == "wazuh" and ("log" in t or "logs" in t) and not ("event" in t or "events" in t):
                continue  # raw-log sample: executed on the real engine by `python -m tools.wazuh_logtest`
            if m["engine"] == "wazuh" and m["rule_id"] in wz:
                ok, detail = eng.run_wazuh_test(wz[m["rule_id"]], t, wz)
            elif m["engine"] == "suricata" and m["rule_id"] in su:
                ok, detail = eng.run_suricata_test(su[m["rule_id"]], t)
            else:
                ok, detail = False, "rule not found"
            results.append((mid, t.get("name", "?"), ok, detail))
    return results


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
def _inject_groups(rule: eng.WazuhRule, state: str, response: str) -> None:
    el = rule.element
    extra = f"siemsoar_{state},resp_{response},"
    group = el.find("group")
    if group is None:
        group = ET.SubElement(el, "group")
        group.text = extra
    else:
        group.text = (group.text or "").rstrip(",") + "," + extra


def _mapping_rule_xml(sid: int, m: dict, rule: eng.SuricataRule) -> ET.Element:
    container = ET.Element("group", name="siemsoar,suricata,")
    el = ET.SubElement(container, "rule", id=str(mapped_wazuh_id(sid)), level=str(m["level"]))
    ET.SubElement(el, "if_sid").text = "86601"  # built-in: Suricata alert event
    f = ET.SubElement(el, "field", name="alert.signature_id")
    f.text = f"^{sid}$"
    ET.SubElement(el, "description").text = f"Suricata: {rule.msg}"
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
    for sid, srule in su.items():
        m = meta[f"suricata-{sid}"]
        if m["state"] != "deprecated":
            containers.append(_mapping_rule_xml(sid, m, srule))
    xml_lines = ["<!-- GENERATED by tools/rulesctl.py build. Do not edit on the host. -->"]
    for c in containers:
        ET.indent(c, space="  ")
        xml_lines.append(ET.tostring(c, encoding="unicode"))
    (out / "wazuh" / "siemsoar_rules.xml").write_text("\n".join(xml_lines) + "\n")

    lines = ["# GENERATED by tools/rulesctl.py build. Do not edit on the host."]
    for sid, srule in su.items():
        state = meta[f"suricata-{sid}"]["state"]
        if state == "deprecated":
            continue
        line = srule.raw
        if state == "enforce":
            if allow_drop:
                line = re.sub(r"^alert\b", "drop", line)
            else:
                print(f"warning: sid {sid} is `enforce` but --allow-drop not set; staying `alert`", file=sys.stderr)
        lines.append(line)
    (out / "suricata" / "siemsoar.rules").write_text("\n".join(lines) + "\n")

    files = []
    for p in sorted(out.rglob("*")):
        if p.is_file() and p.name != "manifest.json":
            files.append({"path": p.relative_to(out).as_posix(), "sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
                          "bytes": p.stat().st_size})
    summary = {s: sum(1 for m in meta.values() if m["state"] == s) for s in STATES}
    manifest = {
        "sha": sha, "commit_time": commit_time, "built_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "files": files, "summary": summary,
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
    return f"{rule_id}: {old} -> {state}"


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
        if str(rid).isdigit() and 110000 <= int(rid) < 120000:  # generated Suricata mapping rule -> sid
            candidates.append(f"suricata-{9000000 + int(rid) - 110000}")
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
    sub.add_parser("test")
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
    if args.cmd == "test":
        results = run_tests()
        bad = [r for r in results if not r[2]]
        for mid, name, ok, detail in results:
            print(f"{'PASS' if ok else 'FAIL'} {mid}: {name}" + ("" if ok else f"  ({detail})"))
        print(f"{len(results) - len(bad)}/{len(results)} passed")
        return 1 if bad else 0
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
