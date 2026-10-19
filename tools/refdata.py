"""refdata: build the pinned, verifiable reference snapshots that rule lint checks against.

  python -m tools.refdata attack [--version 20.0]        # MITRE ATT&CK enterprise techniques (official STIX 2.1)
  python -m tools.refdata wazuh  [--version 4.14.8]      # rule ids shipped with that Wazuh release
  python -m tools.refdata finding-types                  # GuardDuty finding-type catalogue (AWS documentation)
  python -m tools.refdata guardduty                      # GuardDuty finding type -> ATT&CK (MITRE CTID, pinned commit)
  python -m tools.refdata atomic                         # Atomic Red Team Linux test index (pinned commit)
  python -m tools.refdata et-open                        # text of the ET Open rules SIEMSOAR manages (metadata source)
  python -m tools.refdata check                          # are the committed snapshots well formed and consistent?

Why snapshots instead of regexes: a technique id can be well formed and still be revoked (T1562.008 was), and a custom
Wazuh rule can chain `<if_sid>` onto a rule that does not exist in the deployed Wazuh version. Both are silent failures.
Each snapshot records where it came from and the SHA-256 of the exact upstream bytes, so a reviewer can re-derive it.

Output: rules/reference/attack-enterprise-<version>.json, rules/reference/wazuh-<version>.json and
src/lambdas/siemsoar/guardduty_attack.json (read at run time by the normaliser, so it ships inside the Lambda package).
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import html
import io
import json
import re
import sys
import tarfile
import urllib.request
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REF = ROOT / "rules" / "reference"
ATTACK_URL = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
              "enterprise-attack/enterprise-attack-{version}.json")
WAZUH_URL = "https://github.com/wazuh/wazuh/archive/refs/tags/v{version}.tar.gz"
VERSION_RE = re.compile(r"^\d+\.\d+(\.\d+)?$")
TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


def _fetch(url: str, timeout: int = 180) -> bytes:
    if not url.startswith("https://"):
        raise ValueError("reference data must be fetched over https")
    with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 (https, fixed hosts)
        return resp.read()


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------- ATT&CK
def parse_attack(bundle: dict) -> dict[str, dict]:
    """{technique id: {name, tactics, revoked, deprecated, revoked_by}} from an ATT&CK STIX bundle (tactics are the
    technique's `kill_chain_phases` in the mitre-attack kill chain, e.g. "lateral-movement")."""
    objects = bundle["objects"]
    by_stix = {o["id"]: o for o in objects}

    def attack_id(obj: dict) -> str | None:
        return next((r["external_id"] for r in obj.get("external_references", [])
                     if r.get("source_name") == "mitre-attack"), None)

    successor = {}
    for o in objects:
        if o.get("type") == "relationship" and o.get("relationship_type") == "revoked-by":
            target = by_stix.get(o["target_ref"])
            if target is not None:
                successor[o["source_ref"]] = attack_id(target)
    out: dict[str, dict] = {}
    for o in objects:
        if o.get("type") != "attack-pattern":
            continue
        tid = attack_id(o)
        if tid and TECHNIQUE_RE.match(tid):
            out[tid] = {"name": o["name"],
                        "tactics": sorted(k["phase_name"] for k in o.get("kill_chain_phases", [])
                                          if k.get("kill_chain_name") == "mitre-attack"),
                        "revoked": bool(o.get("revoked")),
                        "deprecated": bool(o.get("x_mitre_deprecated")), "revoked_by": successor.get(o["id"])}
    return out


def build_attack(version: str, raw: bytes | None = None) -> dict:
    url = ATTACK_URL.format(version=version)
    raw = raw if raw is not None else _fetch(url)
    techniques = parse_attack(json.loads(raw))
    return {"kind": "attack-enterprise", "attack_version": version, "source": url,
            "upstream_sha256": hashlib.sha256(raw).hexdigest(), "generated_at": _now(), "techniques": techniques}


# --------------------------------------------------------------------------- Wazuh
def _number(value: str | None) -> int | str | None:
    """Wazuh allows `$VARIABLE` here (defined by <var>); keep those verbatim instead of guessing a value."""
    if not value:
        return None
    return int(value) if value.isdigit() else value


def parse_wazuh_rules(text: str, filename: str) -> dict[int, dict]:
    """Rule ids, levels, parents and MITRE ids of one Wazuh ruleset file (fragments with several <group> roots)."""
    try:
        root = ET.fromstring(f"<root>{text}</root>")  # noqa: S314 - upstream ruleset, pinned by SHA-256
    except ET.ParseError:
        # Wazuh's own parser accepts a regex such as `\<\w+\>` where strict XML wants entities (ms-exchange rules)
        root = ET.fromstring(f"<root>{text.replace(chr(92) + '<', '&lt;').replace(chr(92) + '>', '&gt;')}</root>")  # noqa: S314
    rules: dict[int, dict] = {}
    for group in root.findall("group"):
        container = [g.strip() for g in (group.get("name") or "").split(",") if g.strip()]
        for el in group.findall("rule"):
            own = [g.strip() for g in (el.findtext("group") or "").split(",") if g.strip()]
            parents = [p.strip() for tag in ("if_sid", "if_matched_sid") for e in el.findall(tag)
                       for p in (e.text or "").split(",") if p.strip()]
            rules[int(el.get("id"))] = {
                "level": int(el.get("level", "0")), "file": filename,
                "description": " ".join((el.findtext("description") or "").split()),
                "parents": sorted({int(p) for p in parents if p.isdigit()}),
                "frequency": _number(el.get("frequency")), "timeframe": _number(el.get("timeframe")),
                "mitre": [(i.text or "").strip() for i in el.findall("mitre/id")],
                "groups": sorted(set(container + own))}
    return rules


def build_wazuh(version: str, raw: bytes | None = None) -> dict:
    url = WAZUH_URL.format(version=version)
    raw = raw if raw is not None else _fetch(url, timeout=300)
    rules: dict[int, dict] = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tar:
        for member in tar:
            if member.isfile() and "/ruleset/rules/" in member.name and member.name.endswith(".xml"):
                name = member.name.rsplit("/", 1)[-1]
                for rid, rule in parse_wazuh_rules(tar.extractfile(member).read().decode("utf-8"), name).items():
                    if rid in rules:
                        raise ValueError(f"rule id {rid} defined twice in the official ruleset ({name})")
                    rules[rid] = rule
    return {"kind": "wazuh-ruleset", "wazuh_version": version, "source": url,
            "upstream_sha256": hashlib.sha256(raw).hexdigest(), "generated_at": _now(),
            "rules": {str(k): v for k, v in sorted(rules.items())}}


# --------------------------------------------------------------------------- GuardDuty -> ATT&CK (CTID)
# AWS publishes finding types but no ATT&CK mapping. The independent one is MITRE Center for Threat-Informed Defense's
# "Mappings Explorer / AWS": per technique, the GuardDuty finding types that can indicate it. Pinned to a commit.
CTID_COMMIT = "a85e55af3c9fa55359a98621745b9b039a088bec"
CTID_RELEASE, CTID_ATTACK = "12.12.2024", "16.1"
CTID_URL = ("https://raw.githubusercontent.com/center-for-threat-informed-defense/mappings-explorer/{commit}/"
            "mappings/aws/attack-{attack}/aws-{release}/enterprise/aws-{release}_attack-{attack}-enterprise.json")
GD_SNAPSHOT = ROOT / "src" / "lambdas" / "siemsoar" / "guardduty_attack.json"  # ships inside the Lambda package
# `Category:ResourceType/Name[.Variant][!DNS]`; `&` occurs in Backdoor:EC2/C&CActivity.B
FINDING_RE = re.compile(r"\b[A-Z][A-Za-z]+:[A-Za-z0-9]+/[A-Za-z0-9&_.!]+")


def parse_ctid_guardduty(bundle: dict) -> dict[str, set[str]]:
    """{finding type: {technique ids}} from the Amazon GuardDuty entries of a Mappings Explorer AWS release."""
    out: dict[str, set[str]] = {}
    for entry in bundle["mapping_objects"]:
        if entry.get("capability_group") != "amazon_guardduty":
            continue
        for finding in {f.rstrip(".") for f in FINDING_RE.findall(entry.get("comments") or "")}:
            out.setdefault(finding, set()).add(entry["attack_object_id"])
    return out


def resolve_techniques(ids: set[str], techniques: dict[str, dict]) -> tuple[list[str], list[str]]:
    """Bring technique ids of an older ATT&CK release to the pinned one: follow `revoked-by`, drop what no longer exists.
    A parent technique listed together with one of its sub-techniques is dropped (the sub-technique is the specific one)."""
    kept: set[str] = set()
    dropped: list[str] = []
    for tid in sorted(ids):
        seen = set()
        while tid in techniques and (techniques[tid]["revoked"] or techniques[tid]["deprecated"]) and tid not in seen:
            seen.add(tid)
            tid = techniques[tid]["revoked_by"] or ""
        if tid in techniques and not techniques[tid]["revoked"] and not techniques[tid]["deprecated"]:
            kept.add(tid)
        else:
            dropped.append(tid or "?")
    kept -= {t.split(".")[0] for t in kept if "." in t}
    return sorted(kept), dropped


def build_guardduty(attack: dict, catalogue: dict, raw: bytes | None = None, commit: str = CTID_COMMIT,
                    release: str = CTID_RELEASE, attack_version: str = CTID_ATTACK) -> dict:
    """CTID names come out of free-text comments, so each one is checked against AWS's own finding-type catalogue: a
    name AWS never published is an extraction error and fails the build instead of becoming a silent wrong mapping."""
    url = CTID_URL.format(commit=commit, release=release, attack=attack_version)
    raw = raw if raw is not None else _fetch(url)
    bundle = json.loads(raw)
    meta = bundle["metadata"]
    if meta.get("attack_version") != attack_version:
        raise ValueError(f"release is for ATT&CK {meta.get('attack_version')}, expected {attack_version}")
    renamed = catalogue.get("renamed", {})
    known = set(catalogue["active"]) | set(catalogue["retired"])
    extracted: dict[str, set[str]] = {}
    for name, ids in parse_ctid_guardduty(bundle).items():  # CTID (2024) may use a name AWS has since renamed
        extracted.setdefault(renamed.get(name, name), set()).update(ids)
    unknown = sorted(f for f in extracted if f not in known)
    if unknown:
        raise ValueError(f"CTID names not in the AWS finding-type catalogue (extraction error?): {unknown}")
    mapping: dict[str, list[str]] = {}
    dropped: dict[str, list[str]] = {}
    for finding, ids in sorted(extracted.items()):
        kept, gone = resolve_techniques(ids, attack["techniques"])
        if kept:
            mapping[finding] = kept
        if gone:
            dropped[finding] = gone
    # a technique shared by many finding types says little about any one of them: list the specific ones first
    spread = {t: sum(t in ids for ids in mapping.values()) for ids in mapping.values() for t in ids}
    mapping = {f: sorted(ids, key=lambda t: (spread[t], t)) for f, ids in mapping.items()}
    return {"kind": "guardduty-attack-mapping", "source": url, "upstream_sha256": hashlib.sha256(raw).hexdigest(),
            "generated_at": _now(), "framework": "MITRE CTID Mappings Explorer - AWS",
            "framework_release": meta.get("mapping_framework_version"), "mapped_to_attack": attack_version,
            "resolved_against_attack": attack["attack_version"], "finding_types": mapping, "dropped": dropped,
            "renamed_by_aws": {o: n for o, n in renamed.items() if o in parse_ctid_guardduty(bundle)},
            "retired_finding_types": sorted(f for f in mapping if f in catalogue["retired"]),
            "active_types_without_mapping": sorted(f for f in catalogue["active"] if f not in mapping),
            "checked_against": catalogue["source"]}


# --------------------------------------------------------------------------- GuardDuty finding-type catalogue (AWS)
GD_TYPES_URLS = {"active": "https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html",
                 "retired": "https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-retired.html",
                 "history": "https://docs.aws.amazon.com/guardduty/latest/ug/doc-history.html"}
_RENAME_RE = re.compile(r"(" + FINDING_RE.pattern + r") has been changed to (" + FINDING_RE.pattern + r")")
_TAG_RE = re.compile(r"<[^>]+>")


def _cells(row: str) -> list[str]:
    return [" ".join(html.unescape(_TAG_RE.sub(" ", c)).split()) for c in re.findall(r"<td[^>]*>(.*?)</td>", row, re.S)]


def parse_finding_types(active_html: str, retired_html: str) -> tuple[dict[str, dict], list[str]]:
    """({type: {resource_type, data_source, severity}} from the table of the active page, [retired types])."""
    active: dict[str, dict] = {}
    for row in re.findall(r"<tr>(.*?)</tr>", active_html, re.S):
        cells = _cells(row)
        if len(cells) == 4 and FINDING_RE.fullmatch(cells[0]):
            active[cells[0]] = {"resource_type": cells[1], "data_source": cells[2], "severity": cells[3]}
    text = html.unescape(_TAG_RE.sub(" ", retired_html))
    retired = sorted({f.rstrip(".") for f in FINDING_RE.findall(text)} - set(active))
    if len(active) < 100:
        raise ValueError(f"only {len(active)} active finding types parsed: the AWS page layout changed")
    return active, retired


def parse_renames(history_html: str, active: dict) -> dict[str, str]:
    """{old: new} from the sentences "<old> has been changed to <new>" of the GuardDuty document history (only renames
    whose new name is an active type are kept)."""
    text = " ".join(html.unescape(_TAG_RE.sub(" ", history_html)).split())
    return {old: new.rstrip(".") for old, new in _RENAME_RE.findall(text) if new.rstrip(".") in active}


def build_finding_types(raw: dict[str, bytes] | None = None) -> dict:
    raw = raw or {k: _fetch(u) for k, u in GD_TYPES_URLS.items()}
    active, retired = parse_finding_types(raw["active"].decode("utf-8"), raw["retired"].decode("utf-8"))
    return {"kind": "guardduty-finding-types", "source": GD_TYPES_URLS["active"], "sources": GD_TYPES_URLS,
            "upstream_sha256": hashlib.sha256(b"".join(raw[k] for k in sorted(raw))).hexdigest(),
            "generated_at": _now(), "active": active, "retired": retired,
            "renamed": parse_renames(raw["history"].decode("utf-8"), active)}


# --------------------------------------------------------------------------- Atomic Red Team (Linux index)
ART_REF = "388942adbd9641f4dfdcf079d7efe9a75ec0ac43"  # same commit the simulation scenarios run
ART_INDEX_URL = ("https://raw.githubusercontent.com/redcanaryco/atomic-red-team/{ref}/atomics/Indexes/Indexes-CSV/"
                 "linux-index.csv")


def build_atomic(ref: str = ART_REF, raw: bytes | None = None) -> dict:
    """{test GUID: technique, test number, name, executor} for every Linux atomic at a pinned commit, so a scenario can
    not claim a technique its atomic does not belong to."""
    if not re.fullmatch(r"[0-9a-f]{40}", ref):
        raise ValueError("Atomic Red Team ref must be a full commit SHA")
    url = ART_INDEX_URL.format(ref=ref)
    raw = raw if raw is not None else _fetch(url)
    tests = {}
    for row in csv.DictReader(io.StringIO(raw.decode("utf-8"))):
        tests[row["Test GUID"]] = {"technique": row["Technique #"], "test_number": int(row["Test #"]),
                                   "name": row["Test Name"], "executor": row["Executor Name"]}
    return {"kind": "atomic-red-team-index", "ref": ref, "platform": "linux", "source": url,
            "upstream_sha256": hashlib.sha256(raw).hexdigest(), "generated_at": _now(), "tests": tests}


# --------------------------------------------------------------------------- Emerging Threats Open (managed sids)
ET_URL = "https://rules.emergingthreats.net/open/suricata-7.0.3/emerging.rules.tar.gz"
ET_VERSION_URL = "https://rules.emergingthreats.net/open/suricata-7.0.3/version.txt"
ET_LICENSE = ("sids 2000000-2799999: BSD licence, Copyright (c) 2003-2026 Emerging Threats; see LICENSE in the archive")


def parse_et_archive(raw: bytes, sids: set[int]) -> tuple[dict[int, dict], int]:
    """Text of the requested sids (whether upstream ships them enabled or commented out) + total rule count."""
    from suricata.update import rule as suricata_rule  # OISF's parser; only needed when building this snapshot

    found: dict[int, dict] = {}
    total = 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tar:
        for member in tar:
            if not (member.isfile() and member.name.endswith(".rules")):
                continue
            for line in tar.extractfile(member).read().decode("utf-8", "replace").splitlines():
                parsed = suricata_rule.parse(line) if "sid:" in line else None
                if parsed is None:
                    continue
                total += 1
                if parsed.sid in sids:
                    found[parsed.sid] = {
                        "raw": line.lstrip("# ").strip(), "enabled_upstream": bool(parsed.enabled), "msg": parsed.msg,
                        "rev": parsed.rev, "classtype": parsed.classtype, "file": member.name.rsplit("/", 1)[-1],
                        "metadata": parsed.metadata}
    missing = sorted(sids - set(found))
    if missing:
        raise ValueError(f"sids not in this ET Open release: {missing}")
    return found, total


def build_et_open(sids: set[int], raw: bytes | None = None, version: str | None = None) -> dict:
    raw = raw if raw is not None else _fetch(ET_URL)
    version = version or _fetch(ET_VERSION_URL).decode().strip()
    rules, total = parse_et_archive(raw, sids)
    return {"kind": "et-open-managed-rules", "source": ET_URL, "version": version, "license": ET_LICENSE,
            "upstream_sha256": hashlib.sha256(raw).hexdigest(), "generated_at": _now(), "upstream_rule_count": total,
            "rules": {str(s): r for s, r in sorted(rules.items())}}


def managed_et_sids(root: Path | None = None) -> set[int]:
    import yaml

    out = set()
    for path in sorted(((root or ROOT / "rules") / "metadata").glob("suricata-*.yml")):
        m = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if m.get("source") == "et-open":
            out.add(int(m["rule_id"]))
    return out


# --------------------------------------------------------------------------- loading (used by rulesctl lint)
def _latest(prefix: str, directory: Path | None = None) -> Path | None:
    files = sorted((directory or REF).glob(f"{prefix}-*.json"),
                   key=lambda p: [int(x) for x in re.findall(r"\d+", p.stem)])
    return files[-1] if files else None


def load_attack(directory: Path | None = None) -> dict | None:
    path = _latest("attack-enterprise", directory)
    return json.loads(path.read_text(encoding="utf-8")) if path else None


def load_wazuh_reference(directory: Path | None = None) -> dict | None:
    path = _latest("wazuh", directory)
    return json.loads(path.read_text(encoding="utf-8")) if path else None


def _single(name: str, directory: Path | None = None) -> dict | None:
    path = (directory or REF) / name
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def load_finding_types(directory: Path | None = None) -> dict | None:
    return _single("guardduty-finding-types.json", directory)


def load_atomic(directory: Path | None = None) -> dict | None:
    return _single("atomic-red-team-linux.json", directory)


def load_et_open(directory: Path | None = None) -> dict | None:
    return _single("et-open-managed.json", directory)


def check_snapshot(doc: dict) -> list[str]:
    errors = []
    for key in ("kind", "source", "upstream_sha256", "generated_at"):
        if not doc.get(key):
            errors.append(f"missing `{key}`")
    if doc.get("kind") == "attack-enterprise" and not doc.get("techniques"):
        errors.append("no techniques")
    if doc.get("kind") == "wazuh-ruleset" and not doc.get("rules"):
        errors.append("no rules")
    if doc.get("kind") == "guardduty-finding-types" and not doc.get("active"):
        errors.append("no active finding types")
    if doc.get("kind") == "atomic-red-team-index" and not doc.get("tests"):
        errors.append("no atomic tests")
    if doc.get("kind") == "et-open-managed-rules" and not doc.get("version"):
        errors.append("no ET Open version")
    if doc.get("kind") == "guardduty-attack-mapping":
        if not doc.get("finding_types"):
            errors.append("no finding types")
        for finding, ids in (doc.get("finding_types") or {}).items():
            if not ids or not all(TECHNIQUE_RE.match(t) for t in ids):
                errors.append(f"{finding}: bad technique list {ids}")
    return errors


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="tools.refdata")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, default in (("attack", "20.0"), ("wazuh", "4.14.8")):
        p = sub.add_parser(name)
        p.add_argument("--version", default=default)
    for name in ("guardduty", "finding-types", "atomic", "et-open", "check"):
        sub.add_parser(name)
    args = ap.parse_args(argv)

    if args.cmd == "check":
        bad = 0
        for path in [*sorted(REF.glob("*.json")), GD_SNAPSHOT]:
            problems = check_snapshot(json.loads(path.read_text(encoding="utf-8")))
            bad += bool(problems)
            print(f"{'FAIL' if problems else 'ok  '} {path.name} {'; '.join(problems)}")
        return 1 if bad or not list(REF.glob("*.json")) else 0
    simple = {"finding-types": ("guardduty-finding-types.json", build_finding_types),
              "atomic": ("atomic-red-team-linux.json", build_atomic),
              "et-open": ("et-open-managed.json", lambda: build_et_open(managed_et_sids()))}
    if args.cmd in simple:
        name, builder = simple[args.cmd]
        doc = builder()
        (REF / name).write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n", encoding="utf-8")
        print(f"wrote {REF / name}, upstream sha256 {doc['upstream_sha256'][:16]}…")
        return 0
    if args.cmd == "guardduty":
        attack, catalogue = load_attack(), load_finding_types()
        if attack is None or catalogue is None:
            ap.error("build the ATT&CK and finding-type snapshots first (refdata attack / refdata finding-types)")
        doc = build_guardduty(attack, catalogue)
        GD_SNAPSHOT.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n", encoding="utf-8")
        print(f"wrote {GD_SNAPSHOT} ({len(doc['finding_types'])} finding types, dropped: {doc['dropped'] or 'none'}), "
              f"upstream sha256 {doc['upstream_sha256'][:16]}…")
        return 0
    if not VERSION_RE.match(args.version):
        ap.error("version must look like 20.0 or 4.14.8")
    REF.mkdir(parents=True, exist_ok=True)
    doc = build_attack(args.version) if args.cmd == "attack" else build_wazuh(args.version)
    out = REF / (f"attack-enterprise-{args.version}.json" if args.cmd == "attack" else f"wazuh-{args.version}.json")
    out.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {out} ({out.stat().st_size // 1024} KiB), upstream sha256 {doc['upstream_sha256'][:16]}…")
    return 0


if __name__ == "__main__":
    sys.exit(main())
