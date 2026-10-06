"""Offline mini-engines used for fast PR feedback on detection rules.

* Wazuh: evaluates the subset of rule syntax used in this repo (if_sid, match, regex, field, program_name,
  decoded_as, srcip, frequency/timeframe/if_matched_sid/same_source_ip) against hand written events.
* Suricata: evaluates content/nocase/sticky-buffer rules against a single buffer value.

They are NOT a replacement for the real engines. The authoritative checks are `wazuh-analysisd -t` /
`wazuh-logtest` (tools/wazuh_logtest.sh) and `suricata -T` + pcap replay (tools/suricata_pcap_test.sh); this module
only catches mistakes (typos in anchors, wrong field names, accidental over-matching) before they run.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

# --------------------------------------------------------------------------- Wazuh


@dataclass
class WazuhRule:
    id: int
    level: int
    description: str = ""
    if_sid: list[int] = field(default_factory=list)
    if_matched_sid: int | None = None
    frequency: int | None = None
    timeframe: int | None = None
    same_source_ip: bool = False
    match: str | None = None
    regex: str | None = None
    program_name: str | None = None
    decoded_as: str | None = None
    srcip: str | None = None
    fields: list[tuple[str, str, bool]] = field(default_factory=list)
    mitre: list[str] = field(default_factory=list)
    groups: list[str] = field(default_factory=list)  # <group name=> of the container + rule-level <group>
    element: ET.Element | None = None
    container: ET.Element | None = None


def _ints(text: str | None) -> list[int]:
    return [int(x) for x in re.split(r"[,\s]+", (text or "").strip()) if x]


def _split_groups(text: str | None) -> list[str]:
    return [g.strip() for g in (text or "").split(",") if g.strip()]


def parse_wazuh_xml(text: str) -> dict[int, WazuhRule]:
    """Rule files are XML fragments with several top level <group> elements: wrap them in a root."""
    root = ET.fromstring(f"<root>{text}</root>")  # noqa: S314 - rule files are repo-owned, reviewed in PRs
    rules: dict[int, WazuhRule] = {}
    for container in root.findall("group"):
        cgroups = _split_groups(container.get("name"))
        for el in container.findall("rule"):
            rid = int(el.get("id"))
            if rid in rules:
                raise ValueError(f"duplicate Wazuh rule id {rid}")
            r = WazuhRule(id=rid, level=int(el.get("level", "0")), element=el, container=container,
                          frequency=int(el.get("frequency")) if el.get("frequency") else None,
                          timeframe=int(el.get("timeframe")) if el.get("timeframe") else None)
            r.description = (el.findtext("description") or "").strip()
            for sid in el.findall("if_sid"):
                r.if_sid += _ints(sid.text)
            ims = el.findtext("if_matched_sid")
            r.if_matched_sid = int(ims) if ims else None
            r.same_source_ip = el.find("same_source_ip") is not None
            r.match = el.findtext("match")
            r.regex = el.findtext("regex")
            r.program_name = el.findtext("program_name")
            r.decoded_as = el.findtext("decoded_as")
            r.srcip = el.findtext("srcip")
            for f in el.findall("field"):
                r.fields.append((f.get("name"), f.text or "", f.get("negate") == "yes"))
            r.mitre = [(i.text or "").strip() for i in el.findall("mitre/id")]
            r.groups = cgroups + _split_groups(el.findtext("group"))
            rules[rid] = r
    return rules


def os_match(pattern: str, text: str) -> bool:
    """Wazuh <match> (OS_Match): alternatives with '|', optional ^ and $ anchors, otherwise a plain substring."""
    for alt in re.split(r"(?<!\\)\|", pattern):
        alt = alt.replace("\\|", "|")
        anchored_start, anchored_end = alt.startswith("^"), alt.endswith("$") and not alt.endswith("\\$")
        core = alt[1 if anchored_start else 0 : -1 if anchored_end else None]
        if anchored_start and anchored_end and text == core:
            return True
        if anchored_start and not anchored_end and text.startswith(core):
            return True
        if anchored_end and not anchored_start and text.endswith(core):
            return True
        if not anchored_start and not anchored_end and core in text:
            return True
    return False


def _wazuh_regex(pattern: str, text: str) -> bool:
    """OS_Regex tokens \\p (punctuation) and friends are translated to Python's re."""
    translated = pattern.replace("\\p", "[\\x21-\\x2f\\x3a-\\x40\\x5b-\\x60\\x7b-\\x7e]")
    return re.search(translated, text) is not None


def eval_event(rule: WazuhRule, event: dict, ruleset: dict[int, WazuhRule]) -> bool:
    """Does `rule` fire for one event? event keys: decoder, parents, program_name, full_log, fields."""
    parents = set(event.get("parents", []))
    if rule.if_sid and not any(s in parents or (s in ruleset and eval_event(ruleset[s], event, ruleset))
                               for s in rule.if_sid):
        return False
    if rule.decoded_as and event.get("decoder") != rule.decoded_as:
        return False
    log, fields = event.get("full_log", ""), event.get("fields", {})
    if rule.program_name and not _wazuh_regex(rule.program_name, event.get("program_name", "")):
        return False
    if rule.match and not os_match(rule.match, log):
        return False
    if rule.regex and not _wazuh_regex(rule.regex, log):
        return False
    if rule.srcip and fields.get("srcip") != rule.srcip:
        return False
    for name, pattern, negate in rule.fields:
        value = fields.get(name)
        if value is None:
            return False
        if _wazuh_regex(pattern, str(value)) == negate:
            return False
    return True


def eval_sequence(rule: WazuhRule, events: list[dict], ruleset: dict[int, WazuhRule]) -> bool:
    """Frequency rules: enough events matching `if_matched_sid` within `timeframe` seconds (same source ip)."""
    if not (rule.frequency and rule.timeframe and rule.if_matched_sid):
        return bool(events) and eval_event(rule, events[-1], ruleset)
    base = rule.if_matched_sid

    def counts(event: dict) -> bool:
        return base in event.get("parents", []) or (base in ruleset and eval_event(ruleset[base], event, ruleset))

    hits = [e for e in events if counts(e)]
    groups: dict[str, list[dict]] = {}
    for e in hits:
        key = str(e.get("fields", {}).get("srcip")) if rule.same_source_ip else "*"
        groups.setdefault(key, []).append(e)
    for group in groups.values():
        times = sorted(e.get("t", 0) for e in group)
        for i, start in enumerate(times):
            if sum(1 for t in times[i:] if t - start <= rule.timeframe) >= rule.frequency:
                return True
    return False


def run_wazuh_test(rule: WazuhRule, test: dict, ruleset: dict[int, WazuhRule]) -> tuple[bool, str]:
    if "events" in test:
        fired = eval_sequence(rule, test["events"], ruleset)
    elif "event" in test:
        fired = eval_event(rule, test["event"], ruleset) if not rule.frequency else False
    else:
        return False, "test needs `event` or `events`"
    want = test["expect"] == "match"
    return fired == want, f"expected {test['expect']}, rule {'fired' if fired else 'did not fire'}"


# --------------------------------------------------------------------------- Suricata


@dataclass
class SuricataContent:
    buffer: str
    value: bytes
    nocase: bool = False
    negated: bool = False


@dataclass
class SuricataRule:
    action: str
    proto: str
    sid: int
    rev: int
    msg: str
    classtype: str | None
    contents: list[SuricataContent]
    raw: str
    options: list[tuple[str, str | None]]


RULE_RE = re.compile(r"^(?P<action>\w+)\s+(?P<proto>\S+)\s+(?P<src>.+?)\s*(?P<dir>->|<>)\s*(?P<dst>.+?)\s*\((?P<opts>.*)\)\s*$")
STICKY = {"http.uri", "http.uri.raw", "http.user_agent", "http.host", "http.method", "http.header", "http.cookie",
          "http.request_body", "http.stat_code", "dns.query", "tls.sni", "file.data", "pkt_data"}


def _split_options(opts: str) -> list[str]:
    out, cur, quoted, esc = [], [], False, False
    for ch in opts:
        if esc:
            cur.append(ch)
            esc = False
        elif ch == "\\":
            cur.append(ch)
            esc = True
        elif ch == '"':
            quoted = not quoted
            cur.append(ch)
        elif ch == ";" and not quoted:
            out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if "".join(cur).strip():
        out.append("".join(cur).strip())
    return out


def _decode_content(raw: str) -> bytes:
    raw = raw.strip()
    if raw.startswith('"') and raw.endswith('"'):
        raw = raw[1:-1]
    out, i = bytearray(), 0
    while i < len(raw):
        if raw[i] == "|":
            j = raw.index("|", i + 1)
            out += bytes.fromhex(raw[i + 1 : j].replace(" ", ""))
            i = j + 1
        elif raw[i] == "\\" and i + 1 < len(raw):
            out.append(ord(raw[i + 1]))
            i += 2
        else:
            out.append(ord(raw[i]))
            i += 1
    return bytes(out)


def parse_suricata_rule(line: str) -> SuricataRule:
    m = RULE_RE.match(line.strip())
    if not m:
        raise ValueError(f"cannot parse suricata rule: {line[:80]}")
    options: list[tuple[str, str | None]] = []
    for opt in _split_options(m.group("opts")):
        key, _, val = opt.partition(":")
        options.append((key.strip(), val.strip() if _ else None))
    contents, buffer, last = [], "payload", None
    for key, val in options:
        if key in STICKY:
            buffer = key
        elif key == "content":
            negated = bool(val and val.lstrip().startswith("!"))
            c = SuricataContent(buffer, _decode_content(val.lstrip("! ")), negated=negated)
            contents.append(c)
            last = c
        elif key == "nocase" and last:
            last.nocase = True
    get = lambda k: next((v for kk, v in options if kk == k), None)  # noqa: E731
    msg = (get("msg") or "").strip('"')
    return SuricataRule(m.group("action"), m.group("proto"), int(get("sid") or 0), int(get("rev") or 0), msg,
                        get("classtype"), contents, line.strip(), options)


def parse_suricata_rules(text: str) -> dict[int, SuricataRule]:
    rules: dict[int, SuricataRule] = {}
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        rule = parse_suricata_rule(line)
        if rule.sid in rules:
            raise ValueError(f"duplicate suricata sid {rule.sid}")
        rules[rule.sid] = rule
    return rules


def run_suricata_test(rule: SuricataRule, test: dict) -> tuple[bool, str]:
    payloads = test.get("payloads") or [test["payload"]]
    fired = bool(rule.contents)
    for c in rule.contents:
        values = [p["value"] for p in payloads if p["buffer"] == c.buffer]
        found = any((c.value.lower() in v.encode().lower()) if c.nocase else (c.value in v.encode()) for v in values)
        if found == c.negated:
            fired = False
            break
    want = test["expect"] == "match"
    return fired == want, f"expected {test['expect']}, rule {'fired' if fired else 'did not fire'}"
