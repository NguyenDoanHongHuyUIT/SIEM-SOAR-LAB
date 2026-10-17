"""Prove the Suricata -> Wazuh hand-off on the real engines.

  python -m tools.eve_logtest --rules dist/<sha>/suricata/siemsoar.rules [--docker-image jasonish/suricata:7.0]
                              [--url https://localhost:55000] [--user wazuh]      (password: env WAZUH_API_PASSWORD)

Why: Suricata raises the alert, but only a *Wazuh* rule decides whether it becomes a case (rulesctl build generates one
mapping rule per Suricata sid, carrying the lifecycle state and response). Suricata tests alone never touch that rule.
This tool replays every positive pcap of rules/metadata/suricata-*.yml through Suricata, takes the genuine EVE alert
events it writes, and sends them through the Wazuh logtest API (the same decoder/rule chain as production) expecting:

  * the generated Wazuh rule named by the metadata's `wazuh_rule_id` fires,
  * its groups carry `siemsoar_<state>` and `resp_<response>` from the metadata (the integration forwards only
    `siemsoar_active/enforce`, so a wrong group here would silently drop or leak alerts),
  * the MITRE ids of the alert equal the metadata.

Nothing is fabricated: the EVE lines are whatever Suricata emitted for the replayed traffic.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path

from tools import rulesctl, suricata_pcap_test
from tools.wazuh_logtest import LogtestClient

EVE_LOCATION = "master->/var/log/suricata/eve.json"


@dataclass
class Check:
    rule: str
    name: str
    ok: bool
    detail: str = ""


def expected_groups(meta: dict) -> set[str]:
    return {f"siemsoar_{meta['state']}", f"resp_{meta['response']}"}


def check_event(client, meta: dict, event: dict) -> Check:
    """Send one EVE alert through Wazuh and compare the resulting alert with the rule metadata."""
    sid = event["alert"]["signature_id"]
    mapped = rulesctl.wazuh_rule_of(meta)
    data = client.logtest(json.dumps(event, separators=(",", ":")), location=EVE_LOCATION, log_format="json",
                          close=True)
    rule = (data.get("output") or {}).get("rule") or {}
    name = f"sid {sid} -> Wazuh rule {mapped}"
    if not data.get("alert") or str(rule.get("id")) != str(mapped):
        return Check(f"suricata-{sid}", name, False, f"fired rule {rule.get('id')!r}, alert={data.get('alert')}")
    missing = expected_groups(meta) - set(rule.get("groups", []))
    if missing:
        return Check(f"suricata-{sid}", name, False, f"groups {rule.get('groups')} lack {sorted(missing)}")
    got = sorted((rule.get("mitre") or {}).get("id", []))
    if got != sorted(meta["mitre"]):
        return Check(f"suricata-{sid}", name, False, f"MITRE {got} != metadata {sorted(meta['mitre'])}")
    return Check(f"suricata-{sid}", name, True)


def run(client, suricata: suricata_pcap_test.Suricata, rules: Path, meta: dict[str, dict]) -> list[Check]:
    checks: list[Check] = []
    suri_meta = {m["rule_id"]: m for m in meta.values() if m["engine"] == "suricata"}
    positive = {(m["rule_id"], t["pcap"]) for m in suri_meta.values() for t in m["tests"] if t["expect"] == "match"}
    pcaps = suricata_pcap_test.pcap_paths({p for _, p in positive})
    events = {p: suricata_pcap_test.alert_events(suricata.replay_events(path, rules)) for p, path in pcaps.items()}
    for sid, pcap in sorted(positive):
        hits = [e for e in events[pcap] if e["alert"]["signature_id"] == sid]
        if not hits:
            checks.append(Check(f"suricata-{sid}", f"{pcap} produced an EVE alert", False, "Suricata raised nothing"))
            continue
        checks.append(check_event(client, suri_meta[sid], hits[0]))
    return checks


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="tools.eve_logtest")
    ap.add_argument("--rules", required=True, help="the BUILT suricata rules (dist/<sha>/suricata/siemsoar.rules)")
    ap.add_argument("--docker-image")
    ap.add_argument("--url", default=os.environ.get("WAZUH_API_URL", "https://localhost:55000"))
    ap.add_argument("--user", default=os.environ.get("WAZUH_API_USER", "wazuh"))
    ap.add_argument("--wait", type=float, default=0)
    args = ap.parse_args(argv)
    if not suricata_pcap_test.Suricata.available(args.docker_image):
        print("no Suricata available (install it or pass --docker-image)", file=sys.stderr)
        return 2
    client = LogtestClient(args.url, args.user, os.environ.get("WAZUH_API_PASSWORD", ""))
    if args.wait:
        client.wait_ready(args.wait)
    checks = run(client, suricata_pcap_test.Suricata(args.docker_image), Path(args.rules), rulesctl.load_metadata())
    for c in checks:
        print(f"{'PASS' if c.ok else 'FAIL'} {c.rule}: {c.name}" + ("" if c.ok else f"  ({c.detail})"))
    bad = [c for c in checks if not c.ok]
    print(f"{len(checks) - len(bad)}/{len(checks)} passed")
    return 1 if bad or not checks else 0


if __name__ == "__main__":
    sys.exit(main())
