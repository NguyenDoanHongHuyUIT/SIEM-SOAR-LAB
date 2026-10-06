"""Authoritative Suricata check: syntax test + pcap replay against the rule file (needs a suricata binary).

  python -m tools.suricata_pcap_test [--rules rules/suricata/siemsoar.rules] [--config /etc/suricata/suricata.yaml]

For every rules/metadata/suricata-*.yml that declares `pcap: {file, expect_sids}` it replays the generated pcap
and requires exactly those SIEMSOAR sids to alert; `benign.pcap` must raise no SIEMSOAR alert at all.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from tools import make_pcaps, rulesctl

ROOT = Path(__file__).resolve().parent.parent


def replay(pcap: Path, rules: Path, config: str) -> set[int]:
    with tempfile.TemporaryDirectory() as logdir:
        subprocess.run(["suricata", "-c", config, "-S", str(rules), "-r", str(pcap), "-l", logdir, "-k", "none",
                        "--runmode", "single"], check=True, capture_output=True, text=True)
        eve = Path(logdir) / "eve.json"
        sids = set()
        if eve.exists():
            for line in eve.read_text().splitlines():
                ev = json.loads(line)
                if ev.get("event_type") == "alert":
                    sids.add(ev["alert"]["signature_id"])
        return {s for s in sids if 9000000 <= s < 9100000}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rules", default=str(ROOT / "rules/suricata/siemsoar.rules"))
    ap.add_argument("--config", default="/etc/suricata/suricata.yaml")
    args = ap.parse_args(argv)
    if not shutil.which("suricata"):
        print("suricata binary not found (apt install suricata / use the jasonish/suricata image)", file=sys.stderr)
        return 2
    rules = Path(args.rules)
    syntax = subprocess.run(["suricata", "-T", "-c", args.config, "-S", str(rules)], capture_output=True, text=True)
    if syntax.returncode:
        print(syntax.stdout[-2000:], syntax.stderr[-2000:])
        print("FAIL suricata -T (rule syntax)")
        return 1
    print("PASS suricata -T")

    failures = 0
    with tempfile.TemporaryDirectory() as tmp:
        pcaps = Path(tmp)
        for name, make in make_pcaps.PCAPS.items():
            make_pcaps.write_pcap(pcaps / name, make())
        expectations = {m["pcap"]["file"]: set(m["pcap"]["expect_sids"])
                        for m in rulesctl.load_metadata().values() if m.get("pcap")}
        expectations.setdefault("benign.pcap", set())
        for name, expected in sorted(expectations.items()):
            got = replay(pcaps / name, rules, args.config)
            ok = got == expected
            failures += not ok
            print(f"{'PASS' if ok else 'FAIL'} {name}: alerts={sorted(got)} expected={sorted(expected)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
