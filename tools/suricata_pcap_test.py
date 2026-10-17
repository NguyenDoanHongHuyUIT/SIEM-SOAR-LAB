"""Authoritative Suricata check: syntax test + pcap replay of every metadata test.

  python -m tools.suricata_pcap_test [--rules rules/suricata/siemsoar.rules] [--config /etc/suricata/suricata.yaml]
                                     [--docker-image jasonish/suricata:7.0]

Runs on the real Suricata: either a local `suricata` binary or, when no binary is installed (Windows/macOS dev boxes), the
official `jasonish/suricata` container. Each rules/metadata/suricata-*.yml test names a pcap in rules/pcaps and
`expect: match|no_match`: the rule's sid must (not) alert when that pcap is replayed. Every pcap is replayed once.

The pcaps are captures of real tool executions (tools/capture_pcaps.py; procedure, commands, image digests and SHA-256
in rules/pcaps/provenance.json), checked against their recorded hash before use. Pass the BUILT rules file: it holds
both local rules and the pinned text of the managed ET Open rules.

Benign captures (procedure "benign") must not raise an alert of a rule in state active/enforce: such an alert would
become a case. Shadow rules may fire on them; that measured false positive is what keeps them in shadow.

The sensor runs Suricata with EXTERNAL_NET = any (suricata/bootstrap_sensor.sh) so that traffic between lab hosts is
inspected by $EXTERNAL_NET -> $HOME_NET rules; the replay uses the same setting (SENSOR_VARS).

The EVE alert events produced here are the real thing Wazuh later receives; `tools.eve_logtest` feeds them to the Wazuh
engine to prove the Suricata -> Wazuh mapping rules fire.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from tools import rulesctl

ROOT = Path(__file__).resolve().parent.parent
PCAP_DIR = ROOT / "rules" / "pcaps"
DEFAULT_CONFIG = "/etc/suricata/suricata.yaml"
# address groups the sensor overrides in suricata.yaml (bootstrap_sensor.sh applies exactly these)
SENSOR_VARS = {"vars.address-groups.EXTERNAL_NET": "any"}


class Suricata:
    """A Suricata invocation: local binary, or the official container with the work directory mounted at /work."""

    def __init__(self, image: str | None = None, config: str = DEFAULT_CONFIG):
        self.image, self.config = image, config
        if image is None and not shutil.which("suricata"):
            raise FileNotFoundError("suricata binary not found (apt install suricata) and no --docker-image given")

    @staticmethod
    def available(image: str | None = None) -> bool:
        return bool(image) or bool(shutil.which("suricata"))

    def _run(self, work: Path, args: list[str]) -> subprocess.CompletedProcess:
        if self.image:  # paths in args are relative to /work
            cmd = ["docker", "run", "--rm", "-v", f"{work.resolve()}:/work", "-w", "/work", self.image, *args]
        else:
            cmd = ["suricata", *args]
        return subprocess.run(cmd, cwd=work, capture_output=True, text=True, check=False)

    def _vars(self) -> list[str]:
        return [arg for k, v in SENSOR_VARS.items() for arg in ("--set", f"{k}={v}")]

    def syntax_test(self, rules: Path) -> subprocess.CompletedProcess:
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            shutil.copy(rules, work / "rules.rules")
            return self._run(work, ["-T", "-c", self.config, "-S", "rules.rules", *self._vars()])

    def replay_events(self, pcap: Path, rules: Path) -> list[dict]:
        """Every EVE event Suricata writes when `pcap` is replayed against `rules`."""
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            shutil.copy(rules, work / "rules.rules")
            shutil.copy(pcap, work / "in.pcap")
            (work / "log").mkdir()
            res = self._run(work, ["-c", self.config, "-S", "rules.rules", "-r", "in.pcap", "-l", "log", "-k", "none",
                                   "--runmode", "single", *self._vars()])
            if res.returncode:
                raise RuntimeError(f"suricata replay failed ({res.returncode}): {res.stderr[-600:]}")
            eve = work / "log" / "eve.json"
            return [json.loads(line) for line in eve.read_text().splitlines()] if eve.exists() else []


def alert_events(events: list[dict], sids: set[int] | None = None) -> list[dict]:
    """EVE alert events, optionally only those of `sids` (the rules the metadata manages)."""
    return [e for e in events if e.get("event_type") == "alert"
            and (sids is None or e["alert"]["signature_id"] in sids)]


def replay(pcap: Path, rules: Path, config: str = DEFAULT_CONFIG, image: str | None = None) -> set[int]:
    """Sids that alert when `pcap` is replayed through Suricata with `rules`."""
    return {e["alert"]["signature_id"] for e in alert_events(Suricata(image, config).replay_events(pcap, rules))}


def provenance() -> dict:
    path = PCAP_DIR / "provenance.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def pcap_paths(names: set[str]) -> dict[str, Path]:
    """The committed captures, refusing any whose bytes no longer match provenance.json."""
    prov, out = provenance(), {}
    for name in sorted(names):
        path = PCAP_DIR / name
        if name not in prov or not path.exists():
            raise FileNotFoundError(f"{name}: not a captured pcap (run python -m tools.capture_pcaps)")
        if hashlib.sha256(path.read_bytes()).hexdigest() != prov[name]["sha256"]:
            raise ValueError(f"{name}: content differs from rules/pcaps/provenance.json")
        out[name] = path
    return out


def run_tests(rules: Path, config: str = DEFAULT_CONFIG, meta: dict[str, dict] | None = None,
              image: str | None = None) -> list[tuple[str, str, bool, str]]:
    """[(rule, test name, ok, detail)] for every Suricata metadata test plus the benign-traffic guard."""
    meta = meta if meta is not None else rulesctl.load_metadata()
    prov = provenance()
    benign = {n for n, p in prov.items() if "benign" in (p.get("procedure") or {})}
    wanted = {t["pcap"] for m in meta.values() if m["engine"] == "suricata" for t in m["tests"]} | benign
    try:
        pcaps = pcap_paths(wanted)
    except (FileNotFoundError, ValueError) as err:
        return [("-", "pcap provenance", False, str(err))]
    alerts = {name: replay(path, rules, config, image) for name, path in pcaps.items()}
    results = []
    for mid, m in sorted(meta.items()):
        if m["engine"] != "suricata":
            continue
        for t in m["tests"]:
            fired = m["rule_id"] in alerts[t["pcap"]]
            results.append((mid, t["name"], fired == (t["expect"] == "match"),
                            f"{t['pcap']}: alerts={sorted(alerts[t['pcap']])}, expected {t['expect']}"))
    live = {int(m["rule_id"]) for m in meta.values() if m["engine"] == "suricata"
            and m["state"] in ("active", "enforce")}
    for name in sorted(benign):
        hits = sorted(alerts[name] & live)
        results.append(("benign", f"{name} raises no alert of an active/enforce rule", not hits, f"alerts={hits}"))
    return results


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rules", required=True, help="the BUILT rules file (dist/<sha>/suricata/siemsoar.rules)")
    ap.add_argument("--config", default=DEFAULT_CONFIG)
    ap.add_argument("--docker-image", help="run the official Suricata container instead of a local binary")
    args = ap.parse_args(argv)
    if not Suricata.available(args.docker_image):
        print("suricata binary not found (apt install suricata, or pass --docker-image jasonish/suricata:7.0)",
              file=sys.stderr)
        return 2
    rules = Path(args.rules)
    syntax = Suricata(args.docker_image, args.config).syntax_test(rules)
    if syntax.returncode:
        print(syntax.stdout[-2000:], syntax.stderr[-2000:])
        print("FAIL suricata -T (rule syntax)")
        return 1
    print("PASS suricata -T")
    results = run_tests(rules, args.config, image=args.docker_image)
    for rule, name, ok, detail in results:
        print(f"{'PASS' if ok else 'FAIL'} {rule}: {name}" + ("" if ok else f"  ({detail})"))
    failed = [r for r in results if not r[2]]
    print(f"{len(results) - len(failed)}/{len(results)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
