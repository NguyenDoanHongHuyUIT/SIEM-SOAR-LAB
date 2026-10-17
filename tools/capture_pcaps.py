"""Capture the pcaps the Suricata rule tests replay, from REAL tool executions (no packet is hand-crafted).

  python -m tools.capture_pcaps [--only t1046_nmap_syn_scan] [--out rules/pcaps]

Each capture runs an attack procedure inside a throw-away Docker network while tcpdump records the attacker's interface:

  * attacker: nicolaka/netshoot (nmap, curl, telnet, nc, tcpdump), target: nginx (a real HTTP server)
  * atomic procedures are the Atomic Red Team test of the pinned commit (refdata.ART_REF), fetched from GitHub and
    rendered with their own `#{input}` substitution. The only changes, recorded in provenance.json, are: a leading
    `sudo` is dropped (the container already runs as root) and every command line runs under `timeout` with stdin
    closed (telnet/nc would otherwise wait for input forever).
  * benign procedures are ordinary client commands, listed verbatim in this file.

provenance.json records for every pcap: the procedure (ATT&CK technique + test GUID, or "benign"), the exact command
lines executed, the Docker image digests, the tool versions reported by the container and the SHA-256 of the pcap.
`tests/unit/test_pcaps.py` checks that the committed files still match it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shlex
import subprocess
import sys
import tempfile
import time
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

import yaml

from tools import refdata

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "rules" / "pcaps"
ATTACKER_IMAGE = "nicolaka/netshoot:v0.13"
TARGET_IMAGE = "nginx:1.27-alpine"
NETWORK = "siemsoar-capture"
ART_YAML = "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/{ref}/atomics/{t}/{t}.yaml"
LINE_TIMEOUT = 15

# name -> procedure. {target} is replaced by the target container's IP address.
CAPTURES: dict[str, dict] = {
    "t1046_nmap_syn_scan.pcap": {
        "atomic": {"technique": "T1046", "test_guid": "515942b0-a09f-4163-a7bb-22fefb6f185f",
                   "args": {"host": "{target}", "port": "80", "network_range": "{target}/32"}}},
    "t1071_001_malicious_user_agents.pcap": {
        "atomic": {"technique": "T1071.001", "test_guid": "2d7c471a-e887-4b78-b0dc-b0df1f2e0658",
                   "args": {"domain": "{target}"}}},
    "benign_http_clients.pcap": {
        "benign": "an administrator checks a web server with curl and wget (default user agents)",
        "commands": ["curl -s -m3 http://{target}/", "curl -s -m3 http://{target}/index.html",
                     "wget -q -T3 -O /dev/null http://{target}/"]},
}


def fetch_atomic(technique: str, guid: str, ref: str = refdata.ART_REF) -> dict:
    """The atomic test with this GUID, from the pinned commit; refuses a GUID filed under another technique."""
    with urllib.request.urlopen(ART_YAML.format(ref=ref, t=technique), timeout=60) as resp:  # noqa: S310 (fixed host)
        doc = yaml.safe_load(resp.read())
    for test in doc["atomic_tests"]:
        if test["auto_generated_guid"] == guid:
            return test
    raise ValueError(f"{guid} is not a test of {technique} at {ref}")


def render_atomic(test: dict, args: dict[str, str]) -> list[str]:
    """Executor command with Atomic Red Team's `#{name}` substitution (explicit args, else the test's defaults)."""
    values = {k: str(v.get("default", "")) for k, v in (test.get("input_arguments") or {}).items()}
    unknown = set(args) - set(values)
    if unknown:
        raise ValueError(f"not input arguments of {test['name']!r}: {sorted(unknown)}")
    values.update(args)
    command = re.sub(r"#\{(\w+)\}", lambda m: values[m.group(1)], test["executor"]["command"])
    return [line.strip() for line in command.splitlines() if line.strip()]


def contained(line: str) -> str:
    """The documented adaptation for a root container: drop a leading sudo, bound the runtime, close stdin."""
    line = re.sub(r"^sudo\s+", "", line)
    return f"timeout {LINE_TIMEOUT} sh -c {shlex.quote(line)} </dev/null || true"


def _docker(*args: str, check: bool = True) -> str:
    return subprocess.run(["docker", *args], capture_output=True, text=True, check=check).stdout.strip()


def _digest(image: str) -> str:
    return _docker("image", "inspect", "-f", "{{index .RepoDigests 0}}", image)


def capture(name: str, spec: dict, out: Path) -> dict:
    _docker("rm", "-f", "cap-target", "cap-attacker", check=False)
    _docker("network", "create", NETWORK, check=False)
    try:
        _docker("run", "-d", "--name", "cap-target", "--network", NETWORK, TARGET_IMAGE)
        _docker("run", "-d", "--name", "cap-attacker", "--network", NETWORK, "--cap-add", "NET_RAW", "--cap-add",
                "NET_ADMIN", ATTACKER_IMAGE, "sleep", "600")
        target = _docker("inspect", "-f", "{{(index .NetworkSettings.Networks \"" + NETWORK + "\").IPAddress}}",
                         "cap-target")
        time.sleep(2)  # nginx up
        if "atomic" in spec:
            a = spec["atomic"]
            test = fetch_atomic(a["technique"], a["test_guid"])
            lines = render_atomic(test, {k: v.replace("{target}", target) for k, v in a["args"].items()})
            procedure = {"atomic_red_team": {"technique": a["technique"], "test_guid": a["test_guid"],
                                             "test_name": test["name"], "ref": refdata.ART_REF,
                                             "args": a["args"]}}
        else:
            lines = [c.replace("{target}", target) for c in spec["commands"]]
            procedure = {"benign": spec["benign"]}
        executed = [contained(line) for line in lines]
        script = "; ".join(["tcpdump -i eth0 -Z root -U -w /tmp/cap.pcap 2>/dev/null & P=$!", "sleep 2", *executed,
                            "sleep 2", "kill $P", "sleep 1"])
        _docker("exec", "cap-attacker", "sh", "-c", script)
        with tempfile.TemporaryDirectory() as tmp:
            _docker("cp", "cap-attacker:/tmp/cap.pcap", str(Path(tmp) / name))
            data = (Path(tmp) / name).read_bytes()
        (out / name).write_bytes(data)
        versions = _docker("exec", "cap-attacker", "sh", "-c",
                           "nmap --version | head -1; curl --version | head -1; tcpdump --version 2>&1 | head -1")
        return {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data),
                "captured_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"), "procedure": procedure,
                "commands_run": executed, "target_ip": target,
                "images": {"attacker": _digest(ATTACKER_IMAGE), "target": _digest(TARGET_IMAGE)},
                "tool_versions": versions.splitlines()}
    finally:
        _docker("rm", "-f", "cap-target", "cap-attacker", check=False)
        _docker("network", "rm", NETWORK, check=False)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="tools.capture_pcaps")
    ap.add_argument("--only", action="append")
    ap.add_argument("--out", default=str(OUT))
    args = ap.parse_args(argv)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    prov_path = out / "provenance.json"
    provenance = json.loads(prov_path.read_text(encoding="utf-8")) if prov_path.exists() else {}
    for pull in (ATTACKER_IMAGE, TARGET_IMAGE):
        _docker("pull", "-q", pull)
    for name, spec in CAPTURES.items():
        if args.only and name not in args.only:
            continue
        provenance[name] = capture(name, spec, out)
        print(f"captured {name}: {provenance[name]['bytes']} bytes, sha256 {provenance[name]['sha256'][:16]}…")
    prov_path.write_text(json.dumps(provenance, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
