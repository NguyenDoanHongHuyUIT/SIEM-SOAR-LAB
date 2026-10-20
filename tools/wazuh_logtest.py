"""Run the Wazuh rule tests on the REAL Wazuh analysis engine (the same code as `wazuh-analysisd`).

  python -m tools.wazuh_logtest [--url https://localhost:55000] [--user wazuh] [--container wazuh] [--strict] [--wait 180]
  (password: env WAZUH_API_PASSWORD)

The whole chain decoder -> parent rule -> custom rule -> frequency/timeframe is exercised exactly as in production.
Two kinds of metadata tests (rules/metadata/wazuh-*.yml):

  * raw logs, through the logtest API (`PUT /logtest`, also what `wazuh-logtest` uses):

      - name: six ssh failures from one source
        expect: match                 # the rule under test must fire on the LAST line
        logs:                         # `log: "<line>"` for a single line
          - "Oct  7 10:00:00 host sshd[1]: Failed password for root from 10.0.1.99 port 4000 ssh2"
          - ...
        # optional: location (default master->/var/log/syslog), log_format (default syslog)

  * file-integrity events: `fim: {path: /etc/passwd, type: modified|added}`. Syscheck events never go through logtest
    (they use a dedicated analysisd path), so they are written to analysisd's queue socket inside the manager
    container (`--container`, via `docker exec`) and the resulting alert is read back from alerts.json.
    `fim: {..., audit: {process_name: /usr/bin/dpkg, ...}}` sends a who-data event (`mode: whodata`): the `audit`
    object is the agent's, keys as parsed by src/analysisd/decoders/syscheck.c (user_name, process_name, parent_name,
    ppid, process_id, ...); rules see them as fields of the same names.

Each logtest test opens a fresh session (no token on the first request), so `firedtimes`/frequency state never leaks
between tests; the session is closed afterwards. `no_match` means the rule never fires on any line. Wazuh counts
frequency by arrival time, so timing-based cases (events spread over the timeframe) cannot be replayed here.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass

import requests
import urllib3

DEFAULT_LOCATION = "master->/var/log/syslog"


class LogtestError(RuntimeError):
    pass


class LogtestClient:
    """Thin client for the Wazuh server API logtest endpoints (JWT auth, self-signed TLS accepted).

    `verify` is passed on every request: a session-level `verify=False` is silently overridden by REQUESTS_CA_BUNDLE.
    """

    def __init__(self, url: str, user: str, password: str, verify: bool = False, session: requests.Session | None = None):
        self.url, self.user, self.password = url.rstrip("/"), user, password
        self.http, self.verify = session or requests.Session(), verify
        if not verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self._jwt: str | None = None

    def _auth(self) -> dict:
        if self._jwt is None:
            res = self.http.post(f"{self.url}/security/user/authenticate", params={"raw": "true"},
                                 auth=(self.user, self.password), timeout=15, verify=self.verify)
            if res.status_code != 200:
                raise LogtestError(f"authentication failed: HTTP {res.status_code}")
            self._jwt = res.text.strip()
        return {"Authorization": f"Bearer {self._jwt}"}

    def wait_ready(self, timeout: float = 180, interval: float = 3) -> None:
        """The manager container needs a while to start analysisd and the API."""
        end, last = time.time() + timeout, "not tried"
        while time.time() < end:
            try:
                self.logtest("Oct  7 10:00:00 ready sshd[1]: probe", token=None, close=True)
                return
            except (requests.RequestException, LogtestError) as err:
                last, self._jwt = str(err), None
                time.sleep(interval)
        raise LogtestError(f"Wazuh API not ready after {timeout:.0f}s: {last}")

    def logtest(self, event: str, token: str | None = None, location: str = DEFAULT_LOCATION,
                log_format: str = "syslog", close: bool = False) -> dict:
        body: dict = {"event": event, "log_format": log_format, "location": location}
        if token:
            body["token"] = token
        res = self.http.put(f"{self.url}/logtest", json=body, headers=self._auth(), timeout=30, verify=self.verify)
        if res.status_code != 200:
            raise LogtestError(f"logtest HTTP {res.status_code}: {res.text[:300]}")
        data = res.json()["data"]
        if close:
            self.close_session(data["token"])
        return data

    def close_session(self, token: str | None) -> None:
        if token:
            self.http.delete(f"{self.url}/logtest/sessions/{token}", headers=self._auth(), timeout=15, verify=self.verify)


# Runs inside the manager container with Wazuh's embedded Python: queue one syscheck event for analysisd, then wait
# for the alert it produces (one alert per event: the most specific rule that matched) and print that rule id.
_FIM_SCRIPT = r"""
import json, os, socket, sys, time
path, kind, audit = sys.argv[1], sys.argv[2], json.loads(sys.argv[3])
alerts_file = "/var/ossec/logs/alerts/alerts.json"
offset = os.path.getsize(alerts_file) if os.path.exists(alerts_file) else 0
attrs = {"type": "file", "size": 1200, "perm": "rw-r--r--", "uid": "0", "gid": "0", "user_name": "root",
         "group_name": "root", "inode": 123, "mtime": 1760000000, "hash_md5": "a" * 32, "hash_sha1": "b" * 40,
         "hash_sha256": "c" * 64, "checksum": "d" * 40}
data = {"path": path, "mode": "whodata" if audit else "realtime", "type": kind, "timestamp": int(time.time()),
        "attributes": attrs}
if audit:
    data["audit"] = audit
if kind == "modified":
    data["changed_attributes"] = ["size", "mtime", "md5", "sha1", "sha256"]
    data["old_attributes"] = {**attrs, "size": 1100, "hash_md5": "e" * 32}
sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
sock.connect("/var/ossec/queue/sockets/queue")
sock.send(("8:syscheck:" + json.dumps({"type": "event", "data": data})).encode())
end = time.time() + 20
while time.time() < end:
    time.sleep(0.5)
    try:
        with open(alerts_file, "rb") as fh:
            fh.seek(offset)
            chunk = fh.read()
    except FileNotFoundError:
        continue
    # analysisd may be half-way through writing an alert: only consume complete lines, re-read the rest next time
    complete, newline, _ = chunk.rpartition(b"\n")
    if not newline:
        continue
    offset += len(complete) + 1
    for line in complete.split(b"\n"):
        try:
            alert = json.loads(line)
        except ValueError:
            continue
        if alert.get("syscheck", {}).get("path") == path:
            print(alert["rule"]["id"])
            sys.exit(0)
sys.exit(3)
"""


class FimQueue:
    """Injects syscheck events into a manager running in a container (`docker exec`)."""

    def __init__(self, container: str):
        self.container = container

    def rule_for(self, path: str, kind: str = "modified", audit: dict | None = None) -> str | None:
        """Id of the rule that alerted for a FIM event on `path`, None if no alert was produced in time.
        `audit` (who-data: the process that wrote the file) makes it a who-data event."""
        res = subprocess.run(["docker", "exec", "-i", self.container, "/var/ossec/framework/python/bin/python3", "-",
                              path, kind, json.dumps(audit or {})], input=_FIM_SCRIPT, capture_output=True, text=True,
                             timeout=60)
        if res.returncode == 3:
            return None
        if res.returncode:
            raise LogtestError(f"fim injection failed: {res.stderr[-300:]}")
        return res.stdout.strip()


@dataclass
class Result:
    rule: str
    test: str
    status: str  # PASS | FAIL | SKIP
    detail: str = ""


def lines_of(test: dict) -> list[str]:
    if "logs" in test:
        return [str(x) for x in test["logs"]]
    return [str(test["log"])] if "log" in test else []


def run_sample(client, rule_id: int | str, test: dict) -> tuple[bool, str]:
    """True when the outcome equals `expect`. `match`: the rule fires on the last line; `no_match`: never fires."""
    lines = lines_of(test)
    token, fired_at = None, []
    try:
        for i, line in enumerate(lines):
            data = client.logtest(line, token=token, location=test.get("location", DEFAULT_LOCATION),
                                  log_format=test.get("log_format", "syslog"))
            token = data["token"]
            rule = (data.get("output") or {}).get("rule") or {}
            if data.get("alert") and str(rule.get("id")) == str(rule_id):
                fired_at.append(i)
    finally:
        client.close_session(token)
    if test["expect"] == "match":
        ok = bool(fired_at) and fired_at[-1] == len(lines) - 1
    else:
        ok = not fired_at
    return ok, f"rule {rule_id} fired on line(s) {[n + 1 for n in fired_at] or 'none'} of {len(lines)}"


def run_fim(fim: FimQueue, rule_id: int | str, test: dict) -> tuple[bool, str]:
    spec = test["fim"]
    fired = fim.rule_for(spec["path"], spec.get("type", "modified"), spec.get("audit"))
    ok = (fired == str(rule_id)) == (test["expect"] == "match")
    who = f" written by {spec['audit'].get('process_name')}" if spec.get("audit") else ""
    return ok, f"FIM event on {spec['path']}{who} alerted with rule {fired or 'none'}"


def run_all(client, meta: dict[str, dict], fim: FimQueue | None = None) -> list[Result]:
    results: list[Result] = []
    for mid, m in sorted(meta.items()):
        if m.get("engine") != "wazuh":
            continue
        for t in m.get("tests", []) or []:
            name = t.get("name", "?")
            if lines_of(t):
                ok, detail = run_sample(client, m["rule_id"], t)
            elif "fim" in t and fim is None:
                results.append(Result(mid, name, "SKIP", "FIM test needs --container (manager running in docker)"))
                continue
            elif "fim" in t:
                ok, detail = run_fim(fim, m["rule_id"], t)
            else:
                results.append(Result(mid, name, "FAIL", "test has neither log(s) nor fim"))
                continue
            results.append(Result(mid, name, "PASS" if ok else "FAIL", "" if ok else detail))
    return results


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="tools.wazuh_logtest")
    ap.add_argument("--url", default=os.environ.get("WAZUH_API_URL", "https://localhost:55000"))
    ap.add_argument("--user", default=os.environ.get("WAZUH_API_USER", "wazuh"))
    ap.add_argument("--wait", type=float, default=0, help="seconds to wait for the API to come up")
    ap.add_argument("--container", help="manager container name: enables the FIM tests (docker exec)")
    ap.add_argument("--strict", action="store_true",
                    help="fail when a test of an active/enforce rule was skipped (it never ran on the engine)")
    args = ap.parse_args(argv)

    from tools import rulesctl  # local import: keeps this module importable without PyYAML in unit tests

    client = LogtestClient(args.url, args.user, os.environ.get("WAZUH_API_PASSWORD", ""))
    if args.wait:
        client.wait_ready(args.wait)
    meta = rulesctl.load_metadata()
    results = run_all(client, meta, FimQueue(args.container) if args.container else None)
    for r in results:
        print(f"{r.status} {r.rule}: {r.test}" + (f"  ({r.detail})" if r.detail else ""))
    failed = [r for r in results if r.status == "FAIL"]
    strict_skips = [r for r in results if r.status == "SKIP" and meta[r.rule]["state"] in ("active", "enforce")]
    print(f"{sum(r.status == 'PASS' for r in results)} passed, {len(failed)} failed, "
          f"{sum(r.status == 'SKIP' for r in results)} skipped")
    if args.strict and strict_skips:
        print("strict: tests of active/enforce rules never executed on the real engine: "
              + ", ".join(r.rule for r in strict_skips), file=sys.stderr)
    return 1 if failed or (args.strict and strict_skips) else 0


if __name__ == "__main__":
    sys.exit(main())
