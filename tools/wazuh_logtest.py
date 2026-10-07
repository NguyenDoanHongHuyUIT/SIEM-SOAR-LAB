"""Run the rule tests on the REAL Wazuh analysis engine (logtest API) instead of the offline mini-engine.

  python -m tools.wazuh_logtest [--url https://localhost:55000] [--user wazuh] [--strict] [--wait 180]
  (password: env WAZUH_API_PASSWORD)

Why: `tools/rule_engine.py` is a Python re-implementation of a subset of Wazuh's rule language. It is fast, but it
asserts the parent rules by hand (`parents: [5902]`) and uses Python `re` where Wazuh uses OS_Regex, so it can pass
rules that Wazuh would reject or mis-evaluate. Wazuh ships its own tester (`wazuh-logtest`, also exposed as the API
endpoint `PUT /logtest`) that shares the engine with `wazuh-analysisd`, so the whole chain
decoder -> parent rule -> custom rule -> frequency/timeframe is exercised exactly as in production.

Metadata tests that carry raw log lines are executed here (the mini-engine ignores them):

  tests:
    - name: six ssh failures from one source
      expect: match                 # the rule under test must fire on the LAST line
      logs:                         # `log: "<line>"` for a single line
        - "Oct  7 10:00:00 host sshd[1]: Failed password for root from 10.0.1.99 port 4000 ssh2"
        - ...
      # optional: location (default master->/var/log/syslog), log_format (default syslog)

Each test opens a fresh logtest session (no token on the first request), so `firedtimes`/frequency state never leaks
between tests; the session is closed afterwards. `no_match` means the rule never fires on any line.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from dataclasses import dataclass

import requests
import urllib3

DEFAULT_LOCATION = "master->/var/log/syslog"


class LogtestError(RuntimeError):
    pass


class LogtestClient:
    """Thin client for the Wazuh server API logtest endpoints (JWT auth, self-signed TLS accepted)."""

    def __init__(self, url: str, user: str, password: str, verify: bool = False, session: requests.Session | None = None):
        self.url, self.user, self.password = url.rstrip("/"), user, password
        self.http = session or requests.Session()
        self.http.verify = verify
        if not verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self._jwt: str | None = None

    def _auth(self) -> dict:
        if self._jwt is None:
            res = self.http.post(f"{self.url}/security/user/authenticate", params={"raw": "true"},
                                 auth=(self.user, self.password), timeout=15)
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
        res = self.http.put(f"{self.url}/logtest", json=body, headers=self._auth(), timeout=30)
        if res.status_code != 200:
            raise LogtestError(f"logtest HTTP {res.status_code}: {res.text[:300]}")
        data = res.json()["data"]
        if close:
            self.close_session(data["token"])
        return data

    def close_session(self, token: str | None) -> None:
        if token:
            self.http.delete(f"{self.url}/logtest/sessions/{token}", headers=self._auth(), timeout=15)


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


def run_all(client, meta: dict[str, dict]) -> list[Result]:
    results: list[Result] = []
    for mid, m in sorted(meta.items()):
        if m.get("engine") != "wazuh":
            continue
        samples = [t for t in m.get("tests", []) or [] if lines_of(t)]
        if not samples:
            results.append(Result(mid, "-", "SKIP", f"no raw-log sample (state: {m.get('state')})"))
            continue
        for t in samples:
            ok, detail = run_sample(client, m["rule_id"], t)
            results.append(Result(mid, t.get("name", "?"), "PASS" if ok else "FAIL", "" if ok else detail))
    return results


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="tools.wazuh_logtest")
    ap.add_argument("--url", default=os.environ.get("WAZUH_API_URL", "https://localhost:55000"))
    ap.add_argument("--user", default=os.environ.get("WAZUH_API_USER", "wazuh"))
    ap.add_argument("--wait", type=float, default=0, help="seconds to wait for the API to come up")
    ap.add_argument("--strict", action="store_true",
                    help="fail when an active/enforce Wazuh rule has no raw-log sample (it was never run on the engine)")
    args = ap.parse_args(argv)

    from tools import rulesctl  # local import: keeps this module importable without PyYAML in unit tests

    client = LogtestClient(args.url, args.user, os.environ.get("WAZUH_API_PASSWORD", ""))
    if args.wait:
        client.wait_ready(args.wait)
    meta = rulesctl.load_metadata()
    results = run_all(client, meta)
    for r in results:
        print(f"{r.status} {r.rule}: {r.test}" + (f"  ({r.detail})" if r.detail else ""))
    failed = [r for r in results if r.status == "FAIL"]
    strict_skips = [r for r in results if r.status == "SKIP" and meta[r.rule]["state"] in ("active", "enforce")]
    print(f"{sum(r.status == 'PASS' for r in results)} passed, {len(failed)} failed, "
          f"{sum(r.status == 'SKIP' for r in results)} skipped")
    if args.strict and strict_skips:
        print("strict: active/enforce rules never executed on the real engine: "
              + ", ".join(r.rule for r in strict_skips), file=sys.stderr)
    return 1 if failed or (args.strict and strict_skips) else 0


if __name__ == "__main__":
    sys.exit(main())
