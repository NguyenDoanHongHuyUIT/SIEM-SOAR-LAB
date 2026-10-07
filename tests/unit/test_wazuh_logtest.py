"""The logtest runner is tested against a fake client that mimics the documented API response shape
(data.token, data.alert, data.output.rule.id). Against a live Wazuh it runs in CI (job `wazuh-engine`)."""

import re
from pathlib import Path

from tools import rulesctl
from tools import wazuh_logtest as wl

ROOT = Path(__file__).resolve().parents[2]


class FakeClient:
    """Rule 100120 fires when 6 lines of the same session contain 'Failed password'; 100130 on the marker."""

    def __init__(self):
        self.sessions, self.closed, self.tokens_seen = {}, [], []

    def logtest(self, event, token=None, location=wl.DEFAULT_LOCATION, log_format="syslog", close=False):
        token = token or f"tok{len(self.sessions) + 1}"
        self.tokens_seen.append(token)
        seen = self.sessions.setdefault(token, [])
        seen.append(event)
        rule = {"id": "5760", "level": 5}
        if sum("Failed password" in e for e in seen) >= 6:
            rule = {"id": "100120", "level": 10}
        if "siemsoar-sim: technique=" in event:
            rule = {"id": "100130", "level": 8}
        return {"token": token, "alert": True, "output": {"rule": rule}}

    def close_session(self, token):
        self.closed.append(token)


def test_burst_fires_only_on_last_line_and_uses_one_session():
    c = FakeClient()
    t = {"expect": "match", "logs": ["Failed password"] * 6}
    assert wl.run_sample(c, 100120, t)[0]
    assert len(set(c.tokens_seen)) == 1 and c.closed == ["tok1"]


def test_not_enough_events_is_a_no_match_and_a_failed_match_expectation():
    c = FakeClient()
    assert wl.run_sample(c, 100120, {"expect": "no_match", "logs": ["Failed password"] * 3})[0]
    ok, detail = wl.run_sample(FakeClient(), 100120, {"expect": "match", "logs": ["Failed password"] * 3})
    assert not ok and "none" in detail


def test_each_test_gets_a_fresh_session():
    c = FakeClient()
    wl.run_sample(c, 100130, {"expect": "match", "log": "x siemsoar-sim: technique=T1"})
    wl.run_sample(c, 100130, {"expect": "no_match", "log": "cron: technique=T1"})
    assert c.closed == ["tok1", "tok2"]


def test_run_all_skips_rules_without_raw_samples_and_reports_state():
    meta = {"wazuh-1": {"engine": "wazuh", "rule_id": 1, "state": "active",
                        "tests": [{"name": "structured only", "expect": "match", "event": {}}]},
            "suricata-9": {"engine": "suricata", "rule_id": 9, "tests": []}}
    res = wl.run_all(FakeClient(), meta)
    assert [(r.rule, r.status) for r in res] == [("wazuh-1", "SKIP")]


def test_repository_samples_are_well_formed_and_mini_engine_ignores_them():
    meta = rulesctl.load_metadata()
    with_raw = [m for m in meta.values() if m["engine"] == "wazuh" and any(wl.lines_of(t) for t in m["tests"])]
    assert with_raw, "at least one rule must carry raw-log samples"
    assert all(r[2] for r in rulesctl.run_tests())  # raw-log tests must not break the offline mini-engine


def test_ci_engine_version_matches_the_version_deployed_by_terraform():
    """The engine that tests the rules must be the engine that runs them."""
    tf = (ROOT / "infra/modules/lab-ondemand/variables.tf").read_text()
    deployed = re.search(r'variable "wazuh_version"\s*{[^}]*default\s*=\s*"([^"]+)"', tf).group(1)
    ci = (ROOT / ".github/workflows/ci.yml").read_text()
    tested = re.search(r'WAZUH_VERSION:\s*"?([0-9.]+)"?', ci).group(1)
    assert tested == deployed or tested.startswith(deployed + "."), (tested, deployed)
