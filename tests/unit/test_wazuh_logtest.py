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


def test_run_all_ignores_suricata_and_fails_tests_nothing_can_run():
    meta = {"wazuh-1": {"engine": "wazuh", "rule_id": 1, "state": "active",
                        "tests": [{"name": "hand written", "expect": "match", "event": {}}]},
            "suricata-9": {"engine": "suricata", "rule_id": 9, "tests": []}}
    res = wl.run_all(FakeClient(), meta)
    assert [(r.rule, r.status) for r in res] == [("wazuh-1", "FAIL")]


class FakeFim:
    def __init__(self, rule):
        self.rule, self.calls = rule, []

    def rule_for(self, path, kind="modified"):
        self.calls.append((path, kind))
        return self.rule if path == "/etc/passwd" else "550"


def test_fim_tests_use_the_queue_and_skip_without_a_container():
    meta = {"wazuh-100100": {"engine": "wazuh", "rule_id": 100100, "state": "active", "tests": [
        {"name": "hit", "expect": "match", "fim": {"path": "/etc/passwd"}},
        {"name": "miss", "expect": "no_match", "fim": {"path": "/etc/hosts", "type": "added"}}]}}
    fim = FakeFim("100100")
    assert [r.status for r in wl.run_all(FakeClient(), meta, fim)] == ["PASS", "PASS"]
    assert fim.calls == [("/etc/passwd", "modified"), ("/etc/hosts", "added")]
    assert [r.status for r in wl.run_all(FakeClient(), meta)] == ["SKIP", "SKIP"]
    assert [r.status for r in wl.run_all(FakeClient(), meta, FakeFim("550"))] == ["FAIL", "PASS"]


def test_repository_wazuh_tests_are_all_executable_on_the_real_engine():
    for mid, m in rulesctl.load_metadata().items():
        if m["engine"] == "wazuh":
            assert all(wl.lines_of(t) or "fim" in t for t in m["tests"]), mid


def test_ci_engine_version_matches_the_version_deployed_by_terraform():
    """The engine that tests the rules must be the engine that runs them."""
    tf = (ROOT / "infra/modules/lab-ondemand/variables.tf").read_text()
    deployed = re.search(r'variable "wazuh_version"\s*{[^}]*default\s*=\s*"([^"]+)"', tf).group(1)
    ci = (ROOT / ".github/workflows/ci.yml").read_text()
    tested = re.search(r'WAZUH_VERSION:\s*"?([0-9.]+)"?', ci).group(1)
    assert tested == deployed or tested.startswith(deployed + "."), (tested, deployed)
