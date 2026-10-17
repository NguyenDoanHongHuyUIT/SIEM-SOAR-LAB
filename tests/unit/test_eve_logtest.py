"""Unit tests of the Suricata -> Wazuh hand-off checker. The behaviour itself is proven on the real engines by
`python -m tools.eve_logtest` (CI job wazuh-engine); here the engines are replaced by stubs."""

import hashlib
import json

import pytest

from tests.fixtures.real_alerts import REAL_SURICATA_EVE
from tools import eve_logtest, rulesctl, suricata_pcap_test

META = {"rule_id": 2009525, "wazuh_rule_id": 110102, "state": "active", "response": "none", "mitre": ["T1071.001"]}
EVENT = REAL_SURICATA_EVE  # verbatim EVE alert from Suricata 7 + ET Open for the Atomic T1071.001 capture


class StubWazuh:
    def __init__(self, rule_id="110102", groups=("siemsoar", "suricata", "siemsoar_active", "resp_none"),
                 mitre=("T1071.001",), alert=True):
        self.out = {"alert": alert, "output": {"rule": {"id": rule_id, "groups": list(groups),
                                                        "mitre": {"id": list(mitre)}}}}
        self.sent = []

    def logtest(self, event, **kw):
        self.sent.append((event, kw))
        return self.out


def test_a_correct_mapping_passes_and_sends_the_eve_line_as_json():
    wazuh = StubWazuh()
    check = eve_logtest.check_event(wazuh, META, EVENT)
    assert check.ok, check.detail
    sent, kw = wazuh.sent[0]
    assert json.loads(sent) == EVENT and kw["log_format"] == "json" and kw["location"].endswith("eve.json")
    assert check.name == "sid 2009525 -> Wazuh rule 110102"  # the id declared in metadata, not computed from the sid


def test_wrong_rule_missing_group_or_wrong_mitre_fail():
    assert not eve_logtest.check_event(StubWazuh(rule_id="86601", alert=True), META, EVENT).ok
    assert not eve_logtest.check_event(StubWazuh(alert=False), META, EVENT).ok
    lost = eve_logtest.check_event(StubWazuh(groups=("siemsoar", "suricata", "siemsoar_shadow", "resp_none")), META, EVENT)
    assert not lost.ok and "siemsoar_active" in lost.detail  # state group wrong: the integration would drop the alert
    assert "MITRE" in eve_logtest.check_event(StubWazuh(mitre=("T1059",)), META, EVENT).detail


def test_expected_groups_follow_the_metadata():
    assert eve_logtest.expected_groups({"state": "shadow", "response": "ec2_isolate"}) == {"siemsoar_shadow",
                                                                                         "resp_ec2_isolate"}


def test_run_checks_every_positive_pcap_and_reports_a_silent_suricata():
    class Suri:
        def replay_events(self, pcap, rules):
            if pcap.name == "t1046_nmap_syn_scan.pcap":
                return []  # Suricata stays silent: must be reported, not skipped
            return [{**EVENT, "alert": {**EVENT["alert"], "signature_id": sid}} for sid in (2009525, 2034567)]

    meta = {k: v for k, v in rulesctl.load_metadata().items() if v["engine"] == "suricata"}
    meta = {k: {**v, "state": "active"} for k, v in meta.items()}
    wazuh = StubWazuh(groups=("siemsoar", "suricata", "siemsoar_active", "resp_none"))
    checks = eve_logtest.run(wazuh, Suri(), suricata_pcap_test.ROOT / "unused.rules", meta)
    by_rule = {c.rule: c for c in checks}
    assert not by_rule["suricata-2009582"].ok and "raised nothing" in by_rule["suricata-2009582"].detail
    assert by_rule["suricata-2009525"].ok


def test_committed_pcaps_match_their_provenance_and_come_from_real_procedures():
    prov = suricata_pcap_test.provenance()
    assert prov, "rules/pcaps/provenance.json missing"
    for name, p in prov.items():
        data = (suricata_pcap_test.PCAP_DIR / name).read_bytes()
        assert hashlib.sha256(data).hexdigest() == p["sha256"] and len(data) == p["bytes"], name
        assert p["commands_run"] and p["images"]["attacker"].count("@sha256:") == 1, name
        procedure = p["procedure"]
        assert ("atomic_red_team" in procedure) != ("benign" in procedure), name
        if "atomic_red_team" in procedure:
            art = procedure["atomic_red_team"]
            from tools import refdata
            test = refdata.load_atomic()["tests"][art["test_guid"]]
            assert test["technique"] == art["technique"] and art["ref"] == refdata.ART_REF, name
    used = {t["pcap"] for m in rulesctl.load_metadata().values() if m["engine"] == "suricata" for t in m["tests"]}
    assert used <= set(prov)


def test_a_tampered_pcap_is_refused(tmp_path, monkeypatch):
    name = next(iter(suricata_pcap_test.provenance()))
    (tmp_path / name).write_bytes((suricata_pcap_test.PCAP_DIR / name).read_bytes() + b"x")
    (tmp_path / "provenance.json").write_text((suricata_pcap_test.PCAP_DIR / "provenance.json").read_text())
    monkeypatch.setattr(suricata_pcap_test, "PCAP_DIR", tmp_path)
    with pytest.raises(ValueError, match="differs"):
        suricata_pcap_test.pcap_paths({name})


def test_capture_tool_renders_atomic_commands_from_the_test_itself():
    from tools import capture_pcaps
    test = {"name": "Port Scan Nmap", "input_arguments": {"host": {"default": "192.168.1.1"}, "port": {"default": "80"}},
            "executor": {"command": "sudo nmap -sS #{host} -p #{port}\ntelnet #{host} #{port}\n"}}
    lines = capture_pcaps.render_atomic(test, {"host": "172.19.0.2"})
    assert lines == ["sudo nmap -sS 172.19.0.2 -p 80", "telnet 172.19.0.2 80"]
    assert capture_pcaps.contained(lines[0]).startswith("timeout 15 sh -c 'nmap -sS 172.19.0.2 -p 80'")
    with pytest.raises(ValueError, match="not input arguments"):
        capture_pcaps.render_atomic(test, {"hots": "x"})


def test_docker_mode_mounts_the_workdir_and_uses_the_sensor_variables(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(suricata_pcap_test.subprocess, "run",
                        lambda cmd, **kw: calls.append(cmd) or type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})())
    rules = tmp_path / "r.rules"
    rules.write_text("alert tcp any any -> any any (msg:\"x\"; sid:1; rev:1;)\n")
    suricata_pcap_test.Suricata(image="jasonish/suricata:7.0").syntax_test(rules)
    assert calls[0][:3] == ["docker", "run", "--rm"] and "jasonish/suricata:7.0" in calls[0] and "-T" in calls[0]
    assert "vars.address-groups.EXTERNAL_NET=any" in calls[0]
    monkeypatch.setattr(suricata_pcap_test.shutil, "which", lambda name: None)
    assert suricata_pcap_test.Suricata.available(None) is False
    assert suricata_pcap_test.Suricata.available("any/image") is True


def test_the_sensor_bootstrap_applies_the_same_suricata_variables():
    script = (suricata_pcap_test.ROOT / "suricata" / "bootstrap_sensor.sh").read_text()
    assert suricata_pcap_test.SENSOR_VARS == {"vars.address-groups.EXTERNAL_NET": "any"}
    assert "EXTERNAL_NET:).*/\\1 \"any\"/" in script
