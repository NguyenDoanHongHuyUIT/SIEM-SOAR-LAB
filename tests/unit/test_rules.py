import json
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from tools import rule_engine as eng
from tools import rulesctl

ROOT = Path(__file__).resolve().parents[2]


def test_repository_rules_lint_clean():
    assert rulesctl.lint() == []


def test_all_embedded_rule_tests_pass():
    results = rulesctl.run_tests()
    assert len(results) >= 20
    failed = [r for r in results if not r[2]]
    assert failed == []


def test_every_active_rule_has_positive_and_negative_test():
    for mid, m in rulesctl.load_metadata().items():
        kinds = {t["expect"] for t in m["tests"]}
        assert kinds == {"match", "no_match"}, mid


# ------------------------------------------------------------------ lint negative cases (on a scratch ruleset)
@pytest.fixture
def scratch(tmp_path):
    shutil.copytree(ROOT / "rules", tmp_path / "rules")
    return tmp_path / "rules"


def _edit_meta(root, name, fn):
    p = root / "metadata" / name
    data = yaml.safe_load(p.read_text())
    fn(data)
    p.write_text(yaml.safe_dump(data))


def test_lint_requires_metadata_for_every_rule(scratch):
    (scratch / "metadata" / "wazuh-100130.yml").unlink()
    assert any("no metadata file" in e for e in rulesctl.lint(scratch))


def test_lint_rejects_metadata_without_negative_test(scratch):
    _edit_meta(scratch, "wazuh-100100.yml", lambda d: d.update(tests=[t for t in d["tests"] if t["expect"] == "match"]))
    assert any("negative test" in e for e in rulesctl.lint(scratch))


def test_lint_rejects_bad_state_and_mitre(scratch):
    def bad(d):
        d["state"] = "live"
        d["mitre"] = ["X123"]
    _edit_meta(scratch, "wazuh-100100.yml", bad)
    errs = rulesctl.lint(scratch)
    assert any("state must be" in e for e in errs) and any("bad ATT&CK id" in e for e in errs)


def test_lint_rejects_mitre_mismatch_with_xml(scratch):
    _edit_meta(scratch, "wazuh-100100.yml", lambda d: d.update(mitre=["T1059"]))
    assert any("!= XML" in e for e in rulesctl.lint(scratch))


def test_lint_blocks_hand_written_lifecycle_groups(scratch):
    p = scratch / "wazuh" / "siemsoar_host.xml"
    p.write_text(p.read_text().replace('<description>SIEMSOAR: /etc/passwd was modified</description>',
                                       '<description>SIEMSOAR: /etc/passwd was modified</description>\n'
                                       '    <group>siemsoar_active,</group>'))
    assert any("injected by the build" in e for e in rulesctl.lint(scratch))


def test_lint_rejects_out_of_range_ids(scratch):
    p = scratch / "wazuh" / "siemsoar_host.xml"
    p.write_text(p.read_text().replace('id="100130"', 'id="5000"'))
    assert any("outside custom range" in e for e in rulesctl.lint(scratch))


def test_lint_rejects_suricata_drop_and_missing_namespace(scratch):
    p = scratch / "suricata" / "siemsoar.rules"
    p.write_text(p.read_text().replace("alert http any any -> any any (msg:\"SIEMSOAR-LAB path", "drop http any any -> any any (msg:\"evil path"))
    errs = rulesctl.lint(scratch)
    assert any("must start with 'SIEMSOAR'" in e for e in errs) and any("write rules as `alert`" in e for e in errs)


def test_lint_reports_unparseable_files(scratch):
    (scratch / "wazuh" / "siemsoar_host.xml").write_text("<group><rule></group>")
    assert any("do not parse" in e for e in rulesctl.lint(scratch))


# ------------------------------------------------------------------ build
def test_build_injects_lifecycle_groups_and_manifest(tmp_path):
    manifest = rulesctl.build(tmp_path, "deadbee", commit_time="2026-10-06T10:00:00+00:00")
    xml = (tmp_path / "deadbee" / "wazuh" / "siemsoar_rules.xml").read_text()
    rules = eng.parse_wazuh_xml(xml)
    assert "siemsoar_active" in " ".join(rules[100100].groups) and "resp_ec2_isolate" in " ".join(rules[100100].groups)
    assert "siemsoar_shadow" in " ".join(rules[100101].groups)
    assert 110001 in rules and "siemsoar_active" in " ".join(rules[110001].groups)  # generated suricata mapping rule
    assert rules[110002].if_sid == [86601] and rules[110002].fields[0][1] == "^9000002$"
    assert manifest["summary"]["shadow"] == 4 and manifest["commit_time"].startswith("2026")
    for f in manifest["files"]:
        data = (tmp_path / "deadbee" / f["path"]).read_bytes()
        import hashlib
        assert hashlib.sha256(data).hexdigest() == f["sha256"]


def test_build_excludes_deprecated_rules(scratch, tmp_path, monkeypatch):
    _edit_meta(scratch, "wazuh-100110.yml", lambda d: d.update(state="deprecated"))
    _edit_meta(scratch, "suricata-9000003.yml", lambda d: d.update(state="deprecated"))
    monkeypatch.setattr(rulesctl, "RULES", scratch)
    rulesctl.build(tmp_path, "cafe123")
    xml = (tmp_path / "cafe123" / "wazuh" / "siemsoar_rules.xml").read_text()
    rules = eng.parse_wazuh_xml(xml)
    assert 100110 not in rules and 110003 not in rules and 100100 in rules
    assert "9000003" not in (tmp_path / "cafe123" / "suricata" / "siemsoar.rules").read_text()


def test_enforce_becomes_drop_only_when_allowed(scratch, tmp_path, monkeypatch):
    _edit_meta(scratch, "suricata-9000001.yml", lambda d: d.update(state="enforce"))
    monkeypatch.setattr(rulesctl, "RULES", scratch)
    rulesctl.build(tmp_path / "a", "s1")
    rulesctl.build(tmp_path / "b", "s2", allow_drop=True)
    assert (tmp_path / "a/s1/suricata/siemsoar.rules").read_text().count("\nalert http") == 2
    assert "\ndrop http" in (tmp_path / "b/s2/suricata/siemsoar.rules").read_text()


# ------------------------------------------------------------------ promote / lifecycle / coverage / tune
def test_promote_changes_only_state_line(scratch, monkeypatch):
    monkeypatch.setattr(rulesctl, "RULES", scratch)
    path = scratch / "metadata" / "wazuh-100101.yml"
    before = path.read_text()
    msg = rulesctl.promote("wazuh-100101", "active")
    after = path.read_text()
    assert msg == "wazuh-100101: shadow -> active"
    diff = [(a, b) for a, b in zip(before.splitlines(), after.splitlines(), strict=True) if a != b]
    assert diff == [("state: shadow", "state: active")]


def test_promote_rejects_illegal_jump(scratch, monkeypatch):
    monkeypatch.setattr(rulesctl, "RULES", scratch)
    with pytest.raises(SystemExit):
        rulesctl.promote("wazuh-100101", "enforce")  # shadow -> enforce skips active


def test_lifecycle_gate_against_git_base(tmp_path):
    """Create a throwaway repo: new rules must enter as shadow; illegal moves are rejected."""
    repo = tmp_path / "r"
    shutil.copytree(ROOT / "rules", repo / "rules")
    run = lambda *a: subprocess.run(a, cwd=repo, check=True, capture_output=True)  # noqa: E731
    run("git", "init", "-q")
    run("git", "-c", "user.email=t@t", "-c", "user.name=t", "add", "-A")
    run("git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "base")
    import tools.rulesctl as rc
    orig_root, orig_rules = rc.ROOT, rc.RULES
    try:
        rc.ROOT, rc.RULES = repo, repo / "rules"
        assert rc.lifecycle_check("HEAD") == []
        _edit_meta(repo / "rules", "wazuh-100101.yml", lambda d: d.update(state="enforce"))  # shadow -> enforce
        assert any("illegal lifecycle move shadow -> enforce" in e for e in rc.lifecycle_check("HEAD"))
        assert rc.lifecycle_check("HEAD", allow_revert=True) == []
        _edit_meta(repo / "rules", "wazuh-100101.yml", lambda d: d.update(state="active"))
        assert rc.lifecycle_check("HEAD") == []
        new = repo / "rules" / "metadata" / "wazuh-100199.yml"
        data = yaml.safe_load((repo / "rules/metadata/wazuh-100100.yml").read_text())
        data.update(id="wazuh-100199", rule_id=100199, state="active")
        new.write_text(yaml.safe_dump(data))
        assert any("new rules must be introduced as `shadow`" in e for e in rc.lifecycle_check("HEAD"))
    finally:
        rc.ROOT, rc.RULES = orig_root, orig_rules


def test_coverage_counts_only_active_and_enforce():
    cov = rulesctl.coverage()
    assert "T1136.001" in cov["techniques"] and "T1110.001" not in cov["techniques"]  # 100120 is shadow


def test_tune_suggestions():
    out = rulesctl.tune({"100100": {"cases": 4, "false_positive": 3}, "100101": {"cases": 5, "false_positive": 0},
                         "100130": {"cases": 1, "false_positive": 1}})
    assert any("demote" in s and "100100" in s for s in out)
    assert any("promotion" in s and "100101" in s for s in out)
    assert not any("100130" in s for s in out)


# ------------------------------------------------------------------ engine details
def test_os_match_semantics():
    assert eng.os_match("technique=", "x technique=T1") and not eng.os_match("^technique=", "x technique=")
    assert eng.os_match("^abc|xyz$", "abcdef") and eng.os_match("^abc|xyz$", "wxyz") and not eng.os_match("^abc|xyz$", "zzz")


def test_suricata_hex_and_nocase_and_negation():
    r = eng.parse_suricata_rule('alert tcp any any -> any any (msg:"SIEMSOAR x"; content:"|41 42|"; content:!"bad"; nocase; sid:9000050; rev:1;)')
    assert r.contents[0].value == b"AB" and r.contents[1].negated and r.contents[1].nocase
    assert eng.run_suricata_test(r, {"expect": "match", "payload": {"buffer": "payload", "value": "xxABxx"}})[0]
    assert eng.run_suricata_test(r, {"expect": "no_match", "payload": {"buffer": "payload", "value": "ABBAD"}})[0]


def test_duplicate_ids_rejected():
    with pytest.raises(ValueError):
        eng.parse_wazuh_xml('<group name="a"><rule id="1" level="1"/><rule id="1" level="1"/></group>')
    with pytest.raises(ValueError):
        eng.parse_suricata_rules('alert tcp any any -> any any (msg:"a"; sid:1; rev:1;)\n'
                                 'alert tcp any any -> any any (msg:"b"; sid:1; rev:1;)')


@pytest.mark.skipif(not shutil.which("suricata"), reason="suricata not installed")
def test_real_suricata_accepts_rules_and_matches_pcaps():
    from tools import suricata_pcap_test
    assert suricata_pcap_test.main([]) == 0


# ------------------------------------------------------------------ wazuh custom integration
def _load_integration():
    import importlib.util
    spec = importlib.util.spec_from_file_location("custom_eventbridge", ROOT / "wazuh/integrations/custom-eventbridge.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_integration_hook_parsing_and_entry():
    m = _load_integration()
    assert m.parse_hook("eventbridge://default?region=ap-southeast-1") == ("default", "ap-southeast-1")
    with pytest.raises(ValueError):
        m.parse_hook("https://evil")
    entry = m.build_entry({"id": "1", "full_log": "x" * 10_000, "rule": {"id": "100100"}}, "default")
    assert entry["Source"] == "siemsoar.wazuh" and len(json.loads(entry["Detail"])["full_log"]) == 4000
    big = {"id": "1", "data": {"blob": "y" * 300_000}, "rule": {"id": "1"}}
    assert len(m.build_entry(big, "default")["Detail"].encode()) <= 200_000


def test_integration_roundtrip_matches_normalizer(tmp_path):
    """What the integration emits must be accepted by the ingest normaliser (contract test)."""
    import boto3
    from moto import mock_aws

    from siemsoar import schema
    from tests.fixtures import events as ev
    m = _load_integration()
    alert_file = tmp_path / "alert.json"
    alert_file.write_text(json.dumps(ev.WAZUH_FIM["detail"]))
    with mock_aws():
        boto3.client("events", region_name="ap-southeast-1")
        assert m.main(["x", str(alert_file), "key", "eventbridge://default?region=ap-southeast-1"]) == 0
    entry = m.build_entry(ev.WAZUH_FIM["detail"], "default")
    event = {"source": entry["Source"], "detail-type": entry["DetailType"], "detail": json.loads(entry["Detail"])}
    assert schema.normalize_event(event)["rule_id"] == "100100"
