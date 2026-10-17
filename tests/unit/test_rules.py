import json
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from tools import rulesctl

ROOT = Path(__file__).resolve().parents[2]


def test_repository_rules_lint_clean():
    assert rulesctl.lint() == []


def test_every_rule_has_positive_and_negative_tests_that_a_real_engine_can_run():
    for mid, m in rulesctl.load_metadata().items():
        assert {t["expect"] for t in m["tests"]} == {"match", "no_match"}, mid
        assert all(any(k in t for k in rulesctl.RUNNABLE_TEST_KEYS[m["engine"]]) for t in m["tests"]), mid


# ------------------------------------------------------------------ lint negative cases (on a scratch ruleset)
@pytest.fixture(autouse=True)
def scenario_copy(tmp_path, monkeypatch):
    """Every test works on a copy of the scenarios: promote/sync_scenarios must never rewrite the repository's files."""
    from simulation import catalog
    copy = tmp_path / "scenarios-copy"
    shutil.copytree(ROOT / "simulation" / "scenarios", copy)
    monkeypatch.setattr(catalog, "SCENARIO_DIR", copy)
    return copy


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
    (scratch / "metadata" / "wazuh-100121.yml").unlink()
    assert any("no metadata file" in e for e in rulesctl.lint(scratch))


def test_lint_rejects_metadata_without_negative_test(scratch):
    _edit_meta(scratch, "wazuh-100100.yml", lambda d: d.update(tests=[t for t in d["tests"] if t["expect"] == "match"]))
    assert any("negative test" in e for e in rulesctl.lint(scratch))


def test_lint_rejects_tests_no_engine_can_run(scratch):
    _edit_meta(scratch, "wazuh-100100.yml",
               lambda d: d["tests"].append({"name": "hand written", "expect": "match", "event": {"parents": [550]}}))
    assert any("must define one of" in e for e in rulesctl.lint(scratch))


def test_lint_rejects_bad_state_and_mitre(scratch):
    def bad(d):
        d["state"] = "live"
        d["mitre"] = ["X123"]
    _edit_meta(scratch, "wazuh-100100.yml", bad)
    errs = rulesctl.lint(scratch)
    assert any("state must be" in e for e in errs) and any("bad ATT&CK id" in e for e in errs)


def test_lint_requires_https_reference_for_every_mitre_id(scratch):
    _edit_meta(scratch, "wazuh-100100.yml", lambda d: d.update(references=["http://example.invalid/source"]))
    errs = rulesctl.lint(scratch)
    assert any("use an HTTPS URL" in e for e in errs)
    assert any("canonical ATT&CK URL" in e for e in errs)


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
    p.write_text(p.read_text().replace('id="100121"', 'id="5000"'))
    assert any("outside custom range" in e for e in rulesctl.lint(scratch))


def test_lint_rejects_suricata_drop_and_missing_namespace(scratch):
    p = scratch / "suricata" / "siemsoar.rules"
    p.write_text(p.read_text() + 'drop http any any -> any any (msg:"evil path"; classtype:bad-unknown; sid:9000050; rev:1;)\n')
    errs = rulesctl.lint(scratch)
    assert any("must start with 'SIEMSOAR'" in e for e in errs) and any("write rules as `alert`" in e for e in errs)
    assert any("9000050: no metadata file" in e for e in errs)


def test_lint_requires_an_explicit_unique_wazuh_rule_for_every_suricata_rule(scratch):
    _edit_meta(scratch, "suricata-2009525.yml", lambda d: d.update(wazuh_rule_id=110101))  # taken by 2009582
    assert any("wazuh_rule_id 110101 is already used" in e for e in rulesctl.lint(scratch))
    _edit_meta(scratch, "suricata-2009525.yml", lambda d: d.pop("wazuh_rule_id"))
    assert any("`wazuh_rule_id` must be an integer" in e for e in rulesctl.lint(scratch))


def test_lint_rejects_a_managed_sid_that_is_not_in_the_pinned_et_open_snapshot(scratch):
    _edit_meta(scratch, "suricata-2009525.yml", lambda d: d.update(rule_id=2999999, id="suricata-2999999"))
    (scratch / "metadata" / "suricata-2009525.yml").rename(scratch / "metadata" / "suricata-2999999.yml")
    assert any("2999999 is not in rules/reference/et-open-managed.json" in e for e in rulesctl.lint(scratch))


def test_lint_rejects_an_attack_label_that_no_source_backs(scratch):
    # sudoers rule labelled T1098: not on the official parent 550 (T1565.001), and the only procedure that triggers it
    # is Atomic Red Team T1548.003 -> the label has no source
    def relabel(d):
        d["mitre"] = ["T1098"]
        d["references"] = [*d["references"], "https://attack.mitre.org/techniques/T1098/"]
    _edit_meta(scratch, "wazuh-100103.yml", relabel)
    p = scratch / "wazuh" / "siemsoar_host.xml"
    p.write_text(p.read_text().replace("<id>T1548.003</id>", "<id>T1098</id>"))
    errs = rulesctl.lint(scratch)
    assert any("wazuh-100103" in e and "ATT&CK T1098 has no source" in e for e in errs)
    # and the scenario that exercises the rule now contradicts it
    assert any("host-sudoers executes ['T1548.003']" in e for e in errs)


def test_every_attack_label_in_the_repository_has_a_source():
    from simulation import catalog
    meta = rulesctl.load_metadata()
    proven = catalog.evidence(catalog.load_scenarios(), meta, catalog.References.load().pcaps)
    assert proven["wazuh-100104"] == {"T1098.004"} and proven["suricata-2009582"] == {"T1046"}
    assert {"T1136.001", "T1078.003"} <= proven["wazuh-100102"]


def test_lint_reports_unparseable_files(scratch):
    (scratch / "wazuh" / "siemsoar_host.xml").write_text("<group><rule></group>")
    assert any("do not parse" in e for e in rulesctl.lint(scratch))


# ------------------------------------------------------------------ build
def test_build_injects_lifecycle_groups_and_manifest(tmp_path):
    manifest = rulesctl.build(tmp_path, "deadbee", commit_time="2026-10-06T10:00:00+00:00")
    xml = (tmp_path / "deadbee" / "wazuh" / "siemsoar_rules.xml").read_text()
    rules = rulesctl.parse_wazuh_xml(xml)
    # first import: every rule enters in shadow (lifecycle gate); the response plan is still carried for later
    assert "siemsoar_shadow" in " ".join(rules[100100].groups) and "resp_ec2_isolate" in " ".join(rules[100100].groups)
    assert "siemsoar_shadow" in " ".join(rules[100101].groups)
    assert 110101 in rules and "siemsoar_shadow" in " ".join(rules[110101].groups)  # generated suricata mapping rule
    mapping = rules[110101].element
    assert mapping.findtext("if_sid") == "86601" and mapping.findtext("field") == "^2009582$"
    assert rules[110103].element.find("mitre") is None  # no technique claimed -> no empty <mitre/>
    assert manifest["summary"] == {"shadow": 11, "active": 0, "enforce": 0, "deprecated": 0}
    assert manifest["commit_time"].startswith("2026") and manifest["et_open_version"]
    suri = (tmp_path / "deadbee" / "suricata" / "siemsoar.rules").read_text()
    assert 'msg:"ET SCAN NMAP -sS window 1024"' in suri and not any(
        line.startswith("#alert") for line in suri.splitlines())  # disabled upstream, enabled (pinned) by SIEMSOAR
    disabled = (tmp_path / "deadbee" / "suricata" / "disable.conf").read_text().split()
    assert {"1:2009582", "1:2009525", "1:2034567"} <= set(disabled)
    for f in manifest["files"]:
        data = (tmp_path / "deadbee" / f["path"]).read_bytes()
        import hashlib
        assert hashlib.sha256(data).hexdigest() == f["sha256"]


def _drop_expectations(monkeypatch, tmp_path, *rule_ids: str):
    """Scenario copy without expectations on `rule_ids` (a deprecated rule may not be expected by any scenario)."""
    from simulation import catalog
    out = tmp_path / "scenarios"
    out.mkdir()
    for f in catalog.SCENARIO_DIR.glob("*.yml"):
        doc = yaml.safe_load(f.read_text(encoding="utf-8"))
        doc["expect"] = [e for e in doc.get("expect", []) if str(e["rule_id"]) not in rule_ids]
        (out / f.name).write_text(yaml.safe_dump(doc), encoding="utf-8")
    monkeypatch.setattr(catalog, "SCENARIO_DIR", out)


def test_lint_rejects_a_scenario_that_expects_a_deprecated_rule(scratch):
    _edit_meta(scratch, "wazuh-100110.yml", lambda d: d.update(state="deprecated"))
    assert any("expects wazuh-100110, which is deprecated" in e for e in rulesctl.lint(scratch))


def test_build_excludes_deprecated_rules(scratch, tmp_path, monkeypatch):
    _drop_expectations(monkeypatch, tmp_path, "100110", "110103")
    _edit_meta(scratch, "wazuh-100110.yml", lambda d: d.update(state="deprecated"))
    _edit_meta(scratch, "suricata-2034567.yml", lambda d: d.update(state="deprecated"))
    monkeypatch.setattr(rulesctl, "RULES", scratch)
    rulesctl.build(tmp_path, "cafe123")
    xml = (tmp_path / "cafe123" / "wazuh" / "siemsoar_rules.xml").read_text()
    rules = rulesctl.parse_wazuh_xml(xml)
    assert 100110 not in rules and 110103 not in rules and 100100 in rules
    assert "sid:2034567;" not in (tmp_path / "cafe123" / "suricata" / "siemsoar.rules").read_text()
    # still disabled in the floating ET set: a retired rule must not keep alerting through suricata-update
    assert "1:2034567" in (tmp_path / "cafe123" / "suricata" / "disable.conf").read_text()


def test_enforce_becomes_drop_only_when_allowed(scratch, tmp_path, monkeypatch):
    _drop_expectations(monkeypatch, tmp_path, "110102")  # the scenario would now expect a case: not the point here
    _edit_meta(scratch, "suricata-2009525.yml", lambda d: d.update(state="enforce"))
    monkeypatch.setattr(rulesctl, "RULES", scratch)
    rulesctl.build(tmp_path / "a", "s1")
    rulesctl.build(tmp_path / "b", "s2", allow_drop=True)
    assert (tmp_path / "a/s1/suricata/siemsoar.rules").read_text().count("\nalert http") == 2
    assert "\ndrop http" in (tmp_path / "b/s2/suricata/siemsoar.rules").read_text()


# ------------------------------------------------------------------ promote / lifecycle / coverage / tune
def test_promote_changes_only_state_line_and_keeps_scenarios_consistent(scratch, monkeypatch, scenario_copy):
    monkeypatch.setattr(rulesctl, "RULES", scratch)
    path = scratch / "metadata" / "wazuh-100110.yml"
    before = path.read_text()
    msg = rulesctl.promote("wazuh-100110", "active")
    after = path.read_text()
    assert msg.startswith("wazuh-100110: shadow -> active (scenario expectations updated: ")
    diff = [(a, b) for a, b in zip(before.splitlines(), after.splitlines(), strict=True) if a != b]
    assert diff == [("state: shadow", "state: active")]
    useradd = (scenario_copy / "host-useradd.yml").read_text()
    assert 'rule_id: "100110", case: true}' in useradd and 'rule_id: "100100", case: false}' in useradd
    assert rulesctl.lint(scratch) == []  # promotion leaves rules and scenarios consistent: no hand edits needed
    assert (ROOT / "simulation/scenarios/host-useradd.yml").read_text().count('"100110", case: false') == 1


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


def test_coverage_counts_only_active_and_enforce(scratch, monkeypatch):
    monkeypatch.setattr(rulesctl, "RULES", scratch)
    assert rulesctl.coverage()["techniques"] == {}  # first import: everything is in shadow
    rulesctl.promote("wazuh-100110", "active")
    cov = rulesctl.coverage()
    assert cov["techniques"] == {"T1136.001": ["wazuh-100110"]}  # 100120/100121 etc. are still shadow


def test_tune_suggestions(scratch, monkeypatch):
    monkeypatch.setattr(rulesctl, "RULES", scratch)
    rulesctl.promote("wazuh-100100", "active")
    out = rulesctl.tune({"100100": {"cases": 4, "false_positive": 3}, "100101": {"cases": 5, "false_positive": 0},
                         "9999999": {"cases": 1, "false_positive": 1}})
    assert any("demote" in s and "100100" in s for s in out)
    assert any("promotion" in s and "100101" in s for s in out)
    assert not any("9999999" in s for s in out)


def test_fim_watches_directories_not_files():
    """A real-time watch on a file dies when useradd/usermod/visudo replace it by rename: on the lab and on
    wazuh-manager 4.14.8 only the first of three changes alerted. Every real-time entry must be a directory."""
    import re
    xml = (ROOT / "suricata/ossec_agent_additions.xml").read_text()
    # Wazuh's OS_XML parser rejects a line break inside a tag ("Error reading XML file etc/ossec.conf"): one line each
    assert not re.search(r"<[^>]*\n[^>]*>", re.sub(r"<!--.*?-->", "", xml, flags=re.S)), "line break inside a tag"
    for attrs, paths in re.findall(r"<directories([^>]*)>([^<]+)</directories>", xml):
        if 'realtime="yes"' in attrs:
            for path in paths.split(","):
                assert not re.search(r"/(passwd|shadow|sudoers|sshd_config|authorized_keys)$", path.strip()), path


# ------------------------------------------------------------------ rule files
def test_duplicate_ids_rejected():
    with pytest.raises(ValueError):
        rulesctl.parse_wazuh_xml('<group name="a"><rule id="1" level="1"/><rule id="1" level="1"/></group>')
    with pytest.raises(ValueError):
        rulesctl.parse_suricata_rules('alert tcp any any -> any any (msg:"a"; sid:1; rev:1;)\n'
                                      'alert tcp any any -> any any (msg:"b"; sid:1; rev:1;)')


def test_unparseable_suricata_rule_is_reported():
    with pytest.raises(ValueError):
        rulesctl.parse_suricata_rules("this is not a rule")


@pytest.mark.skipif(not shutil.which("suricata"), reason="suricata not installed")
def test_real_suricata_accepts_rules_and_every_pcap_test_passes(tmp_path):
    from tools import suricata_pcap_test
    rulesctl.build(tmp_path, "t")
    assert suricata_pcap_test.main(["--rules", str(tmp_path / "t" / "suricata" / "siemsoar.rules")]) == 0


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


# ------------------------------------------------------------------ references are checked against pinned official data
def test_lint_rejects_revoked_or_unknown_attack_ids(scratch):
    def revoked(d):
        d["mitre"] = ["T1562.008"]
        d["references"] = [*d["references"], "https://attack.mitre.org/techniques/T1562/008/"]
    _edit_meta(scratch, "wazuh-100100.yml", revoked)
    errs = rulesctl.lint(scratch)
    assert any("T1562.008" in e and "revoked; use T1685.002" in e for e in errs)
    _edit_meta(scratch, "wazuh-100100.yml", lambda d: d.update(mitre=["T9999"]))
    assert any("does not exist in the pinned ATT&CK snapshot" in e for e in rulesctl.lint(scratch))


def test_lint_rejects_a_parent_rule_that_does_not_exist_in_the_official_ruleset(scratch):
    p = scratch / "wazuh" / "siemsoar_host.xml"
    p.write_text(p.read_text().replace("<if_sid>5902</if_sid>", "<if_sid>5902999</if_sid>"))
    assert any("parent rule 5902999 exists neither here nor in Wazuh" in e for e in rulesctl.lint(scratch))


def test_lint_requires_wraps_to_match_the_official_parents(scratch):
    _edit_meta(scratch, "wazuh-100120.yml", lambda d: d.update(wraps=[5712]))
    assert any("`wraps`" in e and "5763" in e for e in rulesctl.lint(scratch))
    _edit_meta(scratch, "wazuh-100120.yml", lambda d: d.pop("wraps"))
    assert any("`wraps`" in e for e in rulesctl.lint(scratch))


def test_lint_rejects_a_custom_id_that_collides_with_the_official_ruleset(scratch):
    p = scratch / "wazuh" / "siemsoar_host.xml"
    p.write_text(p.read_text().replace('id="100121"', 'id="5712"'))
    assert any("already used by the official ruleset" in e for e in rulesctl.lint(scratch))


def test_lint_demands_the_reference_snapshots(scratch):
    for f in (scratch / "reference").glob("*.json"):
        f.unlink()
    errs = rulesctl.lint(scratch)
    assert any("no ATT&CK snapshot" in e for e in errs) and any("no Wazuh ruleset snapshot" in e for e in errs)


def test_reference_snapshots_record_where_they_came_from():
    from tools import refdata
    for path in sorted((ROOT / "rules" / "reference").glob("*.json")):
        doc = json.loads(path.read_text(encoding="utf-8"))
        assert refdata.check_snapshot(doc) == [], path.name
        assert doc["source"].startswith("https://") and len(doc["upstream_sha256"]) == 64
    wz = refdata.load_wazuh_reference()
    assert wz["rules"]["5763"]["frequency"] == 8 and wz["rules"]["5763"]["parents"] == [5760]


def test_the_reference_snapshot_matches_the_wazuh_version_the_lab_installs():
    import re
    tf = (ROOT / "infra/modules/lab-ondemand/variables.tf").read_text()
    version = re.search(r'variable "wazuh_version".*?default\s*=\s*"([\d.]+)"', tf, re.S).group(1)
    from tools import refdata
    reference = refdata.load_wazuh_reference()["wazuh_version"]
    assert reference == version or reference.startswith(version + ".")  # lab pins the minor, the snapshot a patch


def test_refdata_parsers_on_small_inputs():
    from tools import refdata
    bundle = {"objects": [
        {"type": "attack-pattern", "id": "attack-pattern--old", "name": "Old", "revoked": True,
         "external_references": [{"source_name": "mitre-attack", "external_id": "T1000.001"}]},
        {"type": "attack-pattern", "id": "attack-pattern--new", "name": "New",
         "external_references": [{"source_name": "mitre-attack", "external_id": "T2000.002"}]},
        {"type": "relationship", "id": "relationship--1", "relationship_type": "revoked-by", "source_ref": "attack-pattern--old",
         "target_ref": "attack-pattern--new"}]}
    t = refdata.parse_attack(bundle)
    assert t["T1000.001"]["revoked"] and t["T1000.001"]["revoked_by"] == "T2000.002" and not t["T2000.002"]["revoked"]
    rules = refdata.parse_wazuh_rules(
        '<group name="g,"><rule id="1" level="3" frequency="$F" timeframe="60"><if_sid>2, 3</if_sid>'
        '<description>a b</description><mitre><id>T1110</id></mitre></rule></group>', "x.xml")
    assert rules[1]["parents"] == [2, 3] and rules[1]["frequency"] == "$F" and rules[1]["timeframe"] == 60
    assert rules[1]["description"] == "a b" and rules[1]["mitre"] == ["T1110"]
