"""The normaliser is driven by policy.toml: parsing is code, judgement is data, and the data is checked."""

import copy
import json
import tomllib

import boto3
import pytest
from handlers import enrich
from siemsoar import pipeline, schema
from siemsoar import policy as pol

from tests.fixtures import events as ev
from tests.fixtures.real_alerts import REAL_FIM_ALERT, REAL_SURICATA_ALERT, sshd_alert

R = "ap-southeast-1"


def _policy():
    return copy.deepcopy(pol.policy())


# ------------------------------------------------------------------ the policy itself
def test_shipped_policy_is_valid_and_every_attack_id_in_it_is_live():
    from tools import refdata
    pol.validate(tomllib.loads(pol.POLICY_PATH.read_text(encoding="utf-8")))
    techniques = refdata.load_attack()["techniques"]
    for finding, ids in pol.finding_techniques().items():
        for t in ids:
            assert t in techniques, f"{finding}: {t} is not an ATT&CK technique"
            assert not techniques[t]["revoked"] and not techniques[t]["deprecated"], f"{finding}: {t} is retired"
    for entry in pol.policy()["guardduty"]["mitre"].get("overrides", []):
        assert all(t in techniques and not techniques[t]["revoked"] for t in entry["techniques"])


def test_the_mapping_file_is_the_pinned_ctid_release_and_is_what_refdata_would_regenerate():
    from tools import refdata
    doc = json.loads(refdata.GD_SNAPSHOT.read_text(encoding="utf-8"))
    assert refdata.check_snapshot(doc) == []
    assert doc["source"].startswith("https://raw.githubusercontent.com/center-for-threat-informed-defense/")
    assert refdata.CTID_COMMIT in doc["source"] and len(doc["upstream_sha256"]) == 64
    assert doc["resolved_against_attack"] == refdata.load_attack()["attack_version"]
    assert doc["finding_types"] == pol.finding_techniques()


@pytest.mark.parametrize("mutate,message", [
    (lambda d: d.update(version=2), "version"),
    (lambda d: d["risk"].update(severity_weight=0), "severity_weight"),
    (lambda d: d["risk"].update(default_criticality="urgent"), "default_criticality"),
    (lambda d: d["severity"].update(bands=[[20, "low"], [80, "critical"]]), "descend"),
    (lambda d: d["guardduty"]["plans"][0].update(plan="delete_account"), "unknown plan"),
    (lambda d: d["guardduty"]["mitre"].pop("mapping_file"), "mapping_file"),
    (lambda d: d["guardduty"]["mitre"].update(overrides=[{"prefix": "X:Y/Z", "techniques": ["T1110"], "basis": "analyst"}]),
     "basis and reason"),
    (lambda d: d["guardduty"]["mitre"].update(overrides=[
        {"prefix": "X:Y/Z", "techniques": ["T1110"], "basis": "analyst", "reason": "r"}] * 2), "duplicate prefix"),
    (lambda d: d["resolution"].update(wazuh_agent=["guess"]), "subset"),
    (lambda d: d["dedup"].update(wazuh=["nonsense"]), "dedup.wazuh"),
    (lambda d: d["entities"]["wazuh"].update(src_ip=[]), "paths needed"),
])
def test_policy_validation_rejects_mistakes(mutate, message):
    doc = _policy()
    mutate(doc)
    with pytest.raises(pol.PolicyError, match=message):
        pol.validate(doc)


# ------------------------------------------------------------------ parsing helpers
def test_dig_handles_missing_steps_lists_and_non_dicts():
    obj = {"a": {"b": [{"c": 1}, {"c": 2}]}, "s": "text"}
    assert schema.dig(obj, "a.b.1.c") == 2 and schema.dig(obj, "a.b.5.c") is None
    assert schema.dig(obj, "a.x.c") is None and schema.dig(obj, "s.c") is None and schema.dig(obj, "a.b.c") is None


def test_entities_come_from_a_real_alert_with_stringified_numbers():
    a = schema.normalize_event(REAL_SURICATA_ALERT)  # verbatim Suricata + Wazuh output (tests/fixtures/real_alerts.py)
    x = a["extra"]
    assert x["src_ip"] == "172.19.0.3" and x["dest_ip"] == "172.19.0.2"
    assert x["dest_port"] == 80 and x["signature_id"] == 2009525 and x["alert_severity"] == 1  # coerced from strings
    assert x["user_agent"] == "Opera/8.81 (Windows NT 6.0; U; en)" and x["alert_category"] == "A Network Trojan was detected"
    assert x["agent_ip"] == "10.0.1.10"
    # Wazuh parsed the 64-bit flow id as a double: kept as delivered, never turned into a (wrong) integer
    assert x["flow_id"] == "822746917091085.000000"
    assert a["source"] == "suricata" and a["title"] == "ET MALWARE Sality - Fake Opera User-Agent"
    assert a["mitre"] == ["T1071.001"] and a["rule_id"] == "110102"


def test_integral_decimal_strings_are_integers_but_fractions_are_not():
    e = ev.clone(REAL_SURICATA_ALERT)
    e["detail"]["data"]["dest_port"] = "443.000000"
    e["detail"]["data"]["src_port"] = "12.5"
    x = schema.normalize_event(e)["extra"]
    assert x["dest_port"] == 443 and "src_port" not in x


def test_sshd_decoder_output_gives_source_ip_port_and_account_for_both_failure_kinds():
    unknown = schema.normalize_event(sshd_alert("invalid_user"))["extra"]
    assert unknown["src_ip"] == "203.0.113.5" and unknown["user"] == "admin" and "src_port" not in unknown
    known = schema.normalize_event(sshd_alert("existing_user"))["extra"]
    assert known["src_ip"] == "203.0.113.5" and known["user"] == "root" and known["src_port"] == 52001


def test_fim_alert_exposes_which_file_changed():
    a = schema.normalize_event(REAL_FIM_ALERT)
    assert a["extra"]["file_path"] == "/etc/passwd" and a["extra"]["file_event"] == "modified"
    assert a["source"] == "wazuh"
    assert a["resource"] == {"type": "agent", "id": "ip-10-0-1-10", "region": None, "account": None}


def test_malformed_optional_fields_do_not_crash_the_ingest():
    e = ev.clone(REAL_SURICATA_ALERT)
    e["detail"]["data"]["alert"] = "not-an-object"       # used to raise AttributeError
    e["detail"]["data"]["dest_port"] = "eighty"          # not a number: ignored, not fatal
    a = schema.normalize_event(e)
    assert "dest_port" not in a["extra"] and a["title"] == "Suricata: ET MALWARE Sality - Fake Opera User-Agent"


def test_guardduty_context_is_extracted():
    e = ev.clone(ev.guardduty_instance())
    e["detail"]["service"]["action"] = {"networkConnectionAction": {"remoteIpDetails": {"ipAddressV4": "203.0.113.9"}}}
    assert schema.normalize_event(e)["extra"] == {"remote_ip": "203.0.113.9", "finding_count": 3,
                                                  "first_seen": "2026-10-06T09:59:00.000Z"}


# ------------------------------------------------------------------ policy drives behaviour
def test_mitre_mapping_comes_from_the_ctid_release_and_never_guesses():
    assert schema.gd_mitre("UnauthorizedAccess:EC2/SSHBruteForce") == ["T1110"]
    # CTID (2024) still says ...InstanceCredentialExfiltration; AWS renamed it to .OutsideAWS in 2021 (doc history)
    assert set(schema.gd_mitre("UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS")) == {
        "T1552.005", "T1078"}
    assert schema.gd_mitre("UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS") == []  # not in CTID
    assert schema.gd_mitre("Stealth:IAMUser/CloudTrailLoggingDisabled") == ["T1685.002"]  # T1562.008 revoked in ATT&CK 20
    unlisted = "Execution:Runtime/NewBinaryExecuted"  # a real GuardDuty type that the pinned CTID release does not list
    assert unlisted not in pol.finding_techniques() and schema.gd_mitre(unlisted) == []


def test_every_mapped_finding_type_is_a_name_aws_publishes():
    from tools import refdata
    catalogue = refdata.load_finding_types()
    known = set(catalogue["active"]) | set(catalogue["retired"])
    assert set(pol.finding_techniques()) <= known
    assert catalogue["renamed"]["UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration"] == (
        "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS")


def test_a_local_override_wins_over_the_ctid_table(monkeypatch):
    doc = _policy()
    doc["guardduty"]["mitre"]["overrides"] = [{"prefix": "UnauthorizedAccess:EC2/SSH", "techniques": ["T1021.004"],
                                               "basis": "analyst", "reason": "test"}]
    monkeypatch.setattr(schema, "policy", lambda: doc)
    assert schema.gd_mitre("UnauthorizedAccess:EC2/SSHBruteForce") == ["T1021.004"]
    assert schema.gd_mitre("UnauthorizedAccess:EC2/RDPBruteForce") == ["T1110"]


def test_removing_a_plan_from_policy_removes_the_response_but_keeps_the_resource_identity(monkeypatch):
    doc = _policy()
    doc["guardduty"]["plans"] = [p for p in doc["guardduty"]["plans"] if p["plan"] != "ec2_isolate"]
    monkeypatch.setattr(schema, "policy", lambda: doc)
    a = schema.normalize_event(ev.guardduty_instance())
    assert a["response_plan"]["type"] == "none" and a["resource"]["id"] == "i-0abc1234def567890"


def test_iam_key_plan_only_for_user_types_listed_in_policy():
    e = ev.clone(ev.guardduty_key())
    e["detail"]["resource"]["accessKeyDetails"]["userType"] = "AssumedRole"
    assert schema.normalize_event(e)["response_plan"]["type"] == "none"


def test_dedup_key_fields_come_from_policy(monkeypatch):
    a = schema.normalize_event(ev.SURICATA)
    other = ev.clone(ev.SURICATA)
    other["detail"]["data"]["src_ip"] = "10.0.1.100"
    assert schema.normalize_event(other)["dedup_key"] != a["dedup_key"]
    doc = _policy()
    doc["dedup"]["suricata"] = ["rule_id", "resource_id"]  # operator decides one case per rule and sensor
    monkeypatch.setattr(schema, "policy", lambda: doc)
    assert schema.normalize_event(other)["dedup_key"] == schema.normalize_event(ev.SURICATA)["dedup_key"]


def test_severity_scales_and_risk_weights_come_from_policy(monkeypatch):
    assert schema.severity_label(85) == "critical" and schema.severity_label(10) == "info"
    doc = _policy()
    doc["risk"]["severity_weight"] = 1.0
    monkeypatch.setattr(schema, "policy", lambda: doc)
    assert schema.compute_risk(50, "low") == 50            # weight 1.0 and a 0-point criticality
    assert schema.compute_risk(50, "no-such-class") == 58  # unknown criticality -> the policy default (medium = 8)


# ------------------------------------------------------------------ agent -> instance resolution (enrichment)
def _instance(ip, name, cidr="10.0.0.0/16", subnet_cidr="10.0.1.0/24"):
    ec2 = boto3.client("ec2", region_name=R)
    vpc = ec2.create_vpc(CidrBlock=cidr)["Vpc"]["VpcId"]
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock=subnet_cidr)["Subnet"]["SubnetId"]
    kw = {"PrivateIpAddress": ip} if ip else {}
    return ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1, SubnetId=subnet, TagSpecifications=[{
        "ResourceType": "instance", "Tags": [{"Key": "Name", "Value": name}, {"Key": "siemsoar:zone", "Value": "workload"}]}],
        **kw)["Instances"][0]["InstanceId"]


def _fim_case(store, agent_name, agent_ip):
    e = ev.clone(REAL_FIM_ALERT)
    e["detail"]["agent"].update(name=agent_name, ip=agent_ip)
    e["detail"]["id"] = f"fim-{agent_name}"  # every real Wazuh alert has its own id
    return pipeline.ingest(schema.normalize_event(e), store, start=lambda cid: "arn:exec")["case_id"]


def test_agent_not_named_after_an_instance_id_is_resolved_by_private_ip(store):
    iid = _instance("10.0.1.77", "web-1")
    plan = schema.normalize_event(REAL_FIM_ALERT)["response_plan"]
    assert plan["type"] == "none" and plan["requested"] == "ec2_isolate"
    assert plan["resolve_via"] == ["private_ip", "name_tag"]
    cid = _fim_case(store, "ip-10-0-1-77", "10.0.1.77")
    out = enrich.handler({"state": {"case_id": cid, "config": {}}})
    case = store.get_case(cid)
    assert out["plan_type"] == "ec2_isolate" and out["plan_params"] == {"instance_id": iid}
    assert case["response_plan"]["resolved_via"] == "private_ip" and case["resource_id"] == iid
    assert case["resource"]["agent_name"] == "ip-10-0-1-77"
    assert "agent_resolved" in [a["action"] for a in store.list_audit(cid)]


def test_agent_falls_back_to_the_name_tag_when_the_ip_is_unknown(store):
    iid = _instance("10.0.1.80", "db-1")
    cid = _fim_case(store, "db-1", "192.0.2.1")
    assert enrich.handler({"state": {"case_id": cid, "config": {}}})["plan_params"] == {"instance_id": iid}
    assert store.get_case(cid)["response_plan"]["resolved_via"] == "name_tag"


def test_ambiguous_or_missing_agent_is_never_contained(store):
    cid = _fim_case(store, "ghost", "192.0.2.50")
    out = enrich.handler({"state": {"case_id": cid, "config": {}}})
    case = store.get_case(cid)
    assert out["plan_type"] == "none" and "could not be mapped to one EC2 instance" in case["plan_note"]
    assert case["resource_id"] == "ghost"  # identity unchanged

    _instance(None, "twin", "10.1.0.0/16", "10.1.1.0/24")
    _instance(None, "twin", "10.2.0.0/16", "10.2.1.0/24")  # two instances share the Name tag: ambiguity
    cid2 = _fim_case(store, "twin", "192.0.2.51")
    assert enrich.handler({"state": {"case_id": cid2, "config": {}}})["plan_type"] == "none"
    assert "2 instances matched" in store.get_case(cid2)["plan_note"]


def test_instance_id_agent_keeps_the_direct_path():
    e = ev.clone(REAL_FIM_ALERT)
    e["detail"]["agent"]["name"] = "i-0abc1234def567890"
    plan = schema.normalize_event(e)["response_plan"]
    assert plan == {"type": "ec2_isolate", "params": {"instance_id": "i-0abc1234def567890"}}
    assert json.dumps(plan)  # serialisable for Step Functions


# ------------------------------------------------------------------ entity paths against the vendors' own schemas
def _gd_shape_has(path: str) -> bool:
    """Does a dotted path of the raw EventBridge `detail` exist in AWS's GuardDuty `Finding` API model (botocore)?"""
    model = boto3.client("guardduty", region_name=R).meta.service_model
    shape = model.shape_for("Finding")
    for step in path.split("."):
        if shape.type_name == "list":
            shape = shape.member
            if step.isdigit():
                continue
        if shape.type_name != "structure":
            return False
        nxt = next((m for name, m in shape.members.items()
                    if m.serialization.get("name", name) == step or name[:1].lower() + name[1:] == step), None)
        if nxt is None:
            return False
        shape = nxt
    return True


def test_every_guardduty_entity_path_exists_in_the_aws_finding_model():
    for name, paths in pol.policy()["entities"]["guardduty"].items():
        for path in paths:
            assert _gd_shape_has(path), f"entities.guardduty.{name}: `{path}` is not a field of the GuardDuty Finding"
    assert not _gd_shape_has("service.action.networkConnectionAction.remoteIpDetails.noSuchField")


def test_every_guardduty_finding_a_scenario_expects_passes_the_eventbridge_threshold():
    """A scenario expecting a case for a finding whose documented severity band is below the EventBridge filter can
    never pass (Stealth:IAMUser/CloudTrailLoggingDisabled is Low: it was dropped at the old threshold of 4)."""
    import re
    from pathlib import Path

    from simulation import catalog
    from tools import refdata
    tf = (Path(__file__).resolve().parents[2] / "infra/modules/serverless-core/variables.tf").read_text()
    threshold = float(re.search(r'variable "min_guardduty_severity" \{.*?default\s*=\s*([\d.]+)', tf, re.S).group(1))
    lowest = {"Low": 1.0, "Medium": 4.0, "High": 7.0, "Critical": 9.0}  # GuardDuty severity bands (AWS docs)
    catalogue = refdata.load_finding_types()["active"]
    for sid, s in catalog.load_scenarios().items():
        for e in s.get("expect", []):
            if e["source"] == "guardduty" and e.get("case", True):
                band = catalogue[e["rule_id"]]["severity"].rstrip(" *")
                assert lowest[band] >= threshold, f"{sid}: {e['rule_id']} is {band}, below the threshold {threshold}"
