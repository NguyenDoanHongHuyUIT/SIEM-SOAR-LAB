"""End-to-end: generated ASL + real handlers on moto EC2/IAM/S3/DynamoDB/SNS (Slack not configured -> SNS only)."""

import json

import boto3
import pytest
from handlers import ingest as ingest_handler
from siemsoar import evidence, response
from siemsoar.decisions import apply_decision

from tests import asl_runner
from tests.fixtures import events as ev

R = "ap-southeast-1"
CFG = {"approval_timeout": 60, "restore_timeout": 60, "stop_risk_threshold": 85, "breaker_limit": 3,
       "breaker_window": 3600, "dry_run": False}


_N = iter(range(1000))


class Lab:
    """Moto-backed lab: VPC, original SG, a workload instance tagged like the Terraform module would."""

    def __init__(self, tags=None, with_role=True):
        ec2, iam = boto3.client("ec2", region_name=R), boto3.client("iam", region_name=R)
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24")["Subnet"]["SubnetId"]
        self.sg = ec2.create_security_group(GroupName="lab-ssm-only", Description="d", VpcId=vpc)["GroupId"]
        kw = {}
        self.role = f"lab-host-role-{next(_N)}"
        if with_role:
            iam.create_role(RoleName=self.role, AssumeRolePolicyDocument="{}")
            iam.create_instance_profile(InstanceProfileName=self.role)
            iam.add_role_to_instance_profile(InstanceProfileName=self.role, RoleName=self.role)
            kw["IamInstanceProfile"] = {"Name": self.role}
        tag_list = {"Name": "lab-host", "siemsoar:zone": "workload", "iac:security_groups": self.sg,
                    "criticality": "high", **(tags or {})}
        res = ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1, SubnetId=subnet,
                                SecurityGroupIds=[self.sg], TagSpecifications=[{
                                    "ResourceType": "instance",
                                    "Tags": [{"Key": k, "Value": v} for k, v in tag_list.items()]}], **kw)
        self.iid = res["Instances"][0]["InstanceId"]
        self.ec2 = ec2

    def sgs(self):
        return response.describe_instance(self.iid)["security_groups"]


def gates(*script):
    """Scripted humans: each item is a decision string or 'timeout'. Delivered via the real apply_decision."""
    queue = list(script)

    def callback(gate, data, token):
        action = queue.pop(0)
        if action == "timeout":
            raise asl_runner.Timeout()
        from siemsoar.store import CaseStore
        apply_decision(CaseStore(), data["case_id"], gate, action, actor="slack:UTEST")

    callback.remaining = queue
    return callback


def start(store, event):
    out = ingest_handler.handler(event)
    return out["case_id"]


def audit_actions(store, cid):
    return [a["action"] for a in store.list_audit(cid)]


# ------------------------------------------------------------------ EC2
def test_ec2_full_lifecycle_false_positive(store, sfn):
    lab = Lab()
    cid = start(store, ev.guardduty_instance(lab.iid, sev=6.0))
    outcome, data, visited = asl_runner.run(cid, CFG, gates("approve", "restore_fp"))
    assert outcome == "Succeed"
    assert visited[-1] == "DoneRestored"
    for s in ("Preflight", "SaveState", "SnapshotEvidence", "IsolateNetwork", "VerifyContainment", "ValidateRestore",
              "ExecuteRestore", "VerifyRestore", "RecordFeedbackFP"):
        assert s in visited, s
    case = store.get_case(cid)
    assert case["status"] == "RESTORED" and case["verdict"] == "false_positive"
    assert lab.sgs() == [lab.sg]  # original SG back
    assert "siemsoar:isolated-case" not in response.describe_instance(lab.iid)["tags"]
    assert case["containment_seconds"] >= 0 and case["evidence_seconds"] >= 0 and case["restore_seconds"] >= 0
    assert case["evidence_snapshots"]
    state, digest = evidence.get_json(cid, "pre_action_state")
    assert state["security_groups"] == [lab.sg] and digest == case["pre_action_state_ref"]["sha256"]
    acts = audit_actions(store, cid)
    for a in ("case_created", "status:NOTIFIED", "status:APPROVED", "status:ISOLATING", "status:ISOLATED",
              "status:RESTORING", "status:RESTORED", "preflight_ok", "fp_feedback_recorded"):
        assert a in acts, a
    assert store.table.query(KeyConditionExpression="pk = :p", ExpressionAttributeValues={
        ":p": f"FEEDBACK#{case['rule_id']}"})["Items"]


def test_ec2_isolation_actually_cuts_network_and_revokes_sessions(store, sfn):
    lab = Lab()
    cid = start(store, ev.guardduty_instance(lab.iid))
    seen = {}

    def spy(gate, data, token):
        if gate == "restore":
            seen["sgs"] = lab.sgs()
            seen["revoked"] = response.has_revoke_policy(lab.role)
            sg = boto3.client("ec2", region_name=R).describe_security_groups(GroupIds=seen["sgs"])["SecurityGroups"][0]
            seen["rules"] = (sg["IpPermissions"], sg["IpPermissionsEgress"])
        gates_cb(gate, data, token)

    gates_cb = gates("approve", "restore_tp")
    outcome, _, _ = asl_runner.run(cid, CFG, spy)
    assert outcome == "Succeed"
    assert len(seen["sgs"]) == 1 and seen["sgs"] != [lab.sg]
    assert seen["rules"] == ([], [])  # zero ingress, zero egress
    assert seen["revoked"] is True
    assert response.has_revoke_policy(lab.role) is False  # restored
    assert store.get_case(cid)["verdict"] == "true_positive"


def test_high_risk_stops_instance_and_restore_starts_it(store, sfn):
    lab = Lab()
    cid = start(store, ev.guardduty_instance(lab.iid, sev=8.9))
    states = []

    def cb(gate, data, token):
        if gate == "restore":
            states.append(response.describe_instance(lab.iid)["state"])
        gates_cb(gate, data, token)

    gates_cb = gates("approve", "restore_tp")
    asl_runner.run(cid, {**CFG, "stop_risk_threshold": 70}, cb)
    assert states[0] in {"stopped", "stopping"}
    assert response.describe_instance(lab.iid)["state"] in {"pending", "running"}


def test_dismiss_records_feedback_and_changes_nothing(store, sfn):
    lab = Lab()
    cid = start(store, ev.guardduty_instance(lab.iid))
    outcome, _, visited = asl_runner.run(cid, CFG, gates("dismiss"))
    assert outcome == "Succeed" and visited[-1] == "DoneDismissed"
    assert store.get_case(cid)["status"] == "DISMISSED"
    assert lab.sgs() == [lab.sg]


def test_approval_timeout_expires_case(store, sfn):
    lab = Lab()
    cid = start(store, ev.guardduty_instance(lab.iid))
    outcome, _, visited = asl_runner.run(cid, CFG, gates("timeout"))
    assert outcome == "Succeed" and "MarkExpired" in visited
    assert store.get_case(cid)["status"] == "EXPIRED" and lab.sgs() == [lab.sg]


def test_sample_finding_without_real_resource_is_acknowledge_only(store, sfn):
    cid = start(store, ev.guardduty_instance("i-99999999999999999", sample=True))
    outcome, _, visited = asl_runner.run(cid, CFG, gates("acknowledge"))
    case = store.get_case(cid)
    assert outcome == "Succeed" and case["status"] == "ACKNOWLEDGED"
    assert case["response_plan"]["type"] == "none" and "sample" in case["plan_note"]
    assert "Preflight" not in visited


def test_protected_instance_fails_safe_without_changes(store, sfn):
    lab = Lab(tags={"siemsoar:protected": "true"})
    cid = start(store, ev.guardduty_instance(lab.iid))
    outcome, data, _ = asl_runner.run(cid, CFG, gates("approve"))
    case = store.get_case(cid)
    assert outcome == "Fail:CaseFailedSafe" and case["status"] == "FAILED"
    assert case["failure_error"] == "PreflightFailed" and "no containment change" in case["safe_state"]
    assert lab.sgs() == [lab.sg]


def test_workload_zone_is_enforced(store, sfn):
    lab = Lab(tags={"siemsoar:zone": "security"})
    cid = start(store, ev.guardduty_instance(lab.iid))
    outcome, _, _ = asl_runner.run(cid, CFG, gates("approve"))
    assert outcome.startswith("Fail") and store.get_case(cid)["failure_error"] == "PreflightFailed"


def test_circuit_breaker_stops_mass_isolation(store, sfn):
    labs = [Lab() for _ in range(3)]
    cfg = {**CFG, "breaker_limit": 2}
    results = []
    for i, lab in enumerate(labs):
        cid = start(store, ev.guardduty_instance(lab.iid, fid=f"f{i}"))
        outcome, _, _ = asl_runner.run(cid, cfg, gates("approve", "restore_fp") if i < 2 else gates("approve"))
        results.append((outcome, store.get_case(cid)))
    assert [r[0] for r in results] == ["Succeed", "Succeed", "Fail:CaseFailedSafe"]
    assert results[2][1]["failure_error"] == "BreakerOpen"
    assert labs[2].sgs() == [labs[2].sg]


def test_failure_mid_containment_keeps_isolation_and_alerts(store, sfn, monkeypatch):
    lab = Lab()
    cid = start(store, ev.guardduty_instance(lab.iid))
    monkeypatch.setattr(response, "revoke_role_sessions", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("iam down")))
    outcome, _, _ = asl_runner.run(cid, CFG, gates("approve"))
    case = store.get_case(cid)
    assert outcome == "Fail:CaseFailedSafe" and case["status"] == "FAILED"
    assert "CONTAINED" in case["safe_state"]
    assert lab.sgs() != [lab.sg]  # still isolated: fail-safe does not roll back


def test_dry_run_walks_the_workflow_without_changing_aws(store, sfn):
    lab = Lab()
    cid = start(store, ev.guardduty_instance(lab.iid))
    outcome, _, _ = asl_runner.run(cid, {**CFG, "dry_run": True}, gates("approve", "restore_fp"))
    assert outcome == "Succeed" and lab.sgs() == [lab.sg]
    tagged = boto3.client("ec2", region_name=R).describe_snapshots(
        Filters=[{"Name": "tag-key", "Values": ["siemsoar:case"]}])["Snapshots"]
    assert not tagged


def test_restore_blocked_by_new_alert_then_allowed(store, sfn):
    lab = Lab()
    cid = start(store, ev.guardduty_instance(lab.iid, fid="f1"))
    queue = gates("approve", "restore_fp", "restore_fp")
    calls = []

    def cb(gate, data, token):
        calls.append(gate)
        if gate == "restore" and len(calls) == 2:  # attacker still active: new alert after isolation
            ingest_handler.handler(ev.guardduty_instance(lab.iid, fid="f2"))
        if gate == "restore" and len(calls) == 3:  # analyst cleared it: pretend counters were reviewed
            store.update_case(cid, alert_count_at_isolation=store.get_case(cid)["alert_count"])
        queue(gate, data, token)

    outcome, _, visited = asl_runner.run(cid, CFG, cb)
    assert outcome == "Succeed" and visited.count("WaitRestoreDecision") == 2
    assert "NotifyBlocked" in visited
    acts = audit_actions(store, cid)
    assert "restore_blocked" in acts and acts[-1] != "restore_blocked"
    assert store.get_case(cid)["status"] == "RESTORED"


def test_restore_blocked_terminally_after_max_attempts(store, sfn):
    lab = Lab()
    cid = start(store, ev.guardduty_instance(lab.iid))
    # someone changed the SG manually during isolation -> drift, can never auto-restore
    queue = gates("approve", "restore_tp", "restore_tp", "restore_tp")

    def cb(gate, data, token):
        if gate == "restore":
            lab.ec2.modify_instance_attribute(InstanceId=lab.iid, Groups=[lab.sg])
        queue(gate, data, token)

    outcome, _, _ = asl_runner.run(cid, CFG, cb)
    case = store.get_case(cid)
    assert outcome == "Fail:CaseFailedSafe" and case["status"] == "FAILED"
    assert case["failure_error"] == "RestoreBlocked" and case["restore_attempts"] == 3


def test_restore_detects_iac_drift_in_saved_state(store, sfn):
    lab = Lab(tags={"iac:security_groups": "sg-0000000000000dead"})
    cid = start(store, ev.guardduty_instance(lab.iid))
    queue = gates("approve", "restore_tp", "restore_tp", "restore_tp")
    outcome, _, _ = asl_runner.run(cid, CFG, queue)
    assert outcome == "Fail:CaseFailedSafe"
    blocked = [a for a in store.list_audit(cid) if a["action"] == "restore_blocked"]
    assert any("IaC" in r for a in blocked for r in a["detail"]["reasons"])


def test_restore_timeout_leaves_resource_isolated(store, sfn):
    lab = Lab()
    cid = start(store, ev.guardduty_instance(lab.iid))
    outcome, _, _ = asl_runner.run(cid, CFG, gates("approve", "timeout"))
    case = store.get_case(cid)
    assert outcome == "Fail:CaseFailedSafe" and case["status"] == "FAILED"
    assert lab.sgs() != [lab.sg] and "CONTAINED" in case["safe_state"]


def test_evidence_is_write_once(store, sfn):
    lab = Lab()
    cid = start(store, ev.guardduty_instance(lab.iid))
    asl_runner.run(cid, CFG, gates("approve", "restore_fp"))
    with pytest.raises(evidence.EvidenceExists):
        evidence.put_json(cid, "pre_action_state", {"tampered": True})


# ------------------------------------------------------------------ IAM
@pytest.fixture
def iam_user():
    iam = boto3.client("iam", region_name=R)
    iam.create_user(UserName="lab-alice", Tags=[{"Key": "owner", "Value": "huy"}])
    key = iam.create_access_key(UserName="lab-alice")["AccessKey"]["AccessKeyId"]
    return key


def test_iam_key_false_positive_reenables_same_key(store, sfn, iam_user):
    cid = start(store, ev.guardduty_key(key=iam_user))
    seen = {}

    def cb(gate, data, token):
        if gate == "restore":
            seen["keys"] = response.list_keys("lab-alice")
        q(gate, data, token)

    q = gates("approve", "restore_fp")
    outcome, _, _ = asl_runner.run(cid, CFG, cb)
    assert outcome == "Succeed"
    assert seen["keys"] == {iam_user: "Inactive"}
    assert response.list_keys("lab-alice") == {iam_user: "Active"}
    assert store.get_case(cid)["status"] == "RESTORED"


def test_iam_key_true_positive_rotates_and_stores_secret_safely(store, sfn, iam_user):
    cid = start(store, ev.guardduty_key(key=iam_user))
    outcome, data, _ = asl_runner.run(cid, CFG, gates("approve", "restore_tp"))
    assert outcome == "Succeed"
    keys = response.list_keys("lab-alice")
    assert iam_user not in keys and len(keys) == 1  # old exposed key deleted, new key issued
    secret = json.loads(boto3.client("secretsmanager", region_name=R).get_secret_value(
        SecretId="/siemsoar/rotated-keys/lab-alice")["SecretString"])
    assert secret["AccessKeyId"] in keys
    blob = json.dumps(data) + json.dumps(store.get_case(cid)) + json.dumps(store.list_audit(cid))
    assert secret["SecretAccessKey"] not in blob  # secret never enters workflow state / DB / logs


def test_iam_user_outside_prefix_is_refused(store, sfn):
    iam = boto3.client("iam", region_name=R)
    iam.create_user(UserName="prod-admin")
    key = iam.create_access_key(UserName="prod-admin")["AccessKey"]["AccessKeyId"]
    event = ev.guardduty_key(user="prod-admin", key=key)
    cid = start(store, event)
    outcome, _, _ = asl_runner.run(cid, CFG, gates("approve"))
    assert outcome.startswith("Fail") and store.get_case(cid)["failure_error"] == "PreflightFailed"
    assert response.list_keys("prod-admin") == {key: "Active"}


# ------------------------------------------------------------------ wazuh host alert end-to-end
def test_wazuh_fim_alert_end_to_end(store, sfn):
    lab = Lab()
    event = ev.clone(ev.WAZUH_FIM)
    event["detail"]["agent"]["name"] = lab.iid
    cid = start(store, event)
    outcome, _, _ = asl_runner.run(cid, CFG, gates("approve", "restore_fp"))
    case = store.get_case(cid)
    assert outcome == "Succeed" and case["source"] == "wazuh" and case["run_id"] == "run-20261006-01"
    assert lab.sgs() == [lab.sg]


def test_injected_fault_after_isolation_matches_the_robustness_scenario(store, sfn, monkeypatch):
    """Same seam the simulation runner uses (FAULT_INJECT on the contain function)."""
    monkeypatch.setenv("LAB_FAULTS_ENABLED", "true")
    monkeypatch.setenv("FAULT_INJECT", "contain.revoke_sessions")
    lab = Lab()
    cid = start(store, ev.guardduty_instance(lab.iid))
    outcome, _, visited = asl_runner.run(cid, CFG, gates("approve"))
    case = store.get_case(cid)
    assert outcome == "Fail:CaseFailedSafe" and visited[-2:] == ["FailSafe", "CaseFailed"]
    assert case["failure_error"] == "InjectedFault" and "CONTAINED" in case["safe_state"]
    assert lab.sgs() != [lab.sg]  # isolation (done before the fault) is kept
    assert "notified:failed" in audit_actions(store, cid)


def test_second_alert_on_already_isolated_host_is_refused_not_double_contained(store, sfn):
    lab = Lab()
    first = start(store, ev.guardduty_instance(lab.iid, fid="f1"))
    out1 = []

    def cb(gate, data, token):
        if gate == "restore":
            # while case 1 holds the host in isolation, a Wazuh alert opens case 2 on the same instance
            event = ev.clone(ev.WAZUH_FIM)
            event["detail"]["agent"]["name"] = lab.iid
            second = start(store, event)
            out1.append(asl_runner.run(second, CFG, gates("approve")))
        queue(gate, data, token)

    queue = gates("approve", "restore_fp")
    asl_runner.run(first, CFG, cb)
    outcome, _, _ = out1[0]
    assert outcome == "Fail:CaseFailedSafe"
    failed = store.list_cases("FAILED")[0]
    assert failed["failure_error"] == "PreflightFailed" and "already isolated by case" in failed["failure_cause"]
    assert store.get_case(first)["status"] == "RESTORED" and lab.sgs() == [lab.sg]


def test_iam_rotation_works_when_user_already_has_two_keys(store, sfn, iam_user):
    iam = boto3.client("iam", region_name=R)
    iam.create_access_key(UserName="lab-alice")  # second key: IAM's per-user limit is now reached
    cid = start(store, ev.guardduty_key(key=iam_user))
    outcome, _, _ = asl_runner.run(cid, CFG, gates("approve", "restore_tp"))
    assert outcome == "Succeed" and iam_user not in response.list_keys("lab-alice")
