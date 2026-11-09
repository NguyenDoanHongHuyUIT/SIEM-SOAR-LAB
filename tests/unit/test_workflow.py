"""End-to-end: generated ASL + real handlers on moto EC2/IAM/S3/DynamoDB/SNS (Slack not configured -> SNS only)."""

import json

import boto3
import pytest
from handlers import ingest as ingest_handler
from siemsoar import evidence, response
from siemsoar.decisions import apply_decision

from evaluation import evaluate
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
              "ExecuteRestore", "VerifyRestore"):
        assert s in visited, s
    case = store.get_case(cid)
    assert case["status"] == "RESTORED" and case["verdict"] == "false_positive"
    assert case["dry_run"] is False and case["containment_verification"] == "ok" and case["restore_verification"] == "ok"
    assert lab.sgs() == [lab.sg]  # original SG back
    assert "siemsoar:isolated-case" not in response.describe_instance(lab.iid)["tags"]
    assert case["containment_seconds"] >= 0 and case["evidence_seconds"] >= 0 and case["restore_seconds"] >= 0
    assert not evaluate.dry_run({**case, "audit": store.list_audit(cid)})  # a real containment: evaluation times it
    assert case["evidence_snapshots"]
    state, digest = evidence.get_json(cid, "pre_action_state")
    assert state["security_groups"] == [lab.sg] and digest == case["pre_action_state_ref"]["sha256"]
    acts = audit_actions(store, cid)
    for a in ("case_created", "status:NOTIFIED", "status:APPROVED", "status:ISOLATING", "status:ISOLATED",
              "status:RESTORING", "status:RESTORED", "preflight_ok"):
        assert a in acts, a


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


def test_dismiss_changes_nothing(store, sfn):
    lab = Lab()
    cid = start(store, ev.guardduty_instance(lab.iid))
    outcome, _, visited = asl_runner.run(cid, CFG, gates("dismiss"))
    assert outcome == "Succeed" and visited[-1] == "DoneDismissed"
    assert store.get_case(cid)["status"] == "DISMISSED"
    assert lab.sgs() == [lab.sg]
    assert "NotifyDismissed" in visited and "notified:dismissed" in audit_actions(store, cid)


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


def _notify_only(store, cid, reason):
    """Out of scope is known before the human is asked: the card offers acknowledge/dismiss, never an approval that
    preflight would have to refuse."""
    from siemsoar.decisions import DecisionRejected

    def try_approve_then_acknowledge(gate, data, token):
        with pytest.raises(DecisionRejected, match="use acknowledge"):
            apply_decision(store, data["case_id"], gate, "approve", actor="slack:UTEST")
        apply_decision(store, data["case_id"], gate, "acknowledge", actor="slack:UTEST")

    outcome, _, visited = asl_runner.run(cid, CFG, try_approve_then_acknowledge)
    case = store.get_case(cid)
    assert outcome == "Succeed" and case["status"] == "ACKNOWLEDGED" and "Preflight" not in visited
    assert case["response_plan"]["type"] == "none" and reason in case["plan_note"]


@pytest.mark.parametrize("tags, reason", [({"siemsoar:protected": "true"}, "siemsoar:protected=true"),
                                          ({"siemsoar:zone": "security"}, "not in zone=workload")])
def test_out_of_scope_instance_is_notify_only(store, sfn, tags, reason):
    lab = Lab(tags=tags)
    cid = start(store, ev.guardduty_instance(lab.iid))
    _notify_only(store, cid, reason)
    assert lab.sgs() == [lab.sg]


def test_preflight_still_refuses_a_target_that_left_scope_while_awaiting_approval(store, sfn):
    """Enrich judged the instance in scope; the tag changed before the click. Preflight re-checks and fails safe."""
    lab = Lab()
    cid = start(store, ev.guardduty_instance(lab.iid))

    def protect_then_approve(gate, data, token):
        lab.ec2.create_tags(Resources=[lab.iid], Tags=[{"Key": "siemsoar:protected", "Value": "true"}])
        apply_decision(store, data["case_id"], gate, "approve", actor="slack:UTEST")

    outcome, _, _ = asl_runner.run(cid, CFG, protect_then_approve)
    case = store.get_case(cid)
    assert outcome == "Fail:CaseFailedSafe" and case["failure_error"] == "PreflightFailed"
    assert "no containment change" in case["safe_state"] and lab.sgs() == [lab.sg]


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
    # verify passed without a change: kept out of response times, read from the audit (the case has no dry_run)
    assert evaluate.dry_run({**store.get_case(cid), "audit": store.list_audit(cid)}) is True
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


def test_a_failed_case_is_recovered_by_hand_completely_and_audited(store, sfn, monkeypatch):
    """Lab 2026-10-19: a new alert merged after isolation blocked restore three times, the case FAILED with the host
    contained. `soarctl recover` (human-gated in the CLI) restores groups AND role sessions, verifies, and audits."""
    from tools import soarctl
    lab = Lab()
    cid = start(store, ev.guardduty_instance(lab.iid, fid="first"))
    queue = gates("approve", "restore_tp", "restore_tp", "restore_tp")

    def cb(gate, data, token):
        if gate == "restore" and len(queue.remaining) == 3:
            ingest_handler.handler(ev.guardduty_instance(lab.iid, fid="after-isolation"))  # merged into the case
        queue(gate, data, token)

    outcome, _, _ = asl_runner.run(cid, CFG, cb)
    case = store.get_case(cid)
    assert case["status"] == "FAILED" and case["failure_error"] == "RestoreBlocked" and case["merged_at"]
    assert lab.sgs() != [lab.sg] and response.has_revoke_policy(lab.role)   # left contained

    out = soarctl.recover(store, cid, "cli:UTEST", "the merged alert was our own test run", "arn:aws:iam::1:user/op")
    assert out["verified"] and lab.sgs() == [lab.sg] and not response.has_revoke_policy(lab.role)
    assert response.CASE_TAG not in response.describe_instance(lab.iid)["tags"]
    [entry] = [a for a in store.list_audit(cid) if a["action"] == "manual_recovery"]
    assert entry["actor"] == "cli:UTEST" and entry["detail"]["reason"].startswith("the merged alert")
    with pytest.raises(ValueError, match="not held by this case"):
        soarctl.recover(store, cid, "cli:UTEST", "again", "arn")  # nothing left to recover


def test_recover_restarts_an_instance_that_containment_stopped(store, sfn, monkeypatch):
    from tools import soarctl
    lab = Lab()
    cid = start(store, ev.guardduty_instance(lab.iid, sev=8.9))
    asl_runner.run(cid, {**CFG, "stop_risk_threshold": 70}, gates("approve", "timeout"))
    case = store.get_case(cid)
    assert case["status"] == "FAILED" and case["instance_stopped"]
    assert response.describe_instance(lab.iid)["state"] in {"stopping", "stopped"}
    assert soarctl.recover(store, cid, "cli:UTEST", "host cleared", "arn:aws:iam::1:user/op")["verified"]
    assert response.describe_instance(lab.iid)["state"] == "running"


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
    _notify_only(store, cid, "outside the containment scope")
    assert response.list_keys("prod-admin") == {key: "Active"}


def test_out_of_scope_iam_user_is_never_read(store, sfn, monkeypatch):
    """Lab session 2: the operator's key deleted a Stratus trail; the SOAR role may not read that user (AccessDenied
    failed the case). Scope is decided from the name alone, before any IAM call."""
    monkeypatch.setattr(response, "list_keys", lambda user: pytest.fail(f"read IAM user {user}"))
    cid = start(store, ev.guardduty_key(user="Huy", key="AKIAIOSFODNN7EXAMPLE"))
    _notify_only(store, cid, "IAM user Huy is outside the containment scope")


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


# ------------------------------------------------------------------ SDK-integration steps (no Lambda): audit + dry-run
def _audit_detail(store, cid, action):
    return next(a["detail"] for a in store.list_audit(cid) if a["action"] == action)


def test_stop_instance_sdk_step_writes_audit_and_case_flag(store, sfn):
    lab = Lab()
    cid = start(store, ev.guardduty_instance(lab.iid, sev=8.9))
    asl_runner.run(cid, {**CFG, "stop_risk_threshold": 70}, gates("approve", "restore_tp"))
    assert _audit_detail(store, cid, "contain:stop_instance") == {"stopped": True}
    assert store.get_case(cid)["instance_stopped"] is True  # written by dynamodb:updateItem, read by restore


def test_low_risk_skips_stop_and_audits_the_decision(store, sfn):
    lab = Lab()
    cid = start(store, ev.guardduty_instance(lab.iid, sev=4.0))
    asl_runner.run(cid, CFG, gates("approve", "restore_tp"))
    assert _audit_detail(store, cid, "contain:stop_instance")["stopped"] is False
    assert not store.get_case(cid).get("instance_stopped")
    assert response.describe_instance(lab.iid)["state"] in {"pending", "running"}


def test_dry_run_skips_sdk_calls_but_still_audits(store, sfn, iam_user):
    lab = Lab()
    cid = start(store, ev.guardduty_instance(lab.iid, sev=8.9))
    asl_runner.run(cid, {**CFG, "dry_run": True, "stop_risk_threshold": 70}, gates("approve", "restore_fp"))
    assert response.describe_instance(lab.iid)["state"] in {"pending", "running"}
    assert _audit_detail(store, cid, "contain:stop_instance") == {"stopped": False, "dry_run": True}
    kid = start(store, ev.guardduty_key(key=iam_user, fid="gd-dry"))
    asl_runner.run(kid, {**CFG, "dry_run": True}, gates("approve", "restore_fp"))
    assert response.list_keys("lab-alice") == {iam_user: "Active"}
    assert _audit_detail(store, kid, "contain:disable_key")["dry_run"] is True


def test_disable_key_sdk_step_audits_and_key_goes_inactive_before_restore(store, sfn, iam_user):
    cid = start(store, ev.guardduty_key(key=iam_user))
    seen = {}

    def cb(gate, data, token):
        if gate == "restore":
            seen["keys"] = response.list_keys("lab-alice")
        q(gate, data, token)

    q = gates("approve", "restore_fp")
    asl_runner.run(cid, CFG, cb)
    assert seen["keys"] == {iam_user: "Inactive"}
    assert _audit_detail(store, cid, "contain:disable_key") == {"status": "Inactive"}


# ------------------------------------------------------------------ the fail-safe reports what was actually reached
def _boom(message):
    def fail(*args, **kwargs):
        raise RuntimeError(message)
    return fail


def _inject(monkeypatch, point):
    monkeypatch.setenv("LAB_FAULTS_ENABLED", "true")
    monkeypatch.setenv("FAULT_INJECT", point)


def _sdk_step(monkeypatch, action, replacement):
    """Replace one Step Functions SDK integration (no Lambda behind it, so there is no fault seam)."""
    real = asl_runner._call_sdk

    def call(resource, params):
        return replacement(resource, params) if resource.endswith(action) else real(resource, params)

    monkeypatch.setattr(asl_runner, "_call_sdk", call)


def _reached(store, cid):
    case = store.get_case(cid)
    assert case["status"] == "FAILED" and "notified:failed" in audit_actions(store, cid)  # the operator is alerted
    return case["safe_state"], case["containment_reached"]["level"]


@pytest.mark.parametrize("point, snapshots", [("contain.snapshot", 0), ("contain.isolate_network", 1)])
def test_failure_before_the_network_is_isolated_is_not_reported_as_contained(store, sfn, monkeypatch, point, snapshots):
    _inject(monkeypatch, point)
    lab = Lab()
    cid = start(store, ev.guardduty_instance(lab.iid))
    outcome, _, _ = asl_runner.run(cid, CFG, gates("approve"))
    safe, level = _reached(store, cid)
    assert outcome == "Fail:CaseFailedSafe" and level == "none" and lab.sgs() == [lab.sg]
    assert safe.startswith("resource NOT contained") and f"{snapshots} evidence snapshot(s) recorded" in safe
    assert "CONTAINED" not in safe


def test_failure_halfway_through_the_interfaces_reports_the_partial_isolation(store, sfn, monkeypatch):
    from tests.unit.test_response import _two_nic_lab
    lab, eni, other = _two_nic_lab()
    real = response._set_groups

    def primary_only(info, target):
        real(info, {n["id"]: target[n["id"]] for n in info["network_interfaces"] if n["device_index"] == 0})
        raise RuntimeError("secondary interface failed")

    monkeypatch.setattr(response, "_set_groups", primary_only)
    cid = start(store, ev.guardduty_instance(lab.iid))
    asl_runner.run(cid, CFG, gates("approve"))
    safe, level = _reached(store, cid)
    assert level == "partial" and safe.startswith("resource only PARTIALLY contained")
    assert "network isolated on 1 of 2 interfaces only" in safe


def test_failure_at_session_revocation_keeps_the_isolation_but_says_it_is_incomplete(store, sfn, monkeypatch):
    _inject(monkeypatch, "contain.revoke_sessions")
    lab = Lab()
    cid = start(store, ev.guardduty_instance(lab.iid))
    asl_runner.run(cid, CFG, gates("approve"))
    safe, level = _reached(store, cid)
    assert level == "partial" and safe.startswith("resource network CONTAINED only") and lab.sgs() != [lab.sg]
    assert "instance role sessions NOT revoked" in safe


def test_failure_at_stop_instance_is_contained_and_says_the_instance_still_runs(store, sfn, monkeypatch):
    _sdk_step(monkeypatch, "stopInstances", _boom("ec2 down"))
    lab = Lab()
    cid = start(store, ev.guardduty_instance(lab.iid, sev=8.9))
    asl_runner.run(cid, {**CFG, "stop_risk_threshold": 70}, gates("approve"))
    safe, level = _reached(store, cid)
    assert level == "full" and safe.startswith("resource left CONTAINED") and "instance running" in safe


def test_failure_at_disable_key_is_not_reported_as_contained(store, sfn, monkeypatch, iam_user):
    _sdk_step(monkeypatch, "updateAccessKey", _boom("iam down"))
    cid = start(store, ev.guardduty_key(key=iam_user))
    outcome, _, visited = asl_runner.run(cid, CFG, gates("approve"))
    safe, level = _reached(store, cid)
    assert outcome == "Fail:CaseFailedSafe" and "DisableKey" in visited and level == "none"
    assert safe.startswith("resource NOT contained") and "access key Active" in safe
    assert response.list_keys("lab-alice") == {iam_user: "Active"}


def test_failure_after_disable_key_reports_the_key_contained_and_the_sessions_open(store, sfn, monkeypatch, iam_user):
    monkeypatch.setattr(response, "revoke_user_sessions", _boom("iam down"))
    cid = start(store, ev.guardduty_key(key=iam_user))
    asl_runner.run(cid, CFG, gates("approve"))
    safe, level = _reached(store, cid)
    assert level == "partial" and safe.startswith("access key CONTAINED only")
    assert "access key Inactive" in safe and "user sessions NOT revoked" in safe


def test_failure_in_restoring_before_any_change_stays_contained(store, sfn, monkeypatch):
    monkeypatch.setattr(response, "restore_instance_sgs", _boom("ec2 down"))
    lab = Lab()
    cid = start(store, ev.guardduty_instance(lab.iid))
    asl_runner.run(cid, CFG, gates("approve", "restore_fp"))
    safe, level = _reached(store, cid)
    assert level == "full" and safe.startswith("resource left CONTAINED") and lab.sgs() != [lab.sg]


def test_failure_in_restoring_after_the_groups_went_back_is_not_reported_as_contained(store, sfn, monkeypatch):
    monkeypatch.setattr(response, "restore_role_sessions", _boom("iam down"))
    lab = Lab()
    cid = start(store, ev.guardduty_instance(lab.iid))
    asl_runner.run(cid, CFG, gates("approve", "restore_fp"))
    safe, level = _reached(store, cid)
    assert lab.sgs() == [lab.sg] and response.has_revoke_policy(lab.role)
    assert level == "partial" and safe.startswith("resource only PARTIALLY contained")
    assert "network NOT isolated" in safe and "instance role sessions revoked" in safe


def test_failure_in_restoring_when_everything_was_undone_reports_not_contained(store, sfn, monkeypatch):
    monkeypatch.setattr(response, "ec2_matches_state", lambda *a, **k: (False, "mismatch"))
    lab = Lab()
    cid = start(store, ev.guardduty_instance(lab.iid))
    asl_runner.run(cid, CFG, gates("approve", "restore_fp"))
    safe, level = _reached(store, cid)
    assert lab.sgs() == [lab.sg] and not response.has_revoke_policy(lab.role)
    assert level == "none" and safe.startswith("resource NOT contained")


def test_failure_restarting_the_instance_reports_it_is_still_stopped(store, sfn, monkeypatch):
    monkeypatch.setattr(response, "set_instance_running", _boom("ec2 down"))
    lab = Lab()
    cid = start(store, ev.guardduty_instance(lab.iid, sev=8.9))
    asl_runner.run(cid, {**CFG, "stop_risk_threshold": 70}, gates("approve", "restore_fp"))
    safe, level = _reached(store, cid)
    assert lab.sgs() == [lab.sg] and level == "partial" and "instance stopped" in safe


def test_failure_while_the_api_is_unreadable_falls_back_to_the_audit_trail(store, sfn, monkeypatch):
    """Low risk: the stop step is audited as skipped, and must not be listed among the completed steps."""
    from handlers import case_ops
    monkeypatch.setattr(case_ops, "_observe_ec2", _boom("api down"))
    monkeypatch.setattr(response, "has_revoke_policy", lambda role: False)  # VerifyContainment fails
    lab = Lab()
    cid = start(store, ev.guardduty_instance(lab.iid, sev=4.0))
    asl_runner.run(cid, CFG, gates("approve"))
    safe, level = _reached(store, cid)
    assert level == "unknown" and "containment state UNKNOWN (API check failed: RuntimeError)" in safe
    assert "contain:snapshot, contain:isolate_network, contain:revoke_sessions" in safe
    assert "contain:stop_instance" not in safe


def test_failure_in_a_dry_run_reports_that_nothing_changed(store, sfn, monkeypatch):
    _inject(monkeypatch, "contain.snapshot")
    lab = Lab()
    cid = start(store, ev.guardduty_instance(lab.iid))
    asl_runner.run(cid, {**CFG, "dry_run": True}, gates("approve"))
    safe, level = _reached(store, cid)
    assert level == "none" and safe.startswith("dry run") and store.get_case(cid)["dry_run"] is True


def test_a_hung_api_cannot_cost_the_fail_safe_its_alert(store, sfn, monkeypatch):
    """The look-up is bounded: Lambda would otherwise be killed before the FAILED transition and the alert."""
    import threading

    from handlers import case_ops
    release, sent = threading.Event(), []
    monkeypatch.setattr(case_ops, "OBSERVE_SECONDS", 0.05)
    monkeypatch.setattr(case_ops, "_observe_ec2", lambda case: release.wait(5))
    monkeypatch.setattr(case_ops, "notify_case", lambda case, kind, **k: sent.append(kind) or {})
    _inject(monkeypatch, "contain.revoke_sessions")
    lab = Lab()
    cid = start(store, ev.guardduty_instance(lab.iid))
    try:
        asl_runner.run(cid, CFG, gates("approve"))
    finally:
        release.set()
    case = store.get_case(cid)
    assert case["status"] == "FAILED" and sent == ["failed"]
    assert case["containment_reached"]["level"] == "unknown" and "TimeoutError" in case["safe_state"]


def test_a_retried_fail_safe_keeps_the_state_the_first_attempt_found(store, sfn, monkeypatch):
    """A Lambda retry finds the case already FAILED: its status must not turn the report into 'no containment change'."""
    from handlers import case_ops
    _inject(monkeypatch, "contain.revoke_sessions")
    lab = Lab()
    cid = start(store, ev.guardduty_instance(lab.iid))
    asl_runner.run(cid, CFG, gates("approve"))
    first, level = _reached(store, cid)
    out = case_ops.handler({"op": "fail_safe", "state": {"case_id": cid, "config": CFG}})
    assert out == {"status": "FAILED", "safe_state": first, "containment": level}


# ------------------------------------------------------------------ verification re-reads every containment action
def _assert_not_verified(store, cid, check):
    case = store.get_case(cid)
    assert case["status"] == "FAILED" and case["failure_error"] == "VerificationFailed"
    assert check in case["failure_cause"] and "containment_verification" not in case


def _fake_snapshot(monkeypatch, snapshot_id="snap-0123456789abcdef0"):
    monkeypatch.setattr(response, "snapshot_volumes", lambda *a, **k: [snapshot_id])


def test_verify_refuses_a_snapshot_that_does_not_exist(store, sfn, monkeypatch):
    _fake_snapshot(monkeypatch)
    lab = Lab()
    cid = start(store, ev.guardduty_instance(lab.iid))
    asl_runner.run(cid, CFG, gates("approve"))
    _assert_not_verified(store, cid, "evidence_snapshots")


def test_verify_refuses_a_containment_with_no_evidence_snapshot(store, sfn, monkeypatch):
    monkeypatch.setattr(response, "snapshot_volumes", lambda *a, **k: [])  # the instance has a root volume
    lab = Lab()
    cid = start(store, ev.guardduty_instance(lab.iid))
    asl_runner.run(cid, CFG, gates("approve"))
    _assert_not_verified(store, cid, "evidence_snapshots")


@pytest.mark.parametrize("snapshot", [{"state": "completed", "case": "C-OTHER"}, {"state": "error", "case": None}])
def test_verify_refuses_a_snapshot_of_another_case_or_in_error(store, sfn, monkeypatch, snapshot):
    lab = Lab()
    cid = start(store, ev.guardduty_instance(lab.iid))
    fixed = {**snapshot, "case": snapshot["case"] or cid}
    monkeypatch.setattr(response, "describe_snapshots", lambda ids: {i: fixed for i in ids})
    asl_runner.run(cid, CFG, gates("approve"))
    _assert_not_verified(store, cid, "evidence_snapshots")


def test_verify_accepts_a_snapshot_still_pending(store, sfn, monkeypatch):
    lab = Lab()
    cid = start(store, ev.guardduty_instance(lab.iid))
    monkeypatch.setattr(response, "describe_snapshots", lambda ids: {i: {"state": "pending", "case": cid} for i in ids})
    asl_runner.run(cid, CFG, gates("approve", "restore_fp"))
    assert store.get_case(cid)["containment_verification"] == "ok"


def test_verify_refuses_an_instance_that_did_not_stop(store, sfn, monkeypatch):
    _sdk_step(monkeypatch, "stopInstances", lambda resource, params: {})  # accepted, but the instance keeps running
    lab = Lab()
    cid = start(store, ev.guardduty_instance(lab.iid, sev=8.9))
    asl_runner.run(cid, {**CFG, "stop_risk_threshold": 70}, gates("approve"))
    _assert_not_verified(store, cid, "instance_stopped")


def test_verify_refuses_a_role_session_revocation_that_is_not_in_place(store, sfn, monkeypatch):
    monkeypatch.setattr(response, "revoke_role_sessions", lambda role, dry=False: {"role": role, "changed": True})
    lab = Lab()
    cid = start(store, ev.guardduty_instance(lab.iid))
    asl_runner.run(cid, CFG, gates("approve"))
    _assert_not_verified(store, cid, "role_sessions_revoked")


def test_verify_lists_every_check_it_made(store, sfn):
    lab = Lab()
    cid = start(store, ev.guardduty_instance(lab.iid, sev=8.9))
    asl_runner.run(cid, {**CFG, "stop_risk_threshold": 70}, gates("approve", "restore_tp"))
    detail = _audit_detail(store, cid, "status:ISOLATED")
    assert detail["verification"] == "ok" and detail["checks"] == {
        "network_isolated": True, "evidence_snapshots": True, "role_sessions_revoked": True, "instance_stopped": True}


def test_verify_refuses_a_user_session_revocation_that_is_not_in_place(store, sfn, monkeypatch, iam_user):
    monkeypatch.setattr(response, "revoke_user_sessions", lambda user, dry=False: {"user": user, "changed": True})
    cid = start(store, ev.guardduty_key(key=iam_user))
    asl_runner.run(cid, CFG, gates("approve"))
    _assert_not_verified(store, cid, "user_sessions_revoked")


def test_verify_refuses_a_key_that_is_still_active(store, sfn, monkeypatch, iam_user):
    _sdk_step(monkeypatch, "updateAccessKey", lambda resource, params: {})
    cid = start(store, ev.guardduty_key(key=iam_user))
    asl_runner.run(cid, CFG, gates("approve"))
    _assert_not_verified(store, cid, "key_disabled")


def test_a_dry_run_is_recorded_as_a_dry_run_and_never_announced_as_verified(store, sfn, monkeypatch):
    from siemsoar import notifier
    sent = []
    monkeypatch.setattr(notifier, "sns_publish", lambda subject, text: sent.append(f"{subject}\n{text}"))
    lab = Lab()
    cid = start(store, ev.guardduty_instance(lab.iid))
    outcome, data, _ = asl_runner.run(cid, {**CFG, "dry_run": True}, gates("approve", "restore_fp"))
    case = store.get_case(cid)
    assert outcome == "Succeed" and case["dry_run"] is True
    assert case["containment_verification"] == "dry_run" and case["restore_verification"] == "dry_run"
    assert data["steps"]["verify"]["out"]["verified"] is False
    assert data["steps"]["verify_restore"]["out"]["verified"] is False
    assert _audit_detail(store, cid, "status:ISOLATED")["verification"] == "dry_run"
    assert _audit_detail(store, cid, "status:RESTORED")["verification"] == "dry_run"
    blob = "\n".join(sent)
    assert "Containment verified" not in blob and "Restore verified" not in blob and "nothing was contained" in blob
    assert "Dry run: nothing was restored" in blob  # the notice's title, not only its detail line


# ------------------------------------------------------------------ restore verification
def test_verify_restore_requires_the_instance_to_run_again(store, sfn, monkeypatch):
    monkeypatch.setattr(response, "set_instance_running",
                        lambda iid, running, dry=False: {"instance_id": iid, "changed": True})
    lab = Lab()
    cid = start(store, ev.guardduty_instance(lab.iid, sev=8.9))
    asl_runner.run(cid, {**CFG, "stop_risk_threshold": 70}, gates("approve", "restore_tp"))
    case = store.get_case(cid)
    assert case["status"] == "FAILED" and case["failure_error"] == "VerificationFailed"
    assert "instance stopped" in case["failure_cause"]


def test_verify_restore_does_not_require_running_when_the_instance_was_never_stopped(store, sfn):
    lab = Lab()
    cid = start(store, ev.guardduty_instance(lab.iid, sev=4.0))
    queue = gates("approve", "restore_fp")

    def cb(gate, data, token):
        if gate == "restore":  # running when its state was saved; an operator stopped it, containment did not
            lab.ec2.stop_instances(InstanceIds=[lab.iid])
        queue(gate, data, token)

    asl_runner.run(cid, CFG, cb)
    case = store.get_case(cid)
    assert case["restore_verification"] == "ok" and not case.get("instance_stopped")


def test_verify_restore_requires_running_not_just_a_start_in_progress(monkeypatch):
    pre = {"network_interfaces": [], "security_groups": ["sg-1"]}
    state = {"security_groups": ["sg-1"], "network_interfaces": [], "tags": {}}
    for current, expected in (("pending", False), ("running", True)):
        monkeypatch.setattr(response, "describe_instance", lambda iid, s=current: {**state, "state": s})
        assert response.ec2_matches_state("i-1", pre, expect_running=True)[0] is expected


def test_rotation_is_not_verified_without_a_working_replacement_key(store, sfn, monkeypatch, iam_user):
    def rotate_without_replacement(user, key, *a, **k):
        boto3.client("iam").delete_access_key(UserName=user, AccessKeyId=key)  # the old key goes, nothing replaces it
        return {"new_access_key_id": "AKIAIOSFODNN7EXAMPLE"}

    monkeypatch.setattr(response, "rotate_key", rotate_without_replacement)
    cid = start(store, ev.guardduty_key(key=iam_user))
    outcome, _, _ = asl_runner.run(cid, CFG, gates("approve", "restore_tp"))
    case = store.get_case(cid)
    assert outcome == "Fail:CaseFailedSafe" and case["failure_error"] == "VerificationFailed"


@pytest.mark.parametrize("target, decision", [("set_key_status", "restore_fp"), ("restore_user_sessions", "restore_fp"),
                                              ("rotate_key", "restore_tp")])
def test_verify_restore_rechecks_the_iam_key_and_sessions(store, sfn, monkeypatch, iam_user, target, decision):
    monkeypatch.setattr(response, target, lambda *a, **k: {"new_access_key_id": "AKIAIOSFODNN7EXAMPLE"})
    cid = start(store, ev.guardduty_key(key=iam_user))
    outcome, _, _ = asl_runner.run(cid, CFG, gates("approve", decision))
    case = store.get_case(cid)
    assert outcome == "Fail:CaseFailedSafe" and case["failure_error"] == "VerificationFailed"
    assert "restore_verification" not in case


def test_a_failed_dismiss_notice_still_closes_the_case(store, sfn, monkeypatch):
    from handlers import notify
    real = notify.notify_case

    def down_for_the_dismissal(case, kind, **kwargs):
        if kind == "dismissed":
            raise RuntimeError("slack and sns down")
        return real(case, kind, **kwargs)

    monkeypatch.setattr(notify, "notify_case", down_for_the_dismissal)
    lab = Lab()
    cid = start(store, ev.guardduty_instance(lab.iid))
    outcome, _, visited = asl_runner.run(cid, CFG, gates("dismiss"))
    assert outcome == "Succeed" and visited[-2:] == ["NotifyDismissed", "DoneDismissed"]
    assert store.get_case(cid)["status"] == "DISMISSED"
