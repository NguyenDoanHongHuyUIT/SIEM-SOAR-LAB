import json

import boto3
import pytest
from botocore.exceptions import WaiterError

from tools import release, rulesctl

R = "ap-southeast-1"


class FakeSsm:
    def __init__(self, status="Success"):
        self.status, self.sent = status, []

    def send_command(self, **kw):
        self.sent.append(kw)
        return {"Command": {"CommandId": "cmd-1"}}

    def get_command_invocation(self, CommandId, InstanceId):  # noqa: N803
        return {"Status": self.status, "StandardErrorContent": "analysisd -t failed" if self.status != "Success" else ""}

    def get_waiter(self, name):
        assert name == "command_executed"
        outer = self

        class _Waiter:
            def wait(self, CommandId, InstanceId, WaiterConfig=None):  # noqa: N803
                if outer.status != "Success":
                    raise WaiterError(name, "Waiter encountered a terminal failure state", {})

        return _Waiter()


@pytest.fixture
def env(monkeypatch, tmp_path):
    from siemsoar import aws
    s3 = boto3.client("s3", region_name=R)
    acct = boto3.client("sts", region_name=R).get_caller_identity()["Account"]
    bucket = f"siemsoar-rules-{acct}"
    s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": R})
    rulesctl.build(tmp_path / "dist", "abc1234", commit_time="2026-10-06T10:00:00+00:00")
    ssm = FakeSsm()
    real = aws.client
    monkeypatch.setattr(aws, "client", lambda svc: ssm if svc == "ssm" else real(svc))
    return bucket, ssm, tmp_path / "dist"


def _lab(roles=("wazuh-manager", "suricata-sensor")):
    ec2 = boto3.client("ec2", region_name=R)
    for role in roles:
        ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1, TagSpecifications=[{
            "ResourceType": "instance", "Tags": [{"Key": "siemsoar:role", "Value": role},
                                                 {"Key": "siemsoar:plane", "Value": "ondemand"}]}])


def test_publish_uploads_deploys_and_records_lead_time(env):
    bucket, ssm, dist = env
    _lab()
    from datetime import UTC, datetime, timedelta
    committed = (datetime.now(UTC) - timedelta(minutes=5)).isoformat()
    doc = release.publish("siemsoar", dist, "abc1234", committed)
    s3 = boto3.client("s3", region_name=R)
    assert release.get_current(bucket) == "abc1234"
    keys = {o["Key"] for o in s3.list_objects_v2(Bucket=bucket, Prefix="releases/abc1234/")["Contents"]}
    assert {"releases/abc1234/manifest.json", "releases/abc1234/wazuh/siemsoar_rules.xml",
            "releases/abc1234/suricata/siemsoar.rules", "releases/abc1234/deployment.json"} <= keys
    assert [t["status"] for t in doc["targets"]] == ["deployed", "deployed"]
    assert {c["Parameters"]["Target"][0] for c in ssm.sent} == {"manager", "sensor"}
    assert all(c["DocumentName"] == "siemsoar-deploy-rules" and c["Parameters"]["Release"] == ["abc1234"] for c in ssm.sent)
    from evaluation import evaluate
    lead = evaluate.compute_metrics([], [], {}, deployments=[doc])["rule_deployment_lead_time_s"]
    assert lead["n"] == 1 and lead["p50"] > 0


def test_publish_with_lab_off_stores_release_for_next_boot(env):
    bucket, ssm, dist = env
    doc = release.publish("siemsoar", dist, "abc1234", None)
    assert {t["status"] for t in doc["targets"]} == {"skipped_lab_off"} and not ssm.sent
    assert release.get_current(bucket) == "abc1234"


def test_failed_host_validation_keeps_current_release(env):
    bucket, ssm, dist = env
    release.set_current("old0000", bucket)
    _lab()
    ssm.status = "Failed"
    with pytest.raises(SystemExit) as e:
        release.publish("siemsoar", dist, "abc1234", None)
    assert "deployment failed" in str(e.value)
    assert release.get_current(bucket) == "old0000"  # current did not move
    rec = json.loads(boto3.client("s3", region_name=R).get_object(
        Bucket=bucket, Key="releases/abc1234/deployment.json")["Body"].read())
    assert rec["targets"][0]["status"] == "failed"


def test_rollback_redeploys_old_release_and_moves_pointer(env):
    bucket, ssm, dist = env
    release.upload(dist, "abc1234", bucket)
    release.set_current("new9999", bucket)
    _lab()
    out = release.rollback("siemsoar", "abc1234")
    assert out["rolled_back_to"] == "abc1234" and release.get_current(bucket) == "abc1234"
    with pytest.raises(SystemExit):
        release.rollback("siemsoar", "doesnotexist")


def test_export_evidence_bundles_cases_and_hashes(store, sfn, tmp_path, env):
    import hashlib

    from handlers import ingest as ingest_handler

    from tests.fixtures import events as ev
    from tools import export_evidence
    bucket, ssm, dist = env
    release.upload(dist, "abc1234", bucket)
    boto3.client("s3", region_name=R).create_bucket(
        Bucket="siemsoar-evidence-123456789012", CreateBucketConfiguration={"LocationConstraint": R})
    ingest_handler.handler(ev.guardduty_instance())
    out = tmp_path / "export"
    manifest = export_evidence.export("siemsoar", out)
    assert manifest["cases"] == 1 and manifest["s3_objects"] >= 3
    cases = json.loads((out / "cases.json").read_text())
    assert cases[0]["audit"][0]["action"] == "case_created"
    for rel, digest in manifest["files"].items():
        assert hashlib.sha256((out / rel).read_bytes()).hexdigest() == digest
    assert (out / "runs.json").exists() and (out / "deployments.json").exists()
