import json
import os

import boto3
import pytest
from moto import mock_aws

os.environ.update({
    "AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing", "AWS_SESSION_TOKEN": "testing",
    "AWS_DEFAULT_REGION": "ap-southeast-1", "AWS_REGION": "ap-southeast-1",
    "CASES_TABLE": "siemsoar-cases", "EVIDENCE_BUCKET": "siemsoar-evidence-test", "NAME_PREFIX": "siemsoar",
    "STATE_MACHINE_ARN": "arn:aws:states:ap-southeast-1:123456789012:stateMachine:siemsoar-case-workflow",
})

REGION = "ap-southeast-1"


def _table(ddb):
    ddb.create_table(
        TableName="siemsoar-cases", BillingMode="PAY_PER_REQUEST",
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": a, "AttributeType": "S"} for a in
                              ("pk", "sk", "dedup_key", "resource_id", "created_at", "status")],
        GlobalSecondaryIndexes=[
            {"IndexName": "dedup-index", "KeySchema": [{"AttributeName": "dedup_key", "KeyType": "HASH"}],
             "Projection": {"ProjectionType": "ALL"}},
            {"IndexName": "resource-index", "KeySchema": [{"AttributeName": "resource_id", "KeyType": "HASH"},
                                                          {"AttributeName": "created_at", "KeyType": "RANGE"}],
             "Projection": {"ProjectionType": "ALL"}},
            {"IndexName": "status-index", "KeySchema": [{"AttributeName": "status", "KeyType": "HASH"},
                                                        {"AttributeName": "created_at", "KeyType": "RANGE"}],
             "Projection": {"ProjectionType": "ALL"}}])


@pytest.fixture(autouse=True)
def aws_env():
    from siemsoar import aws, ssm
    with mock_aws():
        aws.reset()
        ssm.clear()
        _table(boto3.client("dynamodb", region_name=REGION))
        boto3.client("s3", region_name=REGION).create_bucket(
            Bucket="siemsoar-evidence-test", CreateBucketConfiguration={"LocationConstraint": REGION})
        topic = boto3.client("sns", region_name=REGION).create_topic(Name="siemsoar-notify")["TopicArn"]
        os.environ["NOTIFY_TOPIC_ARN"] = topic
        yield
        aws.reset()


@pytest.fixture
def store():
    from siemsoar.store import CaseStore
    return CaseStore()


class FakeSfn:
    """Minimal Step Functions stub: records executions and task results."""

    class exceptions:  # noqa: N801
        class TaskTimedOut(Exception):
            pass

    def __init__(self):
        self.started, self.success = [], []
        self.fail_start = False

    def start_execution(self, **kw):
        if self.fail_start:
            raise RuntimeError("boom")
        self.started.append(kw)
        return {"executionArn": f"arn:exec:{kw['name']}"}

    def send_task_success(self, taskToken, output):
        self.success.append((taskToken, json.loads(output)))


@pytest.fixture
def sfn(monkeypatch):
    from siemsoar import aws
    fake = FakeSfn()
    real = aws.client

    def patched(service):
        return fake if service == "stepfunctions" else real(service)

    monkeypatch.setattr(aws, "client", patched)
    return fake
