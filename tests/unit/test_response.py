"""Containment primitives that Step Functions may retry: they must converge, not fail or leak credentials."""

import json

import boto3
import pytest
from siemsoar import aws, response

R = "ap-southeast-1"


@pytest.fixture
def iam_user():
    iam = boto3.client("iam", region_name=R)
    iam.create_user(UserName="lab-bob")
    return iam, iam.create_access_key(UserName="lab-bob")["AccessKey"]["AccessKeyId"]


def test_rotate_key_is_idempotent_when_the_step_is_retried(iam_user):
    iam, old = iam_user
    first = response.rotate_key("lab-bob", old, "/siemsoar")
    again = response.rotate_key("lab-bob", old, "/siemsoar")  # retry after the first attempt finished
    assert first["rotated"] and again["rotated"] and again["reused_replacement"]
    assert again["new_access_key_id"] == first["new_access_key_id"]
    keys = response.list_keys("lab-bob")
    assert list(keys) == [first["new_access_key_id"]]  # exactly one live key: no third key was issued
    assert "SecretAccessKey" not in json.dumps(again)


def test_rotate_key_resumes_when_the_old_key_is_already_gone(iam_user):
    iam, old = iam_user
    iam.delete_access_key(UserName="lab-bob", AccessKeyId=old)  # crashed right after the delete
    out = response.rotate_key("lab-bob", old, "/siemsoar")
    assert out["rotated"] and list(response.list_keys("lab-bob")) == [out["new_access_key_id"]]


def test_rotate_key_never_leaves_an_unrecorded_credential(iam_user, monkeypatch):
    iam, old = iam_user
    real = aws.client

    class BrokenSecrets:
        def __init__(self, inner):
            self.inner, self.exceptions = inner, inner.exceptions

        def get_secret_value(self, **kw):
            raise self.inner.exceptions.ResourceNotFoundException({"Error": {"Code": "ResourceNotFoundException"}}, "x")

        def create_secret(self, **kw):
            raise RuntimeError("secrets manager unavailable")

    monkeypatch.setattr(aws, "client", lambda s: BrokenSecrets(real(s)) if s == "secretsmanager" else real(s))
    with pytest.raises(RuntimeError):
        response.rotate_key("lab-bob", old, "/siemsoar")
    assert response.list_keys("lab-bob") == {}  # the freshly issued key was removed again


# ------------------------------------------------------------------ containment must cover every network interface
def _two_nic_lab():
    from tests.unit.test_workflow import Lab
    lab = Lab()
    ec2 = lab.ec2
    info = response.describe_instance(lab.iid)
    other = ec2.create_security_group(GroupName="secondary-nic", Description="d", VpcId=info["vpc_id"])["GroupId"]
    eni = ec2.create_network_interface(SubnetId=info["subnet_id"], Groups=[other])["NetworkInterface"]["NetworkInterfaceId"]
    ec2.attach_network_interface(NetworkInterfaceId=eni, InstanceId=lab.iid, DeviceIndex=1)
    return lab, eni, other


def test_isolation_covers_secondary_interfaces_and_restore_puts_each_group_back():
    lab, eni, other = _two_nic_lab()
    before = response.describe_instance(lab.iid)
    assert len(before["network_interfaces"]) == 2

    out = response.isolate_instance(lab.iid, "C-1")
    sg = out["isolation_sg"]
    after = response.describe_instance(lab.iid)
    assert response.is_isolated(after, sg)
    assert response.eni_groups(after)[eni] == [sg]  # the secondary NIC is cut too, not only the primary
    assert out["previous_eni_groups"][eni] == response.eni_groups(before)[eni] and other in out["previous_eni_groups"][eni]

    response.restore_instance_sgs(lab.iid, before["security_groups"], groups_by_eni=response.eni_groups(before))
    assert response.eni_groups(response.describe_instance(lab.iid)) == response.eni_groups(before)


def test_isolation_is_not_reported_verified_while_a_secondary_interface_is_still_open():
    lab, eni, other = _two_nic_lab()
    info = response.describe_instance(lab.iid)
    sg = response.ensure_isolation_sg(info["vpc_id"])
    lab.ec2.modify_instance_attribute(InstanceId=lab.iid, Groups=[sg])  # only the primary NIC was changed
    assert response.describe_instance(lab.iid)["security_groups"] == [sg]
    assert response.is_isolated(response.describe_instance(lab.iid), sg) is False


def test_isolation_sg_creation_tolerates_a_concurrent_creator(monkeypatch):
    from tests.unit.test_workflow import Lab
    lab = Lab()
    vpc = response.describe_instance(lab.iid)["vpc_id"]
    real = aws.client("ec2")
    existing = response.ensure_isolation_sg(vpc)

    class Racing:
        """First lookup misses (the other case has not created it yet), create then reports the duplicate."""

        def __init__(self):
            self.lookups = 0

        def __getattr__(self, name):
            return getattr(real, name)

        def describe_security_groups(self, **kw):
            self.lookups += 1
            return {"SecurityGroups": []} if self.lookups == 1 else real.describe_security_groups(**kw)

    racing = Racing()
    monkeypatch.setattr(aws, "client", lambda s: racing if s == "ec2" else boto3.client(s, region_name=R))
    assert response.ensure_isolation_sg(vpc) == existing


def test_a_prepared_isolation_group_is_used_as_is():
    """The lab's Terraform creates the isolation SG with one egress rule (Wazuh agent -> manager 1514/tcp): the Lambda
    must find it by name and keep that rule, otherwise an isolated host would stop reporting to the SIEM."""
    ec2 = boto3.client("ec2", region_name=R)
    vpc = ec2.create_vpc(CidrBlock="10.9.0.0/16")["Vpc"]["VpcId"]
    manager = ec2.create_security_group(GroupName="mgr", Description="m", VpcId=vpc)["GroupId"]
    iso = ec2.create_security_group(GroupName=response.ISOLATION_SG_NAME, Description="i", VpcId=vpc)["GroupId"]
    ec2.revoke_security_group_egress(GroupId=iso, IpPermissions=[{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    ec2.authorize_security_group_egress(GroupId=iso, IpPermissions=[{
        "IpProtocol": "tcp", "FromPort": 1514, "ToPort": 1514, "UserIdGroupPairs": [{"GroupId": manager}]}])
    assert response.ensure_isolation_sg(vpc) == iso
    egress = ec2.describe_security_groups(GroupIds=[iso])["SecurityGroups"][0]["IpPermissionsEgress"]
    assert [(e["FromPort"], e["UserIdGroupPairs"][0]["GroupId"]) for e in egress] == [(1514, manager)]


def test_the_terraform_isolation_group_matches_what_the_lambda_looks_for():
    import re
    from pathlib import Path
    tf = (Path(__file__).resolve().parents[2] / "infra/modules/lab-ondemand/network.tf").read_text()
    block = re.search(r'resource "aws_security_group" "isolation" \{(.*?)\n\}', tf, re.S).group(1)
    assert f'name        = "{response.ISOLATION_SG_NAME}"' in block and 'ManagedBy = "siemsoar"' in block
    egress = re.findall(r'resource "aws_vpc_security_group_egress_rule" "(\w+)" \{(.*?)\n\}', tf, re.S)
    iso_egress = [body for _, body in egress if "aws_security_group.isolation.id" in body.split("\n")[1]]
    assert len(iso_egress) == 1 and "aws_security_group.manager.id" in iso_egress[0] and "1514" in iso_egress[0]
    assert re.search(r'security_group_id\s+= aws_security_group.manager.id\s+referenced_security_group_id = '
                     r'aws_security_group.isolation.id', tf)
