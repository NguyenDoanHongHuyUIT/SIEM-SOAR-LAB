"""Containment & restore primitives (EC2 isolation, IAM key disable, session revocation).

Every mutating function takes dry_run and returns a description of what was (or would be) done, so
the same code path is exercised in demo (dry run) and real mode.
"""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from . import aws
from .util import iso

ISOLATION_SG_NAME = "siemsoar-isolation"
CASE_TAG = "siemsoar:isolated-case"
REVOKE_POLICY = "AWSRevokeOlderSessions"
REVOKE_SIDE = "SiemSoarRevoke"


class NotFound(Exception):
    pass


# ---------------------------------------------------------------- EC2
def describe_instance(instance_id: str) -> dict:
    ec2 = aws.client("ec2")
    try:
        res = ec2.describe_instances(InstanceIds=[instance_id])
    except ClientError as err:
        if err.response["Error"]["Code"].startswith("InvalidInstanceID"):
            raise NotFound(instance_id) from err
        raise
    inst = res["Reservations"][0]["Instances"][0]
    tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
    profile = inst.get("IamInstanceProfile", {}).get("Arn")
    return {
        "instance_id": instance_id,
        "state": inst["State"]["Name"],
        "vpc_id": inst.get("VpcId"),
        "subnet_id": inst.get("SubnetId"),
        "security_groups": sorted(g["GroupId"] for g in inst.get("SecurityGroups", [])),
        "tags": tags,
        "name": tags.get("Name"),
        "public_ip": inst.get("PublicIpAddress"),
        "instance_profile_arn": profile,
        "volumes": [b["Ebs"]["VolumeId"] for b in inst.get("BlockDeviceMappings", []) if "Ebs" in b],
    }


def instance_role_name(profile_arn: str | None) -> str | None:
    if not profile_arn:
        return None
    name = profile_arn.rsplit("/", 1)[-1]
    try:
        roles = aws.client("iam").get_instance_profile(InstanceProfileName=name)["InstanceProfile"]["Roles"]
    except ClientError:
        return None
    return roles[0]["RoleName"] if roles else None


def check_modify_permission(instance_id: str) -> bool:
    """EC2 DryRun: DryRunOperation means 'would have succeeded'; UnauthorizedOperation means no permission."""
    try:
        aws.client("ec2").modify_instance_attribute(InstanceId=instance_id, DryRun=True,
                                                    Groups=describe_instance(instance_id)["security_groups"])
    except ClientError as err:
        return err.response["Error"]["Code"] == "DryRunOperation"
    return True


def ensure_isolation_sg(vpc_id: str, dry_run: bool = False) -> str | None:
    """Find or create the per-VPC isolation SG with zero ingress and zero egress."""
    ec2 = aws.client("ec2")
    found = ec2.describe_security_groups(Filters=[{"Name": "vpc-id", "Values": [vpc_id]},
                                                  {"Name": "group-name", "Values": [ISOLATION_SG_NAME]}])
    if found["SecurityGroups"]:
        return found["SecurityGroups"][0]["GroupId"]
    if dry_run:
        return None
    sg = ec2.create_security_group(GroupName=ISOLATION_SG_NAME, VpcId=vpc_id,
                                   Description="SIEM-SOAR containment: no ingress, no egress",
                                   TagSpecifications=[{"ResourceType": "security-group", "Tags": [
                                       {"Key": "ManagedBy", "Value": "siemsoar"}]}])["GroupId"]
    try:  # new SGs allow all egress by default; remove it to make isolation real
        ec2.revoke_security_group_egress(GroupId=sg, IpPermissions=[
            {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    except ClientError as err:
        if err.response["Error"]["Code"] != "InvalidPermission.NotFound":
            raise
    return sg


def isolate_instance(instance_id: str, case_id: str, dry_run: bool = False) -> dict:
    info = describe_instance(instance_id)
    sg = ensure_isolation_sg(info["vpc_id"], dry_run)
    action = {"instance_id": instance_id, "previous_security_groups": info["security_groups"],
              "isolation_sg": sg, "dry_run": dry_run}
    if dry_run:
        return {**action, "changed": False}
    if info["security_groups"] == [sg]:
        return {**action, "changed": False, "note": "already isolated"}
    ec2 = aws.client("ec2")
    ec2.modify_instance_attribute(InstanceId=instance_id, Groups=[sg])
    ec2.create_tags(Resources=[instance_id], Tags=[{"Key": CASE_TAG, "Value": case_id},
                                                    {"Key": "siemsoar:isolated-at", "Value": iso()}])
    return {**action, "changed": True}


def restore_instance_sgs(instance_id: str, groups: list[str], dry_run: bool = False) -> dict:
    if dry_run:
        return {"instance_id": instance_id, "restored_security_groups": groups, "changed": False}
    ec2 = aws.client("ec2")
    ec2.modify_instance_attribute(InstanceId=instance_id, Groups=groups)
    ec2.delete_tags(Resources=[instance_id], Tags=[{"Key": CASE_TAG}, {"Key": "siemsoar:isolated-at"}])
    return {"instance_id": instance_id, "restored_security_groups": groups, "changed": True}


def snapshot_volumes(instance_id: str, case_id: str, volumes: list[str], dry_run: bool = False) -> list[str]:
    if dry_run:
        return []
    ec2, ids = aws.client("ec2"), []
    for vol in volumes:
        snap = ec2.create_snapshot(
            VolumeId=vol, Description=f"siemsoar evidence {case_id} {instance_id}",
            TagSpecifications=[{"ResourceType": "snapshot", "Tags": [
                {"Key": "siemsoar:case", "Value": case_id}, {"Key": "siemsoar:source-instance", "Value": instance_id}]}])
        ids.append(snap["SnapshotId"])
    return ids


def set_instance_running(instance_id: str, running: bool, dry_run: bool = False) -> dict:
    if dry_run:
        return {"instance_id": instance_id, "action": "start" if running else "stop", "changed": False}
    ec2 = aws.client("ec2")
    (ec2.start_instances if running else ec2.stop_instances)(InstanceIds=[instance_id])
    return {"instance_id": instance_id, "action": "start" if running else "stop", "changed": True}


# ---------------------------------------------------------------- IAM
def revoke_role_sessions(role_name: str, dry_run: bool = False) -> dict:
    """Standard 'revoke older sessions': deny everything for tokens issued before now."""
    cutoff = iso()[:19] + "Z"
    doc = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Deny", "Action": "*", "Resource": "*",
        "Condition": {"DateLessThan": {"aws:TokenIssueTime": cutoff}}}]}
    if not dry_run:
        aws.client("iam").put_role_policy(RoleName=role_name, PolicyName=REVOKE_POLICY,
                                          PolicyDocument=json.dumps(doc))
    return {"role": role_name, "cutoff": cutoff, "changed": not dry_run}


def restore_role_sessions(role_name: str, dry_run: bool = False) -> dict:
    if not dry_run:
        try:
            aws.client("iam").delete_role_policy(RoleName=role_name, PolicyName=REVOKE_POLICY)
        except ClientError as err:
            if err.response["Error"]["Code"] != "NoSuchEntity":
                raise
    return {"role": role_name, "changed": not dry_run}


def has_revoke_policy(role_name: str) -> bool:
    try:
        aws.client("iam").get_role_policy(RoleName=role_name, PolicyName=REVOKE_POLICY)
        return True
    except ClientError:
        return False


def list_keys(user: str) -> dict[str, str]:
    keys = aws.client("iam").list_access_keys(UserName=user)["AccessKeyMetadata"]
    return {k["AccessKeyId"]: k["Status"] for k in keys}


def set_key_status(user: str, key_id: str, active: bool, dry_run: bool = False) -> dict:
    status = "Active" if active else "Inactive"
    if not dry_run:
        aws.client("iam").update_access_key(UserName=user, AccessKeyId=key_id, Status=status)
    return {"user": user, "access_key_id": key_id, "status": status, "changed": not dry_run}


def revoke_user_sessions(user: str, dry_run: bool = False) -> dict:
    """Deny temporary credentials issued (GetSessionToken/federation) before now to this user."""
    cutoff = iso()[:19] + "Z"
    doc = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Deny", "Action": "*", "Resource": "*",
        "Condition": {"DateLessThan": {"aws:TokenIssueTime": cutoff}}}]}
    if not dry_run:
        aws.client("iam").put_user_policy(UserName=user, PolicyName=REVOKE_POLICY, PolicyDocument=json.dumps(doc))
    return {"user": user, "cutoff": cutoff, "changed": not dry_run}


def restore_user_sessions(user: str, dry_run: bool = False) -> dict:
    if not dry_run:
        try:
            aws.client("iam").delete_user_policy(UserName=user, PolicyName=REVOKE_POLICY)
        except ClientError as err:
            if err.response["Error"]["Code"] != "NoSuchEntity":
                raise
    return {"user": user, "changed": not dry_run}


def rotate_key(user: str, old_key_id: str, secret_prefix: str, dry_run: bool = False) -> dict:
    """Delete the exposed key, issue a replacement and store it in Secrets Manager (never in logs/Step Functions).

    The old key goes first: it is compromised, and deleting it also frees a slot (IAM allows two keys per user).
    """
    if dry_run:
        return {"user": user, "rotated": False, "dry_run": True}
    iam, sm = aws.client("iam"), aws.client("secretsmanager")
    iam.delete_access_key(UserName=user, AccessKeyId=old_key_id)
    new = iam.create_access_key(UserName=user)["AccessKey"]
    name = f"{secret_prefix}/rotated-keys/{user}"
    payload = json.dumps({"AccessKeyId": new["AccessKeyId"], "SecretAccessKey": new["SecretAccessKey"]})
    try:
        arn = sm.create_secret(Name=name, SecretString=payload)["ARN"]
    except sm.exceptions.ResourceExistsException:
        arn = sm.put_secret_value(SecretId=name, SecretString=payload)["ARN"]
    return {"user": user, "rotated": True, "new_access_key_id": new["AccessKeyId"], "secret_arn": arn,
            "deleted_access_key_id": old_key_id}


def wait_until(predicate, timeout: float = 20, interval: float = 2) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()
