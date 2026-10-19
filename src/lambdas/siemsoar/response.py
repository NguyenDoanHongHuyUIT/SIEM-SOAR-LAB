"""Containment & restore primitives (EC2 isolation, IAM key disable, session revocation).

Every mutating function takes dry_run and returns a description of what was (or would be) done, so
the same code path is exercised in demo (dry run) and real mode.
"""

from __future__ import annotations

import json

from botocore.exceptions import ClientError

from . import aws
from .util import iso

ISOLATION_SG_NAME = "siemsoar-isolation"
CASE_TAG = "siemsoar:isolated-case"
REVOKE_POLICY = "AWSRevokeOlderSessions"


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
    primary_groups = sorted(g["GroupId"] for g in inst.get("SecurityGroups", []))
    enis = sorted(({"id": n["NetworkInterfaceId"], "device_index": n.get("Attachment", {}).get("DeviceIndex", 0),
                    # the instance-level list is the authoritative view of the primary interface
                    "groups": primary_groups if n.get("Attachment", {}).get("DeviceIndex", 0) == 0
                    else sorted(g["GroupId"] for g in n.get("Groups", [])),
                    "subnet_id": n.get("SubnetId")} for n in inst.get("NetworkInterfaces", [])),
                  key=lambda n: n["device_index"])
    return {
        "instance_id": instance_id,
        "state": inst["State"]["Name"],
        "vpc_id": inst.get("VpcId"),
        "subnet_id": inst.get("SubnetId"),
        "security_groups": primary_groups,  # primary interface
        "network_interfaces": enis,
        "tags": tags,
        "name": tags.get("Name"),
        "public_ip": inst.get("PublicIpAddress"),
        "private_ip": inst.get("PrivateIpAddress"),
        "instance_profile_arn": profile,
        "volumes": [b["Ebs"]["VolumeId"] for b in inst.get("BlockDeviceMappings", []) if "Ebs" in b],
    }


def find_instances_where(filters: list[dict], states: tuple[str, ...] = ("running",)) -> list[dict]:
    """Instances matching raw EC2 `filters` in one of `states`: [{"id", "state", "tags"}]."""
    flt = [*filters, {"Name": "instance-state-name", "Values": list(states)}]
    pages = aws.client("ec2").get_paginator("describe_instances").paginate(Filters=flt)
    return [{"id": i["InstanceId"], "state": i["State"]["Name"], "tags": {t["Key"]: t["Value"] for t in i.get("Tags", [])}}
            for page in pages for r in page["Reservations"] for i in r["Instances"]]


def find_instances(tags: dict[str, str], states: tuple[str, ...] = ("running",)) -> list[dict]:
    """Instances matching all `tags` in one of `states` (operator tools, not the Lambdas)."""
    return find_instances_where([{"Name": f"tag:{k}", "Values": [v]} for k, v in tags.items()], states)


def instance_role_name(profile_arn: str | None) -> str | None:
    if not profile_arn:
        return None
    name = profile_arn.rsplit("/", 1)[-1]
    try:
        roles = aws.client("iam").get_instance_profile(InstanceProfileName=name)["InstanceProfile"]["Roles"]
    except ClientError as err:
        if err.response["Error"]["Code"] == "NoSuchEntity":
            return None
        raise  # AccessDenied etc. must surface: silently skipping session revocation would be fail-open
    return roles[0]["RoleName"] if roles else None


def eni_groups(info: dict) -> dict[str, list[str]]:
    """{eni id: sorted security groups} for every interface of a describe_instance() result."""
    return {n["id"]: list(n["groups"]) for n in info.get("network_interfaces", [])}


def is_isolated(info: dict, isolation_sg: str | None) -> bool:
    """True only when EVERY interface carries just the isolation SG (the primary ENI alone is not enough)."""
    enis = info.get("network_interfaces") or []
    if not isolation_sg:
        return False
    return (info["security_groups"] == [isolation_sg]) and all(n["groups"] == [isolation_sg] for n in enis)


def _dry_run_ok(call, **kwargs) -> bool:
    """EC2 DryRun: DryRunOperation means 'would have succeeded'; anything else (UnauthorizedOperation) means no."""
    try:
        call(DryRun=True, **kwargs)
    except ClientError as err:
        return err.response["Error"]["Code"] == "DryRunOperation"
    return True


def check_modify_permission(instance_id: str) -> bool:
    """The SOAR role must be able to change the groups of the primary interface and of every secondary one."""
    ec2, info = aws.client("ec2"), describe_instance(instance_id)
    if not _dry_run_ok(ec2.modify_instance_attribute, InstanceId=instance_id, Groups=info["security_groups"]):
        return False
    return all(_dry_run_ok(ec2.modify_network_interface_attribute, NetworkInterfaceId=n["id"], Groups=n["groups"])
               for n in info["network_interfaces"] if n["device_index"] != 0)


def ensure_isolation_sg(vpc_id: str, dry_run: bool = False) -> str | None:
    """Find or create the per-VPC isolation SG with zero ingress and zero egress (safe under concurrent callers)."""
    ec2 = aws.client("ec2")
    flt = [{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": [ISOLATION_SG_NAME]}]
    found = ec2.describe_security_groups(Filters=flt)
    if found["SecurityGroups"]:
        return found["SecurityGroups"][0]["GroupId"]
    if dry_run:
        return None
    try:
        sg = ec2.create_security_group(GroupName=ISOLATION_SG_NAME, VpcId=vpc_id,
                                       Description="SIEM-SOAR containment: no ingress, no egress",
                                       TagSpecifications=[{"ResourceType": "security-group", "Tags": [
                                           {"Key": "ManagedBy", "Value": "siemsoar"}]}])["GroupId"]
    except ClientError as err:
        if err.response["Error"]["Code"] != "InvalidGroup.Duplicate":
            raise
        # another case created it between our lookup and create: use that one
        return ec2.describe_security_groups(Filters=flt)["SecurityGroups"][0]["GroupId"]
    try:  # new SGs allow all egress by default; remove it to make isolation real
        ec2.revoke_security_group_egress(GroupId=sg, IpPermissions=[
            {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    except ClientError as err:
        if err.response["Error"]["Code"] != "InvalidPermission.NotFound":
            raise
    return sg


def _set_groups(info: dict, groups_by_eni: dict[str, list[str]]) -> None:
    """Primary interface through the instance (tag-scoped IAM), secondary ones through their own attribute call."""
    ec2 = aws.client("ec2")
    for eni in info["network_interfaces"]:
        groups = groups_by_eni.get(eni["id"])
        if groups is None or groups == eni["groups"]:
            continue
        if eni["device_index"] == 0:
            ec2.modify_instance_attribute(InstanceId=info["instance_id"], Groups=groups)
        else:
            ec2.modify_network_interface_attribute(NetworkInterfaceId=eni["id"], Groups=groups)


def isolate_instance(instance_id: str, case_id: str, dry_run: bool = False) -> dict:
    info = describe_instance(instance_id)
    sg = ensure_isolation_sg(info["vpc_id"], dry_run)
    action = {"instance_id": instance_id, "previous_security_groups": info["security_groups"],
              "previous_eni_groups": eni_groups(info), "isolation_sg": sg, "dry_run": dry_run}
    if dry_run:
        return {**action, "changed": False}
    if is_isolated(info, sg):
        return {**action, "changed": False, "note": "already isolated"}
    _set_groups(info, {n["id"]: [sg] for n in info["network_interfaces"]})
    aws.client("ec2").create_tags(Resources=[instance_id], Tags=[{"Key": CASE_TAG, "Value": case_id},
                                                                  {"Key": "siemsoar:isolated-at", "Value": iso()}])
    return {**action, "changed": True}


def restore_instance_sgs(instance_id: str, groups: list[str], dry_run: bool = False,
                         groups_by_eni: dict[str, list[str]] | None = None) -> dict:
    """Put the pre-action groups back. `groups_by_eni` (from the saved state) restores every interface; without it
    only the primary interface is restored (states saved before multi-ENI support)."""
    out = {"instance_id": instance_id, "restored_security_groups": groups, "restored_eni_groups": groups_by_eni or {}}
    if dry_run:
        return {**out, "changed": False}
    info = describe_instance(instance_id)
    target = dict(groups_by_eni or {})
    primary = next((n["id"] for n in info["network_interfaces"] if n["device_index"] == 0), None)
    if primary and primary not in target:
        target[primary] = groups
    _set_groups(info, target)
    aws.client("ec2").delete_tags(Resources=[instance_id], Tags=[{"Key": CASE_TAG}, {"Key": "siemsoar:isolated-at"}])
    return {**out, "changed": True}


def restore_ec2_from_state(instance_id: str, pre: dict, dry_run: bool = False, start: bool = False) -> dict:
    """Undo an EC2 containment from its saved pre-action state: every interface's groups, the instance role's session
    revocation, and a restart if containment stopped a running instance. One procedure for the workflow's restore, the
    runner's recovery after robustness tests and `soarctl recover` (a lab recovery once restored the groups but left
    AWSRevokeOlderSessions on the role)."""
    per_eni = {n["id"]: n["groups"] for n in pre.get("network_interfaces", [])}
    out = {"security_groups": restore_instance_sgs(instance_id, pre["security_groups"], dry_run, per_eni)}
    if pre.get("role_name"):
        out["sessions"] = restore_role_sessions(pre["role_name"], dry_run)
    if start and pre.get("state") == "running":
        out["start"] = set_instance_running(instance_id, True, dry_run)
    return out


def ec2_matches_state(instance_id: str, pre: dict) -> tuple[bool, str]:
    """(restored?, summary): groups as saved on every interface, no isolation tag, no session revocation left."""
    cur = describe_instance(instance_id)
    expected = {n["id"]: n["groups"] for n in pre.get("network_interfaces", [])}
    groups_ok = (eni_groups(cur) == expected) if expected else cur["security_groups"] == pre["security_groups"]
    ok = groups_ok and CASE_TAG not in cur["tags"] and not (pre.get("role_name") and has_revoke_policy(pre["role_name"]))
    return ok, f"security groups {expected or cur['security_groups']} restored (now {eni_groups(cur)})"


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
def _revoke_older_sessions_policy() -> tuple[str, str]:
    """The console's 'Revoke active sessions' policy: deny everything for credentials issued before now."""
    cutoff = iso()[:19] + "Z"
    doc = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Deny", "Action": "*", "Resource": "*",
        "Condition": {"DateLessThan": {"aws:TokenIssueTime": cutoff}}}]}
    return cutoff, json.dumps(doc)


def revoke_role_sessions(role_name: str, dry_run: bool = False) -> dict:
    cutoff, doc = _revoke_older_sessions_policy()
    if not dry_run:
        aws.client("iam").put_role_policy(RoleName=role_name, PolicyName=REVOKE_POLICY, PolicyDocument=doc)
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
    cutoff, doc = _revoke_older_sessions_policy()
    if not dry_run:
        aws.client("iam").put_user_policy(UserName=user, PolicyName=REVOKE_POLICY, PolicyDocument=doc)
    return {"user": user, "cutoff": cutoff, "changed": not dry_run}


def restore_user_sessions(user: str, dry_run: bool = False) -> dict:
    if not dry_run:
        try:
            aws.client("iam").delete_user_policy(UserName=user, PolicyName=REVOKE_POLICY)
        except ClientError as err:
            if err.response["Error"]["Code"] != "NoSuchEntity":
                raise
    return {"user": user, "changed": not dry_run}


def _secret_name(secret_prefix: str, user: str) -> str:
    return f"{secret_prefix}/rotated-keys/{user}"


def _existing_replacement(sm, name: str, live_keys: dict[str, str]) -> dict | None:
    """The replacement key a previous (interrupted) attempt already issued, if its secret is stored and still live."""
    try:
        stored = json.loads(sm.get_secret_value(SecretId=name)["SecretString"])
    except sm.exceptions.ResourceNotFoundException:
        return None
    key_id = stored.get("AccessKeyId")
    if key_id in live_keys:
        return {"new_access_key_id": key_id, "secret_arn": sm.describe_secret(SecretId=name)["ARN"]}
    return None


def rotate_key(user: str, old_key_id: str, secret_prefix: str, dry_run: bool = False) -> dict:
    """Delete the exposed key, issue a replacement and store it in Secrets Manager (never in logs/Step Functions).

    Idempotent, because Step Functions may retry this step after a partial success: an already deleted key is fine, a
    replacement stored by an earlier attempt is reused instead of issuing a third key, and a key that could not be
    stored is deleted again so no unrecorded credential is left behind. The old key goes first: it is compromised, and
    deleting it also frees a slot (IAM allows two keys per user).
    """
    if dry_run:
        return {"user": user, "rotated": False, "dry_run": True}
    iam, sm = aws.client("iam"), aws.client("secretsmanager")
    try:
        iam.delete_access_key(UserName=user, AccessKeyId=old_key_id)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchEntity":
            raise
    name = _secret_name(secret_prefix, user)
    done = _existing_replacement(sm, name, list_keys(user))
    if done:
        return {"user": user, "rotated": True, "deleted_access_key_id": old_key_id, "reused_replacement": True, **done}
    new = iam.create_access_key(UserName=user)["AccessKey"]
    payload = json.dumps({"AccessKeyId": new["AccessKeyId"], "SecretAccessKey": new["SecretAccessKey"]})
    try:
        try:
            arn = sm.create_secret(Name=name, SecretString=payload)["ARN"]
        except sm.exceptions.ResourceExistsException:
            arn = sm.put_secret_value(SecretId=name, SecretString=payload)["ARN"]
    except Exception:
        iam.delete_access_key(UserName=user, AccessKeyId=new["AccessKeyId"])  # never leave an unrecorded credential
        raise
    return {"user": user, "rotated": True, "new_access_key_id": new["AccessKeyId"], "secret_arn": arn,
            "deleted_access_key_id": old_key_id}
