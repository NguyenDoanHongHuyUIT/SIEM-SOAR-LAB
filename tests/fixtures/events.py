"""Sample EventBridge events used across tests (shapes follow the real GuardDuty / Wazuh payloads)."""

import copy


def guardduty_instance(instance_id="i-0abc1234def567890", sev=8.0, ftype="UnauthorizedAccess:EC2/SSHBruteForce",
                       fid="gd-finding-1", sample=False):
    return {"version": "0", "source": "aws.guardduty", "detail-type": "GuardDuty Finding", "detail": {
        "id": fid, "type": ftype, "severity": sev, "accountId": "123456789012", "region": "ap-southeast-1",
        "title": "SSH brute force", "description": "Instance is being brute forced",
        "createdAt": "2026-10-06T10:00:00.000Z",
        "resource": {"resourceType": "Instance", "instanceDetails": {"instanceId": instance_id}},
        "service": {"eventFirstSeen": "2026-10-06T09:59:00.000Z", "count": 3,
                    "additionalInfo": {"sample": sample}}}}


def guardduty_key(user="lab-alice", key="AKIAIOSFODNN7EXAMPLE", fid="gd-finding-2"):
    return {"version": "0", "source": "aws.guardduty", "detail-type": "GuardDuty Finding", "detail": {
        "id": fid, "type": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS", "severity": 8.0,
        "accountId": "123456789012", "region": "ap-southeast-1", "title": "Credentials used outside AWS",
        "description": "d", "createdAt": "2026-10-06T10:00:00.000Z",
        "resource": {"resourceType": "AccessKey", "accessKeyDetails": {
            "accessKeyId": key, "userName": user, "userType": "IAMUser"}},
        "service": {"eventFirstSeen": "2026-10-06T09:59:00.000Z"}}}


WAZUH_FIM = {"source": "siemsoar.wazuh", "detail-type": "Wazuh Alert", "detail": {
    "id": "1759744800.123", "timestamp": "2026-10-06T10:00:00.000+0000",
    "rule": {"id": "100100", "level": 12, "description": "FIM: /etc/passwd modified",
             "groups": ["syscheck", "siemsoar_active", "resp_ec2_isolate"],
             "mitre": {"id": ["T1136.001"], "tactic": ["Persistence"]}},
    "agent": {"id": "001", "name": "i-0abc1234def567890", "ip": "10.0.1.10"},
    "full_log": "File '/etc/passwd' modified run_id=run-20261006-01", "data": {}}}

SURICATA = {"source": "siemsoar.wazuh", "detail-type": "Wazuh Alert", "detail": {
    "id": "1759744900.456", "timestamp": "2026-10-06T10:05:00.000+0000",
    "rule": {"id": "110001", "level": 10, "description": "Suricata: SIEMSOAR-LAB suspicious path traversal",
             "groups": ["suricata", "siemsoar_active", "resp_none"], "mitre": {"id": ["T1190"]}},
    "agent": {"id": "001", "name": "i-0abc1234def567890"},
    "data": {"src_ip": "10.0.1.99", "event_type": "alert",
             "alert": {"signature_id": 9000001, "signature": "SIEMSOAR-LAB path traversal"}}}}


def clone(event):
    return copy.deepcopy(event)
