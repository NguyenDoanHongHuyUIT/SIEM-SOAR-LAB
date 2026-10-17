"""Alerts in the shape the REAL chain delivers, as opposed to the hand-trimmed ones in events.py.

REAL_SURICATA_ALERT: tests/fixtures/real_suricata_wazuh_alert.json holds VERBATIM tool output: the EVE alert Suricata 7.0
raised (ET Open rule 2009525) when replaying the Atomic Red Team T1071.001 capture, and what the Wazuh 4.14.8 logtest API
returned for that line with the SIEMSOAR rules built from this repository (every number under `data` is a string;
flow_id came back as "822746917091085.000000"). Only the `agent` block is replaced, by a lab instance, because logtest
reports the manager itself as the agent; the result is wrapped like the custom-eventbridge integration does.

REAL_FIM_ALERT: a syscheck (file integrity) alert with the fields Wazuh documents for such events.

REAL_SSHD_DATA: the `data` block that the real Wazuh 4.14.8 `sshd` decoder produced (logtest API, official
wazuh/wazuh-manager image) for the two OpenSSH failure messages below. The wrapping `rule`/`agent` of the alerts built from
it are the project's own; only the decoded fields are captured output. Note the decoder puts the name of an account that
does not exist under `srcuser` and an existing one under `dstuser`.
"""

import json
from pathlib import Path

_CAPTURED = json.loads((Path(__file__).with_name("real_suricata_wazuh_alert.json")).read_text(encoding="utf-8"))
REAL_SURICATA_EVE = _CAPTURED["eve"]
REAL_SURICATA_ALERT = {"source": "siemsoar.wazuh", "detail-type": "Wazuh Alert", "detail": {
    **_CAPTURED["wazuh_output"], "agent": {"id": "001", "name": "i-0abc1234def567890", "ip": "10.0.1.10"}}}

REAL_FIM_ALERT = {"source": "siemsoar.wazuh", "detail-type": "Wazuh Alert", "detail": {
    "id": "1791977800.100", "timestamp": "2026-10-14T11:40:00.000+0000",
    "rule": {"id": "100100", "level": 12, "description": "SIEMSOAR: /etc/passwd was modified",
             "groups": ["siemsoar", "syscheck", "siemsoar_active", "resp_ec2_isolate"], "mitre": {"id": ["T1136.001"]}},
    "agent": {"id": "002", "name": "ip-10-0-1-10", "ip": "10.0.1.10"},
    "syscheck": {"path": "/etc/passwd", "event": "modified", "mode": "realtime"}, "location": "syscheck"}}

SSHD_LINES = {
    "invalid_user": "Oct 15 10:00:01 ip-10-0-1-10 sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 52000 ssh2",
    "existing_user": "Oct 15 10:00:02 ip-10-0-1-10 sshd[1234]: Failed password for root from 203.0.113.5 port 52001 ssh2",
}
REAL_SSHD_DATA = {
    "invalid_user": {"srcip": "203.0.113.5", "srcuser": "admin"},                          # official rule 5710
    "existing_user": {"srcip": "203.0.113.5", "srcport": "52001", "dstuser": "root"},      # official rule 5760
}


def sshd_alert(kind: str, rule_id: str = "100121") -> dict:
    return {"source": "siemsoar.wazuh", "detail-type": "Wazuh Alert", "detail": {
        "id": f"sshd-{kind}", "timestamp": "2026-10-15T10:00:03.000+0000",
        "rule": {"id": rule_id, "level": 10, "description": "SIEMSOAR: SSH brute force",
                 "groups": ["siemsoar", "authentication_failures", "siemsoar_shadow", "resp_none"],
                 "mitre": {"id": ["T1110"]}},
        "agent": {"id": "002", "name": "ip-10-0-1-10", "ip": "10.0.1.10"},
        "decoder": {"name": "sshd"}, "data": dict(REAL_SSHD_DATA[kind]), "full_log": SSHD_LINES[kind],
        "location": "/var/log/auth.log"}}
