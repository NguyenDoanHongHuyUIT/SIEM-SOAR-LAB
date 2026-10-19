#!/bin/bash
# Lab host bootstrap: Wazuh agent (name = EC2 instance id, so SOAR can map alert -> instance) + Suricata IDS.
set -euo pipefail
# shellcheck disable=SC1091
source /opt/siemsoar/env
BOOT=/opt/siemsoar/bootstrap
log() { echo "[bootstrap_sensor] $*"; }
export DEBIAN_FRONTEND=noninteractive

TOKEN=$(curl -fsS -X PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 300')
INSTANCE_ID=$(curl -fsS -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)
IFACE=$(ip -o -4 route show to default | awk '{print $5}' | head -1)
log "instance=$INSTANCE_ID iface=$IFACE manager=$MANAGER_IP"

# ---- Suricata (OISF stable PPA) + traffic tools used by the simulation scenarios
apt-get install -y software-properties-common
# suricata-7.0, not suricata-stable (now 8.x): the CI tests run Suricata 7.0 (jasonish/suricata:7.0), keep the same line
add-apt-repository -y ppa:oisf/suricata-7.0
apt-get update -y
# tcpreplay: pcap_replay scenarios; python3-yaml: scripts/run_atomic.py; the rest are the prerequisites the lab's Atomic Red
# Team tests declare (T1046 test 2: nmap, telnet, nc; T1110.004 test 1: sshpass)
apt-get install -y suricata tcpreplay jq python3-yaml sshpass nmap telnet netcat-openbsd
mkdir -p /opt/atomic-red-team/atomics
sed -i "s/interface: eth0/interface: ${IFACE}/" /etc/suricata/suricata.yaml
# Inspect traffic between lab hosts too: ET rules are written $EXTERNAL_NET -> $HOME_NET and every lab address is inside
# HOME_NET. Same value as tools/suricata_pcap_test.SENSOR_VARS, which the CI replay uses.
sed -i -E 's/^([[:space:]]*EXTERNAL_NET:).*/\1 "any"/' /etc/suricata/suricata.yaml
grep -q "siemsoar.rules" /etc/suricata/suricata.yaml || sed -i '/^rule-files:/a\  - siemsoar.rules' /etc/suricata/suricata.yaml
mkdir -p /var/lib/suricata/rules
touch /var/lib/suricata/rules/siemsoar.rules /var/lib/suricata/rules/suricata.rules
# Broad, community-maintained detection comes from the Emerging Threats Open ruleset (suricata-update enables it by
# default and writes suricata.rules). Those alerts reach Wazuh as plain Suricata events (rule 86601) so analysts see
# them, while only the curated SIEMSOAR rules (siemsoar.rules + their Wazuh mapping rules) can open cases.
suricata-update --no-reload || log "suricata-update failed: continuing with the SIEMSOAR rules only"
bash "$BOOT/scripts/deploy_rules.sh" sensor current || log "no rule release yet, skipping"
systemctl enable suricata
systemctl restart suricata

# ---- Wazuh agent (shared with the targets), plus the sensor's Suricata EVE input
bash "$BOOT/agent/install_wazuh_agent.sh"   # detects /etc/suricata/suricata.yaml and adds the EVE input
log "done"
