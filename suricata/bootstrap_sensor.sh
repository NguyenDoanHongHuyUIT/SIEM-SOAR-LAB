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
add-apt-repository -y ppa:oisf/suricata-stable
apt-get update -y
apt-get install -y suricata tcpreplay jq python3-yaml python3-venv
# Atomic Red Team runner (simulation scenarios of kind `atomic`). atomic-operator 0.9.x does not declare `attrs`.
python3 -m venv /opt/siemsoar/art-venv
/opt/siemsoar/art-venv/bin/pip install --quiet atomic-operator attrs
mkdir -p /opt/atomic-red-team/atomics
sed -i "s/interface: eth0/interface: ${IFACE}/" /etc/suricata/suricata.yaml
grep -q "siemsoar.rules" /etc/suricata/suricata.yaml || sed -i '/^rule-files:/a\  - siemsoar.rules' /etc/suricata/suricata.yaml
mkdir -p /var/lib/suricata/rules
touch /var/lib/suricata/rules/siemsoar.rules /var/lib/suricata/rules/suricata.rules
bash "$BOOT/scripts/deploy_rules.sh" sensor current || log "no rule release yet, skipping"
systemctl enable suricata
systemctl restart suricata

# ---- Wazuh agent. The manager installs for ~10-15 min after boot: wait until it accepts enrolment instead of
# letting the package post-install fail to register.
log "waiting for the Wazuh manager (${MANAGER_IP}:1515)"
for _ in $(seq 1 120); do
  if timeout 3 bash -c "</dev/tcp/${MANAGER_IP}/1515" 2>/dev/null; then break; fi
  sleep 15
done
curl -fsS https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring \
  --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  > /etc/apt/sources.list.d/wazuh.list
apt-get update -y
# The 4.x apt channel always serves the NEWEST 4.x agent, but the manager is pinned to ${WAZUH_VERSION}.
# Wazuh requires manager version >= agent version, so pin the agent to the same minor and hold it.
WAZUH_MANAGER="$MANAGER_IP" WAZUH_AGENT_NAME="$INSTANCE_ID" apt-get install -y "wazuh-agent=${WAZUH_VERSION}.*"
apt-mark hold wazuh-agent

if ! grep -q "BEGIN SIEMSOAR" /var/ossec/etc/ossec.conf; then
  cat "$BOOT/suricata/ossec_agent_additions.xml" >> /var/ossec/etc/ossec.conf
fi
mkdir -p /srv/lab && touch /srv/lab/canary.txt   # FIM canary used by the simulation scenarios
systemctl daemon-reload
systemctl enable --now wazuh-agent
log "done"
