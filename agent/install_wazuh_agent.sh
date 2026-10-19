#!/bin/bash
# Wazuh agent for every lab host (sensor and targets): agent name = EC2 instance id, so the SOAR maps an alert to the
# instance; version pinned to the manager's minor; SIEMSOAR configuration appended. Extra config files (e.g. the
# sensor's Suricata EVE input) are given as arguments and appended after the common block.
set -euo pipefail
# shellcheck disable=SC1091
source /opt/siemsoar/env
BOOT=/opt/siemsoar/bootstrap
log() { echo "[install_wazuh_agent] $*"; }
export DEBIAN_FRONTEND=noninteractive

TOKEN=$(curl -fsS -X PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 300')
INSTANCE_ID=$(curl -fsS -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)

# The manager installs for ~10-15 min after boot: wait until it accepts enrolment instead of letting the package
# post-install fail to register.
log "instance=$INSTANCE_ID waiting for the Wazuh manager (${MANAGER_IP}:1515)"
for _ in $(seq 1 120); do
  if timeout 3 bash -c "</dev/tcp/${MANAGER_IP}/1515" 2>/dev/null; then break; fi
  sleep 15
done
curl -fsS https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring   --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main"   > /etc/apt/sources.list.d/wazuh.list
apt-get update -y
# The 4.x apt channel always serves the NEWEST 4.x agent, but the manager is pinned to ${WAZUH_VERSION}.
# Wazuh requires manager version >= agent version, so pin the agent to the same minor and hold it.
WAZUH_MANAGER="$MANAGER_IP" WAZUH_AGENT_NAME="$INSTANCE_ID" apt-get install -y "wazuh-agent=${WAZUH_VERSION}.*"
apt-mark hold wazuh-agent

# Replace (not skip) the SIEMSOAR blocks, so re-running applies a changed agent configuration
sed -i '/<!-- BEGIN SIEMSOAR/,/<!-- END SIEMSOAR -->/d' /var/ossec/etc/ossec.conf
cat "$BOOT/agent/ossec_agent_additions.xml" "$@" >> /var/ossec/etc/ossec.conf
mkdir -p /srv/lab && touch /srv/lab/canary.txt   # FIM canary used by the simulation scenarios
systemctl daemon-reload
systemctl enable --now wazuh-agent
systemctl restart wazuh-agent
log "done"
