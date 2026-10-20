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

# No unattended package upgrades on a measurement host: on 2026-10-20 unattended-upgrade upgraded systemd and
# openssh-server in the middle of a lab session (sshd and journald restarted, see below). Hosts get their packages
# when they are built; the software under test does not change between two runs of a session.
systemctl disable --now apt-daily-upgrade.timer >/dev/null 2>&1 || true
printf 'APT::Periodic::Unattended-Upgrade "0";\n' > /etc/apt/apt.conf.d/52siemsoar-no-unattended-upgrade

# Ubuntu 22.04 builds systemd-journald with Audit=no: journald turns kernel auditing OFF each time it starts
# (journald.conf(5): "If disabled it will turn it off"). Lab 2026-10-20 07:11: the systemd upgrade restarted journald
# and both target hosts silently lost every audit record (execve, /etc/shadow reads, who-data) until noticed.
# Audit=yes makes a journald restart turn auditing on instead (checked on the lab: restart -> enabled 1).
mkdir -p /etc/systemd/journald.conf.d
printf '[Journal]\nAudit=yes\n' > /etc/systemd/journald.conf.d/60-siemsoar-audit.conf
systemctl restart systemd-journald

# Linux audit (system calls): every root command and reads of the credential stores, whatever tool is used
apt-get install -y auditd
install -m 0640 "$BOOT/agent/siemsoar.rules" /etc/audit/rules.d/siemsoar.rules
augenrules --load
systemctl enable --now auditd

# The sensor also ships its Suricata EVE input; detected so that a refresh needs no host-specific argument
EXTRA=("$@")
if [ ${#EXTRA[@]} -eq 0 ] && [ -f /etc/suricata/suricata.yaml ]; then
  EXTRA=("$BOOT/suricata/ossec_eve_localfile.xml")
fi

# Replace (not skip) the SIEMSOAR blocks, so re-running applies a changed agent configuration
sed -i '/<!-- BEGIN SIEMSOAR/,/<!-- END SIEMSOAR -->/d' /var/ossec/etc/ossec.conf
cat "$BOOT/agent/ossec_agent_additions.xml" "${EXTRA[@]}" >> /var/ossec/etc/ossec.conf
mkdir -p /srv/lab && touch /srv/lab/canary.txt   # FIM canary used by the simulation scenarios
# logcollector's queue towards the agent (internal option, default 1024, 128-220000) overflowed a few seconds after
# every boot ("Target 'agent' message queue is full (1024). Log lines may be lost.", lab 2026-10-19/20)
OPTS=/var/ossec/etc/local_internal_options.conf
sed -i '/^logcollector.queue_size=/d' "$OPTS"
echo "logcollector.queue_size=16384" >> "$OPTS"
systemctl daemon-reload
systemctl enable --now wazuh-agent
since=$(date '+%Y/%m/%d %H:%M:%S')
systemctl restart wazuh-agent

# Check what this script is for instead of reporting success: kernel auditing on, and the who-data engine running.
# syscheckd falls back to real-time without failing when its audit health check fails (lab 2026-10-20 07:43, both
# targets: "(6913) Who-data engine could not start. Switching who-data to real-time").
fim_log() { awk -v s="$since" '($1 " " $2) >= s' /var/ossec/logs/ossec.log | grep -E "\((6019|6913)\)" || true; }
for _ in $(seq 1 45); do
  [ -n "$(fim_log)" ] && break
  sleep 2
done
# outputs captured first: with pipefail, `cmd | grep -q` can fail on SIGPIPE when grep exits early
status=$(auditctl -s); fim=$(fim_log)
grep -q '^enabled 1' <<<"$status" || { log "ERROR: kernel auditing is off"; exit 1; }
grep -q "(6019)" <<<"$fim" || { log "ERROR: who-data engine did not start: ${fim:-no syscheckd message}"; exit 1; }
log "kernel auditing on, who-data engine running"
log "done"
