#!/bin/bash
# Wazuh all-in-one (manager + indexer + dashboard) bootstrap. Idempotent enough to be re-run by hand.
set -euo pipefail
# shellcheck disable=SC1091
source /opt/siemsoar/env
BOOT=/opt/siemsoar/bootstrap
log() { echo "[bootstrap_manager] $*"; }

if [ ! -x /var/ossec/bin/wazuh-control ]; then
  log "installing Wazuh ${WAZUH_VERSION} all-in-one (takes ~10 min)"
  cd /tmp
  curl -fsSLO "https://packages.wazuh.com/${WAZUH_VERSION}/wazuh-install.sh"
  bash wazuh-install.sh -a -i
  # Keep generated credentials out of logs: push the admin password to SSM SecureString, then shred.
  tar -O -xf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt > /tmp/wazuh-passwords.txt
  ADMIN_PW=$(grep -A1 "indexer_username: 'admin'" /tmp/wazuh-passwords.txt | grep indexer_password | cut -d"'" -f2)
  aws ssm put-parameter --region "$REGION" --name "/${PREFIX}/wazuh/admin_password" --type SecureString \
    --overwrite --value "$ADMIN_PW" >/dev/null
  shred -u /tmp/wazuh-passwords.txt wazuh-install-files.tar || true
fi

log "installing custom EventBridge integration"
install -m 750 -o root -g wazuh "$BOOT/wazuh/integrations/custom-eventbridge" /var/ossec/integrations/custom-eventbridge
install -m 750 -o root -g wazuh "$BOOT/wazuh/integrations/custom-eventbridge.py" /var/ossec/integrations/custom-eventbridge.py

if ! grep -q "BEGIN SIEMSOAR" /var/ossec/etc/ossec.conf; then
  log "appending SIEMSOAR block to ossec.conf"
  sed -e "s|__REGION__|${REGION}|g" -e "s|__CLOUDTRAIL_BUCKET__|${CLOUDTRAIL_BUCKET}|g" \
    "$BOOT/wazuh/ossec_manager_additions.xml" >> /var/ossec/etc/ossec.conf
fi

log "deploying current rule release (best effort: none exists on the very first boot)"
bash "$BOOT/scripts/deploy_rules.sh" manager current || log "no rule release yet, skipping"

systemctl enable wazuh-manager
systemctl restart wazuh-manager
log "done"
