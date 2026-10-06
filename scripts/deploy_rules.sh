#!/bin/bash
# Activate a rule release on this host, validating first and rolling back automatically on failure.
#   deploy_rules.sh manager|sensor <git-sha|current>
# Releases are produced by tools/rulesctl.py build and uploaded to s3://<rules bucket>/releases/<sha>/.
set -euo pipefail
# shellcheck disable=SC1091
source /opt/siemsoar/env
TARGET="${1:?target manager|sensor}"
RELEASE="${2:?release sha|current}"
STATE_DIR=/opt/siemsoar/state
mkdir -p "$STATE_DIR"
log() { echo "[deploy_rules:$TARGET] $*"; }

if [ "$RELEASE" = "current" ]; then
  RELEASE=$(aws s3 cp "s3://${BOOT_BUCKET}/releases/current.json" - --region "$REGION" | jq -r .sha)
  [ -n "$RELEASE" ] && [ "$RELEASE" != "null" ] || { log "no current release"; exit 1; }
fi
SRC="s3://${BOOT_BUCKET}/releases/${RELEASE}"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
aws s3 sync "$SRC/" "$WORK/" --region "$REGION" --only-show-errors
[ -f "$WORK/manifest.json" ] || { log "release $RELEASE has no manifest"; exit 1; }
(cd "$WORK" && sha256sum --quiet -c <(jq -r '.files[] | "\(.sha256)  \(.path)"' manifest.json)) \
  || { log "checksum mismatch"; exit 1; }
log "release $RELEASE verified"

if [ "$TARGET" = "manager" ]; then
  DEST=/var/ossec/etc/rules/siemsoar_rules.xml
  BACKUP="$STATE_DIR/siemsoar_rules.xml.prev"
  [ -f "$DEST" ] && cp -p "$DEST" "$BACKUP" || true
  install -m 660 -o root -g wazuh "$WORK/wazuh/siemsoar_rules.xml" "$DEST"
  if ! /var/ossec/bin/wazuh-analysisd -t; then
    log "wazuh-analysisd -t FAILED, rolling back"
    [ -f "$BACKUP" ] && install -m 660 -o root -g wazuh "$BACKUP" "$DEST" || rm -f "$DEST"
    exit 1
  fi
  systemctl restart wazuh-manager
else
  DEST=/var/lib/suricata/rules/siemsoar.rules
  BACKUP="$STATE_DIR/siemsoar.rules.prev"
  [ -f "$DEST" ] && cp -p "$DEST" "$BACKUP" || true
  install -m 644 "$WORK/suricata/siemsoar.rules" "$DEST"
  if ! suricata -T -c /etc/suricata/suricata.yaml >/dev/null 2>&1; then
    log "suricata -T FAILED, rolling back"
    [ -f "$BACKUP" ] && install -m 644 "$BACKUP" "$DEST" || : > "$DEST"
    exit 1
  fi
  systemctl reload suricata 2>/dev/null || systemctl restart suricata
fi

echo "$RELEASE" > "$STATE_DIR/deployed_release_$TARGET"
log "release $RELEASE active"
