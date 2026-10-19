#!/bin/bash
# Target host bootstrap (workload zone): the Wazuh agent with the common SIEMSOAR configuration, and what
# scripts/run_atomic.py needs to run host scenarios here. No Suricata: the sensor observes the cross-host tests.
set -euo pipefail
BOOT=/opt/siemsoar/bootstrap
export DEBIAN_FRONTEND=noninteractive
apt-get install -y jq python3-yaml
bash "$BOOT/agent/install_wazuh_agent.sh"
echo "[bootstrap_target] done"
