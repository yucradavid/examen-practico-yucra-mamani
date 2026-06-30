#!/usr/bin/env bash
set -euo pipefail

# Ejecutar en Ubuntu 22.04 dentro de EC2.
sudo apt update
sudo apt install -y curl vim jq libxml2-utils
curl -sO https://packages.wazuh.com/4.12/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
sudo systemctl status wazuh-manager --no-pager
sudo systemctl status wazuh-indexer --no-pager || true
sudo systemctl status wazuh-dashboard --no-pager || true
