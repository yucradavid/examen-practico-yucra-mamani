#!/usr/bin/env bash
set -euo pipefail

sudo cp lab2/local_rules_ssh.xml /var/ossec/etc/rules/local_rules_ssh.xml
sudo cp lab2/local_rules_exfil.xml /var/ossec/etc/rules/local_rules_exfil.xml
xmllint --noout lab2/local_rules_ssh.xml && echo "local_rules_ssh.xml OK"
xmllint --noout lab2/local_rules_exfil.xml && echo "local_rules_exfil.xml OK"
sudo systemctl restart wazuh-manager
sudo systemctl status wazuh-manager --no-pager
