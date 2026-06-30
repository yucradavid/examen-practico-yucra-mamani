#!/usr/bin/env bash
set -euo pipefail
sudo apt update
sudo apt install -y python3.11 python3.11-venv python3-pip git wget unzip jq libxml2-utils
python3.11 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
python --version
pip freeze | tee versiones_python.txt
