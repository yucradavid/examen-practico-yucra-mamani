#!/usr/bin/env bash
set -euo pipefail

mkdir -p lab1 lab2 lab3
wget -O lab1/auth.log https://raw.githubusercontent.com/abelthf/examen_final_seguridad_informatica/refs/heads/main/lab1/auth.log
wget -O lab1/access.log https://raw.githubusercontent.com/abelthf/examen_final_seguridad_informatica/refs/heads/main/lab1/access.log
wget -O lab2/simular_bruteforce.sh https://raw.githubusercontent.com/abelthf/examen_final_seguridad_informatica/refs/heads/main/lab2/simular_bruteforce.sh
wget -O lab3/network_traffic.csv https://raw.githubusercontent.com/abelthf/examen_final_seguridad_informatica/refs/heads/main/lab3/network_traffic.csv
chmod +x lab2/simular_bruteforce.sh

echo "[OK] Datos descargados desde el repositorio del docente."
