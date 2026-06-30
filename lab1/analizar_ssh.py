#!/usr/bin/env python3
"""
Lab 1.1 — Analisis forense de auth.log
Lee lab1/auth.log, cuenta intentos SSH fallidos por IP y genera reporte_ssh.json.
"""
from __future__ import annotations

import json
import re
from collections import Counter
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
AUTH_LOG = BASE_DIR / "auth.log"
REPORTE = BASE_DIR / "reporte_ssh.json"

FAILED_RE = re.compile(
    r"Failed password(?: for (?:invalid user )?\S+)? from (?P<ip>(?:\d{1,3}\.){3}\d{1,3})\b",
    re.IGNORECASE,
)


def analizar_auth_log(path: Path = AUTH_LOG) -> dict:
    if not path.exists():
        raise FileNotFoundError(f"No existe {path}. Copia auth.log dentro de lab1/")

    contador: Counter[str] = Counter()
    total_fallidos = 0

    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for linea in f:
            if "Failed password" not in linea:
                continue
            match = FAILED_RE.search(linea)
            if match:
                ip = match.group("ip")
                contador[ip] += 1
                total_fallidos += 1

    ranking = contador.most_common(10)
    sospechosas = [
        {"ip": ip, "intentos": intentos, "alerta": intentos > 50}
        for ip, intentos in contador.most_common()
    ]

    reporte = {
        "fecha_analisis": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_intentos_fallidos": total_fallidos,
        "ips_sospechosas": sospechosas,
    }

    print("\n=== TOP 10 IPs con mas intentos SSH fallidos ===")
    for i, (ip, intentos) in enumerate(ranking, start=1):
        print(f"{i:02d}. {ip:<15} {intentos:>5} intentos")
        if intentos > 50:
            print(f"[ALERTA] IP: {ip} — {intentos} intentos fallidos — Posible ataque de fuerza bruta")

    with REPORTE.open("w", encoding="utf-8") as f:
        json.dump(reporte, f, indent=2, ensure_ascii=False)

    print(f"\n[OK] Reporte generado: {REPORTE}")
    return reporte


if __name__ == "__main__":
    analizar_auth_log()
