#!/usr/bin/env python3
"""
Lab 1.2 — Analisis de access.log Apache Combined Log Format.
Detecta escaneo de directorios, errores 4xx/5xx e intentos de SQL Injection.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import unquote, urlsplit

BASE_DIR = Path(__file__).resolve().parent
ACCESS_LOG = BASE_DIR / "access.log"
REPORTE = BASE_DIR / "reporte_web.json"

# Apache Combined Log Format:
# IP - - [10/Oct/2025:13:55:36 -0500] "GET /index.html HTTP/1.1" 200 1234 "-" "UA"
LOG_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<fecha>[^\]]+)\] "(?P<metodo>\S+) (?P<url>\S+) (?P<proto>[^"]+)" '
    r'(?P<status>\d{3}) (?P<bytes>\S+) "(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
)

SQLI_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [r"\bUNION\b", r"\bSELECT\b", r"--", r"\bOR\s+1\s*=\s*1\b", r"'"]
]


def parse_fecha(fecha: str) -> datetime | None:
    for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%d/%b/%Y:%H:%M:%S"):
        try:
            return datetime.strptime(fecha, fmt)
        except ValueError:
            continue
    return None


def limpiar_ruta(url: str) -> str:
    try:
        partes = urlsplit(url)
        return partes.path or "/"
    except Exception:
        return url.split("?")[0]


def analizar_access_log(path: Path = ACCESS_LOG) -> dict:
    if not path.exists():
        raise FileNotFoundError(f"No existe {path}. Copia access.log dentro de lab1/")

    eventos: list[dict] = []
    errores_por_ip: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    sqli: list[dict] = []
    parse_errors = 0

    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for nro, linea in enumerate(f, start=1):
            m = LOG_RE.search(linea.strip())
            if not m:
                parse_errors += 1
                continue

            fecha = parse_fecha(m.group("fecha"))
            if fecha is None:
                parse_errors += 1
                continue

            ip = m.group("ip")
            url_original = m.group("url")
            url_decodificada = unquote(url_original)
            status = int(m.group("status"))
            ruta = limpiar_ruta(url_decodificada)

            evento = {
                "linea": nro,
                "ip": ip,
                "timestamp": fecha,
                "metodo": m.group("metodo"),
                "url": url_original,
                "url_decodificada": url_decodificada,
                "ruta": ruta,
                "status": status,
            }
            eventos.append(evento)

            if 400 <= status <= 599:
                errores_por_ip[ip][str(status)] += 1

            patrones = [p.pattern for p in SQLI_PATTERNS if p.search(url_decodificada)]
            if patrones:
                sqli.append(
                    {
                        "ip": ip,
                        "timestamp": fecha.strftime("%Y-%m-%d %H:%M:%S %z"),
                        "url": url_original,
                        "patrones": patrones,
                        "status": status,
                    }
                )

    # Escaneo de directorios: mas de 20 rutas distintas en menos de 60 segundos por IP.
    por_ip: dict[str, list[dict]] = defaultdict(list)
    for ev in eventos:
        por_ip[ev["ip"]].append(ev)

    escaneos: list[dict] = []
    for ip, lista in por_ip.items():
        lista = sorted(lista, key=lambda x: x["timestamp"])
        inicio = 0
        for fin in range(len(lista)):
            while lista[fin]["timestamp"] - lista[inicio]["timestamp"] > timedelta(seconds=60):
                inicio += 1
            ventana = lista[inicio : fin + 1]
            rutas = sorted({ev["ruta"] for ev in ventana})
            if len(rutas) > 20:
                escaneos.append(
                    {
                        "ip": ip,
                        "inicio": ventana[0]["timestamp"].strftime("%Y-%m-%d %H:%M:%S %z"),
                        "fin": ventana[-1]["timestamp"].strftime("%Y-%m-%d %H:%M:%S %z"),
                        "rutas_distintas": len(rutas),
                        "total_peticiones": len(ventana),
                        "muestra_rutas": rutas[:10],
                    }
                )
                break

    reporte = {
        "fecha_analisis": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_peticiones_parseadas": len(eventos),
        "lineas_no_parseadas": parse_errors,
        "escaneos_directorios": escaneos,
        "errores_por_ip": {ip: dict(codigos) for ip, codigos in errores_por_ip.items()},
        "posibles_sqli": sqli,
    }

    print("\n=== Deteccion de escaneo de directorios ===")
    if escaneos:
        for item in escaneos:
            print(f"[ESCANEO] {item['ip']} — {item['rutas_distintas']} rutas distintas en 60s")
    else:
        print("No se detectaron escaneos segun el umbral configurado.")

    print("\n=== Posibles intentos SQL Injection ===")
    if sqli:
        for item in sqli[:20]:
            print(f"[SQLi] {item['ip']} — {item['url']} — status {item['status']}")
        if len(sqli) > 20:
            print(f"... {len(sqli) - 20} detecciones adicionales en el JSON")
    else:
        print("No se detectaron patrones SQLi.")

    print("\n=== IPs con errores 4xx/5xx ===")
    for ip, codigos in list(errores_por_ip.items())[:20]:
        total = sum(codigos.values())
        print(f"{ip:<15} total={total} detalle={dict(codigos)}")

    with REPORTE.open("w", encoding="utf-8") as f:
        json.dump(reporte, f, indent=2, ensure_ascii=False)

    print(f"\n[OK] Reporte generado: {REPORTE}")
    return reporte


if __name__ == "__main__":
    analizar_access_log()
