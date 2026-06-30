#!/usr/bin/env python3
"""Lab 1.3 — Genera graficas PNG desde auth.log y access.log."""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from urllib.parse import unquote

import matplotlib.pyplot as plt
import pandas as pd

BASE_DIR = Path(__file__).resolve().parent
GRAF_DIR = BASE_DIR / "graficas"
GRAF_DIR.mkdir(exist_ok=True)
AUTH_LOG = BASE_DIR / "auth.log"
ACCESS_LOG = BASE_DIR / "access.log"

FAILED_RE = re.compile(r"Failed password.* from (?P<ip>(?:\d{1,3}\.){3}\d{1,3})\b", re.IGNORECASE)
LOG_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<fecha>[^\]]+)\] "(?P<metodo>\S+) (?P<url>\S+) (?P<proto>[^"]+)" '
    r'(?P<status>\d{3}) (?P<bytes>\S+) "(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
)


def parse_fecha(fecha: str) -> datetime | None:
    for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%d/%b/%Y:%H:%M:%S"):
        try:
            return datetime.strptime(fecha, fmt)
        except ValueError:
            pass
    return None


def grafico_top10_ssh() -> None:
    if not AUTH_LOG.exists():
        raise FileNotFoundError("Falta lab1/auth.log")

    contador = Counter()
    with AUTH_LOG.open("r", encoding="utf-8", errors="ignore") as f:
        for linea in f:
            m = FAILED_RE.search(linea)
            if m:
                contador[m.group("ip")] += 1

    top10 = contador.most_common(10)
    ips = [x[0] for x in top10]
    valores = [x[1] for x in top10]

    plt.figure(figsize=(11, 6))
    plt.bar(ips, valores)
    plt.title("Top 10 IPs con mas intentos fallidos SSH")
    plt.xlabel("IP de origen")
    plt.ylabel("Intentos fallidos")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.savefig(GRAF_DIR / "top10_ssh.png", dpi=150)
    plt.close()


def cargar_access() -> pd.DataFrame:
    filas = []
    if not ACCESS_LOG.exists():
        raise FileNotFoundError("Falta lab1/access.log")

    with ACCESS_LOG.open("r", encoding="utf-8", errors="ignore") as f:
        for linea in f:
            m = LOG_RE.search(linea.strip())
            if not m:
                continue
            fecha = parse_fecha(m.group("fecha"))
            if fecha is None:
                continue
            filas.append(
                {
                    "timestamp": fecha,
                    "ip": m.group("ip"),
                    "url": unquote(m.group("url")),
                    "status": int(m.group("status")),
                }
            )
    return pd.DataFrame(filas)


def grafico_timeline_http(df: pd.DataFrame) -> None:
    df = df.copy()
    df["hora"] = pd.to_datetime(df["timestamp"], utc=True).dt.floor("h")
    serie = df.groupby("hora").size()

    plt.figure(figsize=(11, 6))
    plt.plot(serie.index, serie.values, marker="o")
    plt.title("Numero de peticiones HTTP por hora")
    plt.xlabel("Hora")
    plt.ylabel("Cantidad de peticiones")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.savefig(GRAF_DIR / "timeline_http.png", dpi=150)
    plt.close()


def grafico_heatmap_http(df: pd.DataFrame) -> None:
    df = df.copy()
    df["hora"] = pd.to_datetime(df["timestamp"], utc=True).dt.hour
    codigos = [200, 301, 404, 500]
    tabla = pd.crosstab(df["hora"], df["status"]).reindex(columns=codigos, fill_value=0).fillna(0)
    tabla = tabla.reindex(range(24), fill_value=0)

    plt.figure(figsize=(8, 8))
    plt.imshow(tabla.values, aspect="auto")
    plt.title("Heatmap de peticiones HTTP por hora y codigo de respuesta")
    plt.xlabel("Codigo de respuesta")
    plt.ylabel("Hora del dia")
    plt.xticks(range(len(codigos)), codigos)
    plt.yticks(range(24), range(24))
    plt.colorbar(label="Cantidad de peticiones")
    plt.tight_layout()
    plt.savefig(GRAF_DIR / "heatmap_http.png", dpi=150)
    plt.close()


def main() -> None:
    grafico_top10_ssh()
    df = cargar_access()
    grafico_timeline_http(df)
    grafico_heatmap_http(df)
    print("[OK] Graficas generadas en lab1/graficas/")
    print(" - top10_ssh.png")
    print(" - timeline_http.png")
    print(" - heatmap_http.png")


if __name__ == "__main__":
    main()
