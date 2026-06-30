#!/usr/bin/env python3
"""Uso: python predecir.py nuevo_trafico.csv"""
from __future__ import annotations

import argparse
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "modelo_anomalias.pkl"


def preparar_features(df: pd.DataFrame, paquete: dict) -> tuple[pd.DataFrame, pd.DataFrame]:
    df_original = df.copy()
    df = df.copy()

    if "timestamp" in df.columns:
        ts = pd.to_datetime(df["timestamp"], errors="coerce")
        df["hour"] = ts.dt.hour.fillna(0)
        df["dayofweek"] = ts.dt.dayofweek.fillna(0)
    else:
        df["hour"] = 0
        df["dayofweek"] = 0

    for col in ["dst_port", "bytes_sent", "bytes_recv", "duration_sec", "packets"]:
        if col not in df.columns:
            df[col] = 0
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    df["ratio_bytes"] = df["bytes_sent"] / (df["bytes_recv"] + 1)
    df["bytes_por_segundo"] = (df["bytes_sent"] + df["bytes_recv"]) / (df["duration_sec"] + 1)
    df["packets_por_segundo"] = df["packets"] / (df["duration_sec"] + 1)

    clip_bounds = paquete.get("clip_bounds", {})
    for col, bounds in clip_bounds.items():
        if col in df.columns:
            df[col] = df[col].clip(bounds[0], bounds[1])

    protocolo = pd.get_dummies(df.get("protocol", pd.Series(["UNKNOWN"] * len(df))), prefix="protocol")
    features = pd.concat(
        [
            df[[
                "dst_port",
                "bytes_sent",
                "bytes_recv",
                "duration_sec",
                "packets",
                "hour",
                "dayofweek",
                "ratio_bytes",
                "bytes_por_segundo",
                "packets_por_segundo",
            ]],
            protocolo,
        ],
        axis=1,
    )

    feature_columns = paquete["feature_columns"]
    features = features.reindex(columns=feature_columns, fill_value=0)
    return features, df_original


def main() -> None:
    parser = argparse.ArgumentParser(description="Predice anomalias en trafico de red con Isolation Forest")
    parser.add_argument("csv", help="Archivo CSV nuevo a clasificar")
    args = parser.parse_args()

    if not MODEL_PATH.exists():
        raise FileNotFoundError("No existe lab3/modelo_anomalias.pkl. Ejecuta primero el notebook.")

    paquete = joblib.load(MODEL_PATH)
    modelo = paquete["model"]
    scaler = paquete["scaler"]
    threshold = paquete.get("threshold", 0.0)

    df = pd.read_csv(args.csv)
    features, original = preparar_features(df, paquete)
    X = scaler.transform(features)
    scores = modelo.decision_function(X)
    pred = np.where(scores < threshold, -1, 1)

    resultado = original.copy()
    resultado["score_anomalia"] = scores
    resultado["prediccion"] = pred
    anomalos = resultado[resultado["prediccion"] == -1].sort_values("score_anomalia")

    print("=== Registros clasificados como anomalia ===")
    if anomalos.empty:
        print("No se detectaron anomalias con el umbral configurado.")
    else:
        print(anomalos.to_string(index=False))


if __name__ == "__main__":
    main()
