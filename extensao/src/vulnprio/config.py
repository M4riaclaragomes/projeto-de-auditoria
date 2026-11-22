"""Constantes do protocolo congelado (Fase B, seção 13). Alterá-las exige registro de desvio."""
from __future__ import annotations

import os
from datetime import date
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[2]
FASE_A = Path(os.environ.get("FASE_A_DIR", RAIZ.parent / "projeto")).resolve()

RAW = RAIZ / "data" / "raw"
DERIVED = RAIZ / "data" / "derived"
RESULTS = RAIZ / "results"

CORPUS_VARIANTE = FASE_A / "data" / "nvd-2024-filtered-variant.jsonl"
METRICAS_VARIANTE = FASE_A / "data" / "nvd-2024-strategy-metrics-variant.csv"
KEV_JSON = RAW / "kev" / "known_exploited_vulnerabilities_2026.11.20.json"
EPSS_DIR = RAW / "epss_daily"

# Calendário da coorte de desenvolvimento (2024, EPSS v3)
PRIMEIRA_DECISAO = date(2024, 1, 1)      # segunda-feira
T_FIM = date(2025, 3, 16)                # último dia do EPSS v3
EPSS_INICIO = date(2024, 1, 1)
MODELO_ESPERADO = "v2023.03.01"
W_DIAS = 365                              # horizonte do rótulo
F_CONGELAMENTO = date(2026, 11, 20)       # catálogo KEV 2026.11.20

K_PRIMARIO = 50
GRADE_K = (10, 25, 50, 100, 250, 500)
N_SEMENTES = 20
BOOTSTRAP_B = 10_000
EFEITO_MINIMO_KEV = 5                     # >= 5 KEV adicionais (5 p.p. de 86)
