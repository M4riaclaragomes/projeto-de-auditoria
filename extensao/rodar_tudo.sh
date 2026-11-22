#!/usr/bin/env bash
# Reproduz a Fase B (experimento mínimo EST x DIN-1, coorte 2024) do zero.
# Pré-requisito: a pasta da Fase A em ../projeto (ou FASE_A_DIR apontando para ela).
set -euo pipefail
cd "$(dirname "$0")"
export PYTHONPATH=src

python scripts/coleta_kev.py                       # catálogo KEV 2026.11.20 (ver --arquivo no script)
python scripts/coleta_epss_diario.py --inicio 2024-01-01 --fim 2025-03-16
python -m vulnprio.dados                           # tabelas derivadas
python -m pytest -v -rs tests | tee results/testes_saida_completa.txt
python -m vulnprio.experimentos --etapa descritivo
python -m vulnprio.experimentos --etapa deterministico
python -m vulnprio.experimentos --etapa sementes
python -m vulnprio.experimentos --etapa estatistica
python -m vulnprio.graficos
