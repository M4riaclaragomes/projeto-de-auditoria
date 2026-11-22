#!/usr/bin/env bash
# Reproduz a Fase C (DIN-ESTAB, K = 50, coorte 2024). Requer os dados derivados da Fase B (rodar_tudo.sh).
set -euo pipefail
cd "$(dirname "$0")"
export PYTHONPATH=src
mkdir -p results/fase_c_2024
python -m pytest -v -rs tests | tee results/fase_c_2024/testes_saida.txt
python -m vulnprio.experimentos_c
python -m vulnprio.graficos_c
