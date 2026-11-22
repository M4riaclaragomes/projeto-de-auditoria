"""Figuras e tabela de comparação de coortes da Fase D (arquivo novo)."""
from __future__ import annotations

import json
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd

from . import config as C, coorte_s, dados_d, estado as ESTADO

OUT = C.RESULTS / "fase_d"
COR = {"EST": "#8c8c8c", "DIN-1": "#1f4e9c", "DIN-ESTAB λ=∞": "#c0392b", "DIN-ESTAB λ=0,3": "#e67e22",
       "DIN-4": "#2e8b57", "DIN-2": "#7fbf7f", "EST-travada": "#4d4d4d"}


def pareto(coortes):
    fig, axs = plt.subplots(1, len(coortes), figsize=(5.2 * len(coortes), 4.2), sharey=True)
    for ax, c in zip(axs if len(coortes) > 1 else [axs], coortes):
        r = pd.read_csv(OUT / c / "resumo_politicas_K50.csv")
        for _, x in r.iterrows():
            ax.scatter(x.revisoes_total, x.N_A, s=60, color=COR[x.politica], zorder=3)
            ax.annotate(x.politica, (x.revisoes_total, x.N_A), textcoords="offset points", xytext=(6, -3), fontsize=8)
        ax.set_title(f"Coorte {c} (K = 50)", fontsize=10)
        ax.set_xlabel("Revisões do plano ΣR (não são cancelamentos)")
        ax.grid(alpha=.3)
        ax.set_xlim(-80, 2050)
    (axs[0] if len(coortes) > 1 else axs).set_ylabel("KEV antecipados (N)")
    fig.tight_layout()
    (OUT / "figuras").mkdir(exist_ok=True)
    fig.savefig(OUT / "figuras" / "fd1_eficacia_vs_revisoes.png", dpi=160)


def comparar_coortes():
    coorte_b, _ = ESTADO.carregar()
    nvd = coorte_s.ler_nvd(C.FASE_A / "data" / "nvd-2024-raw")
    s = pd.read_csv(dados_d.DERIVED_D / "2024-S" / "coorte.csv.gz", keep_default_na=False)
    cmp = coorte_s.comparar_com_variante(s, coorte_b["cve"], nvd)
    linhas = []
    for c in ["2024-variante", "2024-S", "2024-S+rej"]:
        d = json.loads((OUT / c / "descritivo.json").read_text())
        r = pd.read_csv(OUT / c / "resumo_politicas_K50.csv").set_index("politica")
        linhas.append({"coorte": c, "CVEs": d["contagens"]["incluidas"], "KEV_no_catalogo": d["kev_no_catalogo"],
                       "conhecidos_na_entrada": d["conhecidos_na_entrada"], "A": d["A"], "A_T": d["A_T"],
                       "A_pos": d["A_pos"], "tardios": d["tardios"], "chegadas_semana": r.loc["EST", "chegadas_media"],
                       "fila_elegivel_mediana": r.loc["EST", "elegiveis_mediana"],
                       "K_sobre_E_mediana": r.loc["EST", "K_sobre_E_mediana"]})
    pd.DataFrame(linhas).to_csv(OUT / "comparacao_coortes_2024.csv", index=False)
    (OUT / "variante_vs_S_2024.json").write_text(json.dumps(cmp, indent=1, ensure_ascii=False))
    ev_v = pd.read_csv(OUT / "2024-variante" / "eventos_A.csv")
    ev_s = pd.read_csv(OUT / "2024-S" / "eventos_A.csv")
    so = sorted(set(ev_s.cve) ^ set(ev_v.cve))
    (OUT / "eventos_A_diferentes_variante_vs_S.json").write_text(json.dumps(so))
    return cmp, so


if __name__ == "__main__":
    pareto(sys.argv[1:] or ["2024-variante", "2024-S"])
    print(comparar_coortes())
