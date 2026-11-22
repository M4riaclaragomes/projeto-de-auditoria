"""Figura da Fase C: KEV antecipados x revisões do plano (fronteira de Pareto), K = 50."""
from __future__ import annotations

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd

from . import config as C

CINZA, AZUL, ESCURO = "#8a8a8a", "#2f6fdb", "#1b1b1b"


def gerar():
    d = C.RESULTS / "fase_c_2024"
    (d / "figuras").mkdir(exist_ok=True)
    t = pd.read_csv(d / "resumo_configuracoes_K50.csv")
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.4), sharex=True)
    for ax, col, titulo in ((axes[0], "N_A", "KEV antecipados (de 86)"),
                            (axes[1], "N_folga30", "KEV antecipados com folga ≥ 30 dias")):
        par = t[t["pareto_N" if col == "N_A" else "pareto_N30"]].sort_values("revisoes_total")
        ax.step(par.revisoes_total, par[col], where="post", color=AZUL, lw=1, alpha=0.5)
        for _, r in t.iterrows():
            cor = CINZA if r.config == "EST" else (ESCURO if r.config == "DIN-1" else AZUL)
            pareto = r[("pareto_N" if col == "N_A" else "pareto_N30")]
            ax.scatter(r.revisoes_total, r[col], s=70 if pareto else 40, color=cor, zorder=3,
                       edgecolor=ESCURO if pareto else cor, linewidth=1.2)
            rot = r.config.replace("DIN-ESTAB ", "")
            if rot in ("λ=0.001", "λ=0.003"):
                continue
            if rot == "λ=0.01":
                rot = "λ = 0,001 a 0,01"
            dy = -12 if rot in ("DIN-1", "λ=0.03") else 6
            ax.annotate(rot.replace("0.", "0,"), (r.revisoes_total, r[col]), textcoords="offset points",
                        xytext=(-4 if rot == "DIN-1" else 5, dy), fontsize=8, color=cor,
                        ha="right" if rot.startswith("λ = 0,001") else "left")
        ax.set_xlabel("Revisões do plano em 63 semanas (ΣR)")
        ax.set_ylabel(titulo)
        ax.spines[["top", "right"]].set_visible(False)
    fig.suptitle("Fase C, K = 50: antecipação × revisões do plano (linha e contorno = fronteira de Pareto)", fontsize=11)
    fig.tight_layout()
    fig.savefig(d / "figuras" / "fc1_pareto_K50.png", dpi=150)
    plt.close(fig)


if __name__ == "__main__":
    gerar()
