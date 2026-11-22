"""Figuras do experimento mínimo (lê apenas results/<id>/)."""
from __future__ import annotations

import argparse

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from . import config as C

CINZA, AZUL = "#8a8a8a", "#2f6fdb"


def gerar(run_id: str = "fase_b_2024"):
    d = C.RESULTS / run_id
    fig_dir = d / "figuras"
    fig_dir.mkdir(exist_ok=True)
    r = pd.read_csv(d / "resumo_por_politica_K.csv")
    st = pd.read_csv(d / "estatistica_mcnemar_bootstrap.csv")
    log = pd.read_csv(d / "log_semanal.csv.gz")
    ev = pd.read_csv(d / "eventos_A_por_K.csv")

    # F1: KEV antecipados por K
    fig, ax = plt.subplots(figsize=(7, 4))
    for pol, cor in (("EST", CINZA), ("DIN-1", AZUL)):
        x = r[r.politica == pol]
        ax.plot(x.K, x.N_A, "o-", color=cor, label=pol)
        for k, n in zip(x.K, x.N_A):
            ax.annotate(str(n), (k, n), textcoords="offset points", xytext=(0, 6 if pol == "DIN-1" else -13), ha="center", fontsize=8, color=cor)
    ax.set_xscale("log")
    ax.set_xticks(C.GRADE_K, [str(k) for k in C.GRADE_K])
    ax.set_xlabel("Orçamento K (seleções por semana)")
    ax.set_ylabel("KEV antecipados (de 86)")
    ax.set_title("KEV selecionados antes da inclusão no catálogo, coorte 2024")
    ax.legend(frameon=False)
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(fig_dir / "f1_kev_antecipados_por_K.png", dpi=150)
    plt.close(fig)

    # F2: diferença de recall com IC 95% (bootstrap por eventos)
    fig, ax = plt.subplots(figsize=(7, 4))
    y = st.dR_A * 100
    ax.errorbar(st.K, y, yerr=[y - st.dR_IC95_inf * 100, st.dR_IC95_sup * 100 - y], fmt="o", color=AZUL, capsize=4)
    ax.axhline(0, color="black", lw=0.8)
    ax.axhline(5, color=CINZA, lw=0.8, ls="--")
    ax.text(C.GRADE_K[0], 5.6, "relevância mínima (5 p.p.)", fontsize=8, color=CINZA)
    ax.set_xscale("log")
    ax.set_xticks(C.GRADE_K, [str(k) for k in C.GRADE_K])
    ax.set_xlabel("Orçamento K (seleções por semana)")
    ax.set_ylabel("ΔR = R(DIN-1) − R(EST), p.p.")
    ax.set_title("Ganho de recall da atualização semanal (IC 95%, desempate fixo)")
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(fig_dir / "f2_delta_recall_IC95.png", dpi=150)
    plt.close(fig)

    # F3: estabilidade semanal com K = 50
    lg = log[log.K == C.K_PRIMARIO].copy()
    lg["semana"] = pd.to_datetime(lg.semana)
    fig, ax = plt.subplots(figsize=(8, 4))
    for pol, cor in (("EST", CINZA), ("DIN-1", AZUL)):
        x = lg[lg.politica == pol].iloc[1:]
        ax.plot(x.semana, x.alfa.rolling(4, min_periods=1).mean(), color=cor, lw=2,
                label=f"{pol}: aderência ao plano α (média móvel de 4 semanas)")
    x = lg[lg.politica == "DIN-1"].iloc[1:]
    ax.plot(x.semana, x.U.rolling(4, min_periods=1).mean(), color=AZUL, ls=":", lw=2,
            label="DIN-1: fração trocada pela atualização U (média móvel)")
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("Fração da seleção semanal")
    ax.set_title(f"Estabilidade das prioridades, K = {C.K_PRIMARIO}")
    ax.legend(frameon=False, fontsize=8)
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(fig_dir / "f3_estabilidade_semanal_K50.png", dpi=150)
    plt.close(fig)

    # F4: folga dos KEV antecipados, K = 50
    e = ev[ev.K == C.K_PRIMARIO]
    fig, ax = plt.subplots(figsize=(7, 3.6))
    dados = [e.folga_EST[e.ant_EST].to_numpy(), e.folga_DIN[e.ant_DIN].to_numpy()]
    rng = np.random.default_rng(0)
    for i, (vals, cor) in enumerate(zip(dados, (CINZA, AZUL))):
        ax.scatter(vals, i + rng.uniform(-0.12, 0.12, len(vals)), color=cor, s=18, alpha=0.8)
        if len(vals):
            ax.plot([np.median(vals)] * 2, [i - 0.25, i + 0.25], color="black", lw=1.5)
    ax.set_yticks([0, 1], [f"EST (n={len(dados[0])})", f"DIN-1 (n={len(dados[1])})"])
    ax.set_xlabel("Dias entre a seleção e a inclusão no KEV (traço = mediana)")
    ax.set_title(f"Antecedência dos KEV antecipados, K = {C.K_PRIMARIO}")
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(fig_dir / "f4_antecedencia_K50.png", dpi=150)
    plt.close(fig)
    return sorted(p.name for p in fig_dir.iterdir())


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-id", default="fase_b_2024")
    print(gerar(ap.parse_args().run_id))
