"""Executa o experimento mínimo EST x DIN-1 na coorte de 2024 (protocolo congelado, seção 13.9).

Uso (a partir de extensao/):
    PYTHONPATH=src python -m vulnprio.experimentos --etapa descritivo
    PYTHONPATH=src python -m vulnprio.experimentos --etapa deterministico
    PYTHONPATH=src python -m vulnprio.experimentos --etapa sementes
    PYTHONPATH=src python -m vulnprio.experimentos --etapa estatistica
Cada etapa grava em results/<id>/ (padrão: results/fase_b_2024/). Nada é gravado fora de extensao/.
"""
from __future__ import annotations

import argparse
import json
import platform
import sys
from datetime import datetime, timezone

import numpy as np
import pandas as pd
import scipy
from scipy.stats import binomtest

from . import config as C
from . import estado as E
from . import metricas as M
from . import politicas as P
from . import rotulos as R
from . import simulador as S


def _saida(run_id: str):
    d = C.RESULTS / run_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def _registrar_ambiente(d):
    info = {
        "executado_em_utc": datetime.now(timezone.utc).isoformat(),
        "python": sys.version,
        "plataforma": platform.platform(),
        "numpy": np.__version__,
        "pandas": pd.__version__,
        "scipy": scipy.__version__,
        "config": {k: (str(v) if not isinstance(v, (int, float, tuple)) else v)
                   for k, v in vars(C).items() if k.isupper()},
    }
    (d / "ambiente.json").write_text(json.dumps(info, indent=1, default=str))


def descritivo(coorte, est, rot, d):
    u = P.desempate(coorte["cve"])
    sem = est.semanas
    vis_sem = [int(est.em(w).visivel.sum()) for w in range(len(est))]
    chegadas = np.bincount(rot.e[rot.e >= 0], minlength=len(est))
    out = {
        "n_cves": int(est.n),
        "n_semanas_decisao": len(est),
        "primeira_decisao": sem[0].isoformat(),
        "ultima_decisao": sem[-1].isoformat(),
        "kev_no_catalogo_F": int((~np.isnat(rot.k)).sum()),
        "kev_rotulo_y": int(rot.y.sum()),
        "conhecidos_na_entrada": int(rot.conhecido_entrada.sum()),
        "tardios": int(rot.tardio.sum()),
        "A": int(rot.A.sum()),
        "A_T": int(rot.A_T.sum()),
        "A_pos": int(rot.A_pos.sum()),
        "nunca_visiveis_ate_T_fim": int((rot.e < 0).sum()),
        "chegadas_media_semanal": float(chegadas[1:].mean()),
        "chegadas_mediana_semanal": float(np.median(chegadas[1:])),
        "A_por_atraso": pd.cut(rot.atraso[rot.A], [0, 7, 30, 90, 365]).value_counts().sort_index().astype(int)
        .rename(index=str).to_dict(),
        "A_por_omega": pd.cut(rot.omega[rot.A], [0, 1, 4, 13, 10_000], labels=["1", "2-4", "5-13", ">13"])
        .value_counts().sort_index().astype(int).to_dict(),
    }
    pct_entrada = np.array([est.em(rot.e[i]).pct[i] if rot.e[i] >= 0 else np.nan for i in range(est.n)])
    vc = pd.Series(np.round(pct_entrada[~np.isnan(pct_entrada)], 5)).value_counts()
    out["percentil_entrada_valor_mais_comum_frac"] = float(vc.iloc[0] / vc.sum())
    out["percentil_entrada_valores_distintos"] = int(len(vc))
    sc = np.load(C.DERIVED / "epss_semanal.npz")["score"]
    sc_entrada = np.array([sc[rot.e[i], i] if rot.e[i] >= 0 else np.nan for i in range(est.n)])
    out["score_entrada_le_0_0005_frac"] = float(np.nanmean(sc_entrada <= 0.0005))
    out["score_entrada_gt_0_001_n"] = int(np.nansum(sc_entrada > 0.001))
    (d / "descritivo.json").write_text(json.dumps(out, indent=1))
    # Exploratório (registrado como desvio 10): acertos das estratégias de limiar do artigo,
    # separados entre KEV já conhecidos e KEV ainda por vir na data do primeiro EPSS.
    kev_nvd = coorte["nvd_kev"] != ""
    k_dt = pd.to_datetime(coorte["k"].replace("", np.nan))
    a_dt = pd.to_datetime(coorte["epss_data_fase_a"])
    p_dt = pd.to_datetime(coorte["p"])
    linhas = []
    for nome, lim in (("EPSS 0.10%", 0.001), ("EPSS 0.50%", 0.005), ("EPSS 1.00%", 0.01)):
        tp = kev_nvd & (coorte["epss_primeiro_fase_a"] > lim)
        linhas.append({"estrategia": nome, "acertos_TP": int(tp.sum()),
                       "kev_ate_data_do_1o_epss": int((tp & (k_dt <= a_dt)).sum()),
                       "kev_ate_publicacao": int((tp & (k_dt <= p_dt)).sum()),
                       "conhecidos_na_entrada": int((tp & rot.conhecido_entrada).sum()),
                       "em_A_antecipaveis": int((tp & rot.A).sum())})
    pd.DataFrame(linhas).to_csv(d / "acertos_artigo_reconhecer_vs_antecipar.csv", index=False)
    pd.DataFrame({"semana": [t.isoformat() for t in sem], "chegadas": chegadas, "visiveis": vis_sem}).to_csv(
        d / "chegadas_por_semana.csv", index=False)
    M.perfil_conjuntos(rot).to_csv(d / "perfil_A_T_vs_A_pos.csv", index=False)
    return out


def deterministico(coorte, est, rot, d):
    u = P.desempate(coorte["cve"])
    resumos, comps, h3, logs, por_evento = [], [], [], [], []
    for K in C.GRADE_K:
        rs = {nome: S.simular(est, cls, K, u) for nome, cls in P.POLITICAS.items()}
        for nome, r in rs.items():
            resumos.append(M.resumir(r, rot, est.semanas))
            lg = pd.DataFrame(r.log)
            lg["politica"], lg["K"] = nome, K
            logs.append(lg)
        comps.append(M.comparar(rs["EST"], rs["DIN-1"], rot, est.semanas))
        h3.append(M.h3_tabelas(rs["EST"], rs["DIN-1"], rot, est.semanas))
        a_e, f_e = M.antecipados(rs["EST"], rot, est.semanas)
        a_d, f_d = M.antecipados(rs["DIN-1"], rot, est.semanas)
        for i in np.flatnonzero(rot.A):
            por_evento.append({"K": K, "cve": coorte.at[i, "cve"], "A_T": bool(rot.A_T[i]),
                               "atraso_dias": rot.atraso[i], "omega": int(rot.omega[i]),
                               "ant_EST": bool(a_e[i]), "ant_DIN": bool(a_d[i]),
                               "folga_EST": f_e[i], "folga_DIN": f_d[i]})
    pd.DataFrame(resumos).to_csv(d / "resumo_por_politica_K.csv", index=False)
    pd.DataFrame(comps).to_csv(d / "comparacao_EST_DIN_por_K.csv", index=False)
    pd.concat(h3).to_csv(d / "h3_atraso_omega.csv", index=False)
    pd.concat(logs).to_csv(d / "log_semanal.csv.gz", index=False, compression="gzip")
    pd.DataFrame(por_evento).to_csv(d / "eventos_A_por_K.csv", index=False)


def sementes(coorte, est, rot, d):
    linhas = []
    for s in range(C.N_SEMENTES):
        u = P.desempate(coorte["cve"], s)
        for K in C.GRADE_K:
            rs = {nome: S.simular(est, cls, K, u, kendall=False) for nome, cls in P.POLITICAS.items()}
            c = M.comparar(rs["EST"], rs["DIN-1"], rot, est.semanas)
            re, rd = (M.resumir(rs[n], rot, est.semanas) for n in ("EST", "DIN-1"))
            linhas.append({"semente": s, "K": K, "N_EST": re["N_A"], "N_DIN": rd["N_A"], "dN_A": c["dN_A"],
                           "dN_A_T": c["dN_A_T"], "LW_EST": re["LW"], "LW_DIN": rd["LW"],
                           "U_DIN": rd["U_medio"], "deslocadas_DIN": rd["deslocadas_total"], "Gamma": c["Gamma"],
                           "so_DIN": c["so_DIN"], "so_EST": c["so_EST"]})
    df = pd.DataFrame(linhas)
    df.to_csv(d / "sementes_20.csv", index=False)
    resumo = df.groupby("K").agg(
        dN_media=("dN_A", "mean"), dN_p2_5=("dN_A", lambda x: np.percentile(x, 2.5)),
        dN_p97_5=("dN_A", lambda x: np.percentile(x, 97.5)), dN_min=("dN_A", "min"), dN_max=("dN_A", "max"),
        N_EST_media=("N_EST", "mean"), N_DIN_media=("N_DIN", "mean"),
        sementes_dN_pos=("dN_A", lambda x: int((x > 0).sum())),
        sementes_dN_neg=("dN_A", lambda x: int((x < 0).sum())),
        U_DIN_media=("U_DIN", "mean")).reset_index()
    resumo.to_csv(d / "sementes_20_resumo.csv", index=False)


def estatistica(coorte, est, rot, d):
    """K primário, desempate determinístico: McNemar exato e bootstrap por eventos (B = 10.000)."""
    ev = pd.read_csv(d / "eventos_A_por_K.csv")
    out = []
    rng = np.random.default_rng(20261121)
    for K in C.GRADE_K:
        e = ev[ev["K"] == K]
        b = int((e.ant_DIN & ~e.ant_EST).sum())
        c = int((e.ant_EST & ~e.ant_DIN).sum())
        p = binomtest(b, b + c, 0.5).pvalue if b + c else 1.0
        dif = (e.ant_DIN.astype(int) - e.ant_EST.astype(int)).to_numpy()
        lw_e = np.clip(np.nan_to_num(e.folga_EST.where(e.ant_EST), nan=0), 0, 90) / 90
        lw_d = np.clip(np.nan_to_num(e.folga_DIN.where(e.ant_DIN), nan=0), 0, 90) / 90
        dlw = np.asarray(lw_d - lw_e, dtype=float)
        n = len(e)
        idx = rng.integers(0, n, size=(C.BOOTSTRAP_B, n))
        bs_r = dif[idx].mean(axis=1)
        bs_lw = dlw[idx].mean(axis=1)
        out.append({"K": K, "n_eventos_A": n, "so_DIN_b": b, "so_EST_c": c, "mcnemar_exato_p": p,
                    "dR_A": dif.mean(), "dR_IC95_inf": np.percentile(bs_r, 2.5),
                    "dR_IC95_sup": np.percentile(bs_r, 97.5), "dLW": dlw.mean(),
                    "dLW_IC95_inf": np.percentile(bs_lw, 2.5), "dLW_IC95_sup": np.percentile(bs_lw, 97.5),
                    "dN": int(dif.sum()), "relevante_dN_ge_5": bool(dif.sum() >= C.EFEITO_MINIMO_KEV)})
    pd.DataFrame(out).to_csv(d / "estatistica_mcnemar_bootstrap.csv", index=False)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--etapa", choices=["descritivo", "deterministico", "sementes", "estatistica", "tudo"],
                    default="tudo")
    ap.add_argument("--run-id", default="fase_b_2024")
    a = ap.parse_args()
    coorte, est = E.carregar()
    rot = R.construir(coorte, est)
    d = _saida(a.run_id)
    _registrar_ambiente(d)
    etapas = ["descritivo", "deterministico", "sementes", "estatistica"] if a.etapa == "tudo" else [a.etapa]
    for et in etapas:
        print(f"== {et}")
        r = globals()[et](coorte, est, rot, d)
        if isinstance(r, dict):
            print(json.dumps(r, indent=1))


if __name__ == "__main__":
    main()
