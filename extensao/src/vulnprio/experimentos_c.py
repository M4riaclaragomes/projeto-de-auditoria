"""Experimento exploratório da Fase C: EST, DIN-1 e DIN-ESTAB na grade pré-registrada de lambda (K = 50).

Uso (a partir de extensao/):  PYTHONPATH=src python -m vulnprio.experimentos_c
Grava apenas em results/fase_c_2024/. Pré-registro: freeze/protocolo_fase_c_preregistro.md.
"""
from __future__ import annotations

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
from . import politicas_c as PC
from . import rotulos as R
from . import simulador_c as SC

K = C.K_PRIMARIO
GRADE_LAMBDA = (0.0, 0.001, 0.003, 0.01, 0.03, 0.1, 0.3, 2.0)   # 2.0 = "infinito" (plano travado)
LAMBDA_MODERADO = 0.01


def rotulo(lam):
    return "∞" if lam > 1 else f"{lam:g}"


def configuracoes():
    yield "EST", PC.EstaticaC, 0.0
    for lam in GRADE_LAMBDA:
        yield ("DIN-1" if lam == 0 else f"DIN-ESTAB λ={rotulo(lam)}"), PC.DinamicaC, lam


def estabilidade(res) -> dict:
    lg = pd.DataFrame(res.log)
    emp = res.empurradas
    sw = res.semana_sel[emp[:, 1]] if len(emp) else np.array([])
    return {
        "revisoes_total": int(lg.revisoes.sum()),
        "revisoes_atualizacao": int(lg.revisoes_por_atualizacao.sum()),
        "revisoes_outras": int(lg.revisoes_outras_causas.sum()),
        "saidas_forcadas_plano": int(lg.saidas_forcadas_plano.sum()),
        "plano_total": int(lg.plano_anterior.sum()),
        "mudancas_contrafactuais": int(lg.deslocadas_por_atualizacao.sum()),
        "empurradas_cves_unicas": int(len(np.unique(emp[:, 1]))) if len(emp) else 0,
        "empurradas_selecionadas_depois_frac": float((sw >= 0).mean()) if len(emp) else np.nan,
    }


def rodar(est, rot, u, kendall=True):
    out = {}
    for nome, cls, lam in configuracoes():
        out[nome] = (lam, SC.simular_c(est, cls(est.n), K, u, lam, kendall=kendall))
    return out


def main():
    d = C.RESULTS / "fase_c_2024"
    d.mkdir(parents=True, exist_ok=True)
    coorte, est = E.carregar()
    rot = R.construir(coorte, est)
    u = P.desempate(coorte["cve"])
    (d / "ambiente.json").write_text(json.dumps({
        "executado_em_utc": datetime.now(timezone.utc).isoformat(), "python": sys.version,
        "plataforma": platform.platform(), "numpy": np.__version__, "pandas": pd.__version__,
        "scipy": scipy.__version__, "K": K, "grade_lambda": GRADE_LAMBDA, "lambda_moderado": LAMBDA_MODERADO,
        "n_sementes": C.N_SEMENTES, "bootstrap_B": C.BOOTSTRAP_B, "bootstrap_semente": 20261121,
        "preregistro": "freeze/protocolo_fase_c_preregistro.md"}, indent=1))

    # 1. Execução determinística
    runs = rodar(est, rot, u)
    linhas, eventos, logs = [], [], []
    ant = {}
    for nome, (lam, r) in runs.items():
        res = M.resumir(r, rot, est.semanas)
        a, f = M.antecipados(r, rot, est.semanas)
        ant[nome] = (a, f)
        linha = {"config": nome, "lambda": lam, "N_A": res["N_A"], "R_A": res["R_A"],
                 "N_A_T": res["N_A_T"], "N_A_pos": res["N_A_pos"],
                 "N_folga30": int(((f >= 30) & a).sum()), "N_folga90": int(((f >= 90) & a).sum()),
                 "folga_mediana_A": res["folga_mediana_A"], "LW": res["LW"], "precisao": res["precisao"],
                 "alfa_medio": res["alfa_medio"], "U_medio": res["U_medio"],
                 "kendall_dist_medio": res["kendall_dist_medio"],
                 "frac_sel_idade_gt90": res["frac_sel_idade_gt90"],
                 "espera_mediana_todas_dias": res["espera_mediana_todas_dias"]}
        linha.update(estabilidade(r))
        linhas.append(linha)
        lg = pd.DataFrame(r.log)
        lg["config"] = nome
        logs.append(lg)
    tab = pd.DataFrame(linhas)
    din = tab[tab.config == "DIN-1"].iloc[0]
    estt = tab[tab.config == "EST"].iloc[0]
    tab["dN_vs_DIN1"] = tab.N_A - din.N_A
    tab["dN_vs_EST"] = tab.N_A - estt.N_A
    tab["reducao_revisoes_vs_DIN1"] = 1 - tab.revisoes_total / din.revisoes_total
    tab["frac_ganho_DIN1_preservado"] = (tab.N_A - estt.N_A) / (din.N_A - estt.N_A)

    # Pareto em (N, revisões) e (N_folga30, revisões)
    def dominadas(col_n):
        dom = []
        for i, a in tab.iterrows():
            por = [b.config for j, b in tab.iterrows() if j != i and b[col_n] >= a[col_n]
                   and b.revisoes_total <= a.revisoes_total
                   and (b[col_n] > a[col_n] or b.revisoes_total < a.revisoes_total)]
            dom.append("; ".join(por))
        return dom
    tab["dominada_por_N"] = dominadas("N_A")
    tab["dominada_por_N30"] = dominadas("N_folga30")
    tab["pareto_N"] = tab.dominada_por_N == ""
    tab["pareto_N30"] = tab.dominada_por_N30 == ""

    # 2. Discordantes, McNemar e bootstrap vs DIN-1 e vs EST
    a_din, f_din = ant["DIN-1"]
    a_est, _ = ant["EST"]
    rng = np.random.default_rng(20261121)
    idxA = np.flatnonzero(rot.A)
    boot = rng.integers(0, len(idxA), size=(C.BOOTSTRAP_B, len(idxA)))
    stats = []
    for nome, (a, f) in ant.items():
        for ref_nome, ref in (("DIN-1", a_din), ("EST", a_est)):
            ganha = a & ~ref
            perde = ref & ~a
            b, c = int(ganha.sum()), int(perde.sum())
            dif = (a.astype(int) - ref.astype(int))[idxA]
            bs = dif[boot].sum(axis=1)
            stats.append({"config": nome, "referencia": ref_nome, "ganha": b, "perde": c,
                          "dN": b - c, "mcnemar_p": binomtest(b, b + c, 0.5).pvalue if b + c else 1.0,
                          "dN_IC95_inf": float(np.percentile(bs, 2.5)), "dN_IC95_sup": float(np.percentile(bs, 97.5))})
            if ref_nome == "DIN-1" and nome != "DIN-1":
                for i in np.flatnonzero(ganha | perde):
                    eventos.append({"config": nome, "cve": coorte.at[i, "cve"],
                                    "tipo": "ganha_vs_DIN1" if ganha[i] else "perde_vs_DIN1",
                                    "atraso_dias": rot.atraso[i], "omega": int(rot.omega[i]),
                                    "A_T": bool(rot.A_T[i]), "folga_config": f[i], "folga_DIN1": f_din[i]})
    pd.DataFrame(stats).to_csv(d / "comparacoes_mcnemar_bootstrap.csv", index=False)
    pd.DataFrame(eventos).to_csv(d / "kev_discordantes_vs_DIN1.csv", index=False)

    # 3. Sementes
    sem = []
    for s in range(C.N_SEMENTES):
        us = P.desempate(coorte["cve"], s)
        for nome, (lam, r) in rodar(est, rot, us, kendall=False).items():
            res = M.resumir(r, rot, est.semanas)
            sem.append({"semente": s, "config": nome, "lambda": lam, "N_A": res["N_A"],
                        "revisoes_total": int(sum(x["revisoes"] for x in r.log)),
                        "mudancas_contrafactuais": res["deslocadas_total"]})
    sem = pd.DataFrame(sem)
    sem.to_csv(d / "sementes_20.csv", index=False)
    rs = sem.groupby("config").agg(N_media=("N_A", "mean"), N_min=("N_A", "min"), N_max=("N_A", "max"),
                                   revisoes_media=("revisoes_total", "mean"),
                                   revisoes_min=("revisoes_total", "min"),
                                   revisoes_max=("revisoes_total", "max")).reset_index()
    tab = tab.merge(rs, on="config", how="left")

    # 4. Hipóteses e regra de escolha pré-registradas
    mod = tab[tab["lambda"] == LAMBDA_MODERADO].iloc[0]
    inf = tab[tab["lambda"] == 2.0].iloc[0]
    perda_inf = int(din.N_A - inf.N_A)
    h = {
        "H1": {"reducao_revisoes_lambda_0.01": float(mod.reducao_revisoes_vs_DIN1),
               "criterio": ">= 0.25", "situacao": "sustentada" if mod.reducao_revisoes_vs_DIN1 >= 0.25 else "refutada"},
        "H2": {"N_lambda_0.01": int(mod.N_A), "criterio": ">= 24",
               "situacao": "sustentada" if mod.N_A >= 24 else "refutada"},
        "H3": {"N_lambda_inf": int(inf.N_A), "N_DIN1": int(din.N_A), "perda": perda_inf,
               "N30_lambda_inf": int(inf.N_folga30), "N30_DIN1": int(din.N_folga30),
               "situacao": ("sustentada" if perda_inf >= 5 and inf.N_folga30 < din.N_folga30
                            else "refutada" if perda_inf <= 2 else "inconclusiva")},
    }
    media_din = float(rs[rs.config == "DIN-1"].N_media.iloc[0])
    cand = tab[(tab["lambda"] > 0) & (tab.N_A >= din.N_A - 2) & (tab.N_media >= media_din - 2)]
    if len(cand):
        esc = cand.sort_values(["revisoes_total", "lambda"]).iloc[0]
        regra = {"lambda_escolhido": float(esc["lambda"]), "config": esc.config,
                 "N_A": int(esc.N_A), "revisoes_total": int(esc.revisoes_total),
                 "candidatos": cand.config.tolist(),
                 "observacao": "Escolha exploratória na coorte de 2024; confirmação só na Fase D, sem recalibração."}
    else:
        regra = {"lambda_escolhido": None, "observacao": "Nenhum lambda > 0 satisfez a regra (resultado negativo)."}
    (d / "hipoteses_e_regra.json").write_text(json.dumps({"hipoteses": h, "regra_escolha": regra}, indent=1,
                                                          ensure_ascii=False))
    # 5. Mecanismo (análise pós-hoc, não pré-registrada): tamanho dos saltos de percentil
    pct = np.load(C.DERIVED / "epss_semanal.npz")["pct"]
    r_din = runs["DIN-1"][1]
    so_din = np.flatnonzero(a_din & ~a_est)
    w_sel = r_din.semana_sel[so_din]
    entrada = pct[rot.e[so_din], so_din]
    na_sel = pct[w_sel, so_din]
    semana_antes = pct[np.maximum(w_sel - 1, 0), so_din]
    dif = np.abs(np.diff(pct, axis=0))
    dif = dif[np.isfinite(dif) & (dif > 0)]
    mec = {"rotulo": "pós-hoc, exploratório",
           "kev_so_DIN1_vs_EST": int(len(so_din)),
           "percentil_entrada_mediana": float(np.median(entrada)), "percentil_entrada_max": float(entrada.max()),
           "salto_entrada_ate_selecao_min": float((na_sel - entrada).min()),
           "salto_entrada_ate_selecao_mediana": float(np.median(na_sel - entrada)),
           "salto_ultima_semana_mediana": float(np.median(na_sel - semana_antes)),
           "variacao_semanal_abs_todas_visiveis": {"mediana": float(np.median(dif)),
                                                   "p90": float(np.percentile(dif, 90)),
                                                   "p99": float(np.percentile(dif, 99))}}
    (d / "mecanismo_saltos_posthoc.json").write_text(json.dumps(mec, indent=1, ensure_ascii=False))
    tab.to_csv(d / "resumo_configuracoes_K50.csv", index=False)
    pd.concat(logs).to_csv(d / "log_semanal_K50.csv.gz", index=False, compression="gzip")
    return tab, h, regra


if __name__ == "__main__":
    tab, h, regra = main()
    pd.set_option("display.width", 250)
    pd.set_option("display.max_columns", 40)
    print(tab[["config", "N_A", "dN_vs_DIN1", "N_folga30", "N_folga90", "folga_mediana_A", "revisoes_total",
               "revisoes_atualizacao", "revisoes_outras", "reducao_revisoes_vs_DIN1", "alfa_medio",
               "mudancas_contrafactuais", "kendall_dist_medio", "N_min", "N_max", "pareto_N", "pareto_N30"]]
          .round(3).to_string())
    print(json.dumps({"hipoteses": h, "regra": regra}, indent=1, ensure_ascii=False))
