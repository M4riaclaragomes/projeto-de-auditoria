"""Experimentos da Fase D (protocolo_fase_d.md). Arquivo novo.

Uso:  PYTHONPATH=src python -m vulnprio.experimentos_d 2024-variante 2024-S 2024-S+rej [T1 T2]

Saída em results/fase_d/<coorte>/. As coortes de 2024 e a T1 são exploratórias/descritivas; só a T2 é
confirmatória, e só pode ser executada quando os dados de 2025 estiverem completos e os testes passarem.
"""
from __future__ import annotations

import dataclasses
import json
import math
import sys
from datetime import date

import numpy as np
import pandas as pd
from scipy.stats import binomtest

from . import config as C
from . import dados_d, estado as ESTADO, metricas as M, politicas as P, rotulos
from . import simulador_c as SC
from .experimentos_c import estabilidade
from .politicas_c import DinamicaC, EstaticaC
from .politicas_d import DinamicaDelta

K = C.K_PRIMARIO
B = C.BOOTSTRAP_B
SEMENTE_BOOT = 20261121
LAMBDA_TRAVADO = 2.0
OUT = C.RESULTS / "fase_d"

# (nome, fábrica, lambda, papel)
POLITICAS = [
    ("EST", lambda n: EstaticaC(n), 0.0, "referência"),
    ("DIN-1", lambda n: DinamicaC(n), 0.0, "referência"),
    ("DIN-ESTAB λ=∞", lambda n: DinamicaC(n), LAMBDA_TRAVADO, "confirmatória"),
    ("DIN-ESTAB λ=0,3", lambda n: DinamicaC(n), 0.3, "exploratória pós-hoc"),
    ("DIN-4", lambda n: DinamicaDelta(n, 4), 0.0, "comparador periódico principal"),
    ("DIN-2", lambda n: DinamicaDelta(n, 2), 0.0, "comparador periódico secundário"),
    ("EST-travada", lambda n: EstaticaC(n), LAMBDA_TRAVADO, "controle secundário"),
]

T_FIM = {"2024-variante": C.T_FIM, "2024-S": C.T_FIM, "2024-S+rej": C.T_FIM,
         "T1": date(2025, 3, 16), "T2": date(2026, 6, 14)}
PAPEL = {"2024-variante": "exploratória", "2024-S": "exploratória (ponte)", "2024-S+rej": "exploratória (sensibilidade)",
         "T1": "descritiva", "T2": "CONFIRMATÓRIA"}


def carregar(nome):
    if nome == "2024-variante":
        coorte, est = ESTADO.carregar()
        info = {"coorte": nome, "incluidas": int(len(coorte))}
    else:
        coorte, est, info = dados_d.carregar(nome)
    rot = rotulos.construir(coorte, est)
    tf = np.datetime64(T_FIM[nome], "D")
    rot = dataclasses.replace(rot, A_T=rot.A & (rot.k <= tf), A_pos=rot.A & (rot.k > tf))
    return coorte, est, rot, info


def simular_todas(est, u, kendall=True):
    out = {}
    for nome, fab, lam, _ in POLITICAS:
        r = SC.simular_c(est, fab(est.n), K, u, lam, kendall=kendall)
        r.politica = nome
        out[nome] = r
    return out


def _bootstrap_soma(x: np.ndarray, rng) -> np.ndarray:
    n = len(x)
    pesos = rng.multinomial(n, np.full(n, 1 / n), size=B)
    return pesos @ x


def hipoteses(rot, ant: dict, folga: dict) -> dict:
    A = np.flatnonzero(rot.A)
    nA = len(A)
    a = {k: v[A].astype(float) for k, v in ant.items()}
    N = {k: int(v.sum()) for k, v in a.items()}
    den = N["DIN-1"] - N["EST"]
    disc = int(((a["DIN-1"] == 1) & (a["EST"] == 0)).sum()), int(((a["DIN-1"] == 0) & (a["EST"] == 1)).sum())
    mc = binomtest(disc[0], sum(disc), 0.5).pvalue if sum(disc) else float("nan")
    rng = np.random.default_rng(SEMENTE_BOOT)
    pesos = rng.multinomial(nA, np.full(nA, 1 / nA), size=B) if nA else np.zeros((B, 0))
    d = a["DIN-ESTAB λ=∞"] - 0.25 * a["EST"] - 0.75 * a["DIN-1"]
    D = float(d.sum())
    Db = pesos @ d
    lo, hi = float(np.percentile(Db, 5)), float(np.percentile(Db, 95))
    num_b = pesos @ (a["DIN-ESTAB λ=∞"] - a["EST"])
    den_b = pesos @ (a["DIN-1"] - a["EST"])
    pos = den_b > 0
    r = {"n_A": nA, "N": N, "pares_discordantes_DIN1_EST": {"DIN1_so": disc[0], "EST_so": disc[1]},
         "mcnemar_exato_DIN1_vs_EST_p": mc}
    h1 = {"denominador_N_DIN1_menos_N_EST": den, "D": D, "D_limite_inf_95_unilateral": lo,
          "D_limite_sup_95_unilateral": hi}
    if den <= 0:
        h1["classe"] = "não avaliável"
    else:
        h1["rho_observada"] = (N["DIN-ESTAB λ=∞"] - N["EST"]) / den
        rho_b = num_b[pos] / den_b[pos]
        h1["rho_IC90_bootstrap"] = [float(np.percentile(rho_b, 5)), float(np.percentile(rho_b, 95))]
        h1["frac_replicas_denominador_positivo"] = float(pos.mean())
        h1["criterio_descritivo_atingido"] = D >= 0
        baixa = []
        if den < C.EFEITO_MINIMO_KEV:
            baixa.append(f"N_DIN1 − N_EST = {den} < {C.EFEITO_MINIMO_KEV}")
        if nA < 30:
            baixa.append(f"|A| = {nA} < 30")
        if sum(disc) < 10:
            baixa.append(f"pares discordantes DIN-1/EST = {sum(disc)} < 10")
        h1["baixa_informacao"] = baixa
        if baixa:
            h1["classe"] = "inconclusivo por poucos eventos"
        elif lo > 0:
            h1["classe"] = "sustentada"
        elif D >= 0:
            h1["classe"] = "descritivamente atingida, estatisticamente inconclusiva"
        elif hi < 0:
            h1["classe"] = "refutada"
        else:
            h1["classe"] = "não atingida, inconclusiva"
    h1["decisao_depende_de_ate_1_evento"] = abs(D) <= 1
    r["H_D1"] = h1
    delta = max(2, math.ceil(0.03 * nA))
    h2 = {"margem_delta": delta, "avaliacao": "confirmatória" if h1.get("classe") == "sustentada" else "apenas descritiva (sequência fixa)"}
    for rot_nome, aa, bb in [("todos", a["DIN-ESTAB λ=∞"], a["DIN-4"]),
                             ("folga_ge_30", (a["DIN-ESTAB λ=∞"] * (folga["DIN-ESTAB λ=∞"][A] >= 30)),
                              (a["DIN-4"] * (folga["DIN-4"][A] >= 30)))]:
        e = aa - bb
        Eb = pesos @ e
        lo2, hi2 = float(np.percentile(Eb, 5)), float(np.percentile(Eb, 95))
        cl = ("superioridade" if lo2 > 0 else "não inferioridade sustentada" if lo2 > -delta
              else "refutada" if hi2 < -delta else "inconclusiva")
        h2[rot_nome] = {"E": float(e.sum()), "lim_inf_95": lo2, "lim_sup_95": hi2, "classe": cl,
                        "ganhos_lambda_inf": int((e > 0).sum()), "perdas_lambda_inf": int((e < 0).sum())}
    h2["decisao_depende_de_ate_1_evento"] = abs(h2["todos"]["E"]) <= 1
    r["H_D2"] = h2
    return r


def rodar(nome, sementes=True):
    coorte, est, rot, info = carregar(nome)
    pasta = OUT / nome
    pasta.mkdir(parents=True, exist_ok=True)
    u = P.desempate(coorte["cve"])
    res = simular_todas(est, u)
    linhas, ant, folga = [], {}, {}
    for nome_p, fab, lam, papel in POLITICAS:
        r = res[nome_p]
        a, f = M.antecipados(r, rot, est.semanas)
        ant[nome_p], folga[nome_p] = a, f
        s = M.resumir(r, rot, est.semanas)
        s.update(estabilidade(r))
        s.update(papel=papel, lambda_=lam, N_folga_ge_30=int((a & (f >= 30)).sum()),
                 N_folga_ge_90=int((a & (f >= 90)).sum()))
        linhas.append(s)
        pd.DataFrame(r.log).to_csv(pasta / f"log_{nome_p.replace(' ', '_').replace('=', '')}.csv.gz",
                                   index=False, compression="gzip")
    resumo = pd.DataFrame(linhas)
    resumo.to_csv(pasta / "resumo_politicas_K50.csv", index=False)
    A = rot.A
    ev = pd.DataFrame({"cve": coorte["cve"][A].to_numpy(), "p": coorte["p"][A].to_numpy(),
                       "k": rot.k[A].astype(str), "atraso_dias": rot.atraso[A], "omega": rot.omega[A],
                       "em_A_T": rot.A_T[A]})
    for nome_p in ant:
        ev[f"ant_{nome_p}"] = ant[nome_p][A]
        ev[f"folga_{nome_p}"] = folga[nome_p][A]
    ev.to_csv(pasta / "eventos_A.csv", index=False)
    desc = {"coorte": nome, "papel": PAPEL[nome], "contagens": info, "n_decisoes": len(est),
            "primeira_decisao": est.semanas[0].isoformat(), "ultima_decisao": est.semanas[-1].isoformat(),
            "kev_no_catalogo": int((coorte["k"] != "").sum()),
            "y_positivos": int(rot.y.sum()), "conhecidos_na_entrada": int(rot.conhecido_entrada.sum()),
            "A": int(rot.A.sum()), "A_T": int(rot.A_T.sum()), "A_pos": int(rot.A_pos.sum()),
            "tardios": int(rot.tardio.sum()), "nunca_elegiveis": int((rot.e < 0).sum()),
            "atraso_mediano_A": float(np.nanmedian(rot.atraso[A])) if A.any() else None,
            "omega_mediano_A": float(np.median(rot.omega[A])) if A.any() else None}
    h = hipoteses(rot, ant, folga)
    h["papel"] = PAPEL[nome]
    (pasta / "descritivo.json").write_text(json.dumps(desc, indent=1, ensure_ascii=False, default=str))
    (pasta / "hipoteses.json").write_text(json.dumps(h, indent=1, ensure_ascii=False, default=str))
    if sementes:
        ls = []
        for s in range(C.N_SEMENTES):
            us = P.desempate(coorte["cve"], s)
            for nome_p, r in simular_todas(est, us, kendall=False).items():
                a, f = M.antecipados(r, rot, est.semanas)
                ls.append({"semente": s, "politica": nome_p, "N_A": int(a.sum()),
                           "N_folga_ge_30": int((a & (f >= 30)).sum()),
                           "revisoes_total": int(pd.DataFrame(r.log).revisoes.sum())})
        sd = pd.DataFrame(ls)
        sd.to_csv(pasta / "sementes_20.csv", index=False)
        sd.groupby("politica").agg(["min", "median", "max"]).to_csv(pasta / "sementes_20_resumo.csv")
    return resumo, desc, h


def main(argv):
    sem = "--sem-sementes" not in argv
    for nome in [a for a in argv if not a.startswith("--")]:
        if nome == "T2" and "--confirmatoria" not in argv:
            raise SystemExit("T2 é confirmatória: rode com --confirmatoria só com dados completos e testes aprovados.")
        resumo, desc, h = rodar(nome, sementes=sem)
        print(nome, json.dumps({"A": desc["A"], "N": h["N"], "H_D1": h["H_D1"].get("classe"),
                                "H_D2": h["H_D2"]["todos"]["classe"]}, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main(sys.argv[1:])
