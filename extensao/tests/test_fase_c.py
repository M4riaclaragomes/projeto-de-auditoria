"""Testes da Fase C (DIN-ESTAB). Os testes da Fase B (test_integridade.py) continuam valendo sem alteração.

Rodar a partir de extensao/:  PYTHONPATH=src python -m pytest -q tests
"""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from vulnprio import config as C
from vulnprio import estado as E
from vulnprio import metricas as M
from vulnprio import politicas as P
from vulnprio import politicas_c as PC
from vulnprio import rotulos as R
from vulnprio import simulador as S
from vulnprio import simulador_c as SC

SRC = Path(__file__).resolve().parents[1] / "src" / "vulnprio"
LAMBDAS = (0.0, 0.001, 0.003, 0.01, 0.03, 0.1, 0.3, 2.0)


@pytest.fixture(scope="module")
def base():
    coorte, est = E.carregar()
    return coorte, est, R.construir(coorte, est), P.desempate(coorte["cve"])


def _logs_iguais(a, b):
    la = pd.DataFrame(a.log)
    lb = pd.DataFrame(b.log)[la.columns]
    num = la.select_dtypes("number").columns
    assert (la.drop(columns=num) == lb.drop(columns=num)).all().all()
    assert np.allclose(la[num].fillna(-9).to_numpy(float), lb[num].fillna(-9).to_numpy(float), rtol=0, atol=0)


def test_fase_b_intacta():
    man = json.loads((C.RAIZ / "freeze" / "fase_b_manifest.json").read_text())
    for f in man["files"]:
        h = hashlib.sha256((C.RAIZ / f["path"]).read_bytes()).hexdigest()
        assert h == f["sha256"], f"Arquivo da Fase B alterado: {f['path']}"


@pytest.mark.parametrize("K", C.GRADE_K)
def test_equivalencia_baselines(base, K):
    coorte, est, rot, u = base
    for pb, pc in ((P.Estatica, PC.EstaticaC), (P.Dinamica, PC.DinamicaC)):
        a = S.simular(est, pb, K, u)
        b = SC.simular_c(est, pc(est.n), K, u, 0.0)
        assert np.array_equal(a.semana_sel, b.semana_sel)
        assert np.array_equal(a.toggles_plano, b.toggles_plano)
        _logs_iguais(a, b)


def test_resumos_conferem_com_csv_congelado_da_fase_b(base):
    coorte, est, rot, u = base
    csv = pd.read_csv(C.RESULTS / "fase_b_2024" / "resumo_por_politica_K.csv")
    for pc in (PC.EstaticaC, PC.DinamicaC):
        r = SC.simular_c(est, pc(est.n), C.K_PRIMARIO, u, 0.0)
        novo = M.resumir(r, rot, est.semanas)
        linha = csv[(csv.politica == r.politica) & (csv.K == C.K_PRIMARIO)].iloc[0]
        for col in ("N_A", "N_A_T", "selecionadas", "deslocadas_total"):
            assert novo[col] == linha[col], col
        for col in ("R_A", "LW", "U_medio", "alfa_medio", "kendall_dist_medio"):
            assert novo[col] == pytest.approx(linha[col], abs=1e-12), col


def test_lambda_zero_reproduz_din1(base):
    coorte, est, rot, u = base
    a = S.simular(est, P.Dinamica, C.K_PRIMARIO, u)
    b = SC.simular_c(est, PC.DinamicaC(est.n), C.K_PRIMARIO, u, lam=0.0)
    assert np.array_equal(a.semana_sel, b.semana_sel)


@pytest.fixture(scope="module")
def grade(base):
    coorte, est, rot, u = base
    return {lam: SC.simular_c(est, PC.DinamicaC(est.n), C.K_PRIMARIO, u, lam) for lam in LAMBDAS}


def test_plano_travado(grade):
    r = grade[2.0]
    assert sum(x["revisoes"] for x in r.log) == 0


def test_orcamento_todas_lambdas(grade):
    for r in grade.values():
        for x in r.log:
            assert x["selecionadas"] == min(C.K_PRIMARIO, x["elegiveis"])


def test_decomposicao_revisoes(grade):
    for r in grade.values():
        for x in r.log:
            assert x["revisoes_por_atualizacao"] + x["revisoes_outras_causas"] == x["revisoes"]
            assert 0 <= x["revisoes_por_atualizacao"] <= x["revisoes"]
            assert x["revisoes"] + x["saidas_forcadas_plano"] <= x["plano_anterior"]


def test_sem_futuro_epss_prefixo(base, grade):
    """Trocar os percentis de todas as semanas > w por ruído não altera nenhuma seleção até w."""
    coorte, est, rot, u = base
    w = 30
    sem = dict(np.load(C.DERIVED / "epss_semanal.npz"))
    rng = np.random.default_rng(1)
    pct = sem["pct"].copy()
    pct[w + 1:] = rng.random(pct[w + 1:].shape).astype(pct.dtype)
    sem["pct"] = pct
    est2 = E.Estado(coorte, sem)
    for lam in (0.0, 0.01, 2.0):
        r2 = SC.simular_c(est2, PC.DinamicaC(est.n), C.K_PRIMARIO, u, lam, kendall=False)
        r1 = grade[lam]
        antes = (r1.semana_sel >= 0) & (r1.semana_sel <= w)
        assert np.array_equal(r1.semana_sel[antes], r2.semana_sel[antes])
        assert ((r2.semana_sel >= 0) & (r2.semana_sel <= w)).sum() == antes.sum()


def test_sem_futuro_kev(base, grade):
    coorte, est, rot, u = base
    c2 = coorte.copy()
    k = pd.to_datetime(c2["k"].replace("", np.nan))
    c2.loc[k.notna() & (k > pd.Timestamp(C.T_FIM)), "k"] = "2026-01-01"
    est2 = E.Estado(c2, dict(np.load(C.DERIVED / "epss_semanal.npz")))
    r2 = SC.simular_c(est2, PC.DinamicaC(est.n), C.K_PRIMARIO, u, 0.01, kendall=False)
    assert np.array_equal(r2.semana_sel, grade[0.01].semana_sel)


def test_modulos_novos_nao_importam_rotulos():
    for mod in ("politicas_c.py", "simulador_c.py"):
        arv = ast.parse((SRC / mod).read_text())
        nomes = {a.name for n in ast.walk(arv) if isinstance(n, (ast.Import, ast.ImportFrom)) for a in n.names}
        mods = {n.module for n in ast.walk(arv) if isinstance(n, ast.ImportFrom) and n.module}
        assert "rotulos" not in nomes and "rotulos" not in mods


def test_determinismo(base, grade):
    coorte, est, rot, u = base
    r = SC.simular_c(est, PC.DinamicaC(est.n), C.K_PRIMARIO, u, 0.01)
    assert np.array_equal(r.semana_sel, grade[0.01].semana_sel)
    assert pd.DataFrame(r.log).equals(pd.DataFrame(grade[0.01].log))
