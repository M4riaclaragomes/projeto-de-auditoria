"""Testes de integridade e regressão (protocolo, seções 9 e 13.8).

Rodar a partir de extensao/:  PYTHONPATH=src python -m pytest -q tests
Testes que dependem de partes não implementadas nesta entrega (EST+30, fila obrigatória)
estão marcados como skip, com o motivo.
"""
from __future__ import annotations

import ast
import gzip
import hashlib
import json
from dataclasses import replace
from datetime import date, timedelta
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from vulnprio import config as C
from vulnprio import estado as E
from vulnprio import estrategias_artigo
from vulnprio import politicas as P
from vulnprio import rotulos as R
from vulnprio import simulador as S

SRC = Path(__file__).resolve().parents[1] / "src" / "vulnprio"


@pytest.fixture(scope="module")
def base():
    coorte, est = E.carregar()
    rot = R.construir(coorte, est)
    u = P.desempate(coorte["cve"])
    return coorte, est, rot, u


@pytest.fixture(scope="module")
def corridas(base):
    coorte, est, rot, u = base
    return {nome: S.simular(est, cls, C.K_PRIMARIO, u) for nome, cls in P.POLITICAS.items()}


# --- Preservação da Fase A -------------------------------------------------

def test_fase_a_intacta():
    man = json.loads((C.RAIZ / "freeze" / "fase_a_manifest.json").read_text())
    for f in man["files"]:
        caminho = C.FASE_A / f["path"]
        h = hashlib.sha256(caminho.read_bytes()).hexdigest()
        assert h == f["sha256"], f"Arquivo da Fase A alterado: {f['path']}"


def test_reproducao_13_estrategias_fase_a(base):
    coorte = base[0]
    novo = estrategias_artigo.avaliar(coorte).set_index("strategy")
    antigo = pd.read_csv(C.METRICAS_VARIANTE).set_index("strategy")
    for s in antigo.index:
        for col in ("tp", "fp", "fn"):
            assert novo.loc[s, col] == antigo.loc[s, col], (s, col)


def test_primeiro_epss_confere_com_fase_a(base):
    """a_i (primeira presença >= publicação) deve igualar o epssDate da Fase A dentro do período v3."""
    coorte = base[0]
    dentro = coorte["epss_data_fase_a"] <= C.T_FIM.isoformat()
    assert (coorte.loc[dentro, "a_pos_publicacao"] == coorte.loc[dentro, "epss_data_fase_a"]).all()
    assert (~dentro).sum() == 2


# --- Sem futuro no EPSS ----------------------------------------------------

def test_sem_futuro_epss():
    sem = np.load(C.DERIVED / "epss_semanal.npz")
    for t, obs, arq in zip(sem["semanas"], sem["dia_obs"], sem["arquivo_mais_recente"]):
        c = (date.fromisoformat(t) - timedelta(days=1)).isoformat()
        usados = obs[obs != ""]
        if len(usados):
            assert max(usados.tolist()) <= c
        if arq:
            assert arq <= c


def test_epss_semanal_confere_com_arquivo_bruto():
    """Amostra: o percentil semanal é o do arquivo bruto mais recente <= c(t) que contém a CVE."""
    coorte = pd.read_csv(C.DERIVED / "coorte_2024.csv.gz", keep_default_na=False)
    sem = np.load(C.DERIVED / "epss_semanal.npz")
    rng = np.random.default_rng(0)
    for w in (10, 30, 47, 62):  # inclui 2024-12-02, cujo c(t) não tem arquivo
        dia = sem["arquivo_mais_recente"][w]
        with gzip.open(C.EPSS_DIR / f"epss_scores-{dia}.csv.gz", "rt") as f:
            df = pd.read_csv(f, skiprows=1).set_index("cve")
        for i in rng.choice(len(coorte), 200, replace=False):
            cve = coorte.at[i, "cve"]
            if cve in df.index and sem["dia_obs"][w][i] == dia:
                assert abs(df.at[cve, "percentile"] - sem["pct"][w][i]) < 1e-5


def test_versao_unica_do_modelo():
    man = json.loads((C.EPSS_DIR / "manifest.json").read_text())
    versoes = {r["model_version"] for r in man["files"] if r.get("file")}
    assert versoes == {C.MODELO_ESPERADO}


# --- Sem futuro no KEV, fila e orçamento -----------------------------------

def test_sem_futuro_kev_e_fila(base, corridas):
    coorte, est, rot, u = base
    k = rot.k
    for res in corridas.values():
        sel = res.semana_sel
        for w in range(len(est)):
            v = est.em(w)
            c = np.datetime64(v.c, "D")
            escolhidas = np.flatnonzero(sel == w)
            # nada selecionado já estava no KEV em c(t), e tudo estava visível
            assert not np.any(~np.isnat(k[escolhidas]) & (k[escolhidas] <= c))
            assert v.visivel[escolhidas].all()


def test_orcamento_discricionario(base, corridas):
    for res in corridas.values():
        for r in res.log:
            assert r["selecionadas"] == min(C.K_PRIMARIO, r["elegiveis"])


def test_fila_sem_expiracao(base, corridas):
    """Uma CVE visível, fora do KEV e não selecionada continua elegível em qualquer idade."""
    coorte, est, rot, u = base
    res = corridas["EST"]
    w = len(est) - 1
    v = est.em(w)
    E_w = v.visivel & ~v.kev_conhecido & ((res.semana_sel < 0) | (res.semana_sel >= w))
    idade = (np.datetime64(v.c, "D") - rot.p).astype(int)
    assert (E_w & (idade > C.W_DIAS)).sum() > 0
    assert res.log[w]["elegiveis"] == int(E_w.sum())


def test_conjuntos_de_avaliacao(base):
    rot = base[2]
    assert not np.any(rot.A_T & rot.A_pos)
    assert np.array_equal(rot.A_T | rot.A_pos, rot.A)
    assert not np.any(rot.A & rot.conhecido_entrada)
    assert (rot.A.sum(), rot.A_T.sum(), rot.A_pos.sum(), rot.conhecido_entrada.sum()) == (86, 73, 13, 63)


def test_conhecidos_na_entrada_nunca_elegiveis(base, corridas):
    rot = base[2]
    for res in corridas.values():
        assert (res.semana_sel[rot.conhecido_entrada] < 0).all()


def test_rotulo_independente_da_politica(base, corridas):
    coorte, est, rot, u = base
    rot2 = R.construir(coorte, est)
    for campo in ("y", "A", "A_T", "A_pos", "omega"):
        assert np.array_equal(getattr(rot, campo), getattr(rot2, campo))


def test_tempo_disponivel(base):
    rot = base[2]
    assert (rot.omega[rot.A] >= 1).all()
    assert (rot.omega[~rot.A] == 0).all()


# --- Políticas ---------------------------------------------------------------

def test_estatica_congelada(base, corridas):
    res = corridas["EST"]
    assert all(r["deslocadas_por_atualizacao"] == 0 for r in res.log)


def test_estatica_usa_score_de_entrada(base):
    coorte, est, rot, u = base
    pol = P.Estatica(est.n)
    primeiros = {}
    for w in range(len(est)):
        v = est.em(w)
        elig = v.visivel & ~v.kev_conhecido
        sc = pol.scores(v, elig)
        for i in np.flatnonzero(elig)[:50]:
            primeiros.setdefault(i, sc[i])
            assert sc[i] == primeiros[i]


def test_politicas_nao_importam_rotulos():
    for mod in ("politicas.py", "simulador.py", "estado.py"):
        arvore = ast.parse((SRC / mod).read_text())
        nomes = {a.name for n in ast.walk(arvore) if isinstance(n, (ast.Import, ast.ImportFrom)) for a in n.names}
        modulos = {n.module for n in ast.walk(arvore) if isinstance(n, ast.ImportFrom) and n.module}
        assert "rotulos" not in nomes and "rotulos" not in modulos


def test_invariancia_ao_futuro_kev(base, corridas):
    """Mudar datas de KEV posteriores a T_fim (para outras datas posteriores) não altera nenhuma seleção."""
    coorte, est, rot, u = base
    c2 = coorte.copy()
    k = pd.to_datetime(c2["k"].replace("", np.nan))
    tarde = k.notna() & (k > pd.Timestamp(C.T_FIM))
    c2.loc[tarde, "k"] = "2026-01-01"
    est2 = E.Estado(c2, dict(np.load(C.DERIVED / "epss_semanal.npz")))
    for nome, cls in P.POLITICAS.items():
        r2 = S.simular(est2, cls, C.K_PRIMARIO, u, kendall=False)
        assert np.array_equal(r2.semana_sel, corridas[nome].semana_sel)


def test_desempate_deterministico(base, corridas):
    coorte, est, rot, u = base
    assert np.array_equal(u, P.desempate(coorte["cve"]))
    assert np.array_equal(P.desempate(coorte["cve"], 3), P.desempate(coorte["cve"], 3))
    r2 = S.simular(est, P.Dinamica, C.K_PRIMARIO, u, kendall=False)
    assert np.array_equal(r2.semana_sel, corridas["DIN-1"].semana_sel)


def test_metricas_de_contexto(base, corridas):
    for res in corridas.values():
        n_sel = (res.semana_sel >= 0).sum()
        assert n_sel <= res.K * len(res.log)
        assert all(r["elegiveis"] >= 0 and r["chegadas"] >= 0 for r in res.log)


@pytest.mark.skip(reason="EST+30 fora do escopo da entrega de 22/11 (registro de desvios)")
def test_est30():
    pass


@pytest.mark.skip(reason="Fila obrigatória (KEV consumindo capacidade) fora do escopo da entrega de 22/11")
def test_orcamento_com_fila_obrigatoria():
    pass
