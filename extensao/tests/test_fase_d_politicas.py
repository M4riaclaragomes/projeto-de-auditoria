"""Testes dos comparadores e das coortes da Fase D (protocolo_fase_d.md, seção 7)."""
from __future__ import annotations

import json
from datetime import date, timedelta

import numpy as np
import pandas as pd
import pytest

from vulnprio import config as C
from vulnprio import dados_d, estado as ESTADO, politicas as P
from vulnprio import simulador_c as SC
from vulnprio.politicas_c import DinamicaC, EstaticaC
from vulnprio.politicas_d import DinamicaDelta

K = 50


@pytest.fixture(scope="module")
def base():
    coorte, est = ESTADO.carregar()
    return coorte, est, P.desempate(coorte["cve"])


def _iguais(r1, r2):
    return np.array_equal(r1.semana_sel, r2.semana_sel)


def test_calendarios_congelados():
    t2 = dados_d.segundas(*dados_d.COORTES["T2"]["dec"])
    t1 = dados_d.segundas(*dados_d.COORTES["T1"]["dec"])
    s24 = dados_d.segundas(*dados_d.COORTES["2024-S"]["dec"])
    assert (len(t2), t2[0], t2[-1]) == (65, date(2025, 3, 24), date(2026, 6, 15))
    assert (len(t1), t1[0], t1[-1]) == (11, date(2025, 1, 6), date(2025, 3, 17))
    assert len(s24) == 63
    # horizonte de 365 dias inteiramente observado no catálogo congelado
    assert dados_d.COORTES["T2"]["pub"][1] + timedelta(days=365) < C.F_CONGELAMENTO
    # cortes dentro da versão do EPSS da coorte
    assert t2[0] - timedelta(days=1) == date(2025, 3, 23) > date(2025, 3, 16)
    assert t1[-1] - timedelta(days=1) == date(2025, 3, 16)


def test_din_delta_1_identica_a_din_1(base):
    _, est, u = base
    r1 = SC.simular_c(est, DinamicaC(est.n), K, u, 0.0, kendall=False)
    rd = SC.simular_c(est, DinamicaDelta(est.n, 1), K, u, 0.0, kendall=False)
    assert _iguais(r1, rd)
    l1, ld = pd.DataFrame(r1.log), pd.DataFrame(rd.log)
    for c in ["revisoes", "revisoes_por_atualizacao", "deslocadas_por_atualizacao"]:
        assert (l1[c] == ld[c]).all(), c


@pytest.mark.parametrize("delta", [2, 4])
def test_din_delta_score_so_muda_na_releitura_ou_entrada(base, delta):
    _, est, _ = base
    pol = DinamicaDelta(est.n, delta)
    sel = np.full(est.n, -1)
    ant = None
    for w in range(len(est)):
        v = est.em(w)
        E = v.visivel & ~v.kev_conhecido & (sel < 0)
        pol.atualizar(v, E)
        sc = pol.score.copy()
        assert pol.releitura == (w % delta == 0)
        if w % delta == 0:
            assert np.array_equal(sc[E], v.pct[E].astype(np.float64))
        elif ant is not None:
            carregadas = E & ~np.isnan(ant)
            assert np.array_equal(sc[carregadas], ant[carregadas])
            novas = E & np.isnan(ant)
            assert np.array_equal(sc[novas], v.pct[novas].astype(np.float64))
        ant = sc
        # seleção arbitrária para avançar a fila, como no simulador
        idx = np.flatnonzero(E)
        sel[idx[:K]] = w


def test_politicas_travadas_sem_revisoes_e_orcamento(base):
    _, est, u = base
    for pol in (DinamicaC(est.n), EstaticaC(est.n), DinamicaDelta(est.n, 4)):
        lam = 0.0 if isinstance(pol, DinamicaDelta) else 2.0
        r = SC.simular_c(est, pol, K, u, lam, kendall=False)
        lg = pd.DataFrame(r.log)
        assert (lg.selecionadas <= K).all()
        assert ((lg.selecionadas == K) | (lg.selecionadas == lg.elegiveis)).all()
        if lam:
            assert lg.revisoes.sum() == 0


def test_din_delta_sem_vazamento(base):
    """Decisões até a semana w não mudam se percentis de semanas posteriores forem alterados."""
    coorte, est, u = base
    w0 = 30
    sem = {"semanas": np.array([t.isoformat() for t in est.semanas]),
           "pct": est._pct.copy(), "score": est._score.copy()}
    sem["pct"][w0 + 1:] = np.where(np.isnan(sem["pct"][w0 + 1:]), np.nan, 1 - sem["pct"][w0 + 1:])
    est2 = ESTADO.Estado(coorte, sem)
    for d in (2, 4):
        r1 = SC.simular_c(est, DinamicaDelta(est.n, d), K, u, 0.0, kendall=False)
        r2 = SC.simular_c(est2, DinamicaDelta(est.n, d), K, u, 0.0, kendall=False)
        m1 = (r1.semana_sel >= 0) & (r1.semana_sel <= w0)
        m2 = (r2.semana_sel >= 0) & (r2.semana_sel <= w0)
        assert np.array_equal(m1, m2) and np.array_equal(r1.semana_sel[m1], r2.semana_sel[m2])


def test_politicas_d_nao_importam_rotulos():
    for f in ("politicas_d.py", "dados_d.py"):
        assert "rotulos" not in (C.RAIZ / "src" / "vulnprio" / f).read_text()


def _ponte_disponivel():
    return (dados_d.DERIVED_D / "2024-S+rej" / "epss_semanal.npz").exists()


@pytest.mark.skipif(not _ponte_disponivel(), reason="coorte 2024-S ainda não construída")
def test_epss_semanal_da_fase_d_reproduz_fase_b():
    coorte_b, est_b = ESTADO.carregar()
    c, est, _ = dados_d.carregar("2024-S+rej")
    pos = pd.Series(np.arange(len(c)), index=c["cve"])
    tem = coorte_b["cve"].isin(pos.index).to_numpy()
    col = pos[coorte_b["cve"][tem]].to_numpy()
    assert np.array_equal(est._pct[:, col], est_b._pct[:, tem], equal_nan=True)
    # as da variante ausentes da coorte S+rej são exatamente as sem EPSS até T_FIM
    assert np.isnan(est_b._pct[:, ~tem]).all()
    assert (c.set_index("cve").loc[coorte_b["cve"][tem], "p"].to_numpy() == coorte_b["p"][tem].to_numpy()).all()


@pytest.mark.skipif(not _ponte_disponivel(), reason="coorte 2024-S ainda não construída")
def test_contagens_2024_S():
    cs = json.loads((dados_d.DERIVED_D / "2024-S" / "contagens.json").read_text())
    cr = json.loads((dados_d.DERIVED_D / "2024-S+rej" / "contagens.json").read_text())
    assert cs["publicadas_na_janela"] == cr["publicadas_na_janela"] == 40704
    assert cs["excluidas_rejected"] == 751
    assert cs["incluidas"] + cs["excluidas_sem_epss"] + cs["excluidas_rejected"] == 40704
    assert cs["versoes_epss_lidas"] == [dados_d.V3]
