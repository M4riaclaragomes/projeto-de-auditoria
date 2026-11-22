"""Simulador da Fase C (arquivo novo; simulador.py da Fase B não foi alterado).

Generaliza o simulador da Fase B com um bônus de estabilidade lambda sobre o plano da semana anterior:

    score_ajustado_i(t) = base_i(t) + lambda * 1[i em Plan_{t-1}]

Com lambda = 0 e as políticas EST e DIN-1, reproduz exatamente o simulador da Fase B
(teste de equivalência em tests/test_fase_c.py). Além das métricas da Fase B, registra:
- revisoes: CVEs do plano anterior ainda elegíveis e não executadas (mudança na composição do plano);
- revisoes_por_atualizacao: dessas, as que teriam sido executadas se os percentis não tivessem mudado;
- saidas_forcadas_plano: CVEs do plano anterior que deixaram de ser elegíveis (entraram no KEV);
- empurradas: pares (semana, CVE) que a seleção contrafactual teria escolhido e a real não escolheu.
Não há modelo de trabalho comprometido e cancelado: seleção = decisão concluída na própria semana.
"""
from __future__ import annotations

import numpy as np
from scipy.stats import kendalltau

from .simulador import Resultado, _ordenar


def simular_c(estado, politica, K: int, u: np.ndarray, lam: float = 0.0, kendall: bool = True) -> Resultado:
    n = estado.n
    sel = np.full(n, -1)
    nome = politica.nome if lam == 0 else f"DIN-ESTAB({lam:g})"
    res = Resultado(nome, K, sel)
    toggles = np.zeros(n, dtype=int)
    em_plano_ant = np.zeros(n, dtype=bool)
    E_ant = None
    pct_ant = None
    plano_ant = np.array([], dtype=int)
    rank_ant = None
    visto = np.zeros(n, dtype=bool)
    empurradas = []
    for w in range(len(estado)):
        v = estado.em(w)
        E = v.visivel & ~v.kev_conhecido & (sel < 0)
        idxE = np.flatnonzero(E)
        chegadas = int((E & ~visto).sum())
        visto |= v.visivel
        politica.atualizar(v, E)
        bonus = np.zeros(n)
        if lam and len(plano_ant):
            bonus[plano_ant] = lam
        score = politica.base(v.pct) + bonus
        ordem = _ordenar(idxE, score, u)
        S = ordem[:K]
        plano = ordem[K:2 * K]
        por_desempate = int((score[S] == score[ordem[K]]).sum()) if len(ordem) > K else 0
        sel[S] = w
        S_cf = S
        if E_ant is not None and len(idxE):
            carregados = E & E_ant
            pct_cf = v.pct.copy()
            pct_cf[carregados] = pct_ant[carregados]
            score_cf = politica.base(pct_cf) + bonus
            S_cf = _ordenar(idxE, score_cf, u)[:K]
            deslocados = len(np.setdiff1d(S, S_cf, assume_unique=True))
            U = deslocados / len(S) if len(S) else np.nan
            empurradas.extend((w, int(i)) for i in np.setdiff1d(S_cf, S, assume_unique=True))
        else:
            deslocados, U = 0, np.nan
        alfa = (len(np.intersect1d(S, plano_ant)) / len(plano_ant)) if len(plano_ant) else np.nan
        plano_eleg = plano_ant[E[plano_ant]] if len(plano_ant) else plano_ant
        nao_exec = np.setdiff1d(plano_eleg, S, assume_unique=True)
        rev_upd = int(len(np.intersect1d(nao_exec, S_cf))) if E_ant is not None else 0
        alfa_eleg = (len(np.intersect1d(S, plano_eleg)) / len(plano_eleg)) if len(plano_eleg) else np.nan
        kd = np.nan
        if len(idxE):
            rank_now = np.full(n, -1)
            rank_now[ordem] = np.arange(len(ordem))
            if kendall and rank_ant is not None:
                M = 4 * K
                carreg = np.flatnonzero(E & E_ant)
                if len(carreg):
                    top = carreg[(rank_ant[carreg] < M) | (rank_now[carreg] < M)]
                    if len(top) >= 3:
                        kd = (1 - kendalltau(rank_ant[top], rank_now[top]).statistic) / 2
            rank_ant = rank_now
        em_plano = np.zeros(n, dtype=bool)
        em_plano[plano] = True
        toggles += em_plano != em_plano_ant
        em_plano_ant = em_plano
        res.log.append(
            {
                "semana": v.t.isoformat(),
                "elegiveis": int(len(idxE)),
                "chegadas": chegadas,
                "selecionadas": int(len(S)),
                "sel_por_desempate": por_desempate,
                "deslocadas_por_atualizacao": int(deslocados),
                "U": U,
                "alfa": alfa,
                "kendall_dist_top4K": kd,
                "plano_anterior": int(len(plano_ant)),
                "saidas_forcadas_plano": int(len(plano_ant) - len(plano_eleg)),
                "revisoes": int(len(nao_exec)),
                "revisoes_por_atualizacao": rev_upd,
                "revisoes_outras_causas": int(len(nao_exec) - rev_upd),
                "alfa_elegivel": alfa_eleg,
            }
        )
        E_ant, pct_ant, plano_ant = E, v.pct.copy(), plano
    res.toggles_plano = toggles
    res.empurradas = np.array(empurradas, dtype=int).reshape(-1, 2)
    return res
