"""Simulação semanal da fila com orçamento K (protocolo, seções 3, 4, 6 e 13.1).

Fila sem expiração: uma CVE sai apenas por seleção, por entrar no KEV (k_i <= c(t)) ou no fim da simulação.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np
from scipy.stats import kendalltau


@dataclass
class Resultado:
    politica: str
    K: int
    semana_sel: np.ndarray                         # índice da semana de seleção, -1 se nunca
    log: list = field(default_factory=list)        # uma entrada por semana
    toggles_plano: np.ndarray | None = None


def _ordenar(idx: np.ndarray, score: np.ndarray, u: np.ndarray) -> np.ndarray:
    """Ordena índices elegíveis por score desc e desempate u asc."""
    s = score[idx]
    return idx[np.lexsort((u[idx], -s))]


def simular(estado, politica_cls, K: int, u: np.ndarray, kendall: bool = True) -> Resultado:
    n = estado.n
    pol = politica_cls(n)
    sel = np.full(n, -1)
    res = Resultado(politica_cls.nome, K, sel)
    toggles = np.zeros(n, dtype=int)
    em_plano_ant = np.zeros(n, dtype=bool)
    E_ant = None
    score_ant = None
    plano_ant = np.array([], dtype=int)
    rank_ant = None
    visto = np.zeros(n, dtype=bool)
    for w in range(len(estado)):
        v = estado.em(w)
        E = v.visivel & ~v.kev_conhecido & (sel < 0)
        idxE = np.flatnonzero(E)
        chegadas = int((E & ~visto).sum())
        visto |= v.visivel
        score = pol.scores(v, E)
        ordem = _ordenar(idxE, score, u)
        S = ordem[:K]
        plano = ordem[K:2 * K]
        # seleções decididas pelo desempate: score igual ao do primeiro não selecionado
        por_desempate = int((score[S] == score[ordem[K]]).sum()) if len(ordem) > K else 0
        sel[S] = w
        # contrafactual S': itens que já estavam na fila mantêm o score usado em t-1
        if E_ant is not None and len(idxE):
            carregados = E & E_ant
            score_cf = score.copy()
            score_cf[carregados] = score_ant[carregados]
            S_cf = _ordenar(idxE, score_cf, u)[:K]
            deslocados = len(np.setdiff1d(S, S_cf, assume_unique=True))
            U = deslocados / len(S) if len(S) else np.nan
        else:
            deslocados, U = 0, np.nan
        alfa = (len(np.intersect1d(S, plano_ant)) / len(plano_ant)) if len(plano_ant) else np.nan
        kd = np.nan
        if kendall and rank_ant is not None and len(idxE):
            rank_now = np.full(n, -1)
            rank_now[ordem] = np.arange(len(ordem))
            M = 4 * K
            carreg = np.flatnonzero(E & E_ant)
            if len(carreg):
                top = carreg[(rank_ant[carreg] < M) | (rank_now[carreg] < M)]
                if len(top) >= 3:
                    tau = kendalltau(rank_ant[top], rank_now[top]).statistic
                    kd = (1 - tau) / 2
            rank_ant = rank_now
        elif len(idxE):
            rank_ant = np.full(n, -1)
            rank_ant[ordem] = np.arange(len(ordem))
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
            }
        )
        E_ant, score_ant, plano_ant = E, score, plano
    res.toggles_plano = toggles
    return res
