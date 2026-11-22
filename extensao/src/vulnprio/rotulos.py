"""Rótulos e conjuntos de avaliação (protocolo, seções 5 e 13.2). Só a avaliação importa este módulo."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

import numpy as np
import pandas as pd

from . import config as C


@dataclass(frozen=True)
class Rotulos:
    k: np.ndarray            # datetime64[D], NaT se fora do KEV em F
    p: np.ndarray
    y: np.ndarray            # p < k <= p + W
    e: np.ndarray            # índice da semana de entrada (primeira em que fica visível), -1 se nunca
    conhecido_entrada: np.ndarray
    tardio: np.ndarray
    A: np.ndarray
    A_T: np.ndarray
    A_pos: np.ndarray
    omega: np.ndarray        # semanas disponíveis para seleção (independe da política)
    atraso: np.ndarray       # k - p em dias (NaN fora do KEV)


def construir(coorte: pd.DataFrame, estado) -> Rotulos:
    p = pd.to_datetime(coorte["p"]).to_numpy("datetime64[D]")
    kser = pd.to_datetime(coorte["k"].replace("", np.nan))
    k = kser.to_numpy("datetime64[D]")
    no_kev = kser.notna().to_numpy().copy()
    F = np.datetime64(C.F_CONGELAMENTO, "D")
    no_kev &= np.where(no_kev, k <= F, False)
    atraso = np.where(no_kev, (k - p).astype("timedelta64[D]").astype(float), np.nan)
    y = no_kev & (atraso > 0) & (atraso <= C.W_DIAS)
    tardio = no_kev & (atraso > C.W_DIAS)

    n_w = len(estado)
    e = np.full(len(coorte), -1)
    for w in range(n_w):
        v = estado.em(w).visivel
        novo = v & (e < 0)
        e[novo] = w
    datas_c = np.array([np.datetime64(estado.semanas[w] - timedelta(days=1), "D") for w in range(n_w)])
    c_e = np.where(e >= 0, datas_c[np.maximum(e, 0)], np.datetime64("NaT", "D"))
    conhecido_entrada = no_kev & (e >= 0) & (k <= c_e)
    A = y & (e >= 0) & ~conhecido_entrada
    T_fim = np.datetime64(C.T_FIM, "D")
    A_T = A & (k <= T_fim)
    A_pos = A & (k > T_fim)
    omega = np.zeros(len(coorte), dtype=int)
    for w in range(n_w):
        cw = datas_c[w]
        ok = (e >= 0) & (e <= w) & (~no_kev | (cw < np.where(no_kev, k, cw)))
        omega += ok
    omega = np.where(A, omega, 0)
    return Rotulos(k, p, y, e, conhecido_entrada, tardio, A, A_T, A_pos, omega, atraso)
