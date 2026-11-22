"""Única porta de acesso das políticas à informação: `Estado.em(w)` devolve o que se sabia em c(t_w).

As políticas nunca leem as tabelas brutas nem o módulo de rótulos. O KEV aparece aqui apenas como
"já conhecido até c(t)", nunca como data futura.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta

import numpy as np
import pandas as pd

from . import config as C


@dataclass(frozen=True)
class Visao:
    w: int
    t: date
    c: date
    visivel: np.ndarray        # publicada até c e com EPSS observado até c
    kev_conhecido: np.ndarray  # k_i <= c
    pct: np.ndarray            # percentil EPSS da última observação <= c (NaN se nenhuma)
    score: np.ndarray


class Estado:
    def __init__(self, coorte: pd.DataFrame, semanal: dict):
        self.cves = coorte["cve"].to_numpy()
        self.n = len(coorte)
        self.semanas = [date.fromisoformat(s) for s in semanal["semanas"]]
        self._pct = semanal["pct"]
        self._score = semanal["score"]
        self._p = pd.to_datetime(coorte["p"]).to_numpy("datetime64[D]")
        k = pd.to_datetime(coorte["k"].replace("", np.nan))
        self._k = k.to_numpy("datetime64[D]")
        self._k_valido = k.notna().to_numpy()

    def __len__(self) -> int:
        return len(self.semanas)

    def em(self, w: int) -> Visao:
        t = self.semanas[w]
        c = t - timedelta(days=1)
        c64 = np.datetime64(c, "D")
        pct = self._pct[w]
        visivel = (self._p <= c64) & ~np.isnan(pct)
        kev_conhecido = self._k_valido & (self._k <= c64)
        return Visao(w, t, c, visivel, kev_conhecido, pct, self._score[w])


def carregar() -> tuple[pd.DataFrame, Estado]:
    coorte = pd.read_csv(C.DERIVED / "coorte_2024.csv.gz", keep_default_na=False)
    sem = dict(np.load(C.DERIVED / "epss_semanal.npz"))
    return coorte, Estado(coorte, sem)
