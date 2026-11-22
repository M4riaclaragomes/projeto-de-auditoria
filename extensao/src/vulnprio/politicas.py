"""Políticas de ordenação. Recebem apenas a Visao do Estado (nunca rótulos ou datas futuras)."""
from __future__ import annotations

import hashlib

import numpy as np


def desempate(cves, semente: int | None = None) -> np.ndarray:
    """u_i em [0,1): hash do identificador (determinístico) ou hash semente:identificador."""
    pref = "" if semente is None else f"{semente}:"
    return np.array(
        [int.from_bytes(hashlib.sha256((pref + c).encode()).digest()[:8], "big") / 2**64 for c in cves]
    )


class Estatica:
    """EST: percentil do EPSS na semana de entrada na fila, congelado."""
    nome = "EST"

    def __init__(self, n: int):
        self.entrada = np.full(n, np.nan, dtype=np.float64)

    def scores(self, visao, elegivel: np.ndarray) -> np.ndarray:
        novos = elegivel & np.isnan(self.entrada)
        self.entrada[novos] = visao.pct[novos]
        return self.entrada.copy()


class Dinamica:
    """DIN-1: percentil do EPSS relido a cada semana."""
    nome = "DIN-1"

    def __init__(self, n: int):
        pass

    def scores(self, visao, elegivel: np.ndarray) -> np.ndarray:
        return visao.pct.astype(np.float64).copy()


POLITICAS = {"EST": Estatica, "DIN-1": Dinamica}
