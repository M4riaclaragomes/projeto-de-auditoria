"""Políticas da Fase C. Arquivo novo: politicas.py da Fase B não foi alterado.

Interface: `atualizar(visao, elegivel)` registra o que a política precisa guardar (só a EST guarda o
percentil de entrada); `base(pct)` devolve o score-base a partir de um vetor de percentis. Separar as
duas coisas permite recalcular o score com percentis contrafactuais (seção 2 do protocolo da Fase C).
O bônus de estabilidade não é da política: o simulador o aplica sobre o plano da semana anterior.
"""
from __future__ import annotations

import numpy as np


class EstaticaC:
    nome = "EST"

    def __init__(self, n: int):
        self.entrada = np.full(n, np.nan, dtype=np.float64)

    def atualizar(self, visao, elegivel: np.ndarray) -> None:
        novos = elegivel & np.isnan(self.entrada)
        self.entrada[novos] = visao.pct[novos]

    def base(self, pct: np.ndarray) -> np.ndarray:
        return self.entrada.copy()


class DinamicaC:
    """Base da DIN-1 e da DIN-ESTAB: percentil corrente."""
    nome = "DIN-1"

    def __init__(self, n: int):
        pass

    def atualizar(self, visao, elegivel: np.ndarray) -> None:
        pass

    def base(self, pct: np.ndarray) -> np.ndarray:
        return pct.astype(np.float64).copy()
