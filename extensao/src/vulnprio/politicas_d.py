"""Comparadores da Fase D (protocolo_fase_d.md, seção 3). Arquivo novo; nenhum módulo anterior foi alterado.

Segue a interface das políticas da Fase C (`atualizar(visao, elegivel)` e `base(pct)`), para rodar no
simulador da Fase C (`simulador_c.simular_c`) sem modificá-lo.

DIN-Δ: decisões numeradas j = 0, 1, 2, ... a partir da primeira decisão da coorte. Nas decisões com
j mod Δ = 0 há releitura global: toda CVE elegível recebe o percentil em c(t). Nas demais, cada CVE mantém
o percentil da última releitura de que participou; CVE que entrou depois da última releitura usa o
percentil da semana de entrada. Sem bônus de plano. Com Δ = 1 é idêntica à DIN-1 (teste).

Contrafactual (métricas de deslocamento e revisões por atualização): o simulador chama `base` duas vezes por
semana, primeiro com `visao.pct` (o real) e depois com uma cópia (o contrafactual "sem atualização desde a
semana anterior"). Para a DIN-Δ, "sem atualização" significa manter os scores da semana anterior para as
CVEs carregadas; a política distingue as duas chamadas pela identidade do vetor recebido em `atualizar`.

EST-travada: `politicas_c.EstaticaC` com bônus λ = 2 no simulador da Fase C; não precisa de classe nova.
"""
from __future__ import annotations

import numpy as np


class DinamicaDelta:
    def __init__(self, n: int, delta: int):
        if delta < 1:
            raise ValueError("delta >= 1")
        self.delta = delta
        self.nome = f"DIN-{delta}"
        self.score = np.full(n, np.nan, dtype=np.float64)
        self.score_ant = self.score.copy()
        self.j = -1
        self.releitura = False
        self._pct_real = None

    def atualizar(self, visao, elegivel: np.ndarray) -> None:
        self.j += 1
        self.releitura = self.j % self.delta == 0
        self.score_ant = self.score.copy()
        self._pct_real = visao.pct
        if self.releitura:
            self.score[elegivel] = visao.pct[elegivel]
        else:
            novos = elegivel & np.isnan(self.score)
            self.score[novos] = visao.pct[novos]

    def base(self, pct: np.ndarray) -> np.ndarray:
        if pct is self._pct_real:
            return self.score.copy()
        # contrafactual: carregadas mantêm o score da semana anterior; novas usam o de entrada
        cf = self.score_ant.copy()
        novas = np.isnan(cf) & ~np.isnan(self.score)
        cf[novas] = self.score[novas]
        return cf
