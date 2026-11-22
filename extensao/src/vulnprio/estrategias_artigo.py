"""As 13 estratégias de limiar do artigo, reimplementadas para o teste de regressão contra a Fase A."""
from __future__ import annotations

import pandas as pd

ESTRATEGIAS = {
    "CVSS 5.0": lambda c, e: c >= 5,
    "CVSS 7.0": lambda c, e: c >= 7,
    "CVSS 9.0": lambda c, e: c >= 9,
    "CVSS 10.0": lambda c, e: c == 10,
    "EPSS 0.05%": lambda c, e: e > 0.0005,
    "EPSS 0.10%": lambda c, e: e > 0.001,
    "EPSS 0.50%": lambda c, e: e > 0.005,
    "EPSS 1.00%": lambda c, e: e > 0.01,
    "EPSS 5.00%": lambda c, e: e > 0.05,
    "CVSS 7.0 AND EPSS 0.50%": lambda c, e: (c >= 7) & (e > 0.005),
    "CVSS 9.0 AND EPSS 0.50%": lambda c, e: (c >= 9) & (e > 0.005),
    "CVSS 9.0 OR EPSS 0.50%": lambda c, e: (c >= 9) | (e > 0.005),
    "CVSS 10.0 OR EPSS 0.50%": lambda c, e: (c == 10) | (e > 0.005),
}


def avaliar(coorte: pd.DataFrame) -> pd.DataFrame:
    """Usa os mesmos insumos da Fase A: CVSS da variante, primeiro EPSS e cisaExploitAdd do NVD."""
    kev = coorte["nvd_kev"] != ""
    c, e = coorte["cvss_cna"], coorte["epss_primeiro_fase_a"]
    linhas = []
    for nome, f in ESTRATEGIAS.items():
        pr = f(c, e)
        linhas.append({"strategy": nome, "tp": int((pr & kev).sum()), "fp": int((pr & ~kev).sum()),
                       "fn": int((~pr & kev).sum())})
    return pd.DataFrame(linhas)
