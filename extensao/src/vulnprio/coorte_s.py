"""Coorte S da Fase D (protocolo_fase_d.md, seção 2.1), lida das páginas brutas do NVD.

Critérios, nesta ordem:
  1. ``published`` (dia, UTC) dentro da janela de publicação;
  2. ``vulnStatus`` diferente de ``Rejected``;
  3. pelo menos uma observação no arquivo diário do EPSS até o fim da janela de decisões.

Este módulo não usa CVSS nem qualquer outro status. A verificação de EPSS recebe o conjunto de CVEs
com EPSS observado, calculado fora daqui a partir do arquivo diário, para manter a leitura do NVD
separada da leitura do EPSS. Não importa ``rotulos`` e não altera nenhum módulo das Fases B e C.
"""
from __future__ import annotations

import datetime as dt
import json
from collections import Counter
from pathlib import Path
from typing import Iterable

import pandas as pd

REJEITADA = "Rejected"


def ler_nvd(pasta: Path) -> pd.DataFrame:
    """Uma linha por CVE: cve, published (date), vuln_status. Aceita arquivos com BOM (Fase A)."""
    linhas = []
    for arq in sorted(Path(pasta).glob("*_start-*.json")):
        p = json.loads(arq.read_bytes().decode("utf-8-sig"))
        for v in p["vulnerabilities"]:
            c = v["cve"]
            linhas.append((c["id"], dt.date.fromisoformat(c["published"][:10]), c.get("vulnStatus", "")))
    df = pd.DataFrame(linhas, columns=["cve", "published", "vuln_status"])
    if df["cve"].duplicated().any():
        raise ValueError(f"IDs repetidos no NVD bruto: {int(df['cve'].duplicated().sum())}")
    return df


def construir(nvd: pd.DataFrame, pub_inicio: dt.date, pub_fim: dt.date,
              com_epss: Iterable[str] | None) -> tuple[pd.DataFrame, dict]:
    """Aplica os critérios e devolve (coorte, contagens por motivo).

    Com ``com_epss=None`` o terceiro critério não é aplicado (útil só para contagens parciais);
    a contagem correspondente fica como None.
    """
    na_janela = nvd[(nvd["published"] >= pub_inicio) & (nvd["published"] <= pub_fim)]
    fora = len(nvd) - len(na_janela)
    rej = na_janela["vuln_status"] == REJEITADA
    nao_rej = na_janela[~rej]
    if com_epss is None:
        incl, sem_epss = nao_rej, None
    else:
        tem = nao_rej["cve"].isin(set(com_epss))
        incl, sem_epss = nao_rej[tem], int((~tem).sum())
    contagens = {
        "janela_publicacao": [pub_inicio.isoformat(), pub_fim.isoformat()],
        "nvd_lidas": int(len(nvd)),
        "fora_da_janela": int(fora),
        "publicadas_na_janela": int(len(na_janela)),
        "excluidas_rejected": int(rej.sum()),
        "excluidas_sem_epss": sem_epss,
        "incluidas": int(len(incl)),
        "status_das_incluidas": dict(Counter(incl["vuln_status"])),
    }
    return incl.sort_values(["published", "cve"]).reset_index(drop=True), contagens


def comparar_com_variante(coorte_s: pd.DataFrame, ids_variante: Iterable[str],
                          nvd: pd.DataFrame) -> dict:
    """Cruza a coorte S com a coorte variante (Fases B/C): quem está só numa, só na outra, e por quê."""
    s, v = set(coorte_s["cve"]), set(ids_variante)
    so_s = nvd[nvd["cve"].isin(s - v)]
    return {
        "em_ambas": len(s & v),
        "so_em_S": len(s - v),
        "so_na_variante": len(v - s),
        "so_em_S_por_status": dict(Counter(so_s["vuln_status"])),
    }
