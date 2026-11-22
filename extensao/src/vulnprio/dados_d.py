"""Construção das coortes da Fase D (protocolo_fase_d.md, seção 2). Arquivo novo.

Para uma lista de CVEs (com data de publicação p e data de inclusão no KEV k) e um calendário de decisões,
lê os arquivos diários do EPSS em ordem e guarda, para cada decisão t, o último percentil/score observado
até c(t) = t − 1 (mesma regra de `dados.py` da Fase B). Toda observação lida tem de ter o `model_version`
esperado para a coorte. Grava em data/derived/fase_d/<nome>/.
"""
from __future__ import annotations

import json
from datetime import date, timedelta
from pathlib import Path

import numpy as np
import pandas as pd

from . import config as C
from . import dados

DERIVED_D = C.DERIVED / "fase_d"
EPSS_V3 = C.RAW / "epss_daily"
EPSS_V4 = C.RAW / "epss_daily_v4"
V3, V4 = "v2023.03.01", "v2025.03.14"

# calendário congelado (seção 2.2 do protocolo)
COORTES = {
    "2024-S": dict(pub=(date(2024, 1, 1), date(2024, 12, 31)), dec=(date(2024, 1, 1), date(2025, 3, 10)),
                   leitura=(date(2024, 1, 1), date(2025, 3, 16)), modelo=V3, dir=EPSS_V3),
    "T1": dict(pub=(date(2025, 1, 1), date(2025, 3, 16)), dec=(date(2025, 1, 6), date(2025, 3, 17)),
               leitura=(date(2024, 11, 1), date(2025, 3, 16)), modelo=V3, dir=EPSS_V3),
    "T2": dict(pub=(date(2025, 3, 17), date(2025, 11, 19)), dec=(date(2025, 3, 24), date(2026, 6, 15)),
               leitura=(date(2025, 3, 17), date(2026, 6, 14)), modelo=V4, dir=EPSS_V4),
}


def segundas(inicio: date, fim: date) -> list[date]:
    assert inicio.weekday() == 0 and fim.weekday() == 0
    return [inicio + timedelta(weeks=i) for i in range((fim - inicio).days // 7 + 1)]


def epss_semanal(cves, decisoes, leitura, pasta: Path, modelo: str) -> dict:
    """pct/score (decisão x CVE) da última observação <= c(t); dia_obs = último dia observado (ou '')."""
    idx = pd.Series(np.arange(len(cves)), index=pd.Index(cves))
    man = json.loads((pasta / "manifest.json").read_text())
    arquivos = {r["date"]: r for r in man["files"] if r.get("file")}
    cortes = {t - timedelta(days=1): w for w, t in enumerate(decisoes)}
    ini, fim = leitura
    if max(cortes) > fim:
        raise ValueError("decisão com corte posterior ao fim da leitura")
    n = len(cves)
    pct = np.full(n, np.nan, np.float32)
    sc = np.full(n, np.nan, np.float32)
    ult = np.full(n, "", dtype="<U10")
    tem_ate_fim = np.zeros(n, bool)
    W = len(decisoes)
    out_p = np.full((W, n), np.nan, np.float32)
    out_s = np.full((W, n), np.nan, np.float32)
    out_d = np.full((W, n), "", dtype="<U10")
    sem_arquivo, versoes = [], set()
    d = ini
    while d <= fim:
        r = arquivos.get(d.isoformat())
        if r is None:
            sem_arquivo.append(d.isoformat())
        else:
            if r["model_version"] != modelo:
                raise ValueError(f"{d}: modelo {r['model_version']} != {modelo}")
            versoes.add(r["model_version"])
            df = pd.read_csv(pasta / r["file"], skiprows=1, compression="gzip", usecols=["cve", "epss", "percentile"])
            pos = df["cve"].map(idx)
            ok = pos.notna().to_numpy()
            col = pos[ok].astype(int).to_numpy()
            pct[col] = df.loc[ok, "percentile"].to_numpy(np.float32)
            sc[col] = df.loc[ok, "epss"].to_numpy(np.float32)
            ult[col] = d.isoformat()
            tem_ate_fim[col] = True
        if d in cortes:
            w = cortes[d]
            out_p[w], out_s[w], out_d[w] = pct, sc, ult
        d += timedelta(days=1)
    return {"pct": out_p, "score": out_s, "dia_obs": out_d, "semanas": np.array([t.isoformat() for t in decisoes]),
            "tem_epss": tem_ate_fim, "dias_sem_arquivo": sem_arquivo, "versoes": sorted(versoes)}


def construir(nome: str, nvd: pd.DataFrame, incluir_rejeitadas: bool = False, salvar: bool = True):
    """nvd: colunas cve, published (date), vuln_status (de coorte_s.ler_nvd)."""
    from . import coorte_s
    cfg = COORTES[nome.split("+")[0]]
    na_janela = nvd[(nvd["published"] >= cfg["pub"][0]) & (nvd["published"] <= cfg["pub"][1])]
    base = na_janela if incluir_rejeitadas else na_janela[na_janela["vuln_status"] != coorte_s.REJEITADA]
    base = base.sort_values(["published", "cve"]).reset_index(drop=True)
    dec = segundas(*cfg["dec"])
    sem = epss_semanal(base["cve"].to_numpy(), dec, cfg["leitura"], cfg["dir"], cfg["modelo"])
    tem = sem.pop("tem_epss")
    coorte = pd.DataFrame({"cve": base["cve"], "p": base["published"].astype(str),
                           "vuln_status": base["vuln_status"]})
    kev = dados.carregar_kev()
    coorte["k"] = coorte["cve"].map(kev).fillna("")
    contagem = {
        "coorte": nome, "janela_publicacao": [str(x) for x in cfg["pub"]],
        "decisoes": [dec[0].isoformat(), dec[-1].isoformat(), len(dec)], "modelo_epss": cfg["modelo"],
        "publicadas_na_janela": int(len(na_janela)),
        "excluidas_rejected": 0 if incluir_rejeitadas else int((na_janela["vuln_status"] == coorte_s.REJEITADA).sum()),
        "excluidas_sem_epss": int((~tem).sum()), "incluidas": int(tem.sum()),
        "status_das_incluidas": coorte.loc[tem, "vuln_status"].value_counts().to_dict(),
        "dias_sem_arquivo_epss": sem.pop("dias_sem_arquivo"), "versoes_epss_lidas": sem.pop("versoes"),
    }
    coorte = coorte[tem].reset_index(drop=True)
    for k in ("pct", "score", "dia_obs"):
        sem[k] = sem[k][:, tem]
    if salvar:
        pasta = DERIVED_D / nome
        pasta.mkdir(parents=True, exist_ok=True)
        coorte.to_csv(pasta / "coorte.csv.gz", index=False, compression="gzip")
        np.savez_compressed(pasta / "epss_semanal.npz", **sem)
        (pasta / "contagens.json").write_text(json.dumps(contagem, indent=1, ensure_ascii=False))
    return coorte, sem, contagem


def carregar(nome: str):
    from .estado import Estado
    pasta = DERIVED_D / nome
    coorte = pd.read_csv(pasta / "coorte.csv.gz", keep_default_na=False)
    sem = dict(np.load(pasta / "epss_semanal.npz"))
    return coorte, Estado(coorte, sem), json.loads((pasta / "contagens.json").read_text())


if __name__ == "__main__":
    # Ex.: PYTHONPATH=src python -m vulnprio.dados_d data/raw/nvd-2025 T1 T2
    import sys
    from . import coorte_s
    pasta_nvd, nomes = Path(sys.argv[1]), sys.argv[2:]
    nvd = coorte_s.ler_nvd(pasta_nvd)
    for nome in nomes:
        _, _, c = construir(nome, nvd)
        print(json.dumps(c, ensure_ascii=False))
