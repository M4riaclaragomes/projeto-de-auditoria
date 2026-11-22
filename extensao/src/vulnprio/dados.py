"""Constrói as tabelas derivadas a partir dos dados brutos (Fase A + EPSS diário + KEV).

Nada aqui escreve na Fase A. Saídas em data/derived/:
- coorte_2024.csv.gz: uma linha por CVE do corpus variante (ordem = índice das matrizes);
- epss_diario.npz: matrizes dia x CVE de percentil e score (NaN = ausente no arquivo do dia);
- epss_semanal.npz: para cada decisão semanal, percentil/score da última observação <= c(t).
"""
from __future__ import annotations

import gzip
import json
from datetime import date, timedelta
from pathlib import Path

import numpy as np
import pandas as pd

from . import config as C


def semanas() -> list[date]:
    """Datas de decisão: segundas-feiras de PRIMEIRA_DECISAO até a última <= T_FIM."""
    out, t = [], C.PRIMEIRA_DECISAO
    while t <= C.T_FIM:
        out.append(t)
        t += timedelta(days=7)
    return out


def corte(t: date) -> date:
    """Corte de informação c(t) = t - 1 dia."""
    return t - timedelta(days=1)


def carregar_coorte_fase_a() -> pd.DataFrame:
    linhas = []
    with open(C.CORPUS_VARIANTE, encoding="utf-8") as f:
        for l in f:
            r = json.loads(l)
            linhas.append(
                {
                    "cve": r["cveId"],
                    "p": r["published"][:10],
                    "nvd_kev": (r.get("cisaExploitAdd") or "")[:10],
                    "cvss_cna": float(r["cvssBaseScore"]),
                    "cvss_type": r.get("cvssType"),
                    "epss_primeiro_fase_a": float(r["epssScore"]),
                    "epss_data_fase_a": r["epssDate"],
                }
            )
    df = pd.DataFrame(linhas).sort_values("cve").reset_index(drop=True)
    return df


def carregar_kev() -> dict[str, str]:
    cat = json.loads(Path(C.KEV_JSON).read_text(encoding="utf-8"))
    assert cat["catalogVersion"] == "2026.11.20", cat["catalogVersion"]
    return {v["cveID"]: v["dateAdded"] for v in cat["vulnerabilities"]}


def construir() -> dict:
    C.DERIVED.mkdir(parents=True, exist_ok=True)
    coorte = carregar_coorte_fase_a()
    kev = carregar_kev()
    coorte["k"] = coorte["cve"].map(kev).fillna("")
    idx = pd.Series(np.arange(len(coorte)), index=coorte["cve"])

    manifest = json.loads((C.EPSS_DIR / "manifest.json").read_text())
    arquivos = {r["date"]: r for r in manifest["files"] if r.get("file")}
    dias = [C.EPSS_INICIO + timedelta(days=i) for i in range((C.T_FIM - C.EPSS_INICIO).days + 1)]
    n_d, n_c = len(dias), len(coorte)
    pct = np.full((n_d, n_c), np.nan, dtype=np.float32)
    score = np.full((n_d, n_c), np.nan, dtype=np.float32)
    presente_dia = np.zeros(n_d, dtype=bool)
    for j, d in enumerate(dias):
        r = arquivos.get(d.isoformat())
        if r is None:
            continue
        if r["model_version"] != C.MODELO_ESPERADO:
            raise ValueError(f"Arquivo {d} com modelo {r['model_version']}")
        presente_dia[j] = True
        df = pd.read_csv(C.EPSS_DIR / r["file"], skiprows=1, compression="gzip")
        pos = df["cve"].map(idx)
        ok = pos.notna().to_numpy()
        col = pos[ok].astype(int).to_numpy()
        pct[j, col] = df.loc[ok, "percentile"].to_numpy(np.float32)
        score[j, col] = df.loc[ok, "epss"].to_numpy(np.float32)

    # primeira presença em qualquer arquivo (a_i) e primeira presença na data de publicação ou depois
    pres = ~np.isnan(pct)
    dias_np = np.array(dias, dtype="datetime64[D]")
    tem = pres.any(axis=0)
    a = np.where(tem, dias_np[np.argmax(pres, axis=0)], np.datetime64("NaT"))
    coorte["a"] = pd.to_datetime(a).strftime("%Y-%m-%d").where(tem, "")
    p_np = pd.to_datetime(coorte["p"]).to_numpy("datetime64[D]")
    apos = pres & (dias_np[:, None] >= p_np[None, :])
    tem2 = apos.any(axis=0)
    a2 = np.where(tem2, dias_np[np.argmax(apos, axis=0)], np.datetime64("NaT"))
    coorte["a_pos_publicacao"] = pd.to_datetime(a2).strftime("%Y-%m-%d").where(tem2, "")

    np.savez_compressed(C.DERIVED / "epss_diario.npz", pct=pct, score=score,
                        dias=np.array([d.isoformat() for d in dias]), presente_dia=presente_dia)

    # semanal: última observação <= c(t), por CVE (forward fill sobre os dias)
    ff_pct = pd.DataFrame(pct).ffill().to_numpy(np.float32)
    ff_score = pd.DataFrame(score).ffill().to_numpy(np.float32)
    # dia da última observação usada por CVE (para teste de não-vazamento)
    ultimo = np.where(pres, np.arange(n_d)[:, None], -1)
    ultimo = np.maximum.accumulate(ultimo, axis=0)
    sem = semanas()
    linhas = [dias.index(corte(t)) if corte(t) >= C.EPSS_INICIO else -1 for t in sem]
    w_pct = np.full((len(sem), n_c), np.nan, np.float32)
    w_score = np.full((len(sem), n_c), np.nan, np.float32)
    w_dia_obs = np.full((len(sem), n_c), "", dtype="<U10")
    w_arquivo_mais_recente = []
    obsoletas = []
    for w, j in enumerate(linhas):
        if j < 0:
            w_arquivo_mais_recente.append("")
            obsoletas.append(0)
            continue
        w_pct[w] = ff_pct[j]
        w_score[w] = ff_score[j]
        u = ultimo[j]
        w_dia_obs[w] = np.where(u >= 0, np.array([d.isoformat() for d in dias])[np.maximum(u, 0)], "")
        jj = j
        while not presente_dia[jj]:
            jj -= 1
        w_arquivo_mais_recente.append(dias[jj].isoformat())
        obsoletas.append(int(((u >= 0) & (u < jj)).sum()))
    np.savez_compressed(C.DERIVED / "epss_semanal.npz", pct=w_pct, score=w_score, dia_obs=w_dia_obs,
                        semanas=np.array([t.isoformat() for t in sem]),
                        arquivo_mais_recente=np.array(w_arquivo_mais_recente))
    coorte.to_csv(C.DERIVED / "coorte_2024.csv.gz", index=False, compression="gzip")
    resumo = {
        "n_cves": int(n_c),
        "n_dias": n_d,
        "dias_sem_arquivo": [d.isoformat() for d, ok in zip(dias, presente_dia) if not ok],
        "n_semanas": len(sem),
        "cves_sem_epss_ate_t_fim": int((~tem).sum()),
        "observacoes_obsoletas_por_semana_max": int(max(obsoletas)),
        "kev_no_catalogo": int((coorte["k"] != "").sum()),
    }
    (C.DERIVED / "resumo_construcao.json").write_text(json.dumps(resumo, indent=1))
    return resumo


if __name__ == "__main__":
    print(json.dumps(construir(), indent=1))
