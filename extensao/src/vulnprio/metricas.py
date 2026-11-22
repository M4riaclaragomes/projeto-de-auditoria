"""Métricas de eficácia, antecedência, estabilidade e operação (protocolo, seções 6 e 13)."""
from __future__ import annotations

from datetime import date

import numpy as np
import pandas as pd

from . import config as C


def datas_selecao(res, semanas: list[date]) -> np.ndarray:
    s = np.array([np.datetime64(t, "D") for t in semanas])
    return np.where(res.semana_sel >= 0, s[np.maximum(res.semana_sel, 0)], np.datetime64("NaT", "D"))


def antecipados(res, rot, semanas) -> tuple[np.ndarray, np.ndarray]:
    """Máscara de KEV antecipados (s_i < k_i, d = 0) e folga em dias."""
    s = datas_selecao(res, semanas)
    ok = (res.semana_sel >= 0) & rot.A
    folga = np.where(ok, (rot.k - s).astype("timedelta64[D]").astype(float), np.nan)
    ant = ok & (folga >= 1)
    return ant, folga


def resumir(res, rot, semanas) -> dict:
    ant, folga = antecipados(res, rot, semanas)
    A, AT, AP = rot.A, rot.A_T, rot.A_pos
    n_sel = int((res.semana_sel >= 0).sum())
    log = pd.DataFrame(res.log)
    e_sem = rot.e
    idade_sel = (res.semana_sel - e_sem)[res.semana_sel >= 0] * 7
    lw = np.where(A, np.clip(np.nan_to_num(folga, nan=0.0), 0, 90) / 90, 0).sum() / A.sum()
    estab = log.iloc[1:]
    out = {
        "politica": res.politica,
        "K": res.K,
        "N_A": int(ant.sum()),
        "N_A_T": int((ant & AT).sum()),
        "N_A_pos": int((ant & AP).sum()),
        "R_A": ant.sum() / A.sum(),
        "R_A_T": (ant & AT).sum() / AT.sum(),
        "R_A_pos": (ant & AP).sum() / AP.sum() if AP.sum() else np.nan,
        "precisao": ant.sum() / n_sel if n_sel else np.nan,
        "selecionadas": n_sel,
        "utilizacao": n_sel / (res.K * len(semanas)),
        "R_L7": ((folga >= 7) & ant).sum() / A.sum(),
        "R_L30": ((folga >= 30) & ant).sum() / A.sum(),
        "R_L90": ((folga >= 90) & ant).sum() / A.sum(),
        "LW": lw,
        "folga_mediana_A_T": float(np.nanmedian(folga[ant & AT])) if (ant & AT).any() else np.nan,
        "folga_mediana_A": float(np.nanmedian(folga[ant])) if ant.any() else np.nan,
        "espera_mediana_KEV_dias": float(np.median((res.semana_sel - e_sem)[ant] * 7)) if ant.any() else np.nan,
        "espera_mediana_todas_dias": float(np.median(idade_sel)) if len(idade_sel) else np.nan,
        "frac_sel_idade_gt90": float((idade_sel > 90).mean()) if len(idade_sel) else np.nan,
        "U_medio": float(estab["U"].mean()),
        "alfa_medio": float(estab["alfa"].mean()),
        "kendall_dist_medio": float(estab["kendall_dist_top4K"].mean()),
        "deslocadas_total": int(log["deslocadas_por_atualizacao"].sum()),
        "elegiveis_mediana": float(log["elegiveis"].median()),
        "K_sobre_E_mediana": float((res.K / log["elegiveis"].replace(0, np.nan)).median()),
        "chegadas_media": float(log["chegadas"].iloc[1:].mean()),
        "toggles_plano_medio_selecionadas": float(res.toggles_plano[res.semana_sel >= 0].mean()) if n_sel else np.nan,
    }
    out["rho"] = res.K / out["chegadas_media"]
    return out


def comparar(est, din, rot, semanas) -> dict:
    a_e, f_e = antecipados(est, rot, semanas)
    a_d, f_d = antecipados(din, rot, semanas)
    so_din, so_est, ambos = a_d & ~a_e, a_e & ~a_d, a_d & a_e
    dN = int(a_d.sum() - a_e.sum())
    out = {
        "K": est.K,
        "dN_A": dN,
        "dN_A_T": int((a_d & rot.A_T).sum() - (a_e & rot.A_T).sum()),
        "dN_A_pos": int((a_d & rot.A_pos).sum() - (a_e & rot.A_pos).sum()),
        "dR_A": dN / rot.A.sum(),
        "so_DIN": int(so_din.sum()),
        "so_EST": int(so_est.sum()),
        "ambos": int(ambos.sum()),
        "folga_mediana_ambos_A_T_DIN": float(np.nanmedian(f_d[ambos & rot.A_T])) if (ambos & rot.A_T).any() else np.nan,
        "folga_mediana_ambos_A_T_EST": float(np.nanmedian(f_e[ambos & rot.A_T])) if (ambos & rot.A_T).any() else np.nan,
        "folga_mediana_so_DIN_A_T": float(np.nanmedian(f_d[so_din & rot.A_T])) if (so_din & rot.A_T).any() else np.nan,
        "folga_mediana_so_EST_A_T": float(np.nanmedian(f_e[so_est & rot.A_T])) if (so_est & rot.A_T).any() else np.nan,
    }
    desl = sum(r["deslocadas_por_atualizacao"] for r in din.log)
    out["Gamma"] = desl / dN if dN > 0 else np.nan
    return out


def h3_tabelas(est, din, rot, semanas) -> pd.DataFrame:
    a_e, _ = antecipados(est, rot, semanas)
    a_d, _ = antecipados(din, rot, semanas)
    linhas = []
    for nome_conj, conj in (("A_T", rot.A_T), ("A", rot.A)):
        atraso = np.where(rot.atraso <= 30, "<=30d", ">30d")
        om = pd.cut(rot.omega, [0, 1, 4, 13, 10_000], labels=["1", "2-4", "5-13", ">13"]).astype(str)
        for dim, chave in (("atraso", atraso), ("omega", om)):
            for val in sorted(set(chave[conj])):
                m = conj & (chave == val)
                linhas.append({"conjunto": nome_conj, "dimensao": dim, "faixa": val, "n": int(m.sum()),
                               "N_EST": int((a_e & m).sum()), "N_DIN": int((a_d & m).sum())})
        for va in ("<=30d", ">30d"):
            for vo in ("1", "2-4", "5-13", ">13"):
                m = conj & (atraso == va) & (om == vo)
                if m.any():
                    linhas.append({"conjunto": nome_conj, "dimensao": "atraso x omega", "faixa": f"{va} | omega {vo}",
                                   "n": int(m.sum()), "N_EST": int((a_e & m).sum()), "N_DIN": int((a_d & m).sum())})
    df = pd.DataFrame(linhas)
    df["dN"] = df["N_DIN"] - df["N_EST"]
    df["K"] = est.K
    return df


def perfil_conjuntos(rot) -> pd.DataFrame:
    linhas = []
    for nome, m in (("A_T", rot.A_T), ("A_pos", rot.A_pos)):
        p = pd.to_datetime(rot.p[m])
        linhas.append({"conjunto": nome, "n": int(m.sum()),
                       "publicacao_mediana": str(p.sort_values()[len(p) // 2].date()) if len(p) else "",
                       "atraso_mediano_dias": float(np.median(rot.atraso[m])) if m.any() else np.nan,
                       "omega_mediano_semanas": float(np.median(rot.omega[m])) if m.any() else np.nan,
                       "omega_min": int(rot.omega[m].min()) if m.any() else 0,
                       "omega_max": int(rot.omega[m].max()) if m.any() else 0})
    return pd.DataFrame(linhas)
