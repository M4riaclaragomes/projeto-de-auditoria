"""Testes offline da coleta do NVD e da coorte S (Fase D).

As páginas brutas de 2024 da Fase A fazem o papel das respostas da API. Nada aqui acessa a rede,
e nada grava nas pastas das Fases A, B ou C.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import json
import shutil
import sys
import urllib.error
import urllib.parse
from pathlib import Path

import pytest

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ / "src"))
from vulnprio import coorte_s  # noqa: E402

_spec = importlib.util.spec_from_file_location("coleta_nvd", RAIZ / "scripts" / "coleta_nvd.py")
cn = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cn)

import os  # noqa: E402
FASE_A = Path(os.environ.get("FASE_A_DIR", RAIZ.parent / "projeto"))
NVD24 = FASE_A / "data" / "nvd-2024-raw"
D = dt.date


def sem_pausa(_s):
    pass


class ApiFalsa:
    """Serve as páginas da Fase A conforme pubStartDate/pubEndDate/startIndex da URL."""

    def __init__(self, pasta=NVD24, falhar_em=None, alterar=None):
        self.pasta, self.chamadas = pasta, []
        self.falhar_em = falhar_em or {}
        self.alterar = alterar

    def __call__(self, url, cab):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
        assert q["resultsPerPage"] == ["2000"]
        j = cn.Janela(D.fromisoformat(q["pubStartDate"][0][:10]), D.fromisoformat(q["pubEndDate"][0][:10]))
        start = int(q["startIndex"][0])
        self.chamadas.append((j.rotulo, start))
        n = self.falhar_em.get((j.rotulo, start), 0)
        if n:
            self.falhar_em[(j.rotulo, start)] = n - 1
            raise urllib.error.HTTPError(url, 503, "indisponível", {}, None)
        dados = (self.pasta / cn.nome_pagina(j, start)).read_bytes()
        return self.alterar(j, start, dados) if self.alterar else dados


@pytest.fixture(scope="module")
def tem_fase_a():
    if not NVD24.exists():
        pytest.skip("páginas brutas da Fase A indisponíveis")


def test_janelas_cobrem_periodo_sem_lacunas():
    for ini, fim in [(D(2025, 1, 1), D(2025, 11, 19)), (D(2024, 1, 1), D(2024, 12, 31)), (D(2025, 3, 3), D(2025, 3, 3))]:
        js = cn.janelas(ini, fim)
        assert js[0].inicio == ini and js[-1].fim == fim
        for a, b in zip(js, js[1:]):
            assert b.inicio == a.fim + dt.timedelta(days=1)
        assert all((j.fim - j.inicio).days + 1 <= 120 for j in js)
    # mesmas janelas que a Fase A usou em 2024
    assert [j.rotulo for j in cn.janelas(D(2024, 1, 1), D(2024, 12, 31))] == [
        "2024-01-01_2024-04-29", "2024-04-30_2024-08-27", "2024-08-28_2024-12-25", "2024-12-26_2024-12-31"]
    assert len(cn.janelas(D(2025, 1, 1), D(2025, 11, 19))) == 3


def test_coleta_completa_reproduz_fase_a(tem_fase_a, tmp_path):
    api = ApiFalsa()
    m = cn.coletar(D(2024, 1, 1), D(2024, 12, 31), tmp_path, obter=api, dormir=sem_pausa)
    assert m["totalResults"] == 40704 == m["ids_unicos"]
    assert len(m["arquivos"]) == 23 and m["paginas_baixadas_nesta_execucao"] == 23
    for a in m["arquivos"]:
        assert a["sha256"] == hashlib.sha256((NVD24 / a["arquivo"]).read_bytes()).hexdigest()
    ref = json.loads((NVD24 / "manifest.json").read_bytes().decode("utf-8-sig"))
    assert [w["totalResults"] for w in m["windows"]] == [w["totalResults"] for w in ref["windows"]]
    assert not list(tmp_path.glob(".parcial_*"))


def test_retomada_nao_rebaixa_nem_sobrescreve(tem_fase_a, tmp_path):
    class Interrompe(ApiFalsa):
        def __call__(self, url, cab):
            if len(self.chamadas) == 9:
                raise KeyboardInterrupt
            return super().__call__(url, cab)

    with pytest.raises(KeyboardInterrupt):
        cn.coletar(D(2024, 1, 1), D(2024, 12, 31), tmp_path, obter=Interrompe(), dormir=sem_pausa)
    gravadas = sorted(tmp_path.glob("*_start-*.json"))
    assert len(gravadas) == 9 and not (tmp_path / "manifest.json").exists()
    mtimes = {p.name: p.stat().st_mtime_ns for p in gravadas}
    api = ApiFalsa()
    m = cn.coletar(D(2024, 1, 1), D(2024, 12, 31), tmp_path, obter=api, dormir=sem_pausa)
    assert len(api.chamadas) == 14 and m["paginas_baixadas_nesta_execucao"] == 14
    assert all((tmp_path / n).stat().st_mtime_ns == t for n, t in mtimes.items())
    assert m["totalResults"] == 40704


def test_retentativa_em_erro_temporario(tem_fase_a, tmp_path):
    api = ApiFalsa(falhar_em={("2024-12-26_2024-12-31", 0): 2})
    esperas = []
    m = cn.coletar(D(2024, 12, 26), D(2024, 12, 31), tmp_path, obter=api, dormir=esperas.append)
    assert m["totalResults"] == 632 and len(api.chamadas) == 3
    assert esperas.count(6) == 1 and esperas.count(12) == 1


def test_erro_definitivo_nao_e_repetido(tmp_path):
    def obter(url, cab):
        raise urllib.error.HTTPError(url, 404, "não encontrado", {}, None)
    with pytest.raises(urllib.error.HTTPError):
        cn.coletar(D(2025, 1, 1), D(2025, 1, 2), tmp_path, obter=obter, dormir=sem_pausa)


def test_total_muda_durante_paginacao_recusa(tem_fase_a, tmp_path):
    def alterar(j, start, dados):
        if start == 4000:
            p = json.loads(dados.decode("utf-8-sig"))
            p["totalResults"] += 1
            return json.dumps(p).encode()
        return dados
    with pytest.raises(cn.ErroIntegridade, match="totalResults mudou"):
        cn.coletar(D(2024, 1, 1), D(2024, 4, 29), tmp_path, obter=ApiFalsa(alterar=alterar), dormir=sem_pausa)
    assert not (tmp_path / "manifest.json").exists()


def _copiar(destino, rotulo):
    for p in NVD24.glob(f"{rotulo}_start-*.json"):
        shutil.copy(p, destino / p.name)


def test_validacao_detecta_ids_repetidos_e_published_fora(tem_fase_a, tmp_path):
    r = "2024-12-26_2024-12-31"
    p = json.loads((NVD24 / f"{r}_start-000000.json").read_bytes().decode("utf-8-sig"))
    rep = json.loads(json.dumps(p))
    rep["vulnerabilities"][1] = rep["vulnerabilities"][0]
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / f"{r}_start-000000.json").write_text(json.dumps(rep))
    with pytest.raises(cn.ErroIntegridade, match="repetidos"):
        cn.coletar(D(2024, 12, 26), D(2024, 12, 31), tmp_path / "a", obter=None)
    fora = json.loads(json.dumps(p))
    fora["vulnerabilities"][0]["cve"]["published"] = "2024-12-20T10:00:00.000"
    (tmp_path / "b").mkdir()
    (tmp_path / "b" / f"{r}_start-000000.json").write_text(json.dumps(fora))
    with pytest.raises(cn.ErroIntegridade, match="fora da janela"):
        cn.coletar(D(2024, 12, 26), D(2024, 12, 31), tmp_path / "b", obter=None)


def test_verificacao_offline_e_pagina_ausente(tem_fase_a, tmp_path):
    _copiar(tmp_path, "2024-04-30_2024-08-27")
    m = cn.coletar(D(2024, 4, 30), D(2024, 8, 27), tmp_path, obter=None)
    assert m["totalResults"] == 14180 and m["paginas_baixadas_nesta_execucao"] == 0
    (tmp_path / "2024-04-30_2024-08-27_start-006000.json").unlink()
    with pytest.raises(cn.ErroIntegridade, match="ausente"):
        cn.coletar(D(2024, 4, 30), D(2024, 8, 27), tmp_path, obter=None)


def test_nunca_sobrescreve(tmp_path):
    alvo = tmp_path / "x.json"
    cn.gravar_exclusivo(alvo, b"1")
    with pytest.raises(FileExistsError):
        cn.gravar_exclusivo(alvo, b"2")
    assert alvo.read_bytes() == b"1" and not list(tmp_path.glob(".parcial_*"))


def test_manifesto_igual_nao_duplica_e_diferente_ganha_novo_nome(tem_fase_a, tmp_path):
    _copiar(tmp_path, "2024-12-26_2024-12-31")
    t0 = dt.datetime(2026, 11, 22, tzinfo=dt.timezone.utc)
    cn.coletar(D(2024, 12, 26), D(2024, 12, 31), tmp_path, obter=None, agora=t0)
    cn.coletar(D(2024, 12, 26), D(2024, 12, 31), tmp_path, obter=None, agora=t0 + dt.timedelta(hours=1))
    assert len(list(tmp_path.glob("manifest*.json"))) == 1
    _copiar(tmp_path, "2024-08-28_2024-12-25")
    cn.coletar(D(2024, 8, 28), D(2024, 12, 31), tmp_path, obter=None, agora=t0 + dt.timedelta(hours=2))
    assert len(list(tmp_path.glob("manifest*.json"))) == 2


def test_coorte_s_2024_reproduz_contagens(tem_fase_a):
    nvd = coorte_s.ler_nvd(NVD24)
    s, c = coorte_s.construir(nvd, D(2024, 1, 1), D(2024, 12, 31), com_epss=None)
    assert c["publicadas_na_janela"] == 40704
    assert c["excluidas_rejected"] == 751
    assert c["incluidas"] == 39953 and REJ not in c["status_das_incluidas"]
    epss_falso = set(s["cve"][:39000])
    s2, c2 = coorte_s.construir(nvd, D(2024, 1, 1), D(2024, 12, 31), com_epss=epss_falso)
    assert c2["incluidas"] == 39000 and c2["excluidas_sem_epss"] == 953
    assert c2["incluidas"] + c2["excluidas_sem_epss"] + c2["excluidas_rejected"] == c2["publicadas_na_janela"]


REJ = coorte_s.REJEITADA


def test_coorte_s_contem_a_variante(tem_fase_a):
    import pandas as pd
    nvd = coorte_s.ler_nvd(NVD24)
    s, _ = coorte_s.construir(nvd, D(2024, 1, 1), D(2024, 12, 31), com_epss=None)
    var = pd.read_json(FASE_A / "data" / "nvd-2024-filtered-variant.jsonl", lines=True)
    cmp = coorte_s.comparar_com_variante(s, var["cveId"], nvd)
    assert cmp["so_na_variante"] == 0
    assert cmp["em_ambas"] == len(var)


def test_coorte_s_nao_importa_rotulos():
    texto = (RAIZ / "src" / "vulnprio" / "coorte_s.py").read_text()
    assert "rotulos" not in texto.split('"""', 2)[2]
