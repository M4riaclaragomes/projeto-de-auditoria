"""Configuração dos testes para quem clona o repositório do GitHub.

Alguns testes originais conferem arquivos que NÃO ficam no Git (dados brutos grandes e o ambiente virtual da
Fase A). Em vez de falharem por "arquivo não encontrado", eles são pulados com o motivo explícito e o caminho
para obter os dados. Nenhum teste foi alterado: só a decisão de pular é feita aqui.

Para conferir esses testes também:  python verificar.py --preparar-dados   (e, para o EPSS diário, ver
extensao/data/raw/LEIAME.md).
"""
import json
import os
from pathlib import Path

import pytest

RAIZ = Path(__file__).resolve().parents[1]
FASE_A = Path(os.environ.get("FASE_A_DIR", RAIZ.parent / "projeto")).resolve()
RAW = RAIZ / "data" / "raw"


def _manifesto_fase_a_completo() -> bool:
    man = json.loads((RAIZ / "freeze" / "fase_a_manifest.json").read_text(encoding="utf-8-sig"))
    return all((FASE_A / f["path"]).exists() for f in man["files"])


def _epss_bruto_disponivel() -> bool:
    return (RAW / "epss_daily" / "epss_scores-2024-03-10.csv.gz").exists()


def _manifesto_epss_disponivel() -> bool:
    return (RAW / "epss_daily" / "manifest.json").exists()


# teste -> (condição para rodar, motivo de pular)
DEPENDE_DE_DADOS = {
    "test_fase_a_intacta": (
        _manifesto_fase_a_completo,
        "o manifesto da Fase A lista 938 arquivos, incluindo um ambiente virtual (.venv) e dados brutos que não "
        "ficam no GitHub. Rode `python verificar.py`, que confere todos os arquivos presentes por SHA-256.",
    ),
    "test_epss_semanal_confere_com_arquivo_bruto": (
        _epss_bruto_disponivel,
        "precisa dos arquivos diários do EPSS (~1,5 GB), que não ficam no Git. "
        "Ver extensao/data/raw/LEIAME.md para baixá-los.",
    ),
    "test_versao_unica_do_modelo": (
        _manifesto_epss_disponivel,
        "precisa de extensao/data/raw/epss_daily/manifest.json. Ver extensao/data/raw/LEIAME.md.",
    ),
}


def _fase_a_descompactada() -> bool:
    """Páginas do NVD 2024 e corpus da variante já descompactados (python verificar.py --preparar-dados)."""
    paginas = list((FASE_A / "data" / "nvd-2024-raw").glob("*_start-*.json"))
    return len(paginas) >= 23 and (FASE_A / "data" / "nvd-2024-filtered-variant.jsonl").exists()


MOTIVO_FASE_A = ("os dados do NVD 2024 estão compactados em dados_compactados/ e ainda não foram "
                 "descompactados. Rode `python verificar.py --preparar-dados` na raiz do repositório.")


def pytest_collection_modifyitems(config, items):
    cache = {}
    for item in items:
        if "tem_fase_a" in getattr(item, "fixturenames", ()):
            if _fase_a_descompactada not in cache:
                cache[_fase_a_descompactada] = _fase_a_descompactada()
            if not cache[_fase_a_descompactada]:
                item.add_marker(pytest.mark.skip(reason=MOTIVO_FASE_A))
            continue
        regra = DEPENDE_DE_DADOS.get(item.name)
        if regra is None:
            continue
        cond, motivo = regra
        if cond not in cache:
            cache[cond] = cond()
        if not cache[cond]:
            item.add_marker(pytest.mark.skip(reason="dados brutos fora do Git: " + motivo))
