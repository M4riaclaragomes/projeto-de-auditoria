"""Coleta do NVD (API 2.0) por data de publicação, para a Fase D.

Protocolo: freeze/protocolo_fase_d.md, seção 8. Para a Fase D, a coleta cobre de 2025-01-01 a 2025-11-19.

O que o script faz
------------------
* Divide o período em janelas de publicação de no máximo 120 dias (limite da API) e pagina cada
  janela com resultsPerPage = 2000. Os nomes dos arquivos seguem o padrão da Fase A:
  ``AAAA-MM-DD_AAAA-MM-DD_start-NNNNNN.json``.
* Retomada: páginas já gravadas são lidas do disco e não são baixadas de novo. Nenhum arquivo é
  sobrescrito; a gravação usa arquivo temporário e criação exclusiva.
* Integridade, por janela: ``totalResults`` igual em todas as páginas, ``startIndex`` e número de
  registros coerentes, total gravado igual a ``totalResults``, todo ``published`` dentro da janela.
  No conjunto: nenhum ID repetido. Se alguma validação falhar, o script para com código 2 e não
  grava manifesto de coleta completa.
* Manifesto: SHA-256 de cada página, totais por janela, data da coleta e resultado das validações.
  Se ``manifest.json`` já existir com conteúdo diferente, grava ``manifest_<timestamp>.json``.

Limite de taxa: com chave (variável ``NVD_API_KEY``), cerca de 0,7 s entre requisições; sem chave,
6,5 s. Em erro HTTP 403/429/5xx ou de rede, tenta de novo com espera crescente (até 8 tentativas).

Se o NVD alterar registros durante a coleta (``totalResults`` muda entre páginas), a janela é
recusada. Nesse caso, apague ou mova *apenas as páginas daquela janela* e rode de novo.

Uso
---
    # coleta (rodar localmente; a API do NVD não é acessível no ambiente de análise)
    python scripts/coleta_nvd.py --inicio 2025-01-01 --fim 2025-11-19 --saida data/raw/nvd-2025

    # só verificar uma pasta já coletada, sem rede
    python scripts/coleta_nvd.py --inicio 2025-01-01 --fim 2025-11-19 --saida data/raw/nvd-2025 --verificar
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

URL_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
POR_PAGINA = 2000
JANELA_MAX_DIAS = 120
PAUSA_COM_CHAVE = 0.7
PAUSA_SEM_CHAVE = 6.5
TENTATIVAS = 8

Obter = Callable[[str, dict], bytes]


class ErroIntegridade(RuntimeError):
    pass


@dataclass(frozen=True)
class Janela:
    inicio: dt.date
    fim: dt.date  # inclusivo

    @property
    def rotulo(self) -> str:
        return f"{self.inicio.isoformat()}_{self.fim.isoformat()}"

    @property
    def pub_start(self) -> str:
        return f"{self.inicio.isoformat()}T00:00:00.000Z"

    @property
    def pub_end(self) -> str:
        return f"{self.fim.isoformat()}T23:59:59.999Z"


def janelas(inicio: dt.date, fim: dt.date, max_dias: int = JANELA_MAX_DIAS) -> list[Janela]:
    """Janelas consecutivas, sem lacuna nem sobreposição, cada uma com no máximo max_dias dias."""
    if fim < inicio:
        raise ValueError("fim anterior ao início")
    out, a = [], inicio
    while a <= fim:
        b = min(a + dt.timedelta(days=max_dias - 1), fim)
        out.append(Janela(a, b))
        a = b + dt.timedelta(days=1)
    return out


def nome_pagina(j: Janela, start: int) -> str:
    return f"{j.rotulo}_start-{start:06d}.json"


def url_pagina(j: Janela, start: int) -> str:
    q = urllib.parse.urlencode({
        "pubStartDate": j.pub_start, "pubEndDate": j.pub_end,
        "resultsPerPage": POR_PAGINA, "startIndex": start,
    })
    return f"{URL_API}?{q}"


def ler_json(dados: bytes) -> dict:
    return json.loads(dados.decode("utf-8-sig"))


def obter_http(url: str, cabecalhos: dict) -> bytes:
    req = urllib.request.Request(url, headers={**cabecalhos, "User-Agent": "vulnprio-fase-d/1.0"})
    with urllib.request.urlopen(req, timeout=180) as r:
        return r.read()


def obter_com_retentativa(obter: Obter, url: str, cabecalhos: dict, dormir=time.sleep) -> bytes:
    for t in range(1, TENTATIVAS + 1):
        try:
            dados = obter(url, cabecalhos)
            ler_json(dados)  # resposta truncada ou HTML de erro conta como falha
            return dados
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, ConnectionError,
                json.JSONDecodeError, UnicodeDecodeError) as e:
            codigo = getattr(e, "code", None)
            if codigo is not None and codigo not in (403, 408, 429) and codigo < 500:
                raise
            if t == TENTATIVAS:
                raise RuntimeError(f"falhou após {t} tentativas: {url}") from e
            espera = min(120, 6 * 2 ** (t - 1))
            print(f"  tentativa {t} falhou ({e}); nova tentativa em {espera}s", file=sys.stderr)
            dormir(espera)
    raise AssertionError("inalcançável")


def gravar_exclusivo(destino: Path, dados: bytes) -> None:
    """Grava sem nunca sobrescrever: temporário na mesma pasta + link exclusivo."""
    fd, tmp = tempfile.mkstemp(dir=destino.parent, prefix=".parcial_")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(dados)
            f.flush()
            os.fsync(f.fileno())
        os.link(tmp, destino)  # FileExistsError se já existir
    finally:
        os.unlink(tmp)


def _data_pub(s: str) -> dt.date:
    return dt.date.fromisoformat(s[:10])


def validar_janela(j: Janela, paginas: list[tuple[int, dict]]) -> dict:
    """Valida as páginas (start, json) de uma janela. Devolve resumo; levanta ErroIntegridade."""
    if not paginas:
        raise ErroIntegridade(f"{j.rotulo}: nenhuma página")
    totais = {p["totalResults"] for _, p in paginas}
    if len(totais) != 1:
        raise ErroIntegridade(f"{j.rotulo}: totalResults mudou durante a paginação: {sorted(totais)}")
    total = totais.pop()
    esperadas = list(range(0, max(total, 1), POR_PAGINA))
    starts = [s for s, _ in paginas]
    if starts != esperadas:
        raise ErroIntegridade(f"{j.rotulo}: páginas {starts} != esperadas {esperadas}")
    ids, fora = [], []
    for s, p in paginas:
        if p.get("startIndex") != s:
            raise ErroIntegridade(f"{j.rotulo}: startIndex {p.get('startIndex')} no arquivo de start {s}")
        esperado = min(POR_PAGINA, total - s) if total else 0
        n = len(p.get("vulnerabilities", []))
        if n != esperado:
            raise ErroIntegridade(f"{j.rotulo} start {s}: {n} registros, esperado {esperado}")
        for v in p["vulnerabilities"]:
            c = v["cve"]
            ids.append(c["id"])
            if not (j.inicio <= _data_pub(c["published"]) <= j.fim):
                fora.append(c["id"])
    if len(ids) != total:
        raise ErroIntegridade(f"{j.rotulo}: {len(ids)} registros != totalResults {total}")
    if len(set(ids)) != len(ids):
        raise ErroIntegridade(f"{j.rotulo}: {len(ids) - len(set(ids))} IDs repetidos")
    if fora:
        raise ErroIntegridade(f"{j.rotulo}: {len(fora)} registros com published fora da janela, ex. {fora[:3]}")
    return {"pubStartDate": j.pub_start, "pubEndDate": j.pub_end, "totalResults": total,
            "pages": len(paginas), "ids": ids}


def coletar_janela(j: Janela, pasta: Path, obter: Obter | None, cabecalhos: dict,
                   pausa: float, dormir=time.sleep) -> tuple[list[tuple[int, dict]], list[dict], int]:
    """Pagina uma janela. Com obter=None, só lê o que está no disco (modo verificação)."""
    paginas, arquivos, baixadas = [], [], 0
    start, total = 0, None
    while total is None or start < total:
        arq = pasta / nome_pagina(j, start)
        if arq.exists():
            dados = arq.read_bytes()
        elif obter is None:
            raise ErroIntegridade(f"página ausente: {arq.name}")
        else:
            if baixadas or pausa:
                dormir(pausa)
            dados = obter_com_retentativa(obter, url_pagina(j, start), cabecalhos, dormir)
            gravar_exclusivo(arq, dados)
            baixadas += 1
            print(f"  gravada {arq.name}")
        p = ler_json(dados)
        if total is None:
            total = p["totalResults"]
        elif p["totalResults"] != total:
            raise ErroIntegridade(
                f"{j.rotulo}: totalResults mudou de {total} para {p['totalResults']} na página {start}")
        paginas.append((start, p))
        arquivos.append({"arquivo": arq.name, "sha256": hashlib.sha256(dados).hexdigest(),
                         "bytes": len(dados), "registros": len(p.get("vulnerabilities", []))})
        start += POR_PAGINA
        if total == 0:
            break
    extras = sorted(x.name for x in pasta.glob(f"{j.rotulo}_start-*.json")
                    if x.name not in {a["arquivo"] for a in arquivos})
    if extras:
        raise ErroIntegridade(f"{j.rotulo}: páginas além de totalResults no disco: {extras}")
    return paginas, arquivos, baixadas


def coletar(inicio: dt.date, fim: dt.date, pasta: Path, obter: Obter | None = obter_http,
            chave: str | None = None, dormir=time.sleep, agora=None) -> dict:
    pasta.mkdir(parents=True, exist_ok=True)
    cab = {"apiKey": chave} if chave else {}
    pausa = 0.0 if obter is None else (PAUSA_COM_CHAVE if chave else PAUSA_SEM_CHAVE)
    resumo_janelas, todos_ids, arquivos, baixadas = [], [], [], 0
    for j in janelas(inicio, fim):
        print(f"janela {j.rotulo}")
        paginas, arqs, b = coletar_janela(j, pasta, obter, cab, pausa, dormir)
        r = validar_janela(j, paginas)
        todos_ids += r.pop("ids")
        resumo_janelas.append(r)
        arquivos += arqs
        baixadas += b
    if len(set(todos_ids)) != len(todos_ids):
        raise ErroIntegridade(f"{len(todos_ids) - len(set(todos_ids))} IDs repetidos entre janelas")
    momento = (agora or dt.datetime.now(dt.timezone.utc)).isoformat()
    manifesto = {
        "api": URL_API, "resultsPerPage": POR_PAGINA, "periodo": [inicio.isoformat(), fim.isoformat()],
        "totalResults": len(todos_ids), "ids_unicos": len(set(todos_ids)),
        "validacoes": "ok", "verificado_em_utc": momento, "paginas_baixadas_nesta_execucao": baixadas,
        "com_chave_api": bool(chave), "windows": resumo_janelas, "arquivos": arquivos,
    }
    gravar_manifesto(pasta, manifesto)
    return manifesto


def gravar_manifesto(pasta: Path, m: dict) -> Path:
    def essencial(x: dict) -> dict:
        return {k: x[k] for k in ("periodo", "totalResults", "windows", "arquivos")}
    corpo = json.dumps(m, indent=1, ensure_ascii=False).encode()
    alvo = pasta / "manifest.json"
    if alvo.exists():
        if essencial(ler_json(alvo.read_bytes())) == essencial(m):
            return alvo
        carimbo = m["verificado_em_utc"].replace(":", "").replace("-", "")[:15]
        alvo = pasta / f"manifest_{carimbo}.json"
    gravar_exclusivo(alvo, corpo)
    return alvo


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--inicio", type=dt.date.fromisoformat, required=True)
    ap.add_argument("--fim", type=dt.date.fromisoformat, required=True)
    ap.add_argument("--saida", type=Path, required=True)
    ap.add_argument("--verificar", action="store_true", help="não acessa a rede; só valida o que está no disco")
    a = ap.parse_args(argv)
    try:
        m = coletar(a.inicio, a.fim, a.saida, obter=None if a.verificar else obter_http,
                    chave=os.environ.get("NVD_API_KEY") or None)
    except ErroIntegridade as e:
        print(f"ERRO DE INTEGRIDADE: {e}", file=sys.stderr)
        return 2
    print(f"ok: {m['totalResults']} CVEs em {len(m['arquivos'])} páginas, {len(m['windows'])} janelas")
    return 0


if __name__ == "__main__":
    sys.exit(main())
