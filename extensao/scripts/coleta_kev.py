"""Grava o catálogo KEV congelado (data F do protocolo) com hash.

O protocolo fixa F = 2026-11-20 (catalogVersion 2026.11.20). O script baixa o catálogo de
cisagov/kev-data e só aceita a versão esperada; se o catálogo publicado já for mais novo,
use --arquivo para apontar uma cópia da versão congelada (por exemplo, obtida do histórico git
do repositório: `git show <commit>:known_exploited_vulnerabilities.json`).

Uso:
    python scripts/coleta_kev.py [--arquivo caminho/known_exploited_vulnerabilities.json]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DESTINO = ROOT / "data" / "raw" / "kev" / "known_exploited_vulnerabilities_2026.11.20.json"
URL = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
VERSAO_ESPERADA = "2026.11.20"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--arquivo", type=Path)
    a = ap.parse_args()
    if DESTINO.exists():
        print(f"Já existe (não sobrescrito): {DESTINO}")
    else:
        dados = a.arquivo.read_bytes() if a.arquivo else urllib.request.urlopen(URL, timeout=120).read()
        versao = json.loads(dados)["catalogVersion"]
        if versao != VERSAO_ESPERADA:
            print(f"Versão {versao} != {VERSAO_ESPERADA}; obtenha a versão congelada e use --arquivo.")
            return 1
        DESTINO.parent.mkdir(parents=True, exist_ok=True)
        DESTINO.write_bytes(dados)
    h = hashlib.sha256(DESTINO.read_bytes()).hexdigest()
    DESTINO.with_suffix(".sha256").write_text(f"{h}  {DESTINO.name}\n")
    cat = json.loads(DESTINO.read_text())
    print(cat["catalogVersion"], cat["count"], h)
    return 0


if __name__ == "__main__":
    sys.exit(main())
