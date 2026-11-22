"""Baixa o arquivo diÃ¡rio do EPSS (empiricalsec/epss_scores) para um intervalo de datas.

Regras do protocolo congelado (seÃ§Ã£o 11):
- dados brutos sÃ£o gravados uma Ãºnica vez: arquivos existentes nunca sÃ£o sobrescritos;
- cada arquivo tem SHA-256 e `model_version` registrados em um manifesto.

Uso:
    python scripts/coleta_epss_diario.py --inicio 2024-01-01 --fim 2025-03-16
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import gzip
import hashlib
import json
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import date, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RAW_DIR = ROOT / "data" / "raw" / "epss_daily_v4"
MANIFEST = RAW_DIR / "manifest.json"
URL = "https://raw.githubusercontent.com/empiricalsec/epss_scores/main/{y}/epss_scores-{d}.csv.gz"


def baixar(dia: date) -> dict:
    destino = RAW_DIR / f"epss_scores-{dia.isoformat()}.csv.gz"
    if destino.exists():
        status = "existente"
    else:
        url = URL.format(y=dia.year, d=dia.isoformat())
        tmp = destino.with_suffix(".part")
        for tentativa in range(4):
            try:
                with urllib.request.urlopen(url, timeout=120) as resp, open(tmp, "wb") as out:
                    while bloco := resp.read(1 << 20):
                        out.write(bloco)
                break
            except urllib.error.HTTPError as erro:
                tmp.unlink(missing_ok=True)
                if erro.code == 404:
                    return {"date": dia.isoformat(), "status": "ausente_no_arquivo"}
                time.sleep(3 * (tentativa + 1))
            except OSError:
                tmp.unlink(missing_ok=True)
                time.sleep(3 * (tentativa + 1))
        else:
            return {"date": dia.isoformat(), "status": "falha"}
        if destino.exists():  # outra execuÃ§Ã£o gravou antes: nÃ£o sobrescrever
            tmp.unlink(missing_ok=True)
        else:
            tmp.rename(destino)
        status = "baixado"
    with gzip.open(destino, "rt", encoding="utf-8") as f:
        meta = f.readline().strip()
    versao = re.search(r"model_version:([^,]+)", meta)
    score_date = re.search(r"score_date:(\d{4}-\d{2}-\d{2})", meta)
    if not score_date or score_date.group(1) != dia.isoformat():
        raise ValueError(f"score_date do arquivo {destino.name} nÃ£o confere: {meta}")
    return {
        "date": dia.isoformat(),
        "status": status,
        "file": destino.name,
        "sha256": hashlib.sha256(destino.read_bytes()).hexdigest(),
        "model_version": versao.group(1) if versao else None,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--inicio", default="2024-01-01")
    ap.add_argument("--fim", default="2025-03-16")
    ap.add_argument("--workers", type=int, default=8)
    a = ap.parse_args()
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    ini, fim = date.fromisoformat(a.inicio), date.fromisoformat(a.fim)
    dias = [ini + timedelta(days=i) for i in range((fim - ini).days + 1)]
    with cf.ThreadPoolExecutor(a.workers) as ex:
        regs = sorted(ex.map(baixar, dias), key=lambda r: r["date"])
    antigo = json.loads(MANIFEST.read_text()) if MANIFEST.exists() else {"files": []}
    por_data = {r["date"]: r for r in antigo["files"]}
    for r in regs:
        anterior = por_data.get(r["date"])
        if anterior and anterior.get("sha256") and r.get("sha256") and anterior["sha256"] != r["sha256"]:
            raise RuntimeError(f"Arquivo bruto de {r['date']} mudou desde o manifesto anterior.")
        por_data[r["date"]] = r
    MANIFEST.write_text(json.dumps({"source": URL, "files": [por_data[k] for k in sorted(por_data)]}, indent=1))
    faltas = [r for r in regs if r["status"] in ("ausente_no_arquivo", "falha")]
    print(f"{len(regs)} dias; {len(faltas)} sem arquivo: {[r['date'] for r in faltas]}")
    return 1 if any(r["status"] == "falha" for r in regs) else 0


if __name__ == "__main__":
    sys.exit(main())

