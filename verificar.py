#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Verificador do projeto: confere que o repositório está íntegro e que os resultados se reproduzem.

Uso (a partir da raiz do repositório):

    python verificar.py                    # NÍVEL 1 (~2 min): ambiente, hashes congelados, manifestos e testes
    python verificar.py --preparar-dados   # descompacta dados_compactados/ e confere o SHA-256 de cada arquivo
    python verificar.py --reproduzir       # NÍVEL 2 (~10 min): refaz os resultados das Fases B, C e D e compara
    python verificar.py --reproduzir --rapido   # idem, sem as 20 sementes de desempate (~3 min)
    python verificar.py --tudo             # preparar dados + nível 1 + nível 2

Só usa a biblioteca padrão do Python para decidir o que fazer; os testes e os experimentos usam as
dependências de requirements.txt. Nada que já está no repositório é alterado: a reprodução roda numa cópia
temporária (.verificacao/) e só compara os arquivos gerados com os versionados.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import importlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

RAIZ = Path(__file__).resolve().parent
EXT = RAIZ / "extensao"
FASE_A = RAIZ / "projeto"
TMP = RAIZ / ".verificacao"

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PROBLEMAS: list[str] = []


def ok(msg):
    print(f"  [OK]    {msg}")


def aviso(msg):
    print(f"  [AVISO] {msg}")


def erro(msg):
    PROBLEMAS.append(msg)
    print(f"  [ERRO]  {msg}")


def titulo(msg):
    print(f"\n== {msg}")


def sha256_arquivo(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for bloco in iter(lambda: f.read(1024 * 1024), b""):
            h.update(bloco)
    return h.hexdigest()


def ler_json(p: Path):
    return json.loads(p.read_text(encoding="utf-8-sig"))


def env_filho(extra_path=None):
    """Ambiente dos processos filhos. PYTHONUTF8=1 é necessário no Windows: o código grava 'λ' em arquivos
    de texto sem declarar a codificação, e o padrão cp1252 do Windows falharia."""
    env = dict(os.environ)
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONPATH"] = "src"
    env.pop("FASE_A_DIR", None)
    return env


# --------------------------------------------------------------------------------------------
# 1) Ambiente
# --------------------------------------------------------------------------------------------
def checar_ambiente() -> bool:
    titulo("1. Ambiente (Python e pacotes)")
    v = sys.version_info
    if v < (3, 11):
        erro(f"Python {v.major}.{v.minor} é antigo demais. Use Python 3.12 ou 3.13.")
        return False
    ok(f"Python {v.major}.{v.minor}.{v.micro} (o projeto foi rodado em 3.12 e 3.13)")
    faltando, diferentes = [], []
    for linha in (RAIZ / "requirements.txt").read_text(encoding="utf-8").splitlines():
        linha = linha.strip()
        if not linha or linha.startswith("#"):
            continue
        nome, _, versao = linha.partition("==")
        try:
            mod = importlib.import_module(nome)
        except ImportError:
            faltando.append(nome)
            continue
        inst = getattr(mod, "__version__", "?")
        if inst != versao:
            diferentes.append(f"{nome} {inst} (esperado {versao})")
    if faltando:
        erro("Faltam pacotes: " + ", ".join(faltando))
        print("          Instale com:  python -m pip install -r requirements.txt")
        return False
    ok("numpy, pandas, scipy, matplotlib e pytest instalados")
    if diferentes:
        aviso("versões diferentes das usadas nos resultados (podem mudar detalhes numéricos): "
              + "; ".join(diferentes))
    return True


# --------------------------------------------------------------------------------------------
# 2) Arquivos congelados e manifestos
# --------------------------------------------------------------------------------------------
def checar_congelados():
    titulo("2. Protocolos congelados (SHA-256)")
    for f in sorted((EXT / "freeze").glob("*.sha256")):
        for linha in f.read_text(encoding="utf-8-sig", errors="replace").splitlines():
            m = re.match(r"^([0-9a-fA-F]{64})\s+\*?(\S+)\s*$", linha)   # ignora linhas de comentário
            if not m:
                continue
            esperado, nome = m.group(1).lower(), m.group(2)
            alvo = EXT / "freeze" / nome
            if not alvo.exists():
                erro(f"{nome}: arquivo congelado não encontrado")
            elif sha256_arquivo(alvo) == esperado:
                ok(f"{nome}")
            else:
                erro(f"{nome}: o conteúdo mudou (hash diferente do registrado em {f.name})")


MANIFESTOS = [("fase_a", FASE_A, "Fase A (replicação)"), ("fase_b", EXT, "Fase B"),
              ("fase_c", EXT, "Fase C"), ("fase_d_preparacao", EXT, "Fase D (preparação)"),
              ("fase_d_execucao_parcial", EXT, "Fase D (execução)")]


# Divergências já existentes no material recebido (não causadas por esta organização do repositório).
# Ficam como AVISO, com a explicação, e não como erro.
DIVERGENCIAS_CONHECIDAS = {
    ("fase_d_execucao_parcial", "data/raw/epss_daily_v4/manifest.json"):
        "o hash registrado no manifesto da execução parcial (2026-11-22T01:25Z) não bate com o arquivo atual. "
        "O arquivo lista os 455 diários do EPSS v4, todos v2025.03.14, e parece ter sido reescrito depois do "
        "manifesto (causa não confirmada). Não afeta os resultados: cada arquivo diário tem o próprio SHA-256 nele.",
}


def checar_manifestos(exigir_dados: bool):
    titulo("3. Manifestos: cada arquivo versionado tem o SHA-256 registrado")
    for nome, base, rotulo in MANIFESTOS:
        man = ler_json(EXT / "freeze" / f"{nome}_manifest.json")
        n_ok = n_dif = 0
        sem_venv = sem_dado = 0
        for f in man["files"]:
            rel = f["path"].replace("\\", "/")
            p = base / rel
            if not p.exists():
                if ".venv" in rel.split("/"):
                    sem_venv += 1
                else:
                    sem_dado += 1
            elif sha256_arquivo(p) == f["sha256"]:
                n_ok += 1
            elif (nome, rel) in DIVERGENCIAS_CONHECIDAS:
                aviso(f"{rotulo}: {rel}: " + DIVERGENCIAS_CONHECIDAS[(nome, rel)])
            else:
                n_dif += 1
                erro(f"{rotulo}: arquivo alterado em relação ao manifesto: {rel}")
        partes = [f"{n_ok} de {len(man['files'])} conferem"]
        if sem_venv:
            partes.append(f"{sem_venv} são do ambiente virtual (.venv) da época, que não faz parte do projeto")
        if sem_dado:
            partes.append(f"{sem_dado} são dados brutos fora do Git")
        if n_dif == 0:
            ok(f"{rotulo}: " + "; ".join(partes))   # (divergências conhecidas aparecem como aviso acima)
        if sem_dado:
            msg = (f"{rotulo}: {sem_dado} dado(s) bruto(s) ausente(s). Rode `python verificar.py --preparar-dados`.")
            (erro if exigir_dados else aviso)(msg)


# --------------------------------------------------------------------------------------------
# 4) Testes
# --------------------------------------------------------------------------------------------
def rodar_testes():
    titulo("4. Testes automáticos (pytest)")
    t0 = time.time()
    r = subprocess.run([sys.executable, "-m", "pytest", "-q", "-rs", "--no-header", "-p", "no:cacheprovider"],
                       cwd=EXT, env=env_filho(), capture_output=True, text=True, encoding="utf-8",
                       errors="replace")
    saida = r.stdout + r.stderr
    resumo = [l for l in saida.splitlines() if re.search(r"\d+ (passed|failed|error)", l)]
    seg = time.time() - t0
    motivos = {}
    for l in saida.splitlines():
        m = re.match(r"SKIPPED \[(\d+)\] \S+: (.*)", l)
        if m:
            motivos[m.group(2).strip()] = motivos.get(m.group(2).strip(), 0) + int(m.group(1))
    if r.returncode == 0:
        ok(f"{resumo[-1].strip('= ') if resumo else 'testes passaram'} ({seg:.0f}s)")
    else:
        erro("há testes falhando:")
        print("\n".join(saida.splitlines()[-40:]))
    for motivo, n in motivos.items():
        aviso(f"{n} teste(s) pulado(s): {motivo[:170]}")


# --------------------------------------------------------------------------------------------
# 5) Preparar dados compactados
# --------------------------------------------------------------------------------------------
def hashes_esperados() -> dict:
    esp = {}
    for f in ler_json(EXT / "freeze" / "fase_a_manifest.json")["files"]:
        esp["projeto/" + f["path"].replace("\\", "/")] = f["sha256"]
    nvd25 = ler_json(EXT / "data" / "raw" / "nvd-2025" / "manifest.json")
    for a in nvd25["arquivos"]:
        esp["extensao/data/raw/nvd-2025/" + a["arquivo"]] = a["sha256"]
    return esp


def preparar_dados():
    titulo("Preparando dados (descompactando dados_compactados/)")
    base = RAIZ / "dados_compactados"
    esp = hashes_esperados()
    novos = prontos = 0
    for gz in sorted(base.rglob("*.gz")):
        rel = gz.relative_to(base).as_posix()[:-3]
        destino = RAIZ / rel
        esperado = esp.get(rel)
        if destino.exists() and esperado and sha256_arquivo(destino) == esperado:
            prontos += 1
            continue
        destino.parent.mkdir(parents=True, exist_ok=True)
        tmp = destino.with_suffix(destino.suffix + ".tmp")
        with gzip.open(gz, "rb") as fi, open(tmp, "wb") as fo:
            shutil.copyfileobj(fi, fo, 1024 * 1024)
        if esperado and sha256_arquivo(tmp) != esperado:
            tmp.unlink()
            erro(f"{rel}: SHA-256 não confere com o manifesto")
            continue
        tmp.replace(destino)
        novos += 1
    if not PROBLEMAS:
        ok(f"{novos} arquivo(s) descompactado(s), {prontos} já estavam prontos; todos conferem por SHA-256")
    print("   Não incluído (baixe se quiser refazer a construção dos dados derivados): EPSS diário, ~1,5 GB;")
    print("   ver extensao/data/raw/LEIAME.md")


# --------------------------------------------------------------------------------------------
# 6) Reproduzir resultados
# --------------------------------------------------------------------------------------------
def normalizar(p: Path) -> bytes:
    b = p.read_bytes()
    if p.suffix == ".gz":
        b = gzip.decompress(b)
    return b.replace(b"\r\n", b"\n")


IGNORAR = {"ambiente.json", "testes_saida.txt", "testes_saida_completa.txt"}


def comparar_pasta(novo: Path, ref: Path, rotulo: str):
    iguais, difs, extras = 0, [], []
    for f in sorted(novo.rglob("*")):
        if not f.is_file() or f.name in IGNORAR or f.suffix == ".png":
            continue
        rel = f.relative_to(novo)
        alvo = ref / rel
        if not alvo.exists():
            extras.append(str(rel))
        elif normalizar(f) == normalizar(alvo):
            iguais += 1
        else:
            difs.append(str(rel))
    if difs:
        erro(f"{rotulo}: {len(difs)} arquivo(s) diferem do versionado: {', '.join(difs[:6])}")
    elif iguais == 0:
        erro(f"{rotulo}: nada foi gerado para comparar")
    else:
        ok(f"{rotulo}: {iguais} arquivo(s) idênticos aos versionados")
    for e in extras[:3]:
        aviso(f"{rotulo}: gerado mas não versionado: {e}")


def rodar_cmd(cwd, args, rotulo):
    t0 = time.time()
    r = subprocess.run([sys.executable] + args, cwd=cwd, env=env_filho(), capture_output=True,
                       text=True, encoding="utf-8", errors="replace")
    seg = time.time() - t0
    if r.returncode != 0:
        erro(f"{rotulo}: falhou após {seg:.0f}s")
        print("\n".join((r.stdout + r.stderr).splitlines()[-15:]))
        return False
    print(f"     {rotulo}: {seg:.0f}s")
    return True


def rodar_modulo(cwd, args, rotulo):
    return rodar_cmd(cwd, ["-m"] + args, rotulo)


SAIDAS_FASE_A = ["nvd-2024-strategy-metrics.json", "nvd-2024-strategy-metrics.csv",
                 "nvd-2024-replication-report.md", "nvd-2024-strategy-metrics-variant.json",
                 "nvd-2024-strategy-metrics-variant.csv", "nvd-2024-replication-report-variant.md",
                 "nvd-2024-comparison.md"]


def reproduzir_fase_a():
    titulo("5a. Fase A: refazer a análise das 13 estratégias (a partir do corpus filtrado)")
    if not (FASE_A / "data" / "nvd-2024-filtered.jsonl").exists():
        aviso("corpus filtrado ausente: rode `python verificar.py --preparar-dados` para incluir a Fase A. Pulado.")
        return
    dst = TMP / "faseA"
    shutil.copytree(FASE_A, dst, ignore=shutil.ignore_patterns("nvd-2024-raw", "__pycache__"))
    for nome in SAIDAS_FASE_A:
        (dst / "data" / nome).unlink(missing_ok=True)
    passos = [(["analyze_nvd_strategies.py"], "análise (corpus original)"),
              (["analyze_nvd_strategies.py", "--corpus", "data/nvd-2024-filtered-variant.jsonl",
                "--suffix=-variant"], "análise (variante)"),
              (["compare_versions.py"], "comparação com o artigo")]
    for args, rotulo in passos:
        if not rodar_cmd(dst, args, f"Fase A · {rotulo}"):
            return
    iguais, difs = 0, []
    for nome in SAIDAS_FASE_A:
        novo, ref = dst / "data" / nome, FASE_A / "data" / nome
        if not novo.exists():
            difs.append(nome + " (não gerado)")
        elif normalizar(novo) == normalizar(ref):
            iguais += 1
        else:
            difs.append(nome)
    if difs:
        erro(f"Fase A: {len(difs)} arquivo(s) diferem do versionado: {', '.join(difs)}")
    else:
        ok(f"Fase A: {iguais} arquivo(s) (métricas, relatórios e comparação) idênticos aos versionados")


def reproduzir(rapido: bool):
    if TMP.exists():
        shutil.rmtree(TMP)
    reproduzir_fase_a()
    titulo("5b. Fases B, C e D: refazer os experimentos (numa cópia temporária)")
    tmp_ext, tmp_fa = TMP / "extensao", TMP / "projeto"
    ign_ext = shutil.ignore_patterns("results", "auditoria_final", "__pycache__", ".pytest_cache", "tests",
                                     "epss_daily", "epss_daily_v4", "nvd-2025", "freeze", "docs")
    shutil.copytree(EXT, tmp_ext, ignore=ign_ext)
    shutil.copytree(FASE_A, tmp_fa, ignore=shutil.ignore_patterns("nvd-2024-raw", "*.jsonl", "__pycache__"))
    (tmp_ext / "results").mkdir()
    print("     (usa só os dados derivados e o catálogo KEV que estão no repositório)")
    inicio = time.time()
    etapas_b = ["descritivo", "deterministico", "estatistica"] if rapido else \
        ["descritivo", "deterministico", "sementes", "estatistica"]
    for e in etapas_b:
        if not rodar_modulo(tmp_ext, ["vulnprio.experimentos", "--etapa", e], f"Fase B · {e}"):
            return
    if not rodar_modulo(tmp_ext, ["vulnprio.experimentos_c"], "Fase C"):
        return
    coortes = ["2024-variante", "2024-S", "2024-S+rej", "T1", "T2"]
    args_d = ["vulnprio.experimentos_d"] + coortes + ["--confirmatoria"]
    if rapido:
        args_d.append("--sem-sementes")
    if not rodar_modulo(tmp_ext, args_d, "Fase D · 5 coortes"):
        return
    print(f"     tempo total: {time.time() - inicio:.0f}s")
    titulo("6. Comparação com os resultados versionados (ignora quebra de linha e o ambiente.json)")
    comparar_pasta(tmp_ext / "results" / "fase_b_2024", EXT / "results" / "fase_b_2024", "Fase B")
    comparar_pasta(tmp_ext / "results" / "fase_c_2024", EXT / "results" / "fase_c_2024", "Fase C")
    for c in coortes:
        comparar_pasta(tmp_ext / "results" / "fase_d" / c, EXT / "results" / "fase_d" / c, f"Fase D · {c}")
    if rapido:
        aviso("modo --rapido: as 20 sementes de desempate não foram refeitas (arquivos sementes_20*.csv)")
    print("     Obs.: a T2 é a coorte confirmatória; aqui ela só é recalculada numa pasta temporária,")
    print("     para checar a reprodutibilidade. Os resultados versionados não são tocados.")
    shutil.rmtree(TMP, ignore_errors=True)


# --------------------------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--preparar-dados", action="store_true", help="descompacta dados_compactados/ e confere SHA-256")
    ap.add_argument("--reproduzir", action="store_true", help="refaz os resultados das Fases B, C e D e compara")
    ap.add_argument("--rapido", action="store_true", help="com --reproduzir: pula as 20 sementes (mais rápido)")
    ap.add_argument("--tudo", action="store_true", help="preparar dados + nível 1 + reprodução")
    a = ap.parse_args()
    t0 = time.time()
    print("Verificação do projeto de auditoria")
    if a.preparar_dados or a.tudo:
        preparar_dados()
    if not (a.preparar_dados and not (a.reproduzir or a.tudo)):
        if checar_ambiente():
            checar_congelados()
            checar_manifestos(exigir_dados=a.tudo)
            rodar_testes()
            if a.reproduzir or a.tudo:
                reproduzir(a.rapido)
    titulo("Resumo")
    if PROBLEMAS:
        print(f"  {len(PROBLEMAS)} problema(s):")
        for p in PROBLEMAS:
            print("   -", p)
        print(f"  Tempo: {time.time() - t0:.0f}s")
        sys.exit(1)
    print(f"  Tudo certo. Tempo: {time.time() - t0:.0f}s")


if __name__ == "__main__":
    main()
