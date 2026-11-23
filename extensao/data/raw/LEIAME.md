# Dados brutos da extensão (`extensao/data/raw/`)

Esta pasta guarda os dados de entrada **brutos**. A maior parte é grande demais para o Git, então fica de fora.
O que você precisa saber depende do que quer fazer:

| Quero... | Preciso de dados brutos? |
|---|---|
| Ver os resultados e as tabelas | Não: estão em `extensao/results/` |
| Rodar os testes e **refazer os resultados das Fases B, C e D** | **Não.** Usam `extensao/data/derived/` e `kev/`, que estão no repositório |
| Refazer os dados derivados (`data/derived/`) a partir do zero | Sim: EPSS diário (abaixo) e o NVD |

## O que está no repositório

| Caminho | O que é |
|---|---|
| `kev/` | Catálogo KEV da CISA congelado em 2026-11-20, com SHA-256. Pequeno, versionado |
| `epss_daily/manifest.json` | Lista dos 441 arquivos diários do EPSS v3 (2024-01-01 a 2025-03-16), com SHA-256 e `model_version` de cada um |
| `epss_daily_v4/manifest.json` | Idem para o EPSS v4 (2025-03-17 a 2026-06-14) |
| `nvd-2025/manifest.json` | Manifesto da coleta do NVD de 2025 (23 páginas, 43.527 CVEs), com SHA-256 de cada página |

Os **arquivos de dados** em si não estão aqui:

* **NVD (2024 e 2025)**: estão compactados em `dados_compactados/` na raiz do repositório. Isso é importante porque
  a API do NVD muda com o tempo e uma nova coleta não reproduz os mesmos dados. Para descompactar e conferir:
  `python verificar.py --preparar-dados`.
* **EPSS diário (~1,5 GB)**: não está no repositório. É público e pode ser baixado de novo (abaixo). Os manifestos
  permitem conferir, por SHA-256, que o download é idêntico ao usado nos resultados.

## Baixar o EPSS diário (opcional, só para refazer `data/derived/`)

A partir de `extensao/` (precisa de internet; leva de dezenas de minutos a poucas horas):

```
python scripts/coleta_epss_diario.py --inicio 2024-01-01 --fim 2025-03-16
python scripts/coleta_epss_v4_local.py --inicio 2025-03-17 --fim 2026-06-14
```

Fonte: <https://github.com/empiricalsec/epss_scores>. Os scripts nunca sobrescrevem arquivos existentes.
Depois, para reconstruir os dados derivados: `PYTHONPATH=src python -m vulnprio.dados` (Fase B) e
`PYTHONPATH=src python -m vulnprio.dados_d data/raw/nvd-2025 T1 T2` (Fase D).

> No Windows, rode antes `$env:PYTHONUTF8 = "1"` (PowerShell). Sem isso, o Python grava os arquivos com a
> codificação do sistema e quebra no caractere "λ". O `python verificar.py` já faz isso sozinho.
