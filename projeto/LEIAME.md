# Fase A: replicação do artigo (somente leitura)

Esta pasta é a replicação do artigo *Evaluating Vulnerability Prioritization Strategies Based on CVSS and EPSS*
(SBSeg 2026) com dados públicos. **Não deve ser modificada**: a extensão (`../extensao/`) depende dela e cada
arquivo tem o SHA-256 registrado em `../extensao/freeze/fase_a_manifest.json`.

## O que cada script faz (ordem do pipeline)

| Etapa | Script | Faz |
|---|---|---|
| 1. Coletar | `fetch_nvd_2024.ps1` | Baixa da API do NVD as 40.704 CVEs publicadas em 2024 (PowerShell) |
| 2. Filtrar | `filter_nvd_2024.ps1` | Aplica os filtros do artigo e a nota CVSS (PowerShell) |
| 3. EPSS | `apply_epss_history_2024.py` / `.ps1` | Associa a primeira nota EPSS após a publicação |
| 4. Variante | `build_variant_corpus.py` | Gera o corpus da variante (exclui as CVEs `Deferred`; nota CVSS da CNA) |
| 5. Analisar | `analyze_nvd_strategies.py` | Calcula as 13 estratégias (VP, FP, FN, precisão, recall, F1, F2) |
| 6. Comparar | `compare_versions.py` | Compara a primeira tentativa, a variante e o artigo |

## Resultados já gerados (`data/`)

* `nvd-2024-replication-report.md` e `nvd-2024-replication-report-variant.md`: relatórios da replicação.
* `nvd-2024-strategy-metrics*.csv|json`: métricas das 13 estratégias.
* `nvd-2024-comparison.md`: comparação com o artigo.
* `epss/`: snapshot do EPSS usado no filtro.

## Rodar de novo

Os dados de entrada estão em `../dados_compactados/`. Da raiz do repositório:

```
python verificar.py --preparar-dados
cd projeto
python build_variant_corpus.py
python analyze_nvd_strategies.py
python compare_versions.py
```

As etapas 1 a 3 (coleta e EPSS) dependem de internet e da API do NVD, e **não reproduzem exatamente os
mesmos números** com o passar do tempo. Por isso os dados originais estão preservados (compactados) e conferidos
por SHA-256.
