# Fase B — Experimento mínimo EST × DIN-1 (coorte 2024)

Extensão da replicação de *Evaluating Vulnerability Prioritization Strategies Based on CVSS and EPSS*
(SBSeg 2026). O experimento compara, com o mesmo orçamento semanal K, duas políticas de fila. A **EST**
ordena pelo percentil do EPSS lido na entrada da CVE na fila e nunca reordena. A **DIN-1** reordena toda
semana pelo percentil mais recente. Protocolo congelado: `freeze/protocolo_fase_b_congelado.md`.

## Estrutura

```
projeto/            Fase A (somente leitura; verificada por hash a cada execução dos testes)
extensao/
  freeze/           manifesto SHA-256 da Fase A e protocolo congelado
  scripts/          coleta do EPSS diário e do KEV (nunca sobrescrevem dados brutos)
  src/vulnprio/     config, dados, estado (única porta de informação), rotulos, politicas,
                    simulador, metricas, estrategias_artigo, experimentos, graficos
  tests/            testes de integridade e regressão (protocolo, seções 9 e 13.8)
  data/raw/         EPSS diário 2024-01-01..2025-03-16 (~660 MB, não incluído no pacote) e KEV
  data/derived/     coorte e matrizes semanais do EPSS
  results/fase_b_2024/  resultados, figuras e saída dos testes
  docs/             registro de desvios
```

## Como reproduzir

Requer Python 3.13 e `pip install -r requirements.txt`. A partir de `extensao/`, com a Fase A em `../projeto`:

```
bash rodar_tudo.sh
```

Etapas individuais (com `PYTHONPATH=src`): `python -m vulnprio.dados`, `python -m pytest -v tests`,
`python -m vulnprio.experimentos --etapa {descritivo|deterministico|sementes|estatistica}`,
`python -m vulnprio.graficos`. A execução completa leva cerca de 3 minutos, mais o download do EPSS.

## Arquivos de resultado (`results/fase_b_2024/`)

| Arquivo | Conteúdo |
|---|---|
| `descritivo.json`, `chegadas_por_semana.csv`, `perfil_A_T_vs_A_pos.csv` | Números descritivos (antes de qualquer comparação) |
| `resumo_por_politica_K.csv` | Métricas por política e K (desempate determinístico) |
| `comparacao_EST_DIN_por_K.csv` | ΔN, ΔR, capturas exclusivas, folgas, Γ |
| `h3_atraso_omega.csv` | H3 por atraso, por ω e pelo cruzamento dos dois |
| `eventos_A_por_K.csv` | Resultado de cada um dos 86 KEV antecipáveis, por K |
| `log_semanal.csv.gz` | Fila elegível, chegadas, seleções, U, α e Kendall por semana |
| `sementes_20.csv`, `sementes_20_resumo.csv` | 20 sementes de desempate |
| `estatistica_mcnemar_bootstrap.csv` | McNemar exato e bootstrap por eventos (B = 10.000) |
| `figuras/` | F1 a F4 |
| `testes_saida.txt`, `ambiente.json` | Saída dos testes, versões e configuração |

Os resultados são **preliminares**: uma coorte, uma versão do EPSS, sem as análises de sensibilidade e
sem bootstrap por blocos. Ver `docs/REGISTRO_DE_DESVIOS.md`.
