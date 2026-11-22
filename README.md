# Projeto de Auditoria — Priorização adaptativa de vulnerabilidades

Replicação, auditoria e extensão do artigo *Evaluating Vulnerability Prioritization Strategies Based on CVSS and
EPSS* (SBSeg 2026), desenvolvida como trabalho da disciplina na UFPE.

A pergunta central: quando a equipe só consegue corrigir **K vulnerabilidades por semana**, como equilibrar
**eficácia** (antecipar as CVEs que depois entram no catálogo CISA KEV), **estabilidade** do plano de trabalho e o
**orçamento** limitado? O trabalho avança em fases. Cada fase é auditada, pré-registrada antes de ver os
resultados, reprodutível e preserva as fases anteriores sem modificá-las. Não há aprendizado de máquina.

## Fases

| Fase | O que é | Onde |
|---|---|---|
| **A** | Auditoria da replicação original (coleta do NVD 2024, filtragem, histórico do EPSS, 13 estratégias por limiar) | `projeto/` |
| **B** | Experimento EST × DIN-1 na coorte 2024 (fila ordenada pelo EPSS fixo na entrada × reordenada toda semana) | `extensao/` |
| **C** | DIN-ESTAB: controle de estabilidade do plano semanal (bônus λ às CVEs já planejadas) | `extensao/` |
| **D** | Validação temporal numa coorte independente de 2025 (EPSS v4). **Em andamento**: protocolo congelado, simulações ainda não confirmatórias | `extensao/` |

Resultados principais das Fases B e C (K = 50, coorte 2024), conforme os arquivos de resultados:

- A DIN-1 antecipou 27 KEV contra 15 da EST (+14 p.p. de recall); a vantagem some com K = 500.
- A DIN-ESTAB com λ = ∞ (plano travado) antecipa 25 KEV com zero revisões do plano (ΣR = 0).
- Os resultados são preliminares: uma coorte, poucos eventos e um único catálogo KEV.

Em caso de divergência entre este texto e um arquivo de resultados ou protocolo congelado, **vale o arquivo**.

## Estrutura do repositório

```
projeto/                 Fase A (somente leitura): scripts PowerShell/Python e dados pequenos
extensao/
  src/vulnprio/          código das políticas, simulador, métricas e experimentos
  tests/                 testes de integridade e regressão
  scripts/               coleta de EPSS diário, KEV e NVD
  freeze/                protocolos congelados e manifestos SHA-256 (não alterar)
  results/               resultados das Fases B, C e D
  auditoria_final/       pacote de auditoria da Fase D (T1 e T2)
  data/derived/          coortes e matrizes de EPSS geradas
  data/raw/kev/          catálogo KEV congelado (2026.11.20)
  docs/                  registros de desvios do protocolo
  CONTINUIDADE.md        histórico completo, decisões e próximos passos
  README*.md             detalhes de cada fase
```

**Por onde começar:** leia `extensao/CONTINUIDADE.md` (visão geral e estado atual) e depois
`extensao/README_FASE_D.md` e `extensao/freeze/protocolo_fase_d.md`.

## Dados brutos (não versionados)

Para caber no GitHub, os dados brutos grandes ficam **fora do repositório** (ver `.gitignore`):

- `extensao/data/raw/epss_daily*/` — EPSS diário (~1,5 GB)
- `extensao/data/raw/nvd-2025/` — páginas da API 2.0 do NVD (~180 MB)
- `projeto/data/nvd-2024-raw/` e os dois `projeto/data/nvd-2024-filtered*.jsonl` (~600 MB)

Eles podem ser recriados com os scripts de coleta (a partir de `extensao/`):

```powershell
python scripts/coleta_epss_diario.py --inicio 2024-01-01 --fim 2025-03-16
python scripts/coleta_kev.py
python scripts/coleta_nvd.py --inicio 2025-01-01 --fim 2025-11-19 --saida data/raw/nvd-2025
```

A Fase A usa `projeto/fetch_nvd_2024.ps1` para o NVD 2024. **Atenção:** a API do NVD muda com o tempo, então uma nova
coleta pode não reproduzir os snapshots originais byte a byte. Os manifestos em `extensao/freeze/` registram o
SHA-256 do que foi usado; guarde um backup dos dados originais.

## Como reproduzir

Requer Python 3.13 (versões fixadas em `extensao/requirements.txt`: numpy, pandas, scipy, matplotlib, pytest).
A partir de `extensao/`, com a Fase A em `../projeto` (ou indicada em `FASE_A_DIR`):

```bash
pip install -r requirements.txt
# conferir que nada congelado mudou
sha256sum -c freeze/protocolo_fase_b_congelado.sha256 freeze/protocolo_fase_c_preregistro.sha256 freeze/protocolo_fase_d.sha256
# testes (esperado com todos os dados: 48 passed, 2 skipped)
PYTHONPATH=src python -m pytest -q -rs tests
# Fases B e C
bash rodar_tudo.sh
bash rodar_fase_c.sh
```

Os testes e a reprodução completa dependem dos dados brutos acima; sem eles, parte da suíte não roda.

## Regras do projeto

- Não modificar a Fase A nem nenhum arquivo listado nos manifestos de `freeze/`.
- Gravar resultados novos em pastas novas e registrar todo desvio do protocolo, com data e motivo, em `docs/`.
- Não alterar hipóteses, limiares ou parâmetros depois de ver dados da coorte confirmatória (T2).
- As políticas só leem dados por `estado.py`, usando apenas informação disponível até o dia anterior à decisão.
- Não introduzir aprendizado de máquina sem decisão explícita da pesquisadora.
- Os arquivos usam `-text` no `.gitattributes`: não converter quebras de linha, pois os hashes SHA-256 dependem dos bytes exatos.
