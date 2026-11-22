# Replicação CVSS × EPSS — artigo vs. dados atuais

## Estratégias e métricas

O total priorizado corresponde a TP + FP. CVSS usa `>=` (exceto CVSS 10.0, que usa `==`); EPSS usa `>` e os limites das estratégias combinadas são 0,50% (`0.005`). KEV é definido por `cisaExploitAdd` não nulo.

| Estratégia | Condição | Artigo TP / total / F2 | Replicação TP / FP / FN / total | P | R | F1 | F2 | Δ F2 (p.p.) |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| CVSS 5.0 | `cvss >= 5` | 155 / 27,715 / 2.73% | 159 / 35,618 / 1 / 35,777 | 0.44% | 99.38% | 0.88% | 2.18% | -0.55 |
| CVSS 7.0 | `cvss >= 7` | 130 / 13,532 / 4.59% | 141 / 18,260 / 19 / 18,401 | 0.77% | 88.12% | 1.52% | 3.70% | -0.89 |
| CVSS 9.0 | `cvss >= 9` | 64 / 2,714 / 9.59% | 70 / 4,229 / 90 / 4,299 | 1.63% | 43.75% | 3.14% | 7.09% | -2.50 |
| CVSS 10.0 | `cvss == 10` | 7 / 132 / 4.63% | 3 / 144 / 157 / 147 | 2.04% | 1.88% | 1.95% | 1.91% | -2.72 |
| EPSS 0.05% | `epss > 0.0005` | 62 / 3,740 / 7.10% | 60 / 3,798 / 100 / 3,858 | 1.56% | 37.50% | 2.99% | 6.67% | -0.43 |
| EPSS 0.10% | `epss > 0.001` | 41 / 309 / 21.97% | 41 / 288 / 119 / 329 | 12.46% | 25.62% | 16.77% | 21.16% | -0.81 |
| EPSS 0.50% | `epss > 0.005` | 28 / 44 / 20.96% | 28 / 20 / 132 / 48 | 58.33% | 17.50% | 26.92% | 20.35% | -0.61 |
| EPSS 1.00% | `epss > 0.01` | 21 / 26 / 16.15% | 21 / 9 / 139 / 30 | 70.00% | 13.12% | 22.11% | 15.67% | -0.48 |
| EPSS 5.00% | `epss > 0.05` | 4 / 5 / 3.18% | 4 / 3 / 156 / 7 | 57.14% | 2.50% | 4.79% | 3.09% | -0.09 |
| CVSS 7.0 AND EPSS 0.50% | `cvss >= 7 and epss > 0.005` | 21 / 36 / 15.91% | 23 / 19 / 137 / 42 | 54.76% | 14.37% | 22.77% | 16.86% | +0.95 |
| CVSS 9.0 AND EPSS 0.50% | `cvss >= 9 and epss > 0.005` | 8 / 19 / 6.22% | 8 / 16 / 152 / 24 | 33.33% | 5.00% | 8.70% | 6.02% | -0.20 |
| CVSS 9.0 OR EPSS 0.50% | `cvss >= 9 or epss > 0.005` | 84 / 2,739 / 12.49% | 90 / 4,233 / 70 / 4,323 | 2.08% | 56.25% | 4.02% | 9.07% | -3.42 |
| CVSS 10.0 OR EPSS 0.50% | `cvss == 10 or epss > 0.005` | 35 / 175 / 21.90% | 31 / 164 / 129 / 195 | 15.90% | 19.38% | 17.46% | 18.56% | -3.34 |

## Corpus e checklist de filtros

O corpus usado tem **39,934 registros**, dos quais **160** têm `cisaExploitAdd` preenchido.

| Etapa | Artigo: restantes | Replicação: restantes |
|---|---:|---:|
| Publicadas em 2024 | 40,704 | 40,704 |
| Após `Rejected` | 39,959 | 39,953 |
| Após análise incompleta | 32,181 | 39,942 |
| Após CVSS disponível | 32,154 | 39,934 |
| Após EPSS disponível | 31,779 | 39,934 |

## Ameaças à validade e interpretação

- **Status NVD mudam com o tempo:** o campo `vulnStatus` foi consultado na versão atual da API, não em um snapshot de 2024. CVEs anteriormente `Awaiting Analysis` podem agora estar `Analyzed` ou em outro status. Por isso, a filtragem atual não recompõe exatamente o corpus do artigo.
- **KEV é dinâmico:** `cisaExploitAdd` reflete o catálogo conhecido no momento da resposta do NVD. Entradas posteriores no KEV alteram positivos verdadeiros e falsos negativos.
- **CVSS pode ser revisado:** avaliações de CNA/NVD podem mudar; a replicação seleciona a versão de CVSS mais recente disponível pela ordem 4.0, 3.1, 3.0, 2.0 e prioriza `Primary`.
- **EPSS é temporal e tem mudanças de modelo:** foram usados arquivos históricos diários, selecionando para cada CVE o primeiro score na data ou após sua publicação. A série usada termina em 2025-03-19.
- **Diferenças não são erro de fórmula:** TP, FP, FN, precisão, recall, F1 e F2 são recalculados sobre o corpus disponível. O F2 de referência do artigo para CVSS 9.0 (64 TP, total 2.714, 156 KEVs) foi validado em 9,59%; diferenças na tabela são apresentadas lado a lado, não corrigidas artificialmente.

Para se aproximar dos valores originais, seriam necessários os snapshots e o pacote de replicação do estudo. Se o pacote estiver indisponível por revisão cega, os dados podem ser solicitados ao autor identificado no artigo; esta execução não contatou o autor.

## Arquivos de dados

- Corpus: [`nvd-2024-filtered.jsonl`](./nvd-2024-filtered.jsonl)
- Métricas completas: [`nvd-2024-strategy-metrics.json`](./nvd-2024-strategy-metrics.json)
- Métricas tabulares: [`nvd-2024-strategy-metrics.csv`](./nvd-2024-strategy-metrics.csv)
- Contagens e metodologia: [`nvd-2024-filter-summary.json`](./nvd-2024-filter-summary.json)
