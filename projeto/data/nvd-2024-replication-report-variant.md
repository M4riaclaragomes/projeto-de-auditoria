# Replicação CVSS × EPSS — artigo vs. dados atuais

## Estratégias e métricas

O total priorizado corresponde a TP + FP. CVSS usa `>=` (exceto CVSS 10.0, que usa `==`); EPSS usa `>` e os limites das estratégias combinadas são 0,50% (`0.005`). KEV é definido por `cisaExploitAdd` não nulo.

| Estratégia | Condição | Artigo TP / total / F2 | Replicação TP / FP / FN / total | P | R | F1 | F2 | Δ F2 (p.p.) |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| CVSS 5.0 | `cvss >= 5` | 155 / 27,715 / 2.73% | 159 / 27,996 / 1 / 28,155 | 0.56% | 99.38% | 1.12% | 2.76% | +0.03 |
| CVSS 7.0 | `cvss >= 7` | 130 / 13,532 / 4.59% | 133 / 14,492 / 27 / 14,625 | 0.91% | 83.12% | 1.80% | 4.36% | -0.23 |
| CVSS 9.0 | `cvss >= 9` | 64 / 2,714 / 9.59% | 62 / 2,832 / 98 / 2,894 | 2.14% | 38.75% | 4.06% | 8.77% | -0.82 |
| CVSS 10.0 | `cvss == 10` | 7 / 132 / 4.63% | 7 / 145 / 153 / 152 | 4.61% | 4.38% | 4.49% | 4.42% | -0.21 |
| EPSS 0.05% | `epss > 0.0005` | 62 / 3,740 / 7.10% | 60 / 3,379 / 100 / 3,439 | 1.74% | 37.50% | 3.33% | 7.35% | +0.25 |
| EPSS 0.10% | `epss > 0.001` | 41 / 309 / 21.97% | 41 / 275 / 119 / 316 | 12.97% | 25.62% | 17.23% | 21.44% | -0.53 |
| EPSS 0.50% | `epss > 0.005` | 28 / 44 / 20.96% | 28 / 17 / 132 / 45 | 62.22% | 17.50% | 27.32% | 20.44% | -0.52 |
| EPSS 1.00% | `epss > 0.01` | 21 / 26 / 16.15% | 21 / 6 / 139 / 27 | 77.78% | 13.12% | 22.46% | 15.74% | -0.41 |
| EPSS 5.00% | `epss > 0.05` | 4 / 5 / 3.18% | 4 / 1 / 156 / 5 | 80.00% | 2.50% | 4.85% | 3.10% | -0.08 |
| CVSS 7.0 AND EPSS 0.50% | `cvss >= 7 and epss > 0.005` | 21 / 36 / 15.91% | 21 / 16 / 139 / 37 | 56.76% | 13.12% | 21.32% | 15.51% | -0.40 |
| CVSS 9.0 AND EPSS 0.50% | `cvss >= 9 and epss > 0.005` | 8 / 19 / 6.22% | 7 / 9 / 153 / 16 | 43.75% | 4.38% | 7.95% | 5.34% | -0.88 |
| CVSS 9.0 OR EPSS 0.50% | `cvss >= 9 or epss > 0.005` | 84 / 2,739 / 12.49% | 83 / 2,840 / 77 / 2,923 | 2.84% | 51.88% | 5.38% | 11.65% | -0.84 |
| CVSS 10.0 OR EPSS 0.50% | `cvss == 10 or epss > 0.005` | 35 / 175 / 21.90% | 35 / 161 / 125 / 196 | 17.86% | 21.88% | 19.66% | 20.93% | -0.97 |

## Corpus e checklist de filtros

O corpus usado tem **32,173 registros**, dos quais **160** têm `cisaExploitAdd` preenchido.

Nesta variante, os registros `Deferred` foram excluídos como aproximação do backlog de análise descrito no artigo.

A variante recalcula CVSS pela versão mais recente disponível e prioriza a nota `Secondary` (CNA), recorrendo a `Primary` e depois à primeira métrica válida. Essa preferência por `Secondary` é uma inferência nossa: o artigo não especifica qual fonte de CVSS foi usada.

| Etapa | Artigo: restantes | Replicação: restantes |
|---|---:|---:|
| Entrada (corpus original filtrado) | — | 39,934 |
| Após excluir `Deferred` | 32,181 | 32,173 |
| Após exigir/recalcular CVSS | 32,154 | 32,173 |

## Ameaças à validade e interpretação

- **Status NVD mudam com o tempo:** o campo `vulnStatus` foi consultado na versão atual da API, não em um snapshot de 2024. CVEs anteriormente `Awaiting Analysis` podem agora estar `Analyzed` ou em outro status. Por isso, a filtragem atual não recompõe exatamente o corpus do artigo.
- **KEV é dinâmico:** `cisaExploitAdd` reflete o catálogo conhecido no momento da resposta do NVD. Entradas posteriores no KEV alteram positivos verdadeiros e falsos negativos.
- **Fonte CVSS:** notas podem ser revisadas; nesta variante selecionamos a versão mais recente disponível e priorizamos `Secondary` (CNA). Essa escolha é uma inferência metodológica nossa, não explicitada pelo artigo.
- **EPSS é temporal e tem mudanças de modelo:** foram usados arquivos históricos diários, selecionando para cada CVE o primeiro score na data ou após sua publicação. A série usada termina em 2025-03-19.
- **Diferenças não são erro de fórmula:** TP, FP, FN, precisão, recall, F1 e F2 são recalculados sobre o corpus disponível. O F2 de referência do artigo para CVSS 9.0 (64 TP, total 2.714, 156 KEVs) foi validado em 9,59%; diferenças na tabela são apresentadas lado a lado, não corrigidas artificialmente.

Para se aproximar dos valores originais, seriam necessários os snapshots e o pacote de replicação do estudo. Se o pacote estiver indisponível por revisão cega, os dados podem ser solicitados ao autor identificado no artigo; esta execução não contatou o autor.

## Arquivos de dados

- Corpus: [`nvd-2024-filtered-variant.jsonl`](./nvd-2024-filtered-variant.jsonl)
- Métricas completas: [`nvd-2024-strategy-metrics-variant.json`](./nvd-2024-strategy-metrics-variant.json)
- Métricas tabulares: [`nvd-2024-strategy-metrics-variant.csv`](./nvd-2024-strategy-metrics-variant.csv)
- Contagens e metodologia: [`nvd-2024-filter-summary-variant.json`](./nvd-2024-filter-summary-variant.json)
