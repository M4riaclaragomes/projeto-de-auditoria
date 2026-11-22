# Comparação das versões da replicação CVSS × EPSS

Corpus original: **39,934** registros, **160 KEVs**.
Variante: **32,173** registros, **160 KEVs**.

A variante exclui `Deferred` e recalcula CVSS pela versão mais recente, preferindo `Secondary` (CNA). A escolha da fonte `Secondary` é uma inferência metodológica, pois o artigo não especifica a fonte.

## Estratégias

| Estratégia | Condição | Artigo (TP / total / F2) | Original (TP / total / F2) | Variante (TP / total / F2) |
|---|---|---:|---:|---:|
| CVSS 5.0 | `cvss >= 5` | 155 / 27,715 / 2.73% | 159 / 35,777 / 2.18% | 159 / 28,155 / 2.76% |
| CVSS 7.0 | `cvss >= 7` | 130 / 13,532 / 4.59% | 141 / 18,401 / 3.70% | 133 / 14,625 / 4.36% |
| CVSS 9.0 | `cvss >= 9` | 64 / 2,714 / 9.59% | 70 / 4,299 / 7.09% | 62 / 2,894 / 8.77% |
| CVSS 10.0 | `cvss == 10` | 7 / 132 / 4.63% | 3 / 147 / 1.91% | 7 / 152 / 4.42% |
| EPSS 0.05% | `epss > 0.0005` | 62 / 3,740 / 7.10% | 60 / 3,858 / 6.67% | 60 / 3,439 / 7.35% |
| EPSS 0.10% | `epss > 0.001` | 41 / 309 / 21.97% | 41 / 329 / 21.16% | 41 / 316 / 21.44% |
| EPSS 0.50% | `epss > 0.005` | 28 / 44 / 20.96% | 28 / 48 / 20.35% | 28 / 45 / 20.44% |
| EPSS 1.00% | `epss > 0.01` | 21 / 26 / 16.15% | 21 / 30 / 15.67% | 21 / 27 / 15.74% |
| EPSS 5.00% | `epss > 0.05` | 4 / 5 / 3.18% | 4 / 7 / 3.09% | 4 / 5 / 3.10% |
| CVSS 7.0 AND EPSS 0.50% | `cvss >= 7 and epss > 0.005` | 21 / 36 / 15.91% | 23 / 42 / 16.86% | 21 / 37 / 15.51% |
| CVSS 9.0 AND EPSS 0.50% | `cvss >= 9 and epss > 0.005` | 8 / 19 / 6.22% | 8 / 24 / 6.02% | 7 / 16 / 5.34% |
| CVSS 9.0 OR EPSS 0.50% | `cvss >= 9 or epss > 0.005` | 84 / 2,739 / 12.49% | 90 / 4,323 / 9.07% | 83 / 2,923 / 11.65% |
| CVSS 10.0 OR EPSS 0.50% | `cvss == 10 or epss > 0.005` | 35 / 175 / 21.90% | 31 / 195 / 18.56% | 35 / 196 / 20.93% |

## Funil de filtros

A variante parte do corpus original já filtrado e com EPSS associado; por isso, as etapas iniciais do artigo não são repetidas. As linhas de entrada e exclusão de `Deferred` mostram as etapas adicionais da variante.

| Etapa | Artigo | Original | Variante |
|---|---:|---:|---:|
| Publicadas em 2024 | 40,704 | 40,704 | — |
| Após remover Rejected | 39,959 | 39,953 | — |
| Após remover análise incompleta | 32,181 | 39,942 | — |
| Após exigir CVSS | 32,154 | 39,934 | — |
| Após exigir EPSS | 31,779 | 39,934 | — |
| Entrada da variante (corpus original filtrado) | — | — | 39,934 |
| Após remover `Deferred` | 32,181 | — | 32,173 |
| Após recalcular CVSS / remover sem CVSS | 32,154 | 39,934 | 32,173 |
| Após exigir EPSS / corpus final | 31,779 | 39,934 | 32,173 |

## Interpretação

A comparação torna explícitas as diferenças entre o artigo, a versão original e a variante; não implica que os snapshots atuais reproduzam os dados históricos usados no estudo.
