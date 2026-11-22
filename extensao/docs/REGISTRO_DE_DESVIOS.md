# Registro de desvios em relação ao protocolo congelado (Fase B)

Protocolo: `freeze/protocolo_fase_b_congelado.md` (congelado em 2026-11-21; a seção 13 prevalece).
SHA-256 do protocolo: ver `freeze/protocolo_fase_b_congelado.sha256`.

| # | Data | Item do protocolo | O que mudou | Motivo / efeito |
|---|---|---|---|---|
| 1 | 2026-11-21 | 13.9 (escopo) | Só EST e DIN-1, coorte 2024, grade de K, 20 sementes, McNemar e bootstrap por eventos. Não executados: EST+30, DIN-Δ, ALEAT, FIFO, CVSS-EST, sensibilidades (seção 8), fila obrigatória, T1, T2, bootstrap por blocos, 200 sementes. | Prazo da disciplina (22/11), conforme 13.9 e aval da equipe. H5 e H7 não foram testadas. Os testes de EST+30 e da fila obrigatória estão marcados como `skip`. |
| 2 | 2026-11-21 | 11 (formato) | Dados derivados em `.npz` e `.csv.gz` em vez de Parquet. | `pyarrow` indisponível no ambiente; sem efeito nos resultados. |
| 3 | 2026-11-21 | 5 / 13.2 (tardios) | Tardios = 12, e não 11. | O catálogo congelado em F inclui a CVE-2024-27834 (dateAdded 2026-11-04), ausente do dump do NVD da Fase A. Como o atraso passa de 365 dias, ela é negativa no caso principal. A, A_T, A_pós e os conhecidos na entrada não mudam (86/73/13/63). |
| 4 | 2026-11-21 | 13.6 (ρ) | As chegadas médias por semana são 519 (mediana 532), e não ~596; com K = 50, ρ ≈ 9,6%, e não 8,4%. | A estimativa do protocolo usava outra aproximação da entrada na fila. O valor correto vem de `descritivo.json`. |
| 5 | 2026-11-21 | 13.6 (viés de H3) | A especulação do protocolo ("A_pós concentra ω baixo") não se confirmou: a mediana de ω é 17 semanas em A_pós e 5 em A_T. | Registrado como achado. Na coorte de 2024, atraso ≤ 30 d coincide exatamente com ω ≤ 4 e atraso > 30 d com ω ≥ 5, então H3 não consegue separar atraso de exposição. |
| 6 | 2026-11-21 | 1 / 10 (empates) | O risco de empates foi superestimado. Pelo percentil de entrada há 3.007 valores distintos (o mais comum cobre 1,9% das CVEs); 82% entram com score bruto ≤ 0,05%. Entre 10% e 32% das seleções semanais são decididas por desempate. | O percentil muda diariamente com a população de CVEs, o que desfaz a maior parte dos empates do score bruto. A variação entre as 20 sementes é pequena (K = 50: ΔN entre 11 e 12). |
| 7 | 2026-11-21 | 3 (arquivo ausente) | Não existe arquivo do EPSS de 2024-12-01 (c(t) da decisão de 2024-12-02). Foi aplicada a regra prevista: arquivo mais recente ≤ c(t) (2024-11-30). | Não é desvio, só registro. |
| 8 | 2026-11-21 | 6 (métricas) | A folga usa a data da decisão (segunda-feira) como s_i e d = 0. A estatística é condicional à fila realizada: o bootstrap reamostra os 86 eventos com desempate fixo. | Conforme 13.7, etapa 6. A incerteza por blocos ficou para a versão de publicação. |
| 9 | 2026-11-21 | 11 (coleta NVD local) | Os scripts de coleta local do NVD (2025 e `cvehistory`) não foram escritos. | Não são necessários para EST × DIN-1 em 2024; ficam para T1/T2. |
| 10 | 2026-11-21 | — (análise não prevista) | Saída exploratória `acertos_artigo_reconhecer_vs_antecipar.csv`: das CVEs que as estratégias de limiar do artigo acertam na variante, quantas já estavam no KEV na data do primeiro EPSS. | Surgiu ao interpretar os resultados; rotulada como exploratória e sem teste de hipótese. Não altera nenhuma métrica do protocolo. |
