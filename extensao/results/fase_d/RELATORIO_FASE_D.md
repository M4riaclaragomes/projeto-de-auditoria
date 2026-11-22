# Fase D — Relatório parcial: comparadores, análises exploratórias de 2024 e preparação da T2

Situação em 2026-11-21: **a Fase D não está concluída.** A validação confirmatória (T2) e a análise descritiva (T1)
não foram executadas, porque o NVD de 2025 não está disponível: o ambiente de análise não alcança a API do NVD e,
pelo protocolo, ele não pode ser substituído por outra fonte. Tudo o que está abaixo é exploratório (coortes de 2024),
salvo indicação contrária. Protocolo: `freeze/protocolo_fase_d.md` (SHA-256 `dca72aeb…3bb4d`), sem alterações.

## 1. Auditoria inicial

Os manifestos das Fases A (938 arquivos), B (40), C (21) e da preparação da Fase D (6) conferem sem divergência, e os
hashes dos três protocolos congelados batem. O pacote recebido não trazia os arquivos diários do EPSS; eles foram
baixados de novo, e os 440 arquivos de 2024-01-01 a 2025-03-16 têm exatamente os SHA-256 da coleta original. Foram
baixados também os 455 arquivos de 2025-03-17 a 2026-06-14, todos com `model_version` v2025.03.14 (o primeiro é de
2025-03-17 e o último de 2026-06-14, como previsto no protocolo). A suíte de testes passa: 57 aprovados e os mesmos 2
pulados de antes (`results/fase_d/testes_saida.txt`).

## 2. O que foi implementado

Em módulos novos, sem alterar nenhum anterior: `politicas_d.py` (DIN-Δ), `dados_d.py` (construção de coortes e
calendários congelados), `experimentos_d.py` (sete políticas, métricas, regras de decisão de H-D1 e H-D2, sementes) e
`graficos_d.py`. A EST-travada usa a política estática da Fase C com o plano travado (λ = 2). Os testes novos
(`tests/test_fase_d_politicas.py`) verificam: calendários de T1, T2 e 2024-S; horizonte de 365 dias inteiramente
observado; DIN-Δ com Δ = 1 idêntica à DIN-1, inclusive nas métricas de revisão; o score da DIN-Δ só muda na releitura
ou na entrada; orçamento semanal; ΣR = 0 nas políticas travadas; ausência de vazamento temporal; módulos de política
sem acesso aos rótulos; e que a matriz semanal de EPSS construída pela Fase D reproduz exatamente a da Fase B para
todas as CVEs da coorte variante.

As políticas EST, DIN-1, λ = ∞ e λ = 0,3 reproduzem, na coorte variante, os números das Fases B e C (15, 27, 25 e 27
KEV antecipados; ΣR de 1.090, 1.730, 0 e 364), o que confirma que nada mudou na implementação.

## 3. Coorte variante × coorte S (2024)

| Coorte | CVEs | KEV no catálogo | Conhecidos na entrada | A | A_T | A_pós | Tardios | Chegadas/semana | Fila elegível (mediana) |
|---|---|---|---|---|---|---|---|---|---|
| 2024-variante | 32.173 | 161 | 63 | 86 | 73 | 13 | 12 | 518 | 17.918 |
| 2024-S | 39.951 | 161 | 63 | 86 | 73 | 13 | 12 | 643 | 21.489 |
| 2024-S + rejeitadas | 40.311 | 161 | 63 | 86 | 73 | 13 | 12 | 649 | 21.772 |

A coorte S parte de 40.704 CVEs publicadas, exclui 751 rejeitadas e 2 sem EPSS até 2025-03-16, e fica com 39.951.
Ela contém 32.171 das 32.173 CVEs da variante (as 2 restantes nunca tiveram EPSS e por isso nunca ficaram visíveis) e
acrescenta 7.780 CVEs, quase todas `Deferred` (7.769) e 11 `Undergoing Analysis`. Os 86 eventos KEV antecipáveis são
exatamente os mesmos nas três coortes. A mudança de definição, portanto, não altera os eventos: só acrescenta cerca de
24% de concorrentes sem KEV à fila (de 518 para 643 chegadas por semana), o que torna o orçamento K = 50 relativamente
mais apertado.

## 4. Resultados exploratórios (K = 50, desempate determinístico)

| Política | Papel | Variante: N | Variante: folga ≥ 30 d | Variante: ΣR | S: N | S: folga ≥ 30 d | S: ΣR |
|---|---|---|---|---|---|---|---|
| EST | referência | 15 | 12 | 1.090 | 14 | 11 | 1.163 |
| DIN-1 | referência | 27 | 19 | 1.730 | 27 | 19 | 1.763 |
| DIN-ESTAB λ = ∞ | confirmatória | 25 | 16 | 0 | 25 | 16 | 0 |
| DIN-ESTAB λ = 0,3 | exploratória pós-hoc | 27 | 19 | 364 | 27 | 17 | 342 |
| DIN-4 | comparador principal | 27 | 19 | 1.170 | 27 | 18 | 1.196 |
| DIN-2 | comparador secundário | 27 | 19 | 1.459 | 27 | 19 | 1.482 |
| EST-travada | controle secundário | 14 | 10 | 0 | 13 | 9 | 0 |

N é o número de KEV antecipados entre os 86 de A; ΣR é o número de revisões do plano, que não são cancelamentos de
trabalho. Nas 20 sementes de desempate, N não varia nas políticas dinâmicas e varia no máximo 1 nas estáticas
(`sementes_20_resumo.csv`). A figura `figuras/fd1_eficacia_vs_revisoes.png` mostra N contra ΣR.

Quatro observações, todas exploratórias:

1. **Ampliar a coorte quase não mudou nada.** As políticas dinâmicas mantêm 27 KEV e a λ = ∞ mantém 25; a EST perde 1.
2. **Atualizar com menos frequência preserva a eficácia em 2024.** A DIN-4 e a DIN-2 antecipam os mesmos 27 KEV da
   DIN-1, com 32% e 16% menos revisões. A DIN-4, porém, ainda revisa o plano cerca de 1.200 vezes; só o plano travado
   zera as revisões, ao custo de 2 KEV (os mesmos CVE-2024-36401 e CVE-2024-6670 da Fase C).
3. **O plano travado não explica sozinho a eficácia.** A EST-travada antecipa 13–14 KEV, contra 25 da λ = ∞: com o
   mesmo controle de estabilidade, atualizar o EPSS rende 11–12 KEV a mais. É a vantagem da atualização, não a do
   travamento.
4. **Mesmo em 2024, com 86 eventos, a H-D1 não seria sustentada estatisticamente.** A razão de preservação é
   ρ = 0,83 na variante e 0,85 na S (critério descritivo de 75% atingido), mas o limite inferior unilateral de 95% de
   D é −1,75 e −1,50. Aplicadas as regras do protocolo, a classe seria "descritivamente atingida, estatisticamente
   inconclusiva". A H-D2 contra a DIN-4 seria inconclusiva (E = −2, margem δ = 3, limites −5 e 0). Isso indica que a
   T2 provavelmente terá pouco poder para sustentar a H-D1, a menos que tenha bem mais eventos que 2024. Esse ponto
   foi observado agora e não muda o protocolo.

A sensibilidade com as rejeitadas dá os mesmos números da coorte S.

## 5. Ameaças à validade (complemento ao protocolo)

As conclusões de 2024 vêm da mesma coorte em que λ = ∞ foi escolhido, então não são independentes. Os contrastes
dependem de poucos eventos discordantes (2 entre λ = ∞ e DIN-1 ou DIN-4). ΣR mede revisões de plano, não trabalho
perdido. A fila contém só CVEs da coorte. O status `Rejected` é lido na coleta. A troca do EPSS v3 pelo v4 pode mudar
a escala dos percentis e o efeito de λ = 0,3.

## 6. O que falta para concluir a Fase D

1. Coletar o NVD de 2025-01-01 a 2025-11-19 (comando abaixo), localmente ou depois de liberar o domínio
   `services.nvd.nist.gov` neste ambiente.
2. Construir T1 e T2, rodar todos os testes e conferir as contagens por motivo.
3. Rodar T1 (descritiva) e T2 (confirmatória) uma única vez e escrever a seção confirmatória deste relatório.

```bash
python scripts/coleta_nvd.py --inicio 2025-01-01 --fim 2025-11-19 --saida data/raw/nvd-2025
python scripts/coleta_nvd.py --inicio 2025-01-01 --fim 2025-11-19 --saida data/raw/nvd-2025 --verificar
PYTHONPATH=src python -m vulnprio.dados_d data/raw/nvd-2025 T1 T2
PYTHONPATH=src python -m pytest -q -rs tests
PYTHONPATH=src python -m vulnprio.experimentos_d T1
PYTHONPATH=src python -m vulnprio.experimentos_d T2 --confirmatoria
```

## 7. Implicações para o artigo

O resultado de 2024 que mais muda a narrativa é o da DIN-4: em 2024, atualizar a cada quatro semanas já basta para
reproduzir a eficácia da atualização semanal, com menos revisões. A contribuição do plano travado passa a ser a de
eliminar as revisões a um custo pequeno de eficácia, e não a de ser a única forma de reduzi-las. A T2 vai dizer se
isso se repete com o EPSS v4; até lá, a terceira contribuição do artigo deve ser apresentada como hipótese em teste,
e o artigo deve antecipar que um resultado inconclusivo é provável e informativo.
