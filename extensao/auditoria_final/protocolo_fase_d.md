# Fase D — Protocolo: confirmação temporal da DIN-ESTAB em coorte independente (2025)

Versão para congelamento, 2026-11-21. Este arquivo é a versão de referência; o hash está em
`protocolo_fase_d.sha256`. Ele prevalece sobre qualquer cópia em outro formato.

## 1. Objetivo e escopo

A Fase D verifica, numa coorte independente de 2025, se o controle de estabilidade escolhido pelo pré-registro
da Fase C (DIN-ESTAB com λ = ∞, plano travado uma semana à frente) preserva a eficácia da atualização semanal
do EPSS. Também verifica se ele oferece vantagem real sobre uma alternativa mais simples, que é atualizar com
menos frequência. A coorte confirmatória é a T2 (EPSS v4). A T1 (EPSS v3) é apenas descritiva. Uma reexecução
de 2024 com a nova definição de coorte serve de ponte com as Fases B e C. Não há aprendizado de máquina nesta
fase. Nenhum parâmetro, hipótese ou limiar deste protocolo pode ser alterado depois que qualquer resultado da T2
for observado. Mudanças anteriores a isso vão para o registro de desvios com data e motivo.

## 2. Coortes, calendário e dados

### 2.1 Definição de coorte S (sem filtro de status)

Uma CVE pertence à coorte S de um período quando cumpre três condições. Primeira: o campo `published` do NVD,
truncado para o dia em UTC, cai na janela de publicação do período. Segunda: o `vulnStatus` do NVD é diferente
de `Rejected`. Terceira: ela tem pelo menos uma observação no arquivo diário do EPSS até o fim da janela de
decisões do período. Não há exigência de CVSS e não há exclusão por `Awaiting Analysis`, `Undergoing Analysis`,
`Deferred` ou qualquer outro status. Os motivos são dois: as políticas desta fase não usam CVSS, e o status
atual de CVEs mais recentes reflete o atraso de análise do NVD, e não uma propriedade da vulnerabilidade.

Duas limitações são declaradas. A exclusão de `Rejected` usa o status no momento da coleta, que é informação
posterior às decisões. Ela é mantida porque CVEs rejeitadas não representam vulnerabilidades. Uma sensibilidade
exploratória na ponte de 2024 inclui as rejeitadas. Já a exigência de EPSS até o fim da janela só define quem
pertence à coorte. Dentro da simulação, a CVE só é visível nas decisões em que o EPSS já existia (seção 2.4),
então essa exigência não antecipa informação para nenhuma decisão.

Toda contagem de inclusão e exclusão é reportada por motivo, para cada coorte: total publicado no NVD,
rejeitadas, sem EPSS até o fim da janela de decisões e incluídas. Na ponte de 2024, as mesmas contagens são
cruzadas com a definição variante da Fase A, que exclui também `Deferred`, análise incompleta e CVEs sem CVSS.

### 2.2 Calendário

| Coorte | Papel | Janela de publicação | Decisões (segundas-feiras) | EPSS | Nº de decisões |
|---|---|---|---|---|---|
| 2024-S (ponte) | Exploratória | 2024-01-01 a 2024-12-31 | 2024-01-01 a 2025-03-10 | v2023.03.01 | 63 |
| T1 | Descritiva | 2025-01-01 a 2025-03-16 | 2025-01-06 a 2025-03-17 | v2023.03.01 | 11 |
| T2 | Confirmatória | 2025-03-17 a 2025-11-19 | 2025-03-24 a 2026-06-15 | v2025.03.14 | 65 |

As datas de transição do EPSS foram conferidas no cabeçalho `model_version` dos arquivos diários. O último
arquivo do v2023.03.01 é de 2025-03-16, o primeiro do v2025.03.14 é de 2025-03-17, o último do v2025.03.14 é
de 2026-06-14 e o primeiro do v2026.06.15 é de 2026-06-15. A decisão de uma segunda-feira t usa o arquivo de
c(t) = t − 1. Por isso a primeira decisão inteiramente sob o v4 é a de 2025-03-24, e não a de 2025-03-17, cujo
c(t) ainda é um arquivo v3. A última decisão da T2 é a de 2026-06-15, com c(t) = 2026-06-14, ainda v4. O script
de coleta e os testes verificam que toda observação usada numa coorte tem a versão indicada na tabela.

Há dois ajustes em relação ao que a Fase B havia esboçado para a T2. A primeira decisão passa de 2025-03-17
para 2025-03-24 (motivo acima). O fim da janela de publicação passa de 2025-11-20 para 2025-11-19, para que a
janela de 365 dias de toda CVE termine em 2026-11-19, antes da data do catálogo KEV congelado (2026-11-20).
A T1 usa a decisão de 2025-03-17, cujo arquivo é v3.

### 2.3 Inicialização da fila

Em cada coorte, a fila começa vazia na primeira decisão e só recebe CVEs da própria coorte. Nenhuma
vulnerabilidade publicada antes da janela de publicação entra na fila: não há backlog herdado de períodos
anteriores, assim como nas Fases B e C. Uma CVE da coorte entra na fila na primeira decisão t em que foi
publicada até c(t), tem EPSS observado até c(t) e não está no KEV até c(t). Se já estiver no KEV nesse momento,
nunca entra: é um "conhecido na entrada" e fica fora do orçamento e do denominador. Fora isso, valem as regras
da Fase B: fila sem expiração, saída por seleção, por inclusão no KEV ou pelo fim da simulação; K = 50 seleções
por semana; e desempate pelo SHA-256 do identificador, igual para todas as políticas.

### 2.4 Informação disponível em cada decisão

A função `estado(i, c)` da Fase B continua sendo a única fonte de informação das políticas. Ela devolve, para
cada CVE, se já foi publicada até c, o último percentil do EPSS com `score_date` ≤ c (ou nenhum) e se já
estava no KEV até c. O status do NVD, o CVSS e qualquer informação de coleta posterior não são usados pelas
políticas.

### 2.5 Desfecho e horizonte

O desfecho é a inclusão no KEV em até 365 dias após a publicação: y_i = 1[p_i < k_i ≤ p_i + 365]. Ele é
medido no catálogo `cisagov/kev-data` versão 2026.11.20, já congelado com hash desde a Fase B. Como toda CVE
de T1 e T2 tem p_i + 365 ≤ 2026-11-19, o horizonte de 365 dias está inteiramente observado para todas. Nenhuma
observação é censurada e nenhuma é tratada como negativa por falta de acompanhamento. A truncagem de
oportunidade (KEV incluído depois da última decisão) é tratada como na Fase B. O denominador A reúne todos os
antecipáveis (y_i = 1 e k_i > c(e_i)), e as partes A_T (k_i até a última decisão) e A_pós são reportadas
separadamente.

### 2.6 Fontes de dados

São três fontes. O dump do NVD de 2025 vem da API 2.0, coletado localmente pela equipe com o script
`scripts/coleta_nvd.py` (seção 8). O arquivo diário do EPSS de 2025-01-01 a 2026-06-14 vem de
`empiricalsec/epss_scores`, coletado com `scripts/coleta_epss_diario.py`. O catálogo KEV 2026.11.20 já está
congelado. O CVEProject/cvelistV5 não é usado no experimento principal; pode entrar no futuro como
sensibilidade sobre a definição de data de publicação.

## 3. Políticas

Todas as políticas usam o mesmo K = 50, o mesmo calendário, as mesmas regras de fila e elegibilidade e o mesmo
desempate. Elas diferem apenas em quando o percentil é lido e se o plano da semana seguinte é travado.

| Política | Score de ordenação | Plano | Papel |
|---|---|---|---|
| EST | Percentil na semana de entrada, congelado | Sem bônus | Referência |
| DIN-1 | Percentil em c(t), toda semana | Sem bônus | Referência |
| DIN-ESTAB λ = ∞ | Percentil em c(t), toda semana | Bônus λ = 2 sobre Plan_{t−1} (plano travado) | Confirmatória |
| DIN-ESTAB λ = 0,3 | Percentil em c(t), toda semana | Bônus 0,3 sobre Plan_{t−1} | Exploratória, escolha pós-hoc da Fase C |
| DIN-4 | Percentil relido a cada 4 decisões | Sem bônus | Comparador periódico principal |
| DIN-2 | Percentil relido a cada 2 decisões | Sem bônus | Comparador periódico secundário |
| EST-travada | Percentil de entrada, congelado | Bônus λ = 2 (plano travado) | Controle secundário |

A DIN-ESTAB é definida como na Fase C: o score ajustado é π_i(c(t)) + λ·1[i ∈ Plan_{t−1}], e Plan_t são as
posições K+1 a 2K do ranking ajustado. A EST-travada aplica o mesmo bônus sobre o score congelado da EST. A
comparação entre DIN-ESTAB λ = ∞ e EST-travada isola o efeito de atualizar o indicador quando as duas
políticas têm o mesmo controle de estabilidade.

**Calendário da DIN-Δ (Δ = 2 ou 4).** Numeram-se as decisões da coorte por j = 0, 1, 2, … a partir da
primeira. Há releitura global nas decisões com j mod Δ = 0, começando pela primeira (j = 0). Numa decisão de
releitura, toda CVE elegível recebe o percentil em c(t). Numa decisão sem releitura, cada CVE mantém o
percentil da última releitura de que participou. Uma CVE que entrou na fila depois da última releitura usa o
percentil da sua semana de entrada até a próxima releitura. Não há bônus de plano. Com Δ = 1, a DIN-Δ é
idêntica à DIN-1, e isso é verificado por teste. Na T2, a DIN-4 relê nas decisões de 2025-03-24, 2025-04-21,
2025-05-19 e assim por diante, a cada 28 dias.

## 4. Métricas

As métricas são as das Fases B e C, sem mudança de definição. Na eficácia: KEV antecipados N (s_i < k_i),
recall sobre A e sobre A_T, N com folga ≥ 30 e ≥ 90 dias e folga mediana. Na instabilidade: revisões do plano
ΣR, com ΣR^atual e ΣR^outras; aderência ao plano α; mudanças contrafactuais por atualização; e distância de
Kendall no top-4K. Na operação: utilização, tamanho da fila elegível, K/|E_t|, chegadas por semana, idade das
seleções e espera até a seleção. Trabalho comprometido e cancelado não é modelado. Todas as métricas são
calculadas para todas as políticas e coortes.

## 5. Hipóteses confirmatórias e regras de decisão

### 5.1 Unidade de análise e inferência

A unidade é o evento KEV antecipável da T2 (o conjunto A). Cada evento tem um resultado binário pareado em cada
política: antecipado ou não. A decisão usa o desempate determinístico. A inferência é por bootstrap não
paramétrico sobre os eventos de A, reamostrados com reposição, com B = 10.000 réplicas e semente 20261121. Esse
bootstrap é condicional à fila realizada: ele representa a incerteza sobre quais eventos ocorreram, e não a
variação de um conjunto inteiro de CVEs. As 20 sementes de desempate são reportadas como verificação de
robustez, mas não entram na regra de decisão. Os testes são unilaterais, com nível de 5%, e o limite inferior
de interesse é o percentil 5 da distribuição bootstrap.

### 5.2 H-D1 (principal): o plano travado preserva pelo menos 75% da vantagem da DIN-1 sobre a EST

A razão de preservação é

    ρ∞ = (N∞ − N_EST) / (N_DIN1 − N_EST).

Para inferência, usa-se a forma aditiva, equivalente quando o denominador é positivo e estável sob
reamostragem:

    D = (N∞ − N_EST) − 0,75 · (N_DIN1 − N_EST) = Σ_{i∈A} d_i,   d_i = a∞_i − 0,25·aEST_i − 0,75·aDIN1_i,

em que a·_i indica se o evento i foi antecipado pela política. ρ∞ ≥ 0,75 equivale a D ≥ 0.

As regras abaixo são aplicadas nesta ordem.

1. **Pré-condição.** Se N_DIN1 − N_EST ≤ 0, a H-D1 é **não avaliável**: a vantagem da DIN-1 observada em 2024
   não se repetiu na T2, e isso é reportado como resultado próprio. Nesse caso, ρ∞ não é calculada.
2. **Baixa informação.** Se 0 < N_DIN1 − N_EST < 5 (abaixo da relevância fixada na Fase B), ou se |A| < 30, ou
   se há menos de 10 pares discordantes entre DIN-1 e EST, o resultado é calculado e reportado, mas classificado
   como **inconclusivo por poucos eventos**, qualquer que seja o valor observado. Nesse caso a H-D1 não é
   declarada nem sustentada nem refutada, e a H-D2 passa a ser apenas descritiva (seção 5.4).
3. **Critério descritivo.** O critério é atingido se ρ∞ ≥ 0,75 (D ≥ 0) no desempate determinístico.
4. **Critério estatístico.** A H-D1 é **sustentada** se o limite inferior unilateral de 95% de D for maior que 0.
   É **descritivamente atingida, estatisticamente inconclusiva** se D ≥ 0 e o limite inferior for ≤ 0. É
   **refutada** se o limite superior unilateral de 95% de D (percentil 95) for menor que 0. Nos demais casos,
   com D < 0 e o limite superior ≥ 0, é **não atingida, inconclusiva**.

São reportados também: ρ∞ observada, com intervalo percentil bootstrap de 90% calculado só nas réplicas com
denominador positivo e com a fração dessas réplicas informada; N de cada política; pares discordantes; e o
McNemar exato da DIN-1 contra a EST, como verificação da pré-condição.

### 5.3 H-D2 (secundária): o plano travado não antecipa menos KEV que a DIN-4

"Pelo menos tantos" é definido como não inferioridade, com margem fixada agora: δ = max(2; ⌈0,03·|A|⌉) KEV.
O valor de 2 KEV é a tolerância da regra da Fase C e a variação observada entre sementes. O termo de 3%
mantém a margem proporcional se a T2 tiver muito mais eventos que 2024. Seja E = N∞ − N_DIN4 = Σ e_i, com
e_i = a∞_i − aDIN4_i.

A H-D2 é **sustentada (não inferioridade)** se o limite inferior unilateral de 95% de E for maior que −δ.
Ela indica **superioridade** se esse limite for maior que 0. É **refutada** se o limite superior unilateral de
95% de E for menor que −δ. Nos demais casos é **inconclusiva**. Contagens iguais, por si só, não são evidência
de não inferioridade. A mesma análise é feita com N restrito a folga ≥ 30 dias, como resultado secundário
descritivo, e os ganhos e perdas individuais entre as duas políticas são listados evento a evento, com atraso
até o KEV e ω.

### 5.4 Multiplicidade

Usa-se teste em sequência fixa. A H-D2 só é avaliada confirmatoriamente se a H-D1 for sustentada. Caso
contrário, a H-D2 é reportada apenas de forma descritiva. Isso mantém em 5% a taxa de erro do conjunto das
duas hipóteses confirmatórias. Nenhuma outra comparação desta fase é confirmatória.

### 5.5 Resultados inconclusivos e eventos raros

Resultados inconclusivos são reportados como tal. Não se estende a janela, não se muda K, não se troca de coorte
e não se acrescentam políticas para "resolver" um resultado inconclusivo. Os eventos discordantes são sempre
listados um a um. Quando a decisão depender de um ou dois eventos (|D| ≤ 1 ou |E| ≤ 1), isso é dito
explicitamente na conclusão.

## 6. Análises exploratórias (sem conclusão confirmatória)

São exploratórias:

- DIN-ESTAB λ = 0,3 em todas as coortes, rotulada como escolha pós-hoc da Fase C;
- DIN-2, e a DIN-4 fora da H-D2;
- EST-travada como controle secundário. O contraste DIN-ESTAB λ = ∞ × EST-travada é a medida descritiva do
  efeito da atualização com estabilidade igual;
- a T1, com 11 decisões, apenas descritiva;
- a ponte de 2024-S, com as sete políticas, comparada à variante das Fases B e C, mais a sensibilidade que
  inclui as rejeitadas;
- a execução de DIN-2 e DIN-4 sobre a coorte variante de 2024, que é a etapa 4 da seção 9;
- as 20 sementes, a fronteira de Pareto em (N, ΣR) e (N com folga ≥ 30, ΣR) e as análises por atraso e ω.

## 7. Comparabilidade e controle de validade

Para cada coorte (2024-variante, 2024-S, T1, T2), são reportados antes de qualquer comparação entre políticas
os números abaixo:

- contagens de inclusão e exclusão por motivo;
- chegadas à fila por semana;
- tamanho da fila elegível;
- K/|E_t| e K/chegadas;
- KEV no catálogo, rótulo positivo, conhecidos na entrada, A, A_T e A_pós, tardios;
- distribuição do atraso até o KEV e de ω;
- distribuição do percentil de entrada;
- versão do EPSS.

Essas razões e distribuições descrevem o contexto. Elas não tornam as coortes diretamente comparáveis.

Os testes automáticos da Fase D precisam passar antes de qualquer resultado ser aceito:

- manifestos das Fases A, B e C intactos;
- todos os testes anteriores continuam passando;
- construtor da coorte S reproduz as contagens do NVD bruto (na ponte de 2024: 40.704 publicadas, 751
  rejeitadas);
- calendário da T2 com 65 decisões, de 2025-03-24 a 2026-06-15;
- toda observação de EPSS usada em T2 com `model_version` v2025.03.14, e em 2024-S e T1 com v2023.03.01;
- nenhum rótulo censurado (p_i + 365 ≤ 2026-11-19 para toda CVE de T1 e T2);
- DIN-Δ com Δ = 1 idêntica à DIN-1;
- na DIN-Δ, o score só muda nas decisões de releitura ou na entrada da CVE;
- EST-travada e DIN-ESTAB λ = ∞ com ΣR = 0;
- orçamento respeitado;
- invariância das decisões passadas a mudanças em percentis futuros e em datas de KEV posteriores à última
  decisão;
- módulos de política sem importar rótulos;
- determinismo;
- integridade do dump do NVD: total por janela igual a `totalResults`, IDs únicos e `published` dentro da janela.

Os resultados da Fase D são gravados em `results/fase_d/`, e nenhum arquivo das fases anteriores é alterado.

| Risco | Tratamento |
|---|---|
| Poucos eventos em T2 | Regras de baixa informação (5.2, item 2); eventos listados |
| Mudança de escala do EPSS v4 | λ = ∞ é indiferente à escala; λ = 0,3 e efeitos de magnitude ficam exploratórios |
| Definição S difere da variante | Ponte de 2024-S com contagens por motivo e as sete políticas |
| Status Rejected é informação atual | Declarado; sensibilidade com rejeitadas na ponte |
| Coleta do NVD incompleta ou alterada durante a paginação | Script recusa total inconsistente, valida IDs e janelas e registra hashes |
| Recalibração depois de ver T2 | Protocolo congelado com hash; T2 só roda com dados completos e testes aprovados |
| Fila restrita à coorte | Mesma limitação das Fases B e C, declarada |

## 8. Coleta de dados do NVD

`scripts/coleta_nvd.py` consulta a API 2.0 do NVD por intervalos de publicação de no máximo 120 dias, com
`resultsPerPage` = 2000. Ele aceita chave de API pela variável `NVD_API_KEY` e respeita o limite de taxa (cerca
de 0,7 s entre requisições com chave e 6,5 s sem chave). Tenta de novo com espera crescente em caso de erro.
Pode ser retomado: páginas já gravadas não são baixadas de novo e nunca são sobrescritas. Ele valida que
`totalResults` não muda durante a paginação de uma janela, que o número de registros gravados é igual a
`totalResults`, que não há IDs repetidos e que todo `published` está dentro da janela. Grava um manifesto com o
SHA-256 de cada página, a data da coleta e o resultado das validações. Para a Fase D, a coleta cobre de
2025-01-01 a 2025-11-19. O NVD não é substituído por outra fonte nesta fase.

## 9. Ordem de execução

1. Congelar este protocolo com hash (feito ao gravar `protocolo_fase_d.sha256`).
2. Preparar e testar offline os scripts de coleta do NVD e o construtor da coorte S.
3. Executar DIN-2 e DIN-4 na coorte variante de 2024 (exploratório).
4. Executar a ponte de 2024-S com as sete políticas (exploratório).
5. A equipe coleta o NVD de 2025 localmente. Em paralelo, coleta-se o EPSS diário de 2025-01-01 a 2026-06-14.
6. Construir T1 e T2, rodar os testes e o relatório descritivo das coortes.
7. Executar T2 (confirmatório) e T1 (descritivo) uma única vez, com as regras deste protocolo.
