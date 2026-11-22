# Fase B — Protocolo do experimento mínimo: política estática × atualização semanal do EPSS

Nov 21, 2026 · @Time Huntly

## 1. Pergunta e critério de benefício

O experimento pergunta em que condições reordenar semanalmente a fila pelo EPSS mais recente identifica, antes da inclusão no KEV, mais vulnerabilidades do que manter a ordem definida na entrada, quando ambas as políticas têm o mesmo número K de seleções por semana. A hipótese de trabalho não é que a política dinâmica vence. É que o ganho dela depende de três condições mensuráveis: o tamanho do orçamento em relação à parte da fila em que o EPSS ainda discrimina, o tempo entre a publicação e a inclusão no KEV, e o custo operacional de mudar a ordem do que já estava planejado.

Por isso o benefício é definido em três camadas, e uma política só é considerada melhor se ganhar na primeira sem perder de forma relevante na segunda e se o ganho compensar o custo da terceira. A primeira é a cobertura antecipada: KEVs selecionados antes da data de inclusão no catálogo, contando apenas os que eram antecipáveis. A segunda é a antecedência: com quantos dias de folga isso aconteceu, porque antecipar por um dia tem pouco valor operacional. A terceira é a estabilidade: quantas prioridades já planejadas foram trocadas por causa da atualização de scores, e quantas dessas trocas foram necessárias para cada KEV adicional antecipado.

Dois achados da Fase A orientam o desenho desde o início. Primeiro, 89% das CVEs de 2024 entram na fila com EPSS ≤ 0,05% e 53% com exatamente o mesmo valor (0,043%), de modo que, além das cerca de 316 CVEs com EPSS inicial acima de 0,1%, a ordem estática é decidida quase toda pelo desempate. Segundo, 38 dos 160 KEV entraram no catálogo entre 1 e 7 dias depois da publicação, prazo que uma decisão semanal dificilmente alcança com qualquer política. O experimento precisa mostrar esses limites, e não escondê-los numa média.

Este experimento não usa ML nem a política com penalidade de estabilidade. Ele mede o trade-off bruto entre as duas políticas e com isso define o espaço em que a Política 4 poderá ou não fazer diferença.

## 2. Coortes, períodos e versões do EPSS

O estudo usa três coortes, e cada uma tem todas as decisões tomadas sob uma única versão do EPSS. A troca do v3 para o v4 foi conferida no arquivo diário: o último arquivo do v3 é de 2025-03-16 e o primeiro do v4 é de 2025-03-17. A troca seguinte, para o v2026.06.15, ocorre em 2026-06-15 e fica fora de todas as janelas de decisão.

&#91;embedded content: Datas de troca de modelo conferidas no cabeçalho \`model\_version\` do arquivo diário do EPSS; demais datas definidas neste protocolo\]

A coorte de desenvolvimento são as CVEs publicadas em 2024 do corpus variante, com decisões semanais de 2024-01-01 a 2025-03-16. É nela que se escolhem a grade de K, o critério de desempate e qualquer detalhe de implementação. A coorte T1 reúne as CVEs publicadas entre 2025-01-01 e 2025-03-16, com decisões no mesmo intervalo, ainda sob o v3. Ela é curta (cerca de 11 semanas) e serve para verificar se o padrão de 2024 se repete no mesmo modelo em outro período. A coorte T2 reúne as CVEs publicadas entre 2025-03-17 e 2025-11-20, com decisões de 2025-03-17 a 2026-06-14, inteiramente sob o v4. O limite de 2025-11-20 vem da janela de rótulo (seção 5): é a última data de publicação que ainda tem 365 dias de acompanhamento até o congelamento do KEV em 2026-11-20.

As coortes são simuladas separadamente, cada uma com sua própria fila. Isso mantém a comparação com o artigo, que trata um ano de publicação por vez, e impede que um modelo pontue a fila de outro. Além das três coortes, uma análise secundária continua a coorte de 2024 atravessando a troca para o v4, só para medir quanto da instabilidade da política dinâmica é produzida pela própria troca de modelo. Ela não entra no teste de hipóteses.

## 3. Notação, corte de informação e conjunto elegível

Três datas por CVE são mantidas separadas o tempo todo, como pedido. A data de publicação pᵢ é o campo `published` do NVD, truncado para o dia em UTC. A data de inclusão no KEV kᵢ é o `dateAdded` do catálogo congelado, e vale +∞ para CVEs que não estão nele. A data de decisão t pertence a um calendário semanal fixo, com uma decisão por segunda-feira dentro da janela da coorte. A essas três soma-se a data aᵢ do primeiro arquivo do EPSS que traz score para a CVE, que pode ser posterior a pᵢ (no corpus original de 2024, 522 CVEs esperaram mais de 30 dias).

O corte de informação de uma decisão em t é c(t) = t − 1 dia. A decisão só enxerga fatos datados até c(t): a CVE precisa ter sido publicada até c(t), o EPSS usado é o do arquivo com `score_date` = c(t) (ou o mais recente anterior, se faltar arquivo naquele dia) e o KEV só é conhecido se kᵢ ≤ c(t). O dia de folga evita que um arquivo publicado na própria segunda-feira, ou um KEV incluído nela, influencie a decisão daquele dia.

A primeira semana em que a CVE i fica visível para a equipe é eᵢ, a menor data de decisão com pᵢ ≤ c(t) e aᵢ ≤ c(t). O conjunto elegível da semana t é então:

```latex
E_t = \{\, i \in C : p_i \le c(t),\; a_i \le c(t),\; k_i > c(t),\; t \le p_i + W,\; i \notin \textstyle\bigcup_{u<t} S_u \,\}
```

em que C é a coorte, W = 365 dias é a janela de acompanhamento e S\_u são as seleções das semanas anteriores. Cada condição tem uma razão. A exigência de EPSS disponível impede que uma CVE sem score seja ranqueada por um valor inventado. A condição kᵢ > c(t) tira da fila discricionária tudo o que já está no KEV: na prática, uma CVE no KEV passa a ser correção obrigatória e sai do orçamento, e, mais importante para o estudo, selecioná-la depois disso não é descoberta nenhuma. A condição t ≤ pᵢ + W faz a CVE sair da fila quando termina sua janela de rótulo, o que alinha fila e desfecho e evita um backlog infinito; a variante sem expiração entra na análise de sensibilidade.

A cada semana a política escolhe S\_t ⊆ E\_t com |S\_t| = min(K, |E\_t|). Selecionar significa decidir remediar: a CVE sai da fila e não volta. A conclusão da correção não é modelada no caso principal, então a avaliação fala sempre em "selecionada antes do KEV", nunca em "corrigida antes do KEV". Para aproximar a segunda leitura, a sensibilidade introduz um atraso de execução d ∈ {0, 7, 30} dias, e uma CVE só conta como antecipada se sᵢ + d < kᵢ.

O critério de ordenação é o percentil do EPSS publicado no próprio arquivo, e não o score bruto. Dentro de uma mesma semana os dois produzem a mesma ordem. A diferença aparece na política estática, que compara CVEs pontuadas em semanas diferentes, e entre versões do modelo, em que o score bruto muda de escala e o percentil muda menos. Empates são desfeitos por um número aleatório uᵢ sorteado uma vez por CVE e compartilhado por todas as políticas na mesma réplica. Isso importa porque, como visto na seção 1, a maior parte da fila está empatada, e o desempate decide boa parte das seleções quando K é grande.

## 4. Políticas comparadas sob o mesmo orçamento K

O contraste principal é entre duas políticas que diferem em uma única coisa: quando o score usado para ordenar é lido. Na estática, o score de cada CVE é o percentil do EPSS na semana em que ela entrou na fila e nunca muda. Na dinâmica, o score é relido toda semana. Todo o resto é idêntico: o mesmo conjunto elegível, o mesmo K, o mesmo desempate e a mesma regra de saída. Assim, qualquer diferença de resultado vem apenas da atualização.

```latex
\sigma_i^{\mathrm{EST}}(t) = \pi_i\big(c(e_i)\big) \qquad \sigma_i^{\mathrm{DIN}}(t) = \pi_i\big(c(t)\big) \qquad S_t = \operatorname{top}_K \{ (\sigma_i(t), u_i) : i \in E_t \}
```

Para responder "em quais condições", a frequência de atualização entra como fator secundário. A família DIN-Δ relê todos os scores a cada Δ semanas e, entre releituras, CVEs recém-chegadas usam o score de entrada. Com Δ = 1 ela é a dinâmica; com Δ = ∞, a estática. Os valores intermediários (2, 4 e 13 semanas) mostram se a maior parte do ganho, se houver, já aparece com reordenações mensais ou trimestrais, que são muito mais baratas de operar. Isso não é a Política 4 com penalidade, que fica para depois. Entra ainda, como exploratória, a EST+30, que relê o score uma única vez 30 dias depois da entrada e o congela; ela testa a explicação rival discutida na seção 10.

Três políticas de referência delimitam o que é um resultado bom ou ruim. A aleatória escolhe K CVEs elegíveis ao acaso e dá o piso: qualquer política que não a supere não tem sinal. A FIFO seleciona as mais antigas primeiro e representa uma equipe que só trabalha por ordem de chegada. A CVSS-EST ordena pela nota CVSS da CNA na entrada, com o EPSS de entrada como desempate, e representa a prática tradicional sob o mesmo orçamento. A nota da CNA é usada aqui com a ressalva da Fase A: ela é provavelmente, mas não comprovadamente, a nota disponível na data.

| Política | Score de ordenação | Atualização | Papel |
| --- | --- | --- | --- |
| EST | Percentil EPSS em eᵢ | Nunca | Contraste principal |
| DIN-1 | Percentil EPSS em c(t) | Semanal | Contraste principal |
| DIN-2, DIN-4, DIN-13 | Percentil EPSS na última releitura | A cada Δ semanas | Fator secundário (frequência) |
| ALEAT | uᵢ | — | Piso |
| FIFO | eᵢ (mais antiga primeiro) | — | Referência operacional |
| CVSS-EST | CVSS da CNA em eᵢ, desempate por EPSS de entrada | Nunca | Referência tradicional |

As regras de limiar do artigo (por exemplo EPSS > 0,5% ou CVSS ≥ 9 OR EPSS > 0,5%) não têm orçamento: elas selecionam tudo o que passa do limiar. Por isso não entram na comparação sob K fixo. Elas são rodadas à parte, no modo sem orçamento e aplicadas na data de entrada, como ponte com a replicação, e para cada uma é reportado o orçamento implícito, isto é, quantas seleções por semana ela teria exigido.

## 5. Rótulos, janela de 365 dias, censura e estratos de KEV

O desfecho de cada CVE é a inclusão no KEV dentro de 365 dias após a publicação, medida no catálogo congelado em F = 2026-11-20 (versão 2026.11.20, com hash do arquivo registrado). Como todas as coortes terminam em pᵢ ≤ F − W, toda CVE do estudo tem a janela inteira observada, e não há censura administrativa do rótulo.

```latex
y_i = \mathbb{1}\,[\, p_i < k_i \le p_i + W \,], \qquad W = 365 \text{ dias}, \quad k_i \le F
```

A data de inclusão no KEV é tratada como o momento em que a exploração se tornou pública e oficialmente reconhecida, e não como o início da exploração. Todo resultado de antecedência é escrito nesses termos: "selecionada N dias antes da inclusão no KEV".

Os KEV são divididos em estratos que nunca se misturam nas métricas. Os conhecidos na entrada têm kᵢ ≤ c(eᵢ): já estavam no catálogo quando a CVE ficou visível para a equipe, nunca entram na fila e não contam como descoberta de nenhuma política. Na coorte de 2024 são pelo menos os 40 incluídos até o dia da publicação, mais parte dos 38 incluídos entre 1 e 7 dias depois; o número exato depende de eᵢ e sai na Fase B. Os antecipáveis têm yᵢ = 1 e kᵢ > c(eᵢ): houve ao menos uma decisão em que a CVE estava elegível antes de entrar no KEV. Eles formam o denominador do recall. Os tardios entraram no KEV depois de 365 dias (11 na coorte de 2024); no caso principal contam como negativos, e na sensibilidade são retirados da conta.

Há uma segunda forma de censura, que não é do rótulo, e sim da oportunidade de decidir. A janela de decisões de cada coorte termina antes que todas as CVEs completem 365 dias: uma CVE de dezembro de 2024 tem só cerca de 11 semanas de decisões sob o v3. Um KEV incluído depois do fim da janela T\_fim só pode ter sido antecipado se foi selecionado antes de T\_fim, e esse corte pode afetar as políticas de forma diferente, numa direção que precisa ser medida (seção 13.2). Por isso o recall principal usa o conjunto A\_T dos antecipáveis com kᵢ ≤ T\_fim, com inclusão no KEV durante a janela de decisões (substituído pela seção 13.2). Os antecipáveis com kᵢ > T\_fim são reportados à parte, como seleções feitas antes do fim da janela.

| Estrato (coorte 2024, variante) | Definição | Tamanho conhecido | Uso |
| --- | --- | --: | --- |
| Conhecidos na entrada | kᵢ ≤ c(eᵢ) | ≥ 40 | Fora da fila; reportado |
| Antecipáveis, dentro da janela de decisão (A\_T) | yᵢ = 1, c(eᵢ) < kᵢ ≤ T\_fim | A calcular | Denominador do recall principal |
| Antecipáveis, após a janela de decisão | yᵢ = 1, kᵢ > T\_fim | A calcular | Reportado à parte |
| Tardios | kᵢ > pᵢ + 365 | 11 | Negativos; excluídos na sensibilidade |
| Negativos | Fora do KEV em F | ≈ 32.000 (exato na Fase B) | Falsos positivos quando selecionados |

Remoções do catálogo, que são raras, são conferidas no histórico git do `cisagov/kev-data` e listadas. O rótulo segue o catálogo em F.

## 6. Métricas

As métricas foram escolhidas para responder às três camadas de benefício da seção 1, e uma consequência do orçamento fixo precisa ficar clara desde já: quando todas as políticas usam toda a capacidade, elas selecionam o mesmo número de CVEs, e precisão e recall passam a ser proporcionais. A precisão continua sendo reportada, para conversar com o artigo, mas não conta como evidência independente, e F1/F2 não são usados como critério principal.

**Eficácia.** Seja sᵢ a semana em que a política selecionou a CVE i (+∞ se nunca selecionou) e d o atraso de execução. O conjunto de KEV antecipados e o recall principal são

```latex
N^{\pi} = \{\, i \in A_T : s_i^{\pi} + d < k_i \,\}, \qquad R^{\pi} = \frac{|N^{\pi}|}{|A_T|}, \qquad P^{\pi} = \frac{|\{ i \in \cup_t S_t : y_i = 1,\, s_i^{\pi} + d < k_i \}|}{|\cup_t S_t|}
```

**Antecedência.** Para cada KEV antecipado, a folga é ℓᵢ = kᵢ − sᵢ − d. São reportados a mediana e a distribuição de ℓ, o recall com folga mínima R(L) para L ∈ {1, 7, 30, 90} dias e um índice que junta quantidade e folga, o recall ponderado pela antecedência, em que um KEV não antecipado vale zero e a folga é limitada a 90 dias para que poucos casos extremos não dominem:

```latex
LW^{\pi} = \frac{1}{|A_T|} \sum_{i \in A_T} \frac{\min\big(\max(k_i - s_i^{\pi} - d,\, 0),\, 90\big)}{90}
```

Completam o bloco o tempo entre a entrada na fila e a seleção dos KEV (sᵢ − eᵢ) e a proporção de seleções feitas para CVEs com mais de 90 dias na fila. Esta última detecta um efeito colateral possível da dinâmica: correr atrás de CVEs antigas cujo score subiu e deixar as novas esperando.

**Estabilidade.** A estabilidade é medida do ponto de vista de quem executa: o que estava planejado para a próxima semana continuou planejado? Em cada semana, depois de selecionar S\_t, o plano para a semana seguinte é Plan\_t, as CVEs nas posições K+1 a 2K do ranking. A aderência ao plano é a fração do trabalho da semana que já estava prevista:

```latex
\alpha_t = \frac{|S_t \cap \mathrm{Plan}_{t-1}|}{|\mathrm{Plan}_{t-1}|}
```

Na política estática, o plano só é desfeito por CVEs novas que chegam com score maior. Na dinâmica, também pela releitura dos scores. Para separar as duas causas, calcula-se em cada semana a seleção contrafactual S′\_t, obtida congelando os scores das CVEs que já estavam na fila nos valores usados em t − 1 e mantendo os das recém-chegadas. A instabilidade causada pela atualização é a fração da seleção que mudou por causa dela, e vale zero na estática por construção:

```latex
U_t = 1 - \frac{|S_t \cap S'_t|}{|S_t|}
```

Como medida secundária da ordem, é calculada a distância de Kendall normalizada entre os rankings de t − 1 e t, restrita às CVEs que permanecem na fila e que estavam entre as 4K primeiras em algum dos dois momentos, além do número de vezes que cada CVE entra e sai do plano antes de ser selecionada (oscilação).

**Custo de mudar prioridades.** A pergunta central é se o ganho paga a instabilidade. O indicador que responde diretamente é o número de seleções trocadas pela atualização para cada KEV adicional antecipado:

```latex
\Gamma = \frac{\sum_t |S_t^{\mathrm{DIN}} \setminus S_t'^{\,\mathrm{DIN}}|}{|N^{\mathrm{DIN}}| - |N^{\mathrm{EST}}|}
```

Se o denominador for zero ou negativo, a dinâmica é dominada e Γ não é calculado. Com Γ em mãos, qualquer leitor pode aplicar o próprio custo por mudança c e verificar se o ganho compensa. Por isso o resultado é apresentado como uma curva de equilíbrio em função de c, e não como um único veredito.

**Operação.** A utilização da capacidade é Σ|S\_t| / (K · |T|), e o tamanho da fila elegível por semana também é registrado. Quando a fila esvazia, as políticas deixam de ser comparáveis em precisão, e isso precisa aparecer.

| Métrica | Responde a | Papel |
| --- | --- | --- |
| R (sobre A\_T) | Eficácia | Primária |
| R(L), mediana de ℓ, LW | Antecedência | Primária (LW) e secundárias |
| U\_t médio, α\_t médio | Estabilidade | Primária (U) e secundária (α) |
| Γ e curva de equilíbrio | Trade-off | Primária para a conclusão |
| P, Kendall, oscilação, idade das seleções, utilização | Contexto | Secundárias |

## 7. Hipóteses testáveis

Há uma hipótese primária e seis condicionais. Quatro delas preveem situações em que a política dinâmica não ajuda ou piora algo, porque o objetivo é mapear as condições do benefício, não confirmá-lo. Todas são fixadas antes de rodar e avaliadas primeiro na coorte de 2024; T1 e T2 só entram em H7.

O K primário é 50 seleções por semana, declarado a priori. Ele seleciona cerca de 3.150 CVEs ao longo das 63 semanas da coorte de 2024, cerca de 10% dela. É um valor intermediário: muito acima das cerca de 316 CVEs com EPSS inicial acima de 0,1%, o que força a política estática a entrar na região de empate, e muito abaixo do tamanho da coorte. O tamanho mínimo de efeito considerado relevante é de 5 pontos percentuais de recall sobre A\_T.

| # | Hipótese | Previsão testável | Como é refutada |
| --- | --- | --- | --- |
| H1 (primária) | Com K = 50, a dinâmica antecipa mais KEV que a estática | ΔR = R^DIN − R^EST > 0, com IC 95% acima de zero e McNemar exato p < 0,05 | IC inclui zero, ou ΔR < 5 p.p. (ganho sem relevância prática) |
| H2 (orçamento) | O ganho não é monótono em K: pequeno quando K é tão baixo que as duas ficam no topo informativo, maior em valores intermediários, e pequeno de novo quando K se aproxima do tamanho da fila | ΔR(K) tem máximo interior na grade {10, 25, 50, 100, 250, 500} | ΔR(K) monótono na grade |
| H3 (tempo até o KEV) | O ganho vem de KEV que demoraram a entrar no catálogo | ΔR ≈ 0 no estrato kᵢ − pᵢ ≤ 30 dias e ΔR > 0 no estrato > 30 dias | Ganho igual ou maior no estrato curto |
| H4 (antecedência) | Os KEV que só a dinâmica captura são capturados tarde | Mediana de ℓ nos capturados só pela dinâmica < mediana nos capturados pelas duas; ganho relativo em LW < ganho relativo em R | Capturas exclusivas da dinâmica com folga igual ou maior |
| H5 (frequência) | Atualizar menos vezes preserva a maior parte do ganho a uma fração do custo | DIN-4 retém ≥ 80% do ΔR de DIN-1 com ≤ 50% da instabilidade acumulada ΣU\_t | DIN-4 perde mais de 20% do ganho, ou não reduz a instabilidade pela metade |
| H6 (efeito colateral) | A dinâmica desloca capacidade para CVEs antigas | Proporção de seleções com mais de 90 dias de fila e tempo até a seleção de CVEs novas maiores na dinâmica | Sem diferença ou diferença inversa |
| H7 (generalização) | O sinal de ΔR em K = 50 se repete fora do desenvolvimento | Mesmo sinal em T1 (v3) e em T2 (v4), analisados separadamente | Sinal invertido em T1 ou em T2 |

H2, H3 e H4 são justamente as condições em que a dinâmica pode não valer a pena. Elas são o produto principal do experimento, mais do que H1. Se H1 falhar, o experimento continua informativo: mostra que, com orçamento fixo e decisão semanal, ler o EPSS uma única vez na entrada já captura o que há para capturar, e que a Política 4 não tem o que equilibrar.

Na análise secundária que atravessa a troca de modelo, há uma previsão descritiva, fora do teste de hipóteses: na semana de 2025-03-17, U\_t da dinâmica deve ficar muito acima da sua mediana semanal sem ganho correspondente em KEV antecipados. Isso mostraria a instabilidade exógena causada pelo modelo, e não por informação nova.

## 8. Fatores, sensibilidade e incerteza

O desenho principal cruza política, orçamento e coorte. A frequência de atualização é um fator secundário, cruzado apenas com o K primário e com a grade de K na coorte de desenvolvimento, para conter o número de comparações.

| Fator | Níveis | Observação |
| --- | --- | --- |
| Política | EST, DIN-1, ALEAT, FIFO, CVSS-EST | Contraste primário EST × DIN-1 |
| Frequência (Δ) | 1, 2, 4, 13 semanas; ∞ | Só na família DIN; Δ = ∞ é a EST |
| Orçamento K por semana | 10, 25, 50, 100, 250, 500 | 50 é o primário |
| Coorte | Desenvolvimento 2024; T1; T2 | T1 e T2 avaliadas uma única vez, separadamente |

A análise de sensibilidade muda um item de cada vez em relação ao caso principal, sempre em K = 50, e pergunta se o sinal e a ordem de grandeza de ΔR, ΔLW e Γ se mantêm.

| Item variado | Caso principal | Alternativa | Por quê |
| --- | --- | --- | --- |
| Corpus | Variante (32.173) | Original (39.934) | Decisão da equipe; a variante usa status atual |
| Janela do rótulo | 365 dias | 180 dias | Robustez à escolha de W |
| KEV tardios | Negativos | Excluídos | Evitar punir seleções corretas fora da janela |
| Critério de ordem | Percentil | Score bruto | Efeito do percentil na estática |
| Corte de informação | t − 1 dia | t − 7 dias | Robustez a atrasos de publicação dos dados |
| Atraso de execução d | 0 | 7 e 30 dias | Aproximar "corrigido antes do KEV" |
| Expiração da fila | Sai em pᵢ + 365 | Sem expiração | Efeito do backlog |
| CVEs com EPSS tardio | Incluídas a partir de aᵢ | Excluídas se aᵢ − pᵢ > 30 dias | Ligadas às 375 exclusões do artigo (hipótese) |
| Dia da decisão | Segunda-feira | Quinta-feira | Artefato do calendário |
| CVSS da referência CVSS-EST | Nota da CNA | Nota `Primary` atual | Quanto a referência tradicional depende da fonte |

A incerteza tem três fontes, tratadas separadamente. A primeira é o desempate: como a maior parte da fila está empatada, o resultado de cada política depende do sorteio de uᵢ. Cada configuração é rodada com 200 sementes, usando a mesma semente para todas as políticas na mesma réplica (números aleatórios comuns), e reportam-se média e intervalo de 2,5% a 97,5% entre sementes.

A segunda é a amostragem dos eventos. Como as duas políticas são avaliadas sobre os mesmos KEV, a inferência primária é pareada: para cada KEV de A\_T registra-se se foi antecipado por EST e por DIN-1. O teste de H1 é o McNemar exato sobre os pares discordantes, e o intervalo de confiança de ΔR e ΔLW vem de bootstrap por KEV (B = 10.000), dentro de cada semente. A terceira é a dependência entre CVEs: CVEs publicadas na mesma semana competem pela mesma capacidade e não são independentes. Como análise de robustez, há um bootstrap por blocos que reamostra semanas de publicação, reconstrói a coorte e roda a simulação de novo (B = 1.000). Ele é o único que dá intervalo para U, α e Γ.

Só H1 é confirmatória, com α = 0,05. As demais são reportadas com estimativas e intervalos e rotuladas como condicionais. Se forem resumidas em testes binários, aplica-se a correção de Holm ao conjunto H3 a H6. O poder estatístico é limitado e isso é dito antes de rodar: com provavelmente menos de 100 KEV em A\_T na coorte de 2024 (o número exato sai na Fase B), 5 p.p. equivalem a no máximo 5 eventos líquidos, e o McNemar só tende a rejeitar com diferenças bem maiores. A leitura principal será o tamanho do efeito com seu intervalo, não o p-valor.

## 9. Controle de vazamento temporal

Toda informação usada por uma política passa por uma única função, `estado(i, c)`, que devolve o que se sabia sobre a CVE i até a data c, e nenhuma política tem acesso direto às tabelas. Essa função devolve a data de publicação se pᵢ ≤ c, o último percentil e score do EPSS com `score_date` ≤ c, junto com a versão do modelo, a nota CVSS da CNA e se a CVE já estava no KEV (kᵢ ≤ c). O rótulo yᵢ e a data kᵢ completa ficam numa tabela separada, que só o módulo de avaliação lê, depois que a simulação termina.

Os testes automáticos abaixo rodam antes de qualquer experimento e precisam passar para que um resultado seja aceito.

| Teste | O que verifica |
| --- | --- |
| Sem futuro no EPSS | Para uma amostra de pares (i, t), toda observação devolvida por `estado(i, c(t))` tem `score_date` ≤ c(t) |
| Sem futuro no KEV | Nenhuma CVE com kᵢ ≤ c(t) aparece em E\_t; nenhuma com kᵢ > c(t) é marcada como conhecida |
| Rotulagem isolada | As políticas não importam o módulo de rótulos (teste de importação) |
| Invariância ao futuro | Mudar valores do EPSS ou do KEV posteriores a T\_fim não altera nenhuma seleção |
| Versão única | Na coorte de 2024 e em T1, toda observação usada tem `model_version` v2023.03.01; em T2, v2025.03.14 |
| Estática congelada | Na EST, o score de cada CVE é igual em todas as semanas; U\_t = 0 |
| Orçamento | \|S\_t\| = min(K, \|E\_t\|) em toda semana e para toda política |
| Reprodução da Fase A | Os 13 resultados da variante são reproduzidos exatamente pelos módulos novos |

Há três vazamentos que não dá para eliminar e por isso são declarados. O corpus variante foi selecionado pelo status atual do NVD, o que é tratado pela sensibilidade com o corpus original. A nota CVSS da CNA pode ter sido adicionada depois da publicação, mas ela só é usada pela referência CVSS-EST e nunca pelas políticas principais. Por fim, o próprio EPSS pode refletir a mesma evidência de exploração que leva a CISA a incluir a CVE no KEV: uma "antecipação" de poucos dias pode ser só o EPSS vendo a exploração antes do catálogo. É por isso que R(7), R(30) e LW pesam mais do que R(1) na interpretação.

## 10. Riscos metodológicos

O risco que mais ameaça a interpretação é uma explicação rival para um eventual ganho da dinâmica: ele pode não vir de atualizar continuamente, mas apenas de ler o EPSS uma vez algumas semanas depois da publicação, quando o score já se estabilizou. Para separar as duas coisas, entra como política exploratória a EST+30, que relê o score uma única vez, 30 dias depois da entrada, e o congela. Se ela capturar quase todo o ganho da DIN-1 com instabilidade mínima, a conclusão muda de "atualize sempre" para "espere a primeira leitura amadurecer".

| Risco | Efeito provável | Mitigação |
| --- | --- | --- |
| Poucos eventos em A\_T | Intervalos largos; H1 pode não atingir significância mesmo com efeito real | Foco em tamanho de efeito; poder declarado antes (seção 8) |
| Empates dominam a fila | Para K alto, o resultado da EST depende do sorteio, não do EPSS | 200 sementes; reportar a fração das seleções feitas dentro de empates |
| Ganho vem de uma leitura tardia, não da atualização contínua | Conclusão errada sobre frequência | Política exploratória EST+30 e família DIN-Δ |
| EPSS e KEV reagem à mesma evidência | "Antecipações" de poucos dias sem valor operacional | Prioridade a R(7), R(30) e LW; distribuição de ℓ sempre mostrada |
| Mudanças dentro de uma mesma versão do EPSS | Instabilidade atribuída à política quando é do modelo (a mediana semanal caiu em abr/2025 e teve um pico em nov/2025, ambos dentro do v4) | Detectar dias com salto na distribuição (distância KS entre dias consecutivos), marcar essas semanas e reportar U com e sem elas |
| Deriva do percentil | O percentil de uma CVE muda porque a população de CVEs muda, sem mudança no risco dela | Sensibilidade com score bruto; parcela de U explicada por variações de score abaixo de um ε |
| Fila só com a coorte | Uma organização real tem backlog misto e vê só as CVEs dos seus ativos | Declarar como limite de validade externa; K é cenário, não produtividade |
| KEV como verdade de referência | Catálogo incompleto, centrado nos EUA; data de inclusão ≠ data da exploração | Linguagem de "antecedência em relação ao KEV"; nenhuma alegação sobre ataques evitados |
| Seleção ≠ correção; esforço uniforme | Superestima o benefício prático | Atraso d na sensibilidade; declarar |
| Corpus filtrado pelo status atual | Viés de seleção | Sensibilidade com o corpus original |
| Falhas no arquivo do EPSS | Dias faltando, CVEs que somem de um arquivo | Regra do último valor ≤ c; registrar contagens de dias e CVEs afetados |
| T1 muito curta (\~11 semanas) | Poucos KEV; resultado instável | T1 é descritiva; H7 exige só a concordância de sinal |
| Escolhas feitas depois de ver dados | Resultado ajustado ao que se queria ver | Protocolo congelado nesta data; qualquer mudança vai para um registro de desvios com data e motivo |

## 11. Execução da Fase B

A Fase B vai rodar numa pasta nova, `extensao/`, ao lado da pasta `projeto/` da Fase A, que passa a ser somente leitura. Na primeira execução, um manifesto com o hash SHA-256 de cada arquivo da Fase A é gravado, e toda execução seguinte confere esses hashes antes de começar e para se algum tiver mudado. Os dados brutos novos são gravados uma única vez: os scripts de coleta se recusam a sobrescrever um arquivo existente. Cada experimento grava numa pasta própria em `extensao/results/<data>-<id>/`, com a configuração usada, as sementes, as versões das bibliotecas e o hash dos dados de entrada.

A coleta se divide entre o que dá para fazer daqui e o que precisa rodar na máquina de vocês, porque a API do NVD está bloqueada neste ambiente.

| Script | Onde roda | O que produz |
| --- | --- | --- |
| `coleta/epss_diario.py` | Aqui ou local | Arquivo diário do EPSS de 2024-01-01 a 2026-06-14, filtrado para as CVEs das coortes, com `model_version`, score e percentil por dia, em Parquet |
| `coleta/kev.py` | Aqui ou local | Catálogo KEV na versão de F, com hash, e a lista de remoções tirada do histórico git |
| `coleta/nvd_cves.py` | Local, com chave de API do NVD | Dump bruto das CVEs publicadas em 2025, no mesmo formato da Fase A, com retomada e controle de taxa |
| `coleta/nvd_historico.py` | Local, com chave de API do NVD | Histórico de mudanças (`cvehistory/2.0`) das CVEs das coortes, para reconstruir CVSS e CWE por data; usado na sensibilidade e nas fases seguintes |

A ordem de execução é a seguinte.

1. Congelar a Fase A (manifesto de hashes) e gravar este protocolo com a data, junto com um registro de desvios vazio.
2. Coletar EPSS diário e KEV; vocês rodam a coleta do NVD de 2025 e do histórico.
3. Construir as tabelas `estado` e `rotulos` e rodar a bateria de testes da seção 9, incluindo a reprodução exata dos 13 resultados da variante.
4. Reportar os números descritivos que este protocolo deixou em aberto (tamanho de A\_T, conhecidos na entrada, empates, utilização) antes de olhar qualquer comparação entre políticas.
5. Rodar a coorte de 2024 e as análises de sensibilidade; só depois, T1 e T2, uma única vez.

O código usa Python com pandas, numpy, pyarrow e scipy, e pytest para os testes. Não há ML nem dependências além dessas.

## 12. Pontos em aberto antes de rodar

Cinco escolhas deste protocolo foram feitas por mim e precisam do aval de vocês antes do congelamento, porque mudam o que conta como resultado.

A primeira é o K primário de 50 por semana e o efeito mínimo relevante de 5 pontos percentuais de recall. Os dois são razoáveis, mas arbitrários, e precisam ser fixados agora, não depois de ver a curva. A segunda é tratar CVEs que entram no KEV como correção obrigatória, fora do orçamento. Isso implementa a decisão de que KEV já conhecido não conta como descoberta, mas também significa que o orçamento K é só o discricionário. A terceira é a saída da fila aos 365 dias, que alinha fila e rótulo mas não é como uma equipe real trabalha; a alternativa sem expiração está na sensibilidade.

A quarta é incluir a EST+30 como política exploratória. Ela não estava no pedido original, mas é a forma mais direta de saber se um eventual ganho vem de atualizar sempre ou só de esperar o score amadurecer. A quinta é operacional: quem roda a coleta do NVD de 2025 e do histórico, com qual chave de API e em qual prazo. Sem o histórico, a sensibilidade da referência CVSS-EST fica limitada à nota atual, e isso será declarado.

Com esses cinco pontos confirmados, o protocolo é congelado com a data do aval, e a execução começa pela etapa 1 da seção 11.

## 13. Revisão 1 — definições afetadas pelo parecer de 21/11 (a congelar)

O primeiro parecer de 21/11 aprovou as decisões 1, 2, 4 e 5 com ajustes e pediu revisão da 3. O segundo parecer, do mesmo dia, pediu três ajustes finais: não presumir a direção do efeito do fim da simulação, corrigir a nomenclatura e acrescentar uma sensibilidade a H3 e H4, e não tratar normalizações como garantia de comparabilidade entre coortes. Os dois pareceres estão incorporados, e esta é a versão para congelamento. Em caso de conflito com as seções 3 a 9 e 11, vale esta seção. Nenhuma política ou hipótese nova foi acrescentada. Os números da coorte de 2024 citados aqui são descritivos, calculados sobre o corpus variante com decisões às segundas-feiras, e não envolvem nenhuma comparação entre políticas.

### 13.1 Três horizontes separados (decisão 3)

A versão anterior usava a janela do rótulo também como prazo de permanência na fila. A revisão separa três horizontes, cada um com uma única função. O horizonte do rótulo, W = 365 dias, só define yᵢ e não interfere na simulação. A permanência na fila passa a ser ilimitada no cenário principal: uma CVE sai da fila apenas quando é selecionada, quando entra no KEV ou quando a simulação termina. O término da simulação, T\_fim, é definido pela versão do EPSS: 2025-03-16 no desenvolvimento e em T1, e 2026-06-14 em T2. A expiração aos 365 dias continua existindo, mas só como sensibilidade.

```latex
E_t = \{\, i \in C : p_i \le c(t),\; a_i \le c(t),\; k_i > c(t),\; t \le T_{\mathrm{fim}},\; i \notin \textstyle\bigcup_{u<t} S_u \,\}
```

Na coorte de 2024 a diferença prática entre os dois cenários é pequena e localizada. Só as 6.696 CVEs publicadas antes de 2024-03-16 chegam a completar 365 dias antes de T\_fim, e ficam no máximo cerca de 11 semanas a mais na fila. Em T2, o mesmo vale para as CVEs publicadas antes de 2025-06-14, por até cerca de 13 semanas. O cenário sem expiração tem uma consequência que precisa aparecer nos resultados: uma CVE pode ser selecionada depois de encerrada sua janela de rótulo. Se ela não entrou no KEV, é um falso positivo comum. Se entrou no KEV depois de 365 dias (os "tardios", 11 na coorte de 2024), ela conta como negativo no caso principal, mesmo tendo sido selecionada antes da inclusão. Por isso os tardios selecionados antes de kᵢ passam a ser contados e reportados à parte em todas as execuções.

### 13.2 Denominador do recall

O parecer está certo: uma seleção feita antes de T\_fim pode antecipar um KEV incluído depois de T\_fim, e excluir esses eventos jogava fora antecipações legítimas. O denominador principal passa a ser o conjunto A de todos os antecipáveis dentro da janela do rótulo, e A\_T vira uma das suas duas partes.

```latex
A = \{\, i : y_i = 1,\; k_i > c(e_i) \,\} = A_T \cup A_{\text{pós}}, \qquad R^{\pi} = \frac{|\{ i \in A : s_i^{\pi} + d < k_i \}|}{|A|}
```

Na coorte de 2024, A tem 86 KEV: 73 com inclusão no KEV durante a janela de decisões (A\_T, kᵢ ≤ T\_fim) e 13 depois dela (A\_pós). Ficam fora os 63 conhecidos na entrada (os 40 incluídos até o dia da publicação e mais 23 incluídos antes da primeira decisão em que a CVE estaria elegível) e os 11 tardios. Para os eventos de A\_pós, nenhuma política decide nada depois de T\_fim, embora o KEV ainda não tenha acontecido. Esse corte pode afetar as políticas de forma diferente, mas a direção não é presumida. Ela é estimada comparando ΔR sobre A, sobre A\_T e sobre A\_pós, e pela análise do tempo disponível ωᵢ (seção 13.6). R sobre A é a métrica principal de H1, e R sobre A\_T é reportado ao lado.

A\_T reúne os KEV com inclusão durante a janela de decisões, o que não significa que tiveram oportunidades temporais equivalentes. Uma CVE publicada em dezembro de 2024 e incluída no KEV em fevereiro de 2025 teve muito menos semanas elegíveis do que uma publicada em janeiro de 2024 e incluída em junho.

### 13.3 KEV conhecidos e orçamento (decisão 2)

No cenário principal, K continua sendo apenas a capacidade discricionária. A sensibilidade pedida acrescenta uma fila obrigatória M\_t com as CVEs da coorte que se tornaram conhecidas no KEV e ainda não tinham sido selecionadas, incluindo as conhecidas na entrada. A cada semana a fila obrigatória é atendida primeiro, por ordem de inclusão no KEV, e só a capacidade que sobra vai para a política: K\_disc(t) = max(0, K − m\_t), em que m\_t é o número de itens obrigatórios atendidos na semana. Essas seleções não contam como antecipação.

Essa variante tem um efeito que precisa ser lido com cuidado: uma política que antecipou um KEV não paga por ele de novo quando a CVE entra no catálogo, de modo que antecipar passa a liberar capacidade futura. Isso é realista, mas cria uma retroalimentação que não existe no cenário principal. Na coorte de 2024 a carga obrigatória chega a no máximo cerca de 140 CVEs em 63 semanas (63 conhecidos na entrada mais os KEV de A\_T que a política não antecipou), ou até 2,2 por semana. Isso é desprezível com K = 50, mas pode consumir mais de 20% da capacidade com K = 10, e é aí que a sensibilidade deve mostrar diferença.

### 13.4 EST+30 (decisão 4)

A CVE é elegível desde eᵢ com o score de entrada. Na primeira decisão rᵢ ≥ eᵢ + 30 dias, o score é relido uma única vez e congelado. Se a CVE for selecionada antes de rᵢ, não há releitura. Se ela entrar no KEV antes de rᵢ, sai da fila como em qualquer outra política.

```latex
\sigma_i^{\mathrm{EST+30}}(t) = \begin{cases} \pi_i\big(c(e_i)\big) & t < r_i \\ \pi_i\big(c(r_i)\big) & t \ge r_i \end{cases} \qquad r_i = \min\{\, t \in \mathcal{T} : t \ge e_i + 30 \text{ dias} \,\}
```

A comparação de leitura direta fica assim: o ganho de EST+30 sobre EST mede o valor de uma leitura tardia, e o ganho de DIN-1 sobre EST+30 mede o valor adicional da atualização contínua. Como EST+30 também muda a ordem uma vez, ela tem U\_t ≠ 0 nas semanas em que ocorrem as releituras, e esse custo entra em Γ do mesmo jeito.

### 13.5 Relevância, significância e relato (decisão 1)

K = 50 e o limiar de 5 p.p. ficam mantidos. Todo resultado passa a trazer o número absoluto de KEV adicionais antecipados, ΔN, ao lado de ΔR, e a grade completa de K sempre aparece, não só o K primário. Com |A| = 86, 5 p.p. equivalem a 4,3 eventos, e o limiar operacional passa a ser de pelo menos 5 KEV adicionais. Significância e relevância são avaliadas separadamente, e a conclusão segue a tabela abaixo.

| Intervalo de ΔR exclui zero? | ΔN ≥ 5? | Leitura |
| --- | --- | --- |
| Sim | Sim | Benefício estatístico e prático |
| Sim | Não | Diferença real, mas pequena demais para justificar a política |
| Não | Sim | Inconclusivo: efeito potencialmente relevante, sem poder para confirmar |
| Não | Não | Sem evidência de benefício |

### 13.6 O que a nova fila muda nas hipóteses, nos denominadores e na comparabilidade

As hipóteses continuam as mesmas. O que muda são os denominadores e uma análise adicional. H1 é testada sobre A. H3 e H4 têm como análise principal o conjunto A\_T, os 73 KEV com inclusão no KEV durante a janela de decisões, e uma sensibilidade sobre os 86 de A. Nas duas, cada evento recebe o tempo efetivamente disponível para seleção, que não depende da política: o número de decisões semanais em que a CVE estava visível, ainda fora do KEV e dentro da simulação.

```latex
\omega_i = \big|\{\, t \in \mathcal{T} : e_i \le t \le T_{\mathrm{fim}},\; c(t) < k_i \,\}\big|
```

A restrição a A\_T pode enviesar a leitura de H3, e esse viés precisa ser verificado, não só declarado. Para entrar no KEV até T\_fim com atraso longo, uma CVE precisa ter sido publicada cedo. Então, dentro de A\_T, o estrato "mais de 30 dias" tende a concentrar CVEs do início de 2024 com ω alto, enquanto A\_pós concentra o oposto. Com isso, atraso até o KEV e tempo disponível ficam correlacionados, e um ganho da dinâmica no estrato longo pode refletir apenas mais semanas para a atualização agir. Por isso H3 é reportada por estrato de atraso, por faixa de ω (1, 2 a 4, 5 a 13 e mais de 13 semanas) e pelo cruzamento dos dois. Além disso, comparam-se as distribuições de data de publicação, atraso e ω entre A\_T e A\_pós. Com poucos eventos por célula, o cruzamento é descritivo. Se o ganho acompanhar ω, e não o atraso dentro de cada faixa de ω, a conclusão de H3 passa a ser sobre exposição, e não sobre o tempo até o KEV.

Para H4, a mediana da folga é calculada sobre A\_T, com sensibilidade sobre A; LW continua sobre A, com teto de 90 dias. H6 fica mais relevante sem expiração, porque o backlog antigo nunca desaparece, e passa a reportar a distribuição completa da idade das CVEs selecionadas. H2 e H5 não mudam.

Nos outros denominadores, a precisão continua dividindo pelo total de seleções, que é igual entre políticas enquanto a fila não esvazia. Sem expiração a fila esvazia mais tarde, o que estende a faixa de K em que precisão e recall continuam proporcionais. As medidas de estabilidade (U\_t, α\_t, Kendall no top-4K) não dependem do tamanho total da fila e não mudam.

A comparabilidade entre políticas dentro de uma coorte não é afetada: todas veem as mesmas chegadas, o mesmo T\_fim e a mesma regra de saída, e a avaliação pareada por evento continua válida. A distância entre os conjuntos elegíveis das políticas cresce com o tempo, porque cada seleção muda a fila seguinte, mas isso é parte do efeito que se quer medir, e não um problema de comparação.

A comparabilidade entre coortes é o ponto mais frágil, e nenhuma normalização a resolve sozinha. As janelas de decisão têm 63, cerca de 11 e cerca de 65 semanas. Sem expiração, o tamanho e a idade da fila dependem desse comprimento, e o volume semanal de CVEs muda de um ano para o outro. Para cada coorte são reportados, semana a semana e resumidos, as chegadas à fila, o tamanho da fila elegível |E\_t|, a utilização da capacidade, a razão K/|E\_t| e a razão sobre as chegadas ρ = K / chegadas semanais médias. Na coorte de 2024 chegam em média cerca de 596 CVEs por semana, então K = 50 corresponde a ρ ≈ 8,4%.

H7 é avaliada com K = 50 e com K ajustado por ρ. Essas razões descrevem o contexto de cada coorte, mas não tornam as coortes diretamente comparáveis. Duas coortes com o mesmo ρ podem ter filas, idades e composições de score muito diferentes, e o mesmo vale para K/|E\_t|. Por isso H7 continua limitada à concordância de sinal de ΔR, e T1 permanece descritiva.

### 13.7 Sequência mínima de execução e incerteza em etapas

Concordo em adiar a parte cara da avaliação de incerteza, com uma ressalva sobre o que é caro. O bootstrap por eventos e o McNemar não exigem nova simulação: reamostram cerca de 86 pares de resultados binários e rodam em segundos, mesmo com 10 mil reamostragens. O custo está em multiplicar as simulações, seja pelas 200 sementes em toda a grade de K, seja pelas 1.000 simulações do bootstrap por blocos. A proposta é incluir na entrega da disciplina a parte barata e deixar a cara para a versão de publicação.

1. Congelar a Fase A (manifesto de hashes) e este protocolo com a Revisão 1.
2. Coletar o EPSS diário só de 2024-01-01 a 2025-03-16, filtrado para a coorte de 2024, e o KEV em F. O dump do NVD de 2024 já existe, então nenhuma coleta do NVD bloqueia a comparação EST × DIN-1.
3. Construir `estado` e `rotulos`, rodar os testes de integridade da seção 9 e reproduzir exatamente os 13 resultados da variante.
4. Relatório descritivo antes de qualquer comparação: tamanhos de A, A\_T e A\_pós, conhecidos na entrada, fila ao longo do tempo, empates e chegadas por semana.
5. Execução determinística: EST, DIN-1, EST+30, DIN-Δ, FIFO, CVSS-EST e uma ALEAT, na grade completa de K, com desempate fixo dado por um hash do identificador da CVE, igual para todas as políticas. Os resultados são rotulados como estimativas pontuais preliminares.
6. Incerteza leve: 20 sementes de desempate, McNemar exato e bootstrap por eventos para K = 50.
7. Sensibilidades com K = 50 (expiração aos 365 dias, KEV consumindo capacidade, atraso d, corpus original, score bruto).
8. Coleta local do NVD de 2025 e execução de T1 e T2, uma única vez.
9. Incerteza completa para publicação: 200 sementes e bootstrap por blocos.

A entrega da disciplina cobre as etapas 1 a 6, e a 7 se houver tempo. Os resultados da etapa 5 nunca aparecem sozinhos como conclusão: o texto da entrega diz explicitamente que se trata de estimativas pontuais com um único desempate, e que a incerteza disponível é apenas a da etapa 6. O rigor para publicação fica preservado porque nada nas etapas 1 a 6 precisa ser refeito depois: as etapas 7 a 9 só acrescentam informação ao mesmo pipeline congelado.

### 13.8 Testes de integridade afetados

Os testes abaixo se somam aos da seção 9. A linha "Orçamento" daquela tabela é substituída pela linha "Orçamento discricionário" desta, e as demais continuam valendo. Os valores fixados para a coorte de 2024 vêm do cálculo descritivo desta revisão e funcionam como teste de regressão: se a implementação der outro número, a diferença precisa ser explicada antes de seguir.

| Teste | O que verifica |
| --- | --- |
| Fila sem expiração | No cenário principal, uma CVE só sai de E\_t por seleção, inclusão no KEV ou t > T\_fim. Na sensibilidade com expiração, nunca aparece com t > pᵢ + W |
| Conjuntos de avaliação | A\_T e A\_pós são disjuntos e somam A; nenhum conhecido na entrada aparece em E\_t; na coorte de 2024, A = 86, A\_T = 73, A\_pós = 13 e 63 conhecidos na entrada |
| Rótulo independente da fila | yᵢ, A, A\_T e A\_pós são idênticos em todos os cenários de fila e em todas as políticas |
| Tempo disponível | ωᵢ é calculado só a partir de eᵢ, kᵢ e T\_fim, é igual em todas as políticas e vale pelo menos 1 para todo evento de A (uma CVE que só ficaria visível depois de T\_fim não entra em A; na coorte de 2024 são 2 CVEs, nenhuma no KEV a confirmar) |
| EST+30 | O score muda no máximo uma vez, na decisão rᵢ; antes de rᵢ é igual ao da EST |
| Orçamento discricionário | Cenário principal: o número de selecionadas na semana é min(K, tamanho de E\_t), sem nenhuma CVE já no KEV. Sensibilidade: os itens obrigatórios são atendidos primeiro, K\_disc(t) = max(0, K − m\_t), e nunca contam como antecipação |
| Desempate determinístico | Na execução determinística, o desempate é um hash fixo do identificador da CVE, igual para todas as políticas, e duas execuções da mesma configuração dão seleções idênticas. Nas 20 sementes, a mesma semente gera o mesmo uᵢ em todas as políticas |
| Métricas de contexto | Chegadas, tamanho de E\_t, utilização e K/tamanho de E\_t são calculados para toda semana e coorte, e a utilização nunca passa de 1 |

### 13.9 Congelamento e escopo para a entrega de 22/11

Com o aval final, este protocolo fica congelado na data do aval, e qualquer mudança posterior vai para o registro de desvios, com data e motivo. Pelo prazo, a entrega de 22/11 se limita à comparação EST × DIN-1 na coorte de 2024, cobrindo as etapas 1 a 5 da seção 13.7: congelamento, coleta do EPSS diário do período v3 e do KEV, testes de integridade, relatório descritivo e execução determinística na grade de K. As outras políticas da execução determinística entram só se não atrasarem esse núcleo. A etapa 6 (20 sementes, McNemar e bootstrap por eventos) entra se os testes passarem a tempo. Se não, a entrega apresenta os resultados determinísticos rotulados como estimativas pontuais preliminares, sem conclusão sobre as hipóteses.
