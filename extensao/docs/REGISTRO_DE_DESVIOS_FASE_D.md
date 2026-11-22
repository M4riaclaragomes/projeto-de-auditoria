# Registro de desvios e decisões de implementação — Fase D

Referência: `freeze/protocolo_fase_d.md`, SHA-256 `dca72aeb…3bb4d`. Nenhuma hipótese, margem, limiar, calendário ou
regra de decisão foi alterada. Todos os itens abaixo foram registrados em 2026-11-21, antes de qualquer dado de 2025
do NVD existir no projeto e, portanto, antes de qualquer resultado de T1 ou T2.

1. **Pasta separada para o EPSS v4.** O manifesto `data/raw/epss_daily/manifest.json` e o teste congelado
   `test_versao_unica_do_modelo` da Fase B exigem um único modelo (v2023.03.01). Os 455 arquivos de 2025-03-17 a
   2026-06-14 (todos v2025.03.14) foram gravados em `data/raw/epss_daily_v4/`, com manifesto próprio. O manifesto da
   Fase B foi restaurado byte a byte, e os 440 arquivos v3 rebaixados têm os mesmos SHA-256 da coleta original.
2. **Janela de leitura do EPSS na T1.** O protocolo não fixa o primeiro arquivo lido. Para a T1 a leitura começa em
   2024-11-01 (v3); observações anteriores à publicação só têm efeito se p ≤ c(t), como em toda a Fase B. Na T2 a
   leitura começa em 2025-03-17, para que só observações v4 sejam usadas. Em 2024 começa em 2024-01-01, como na Fase B.
3. **A_T e A_pós por coorte.** `rotulos.py` (congelado) separa A_T e A_pós com a data fixa de 2025-03-16. Para T1 e
   T2 a separação é refeita em `experimentos_d.py` com o último dia de EPSS usado pela coorte (2025-03-16 e
   2026-06-14), sem alterar `rotulos.py`. Em 2024 a data é a mesma da Fase B. O conjunto A não muda.
4. **Contrafactual da DIN-Δ.** Para as métricas de deslocamento e de revisões por atualização, "sem atualização"
   na DIN-Δ significa manter os scores da semana anterior. A política distingue a chamada real da contrafactual
   pela identidade do vetor de percentis recebido do simulador da Fase C, que não foi alterado. Com Δ = 1 as
   métricas coincidem exatamente com as da DIN-1 (teste).
5. **EST-travada.** Implementada como `EstaticaC` com bônus λ = 2 no simulador da Fase C, sem classe nova.
6. **Teste do não vazamento na DIN-Δ.** Feito por invariância das decisões até a semana 30 quando os percentis
   das semanas posteriores são alterados, com Δ = 2 e Δ = 4.
7. **Bootstrap.** Percentis calculados com a interpolação linear padrão do numpy; reamostragem multinomial dos
   eventos de A com semente 20261121, a mesma para H-D1 e H-D2.
8. **Hipóteses calculadas também em 2024.** A função de decisão da H-D1/H-D2 foi aplicada às coortes de 2024
   apenas para verificar o código e dar contexto. Esses resultados são exploratórios e não substituem a T2.
9. **T1 e T2 não executadas.** O proxy deste ambiente recusa a conexão com `services.nvd.nist.gov` (HTTP 403).
   Conforme o protocolo, o NVD não foi substituído por outra fonte e nada foi simulado para 2025.
