# Registro de desvios e observações — Fase C

Pré-registro: `freeze/protocolo_fase_c_preregistro.md` (SHA-256 e horário em `.sha256`), gravado antes da primeira
execução da DIN-ESTAB. Documento completo: https://claude.ai/artifact/HDg9a6bD55PPsqAsgYTwca (revisão 7).

| # | Data | Item | O que aconteceu | Tratamento |
|---|---|---|---|---|
| 1 | 2026-11-21 | Congelamento | O protocolo completo não foi exportado para arquivo (a exportação não fica gravada no ambiente). O pré-registro em arquivo resume todas as decisões travadas (grade, hipóteses, limiares, métricas, regra de escolha) e aponta a revisão 7 do documento. | Em caso de conflito, vale o arquivo pré-registrado. |
| 2 | 2026-11-21 | H1 | O valor "moderado" pré-registrado (λ = 0,01) reduziu ΣR em só 9,4%, e H1 foi refutada. A escala em que o bônus passa a ter efeito forte ficou entre 0,03 e 0,3. | Mantida como refutada; o valor não foi trocado depois de ver o resultado. |
| 3 | 2026-11-21 | Regra de escolha | A regra pré-registrada escolheu λ = ∞ (perda de 2 KEV, dentro da tolerância de 2, e ΣR = 0). Ela não considera antecedência: com λ = ∞, N com folga ≥ 30 dias cai de 19 para 16. λ = 0,3 não perde nenhum KEV e reduz ΣR em 79%. | A escolha da regra (λ = ∞) é a configuração confirmatória da Fase D. λ = 0,3 aparece apenas como observação exploratória pós-hoc; se for avaliada na Fase D, terá de ser rotulada assim. |
| 4 | 2026-11-21 | Interpretação | EST aparece dominada por λ = 0,1, 0,3 e ∞. Mas o bônus de estabilidade não foi aplicado à EST: uma "EST com plano travado" também teria ΣR = 0. | A dominância não deve ser lida como vantagem da atualização sobre a estabilidade; EST com bônus não foi testada. |
| 5 | 2026-11-21 | Escopo | Só K = 50 e coorte de 2024, conforme o pré-registro. | Outros K, sensibilidades e coortes de 2025 ficam para depois. |
| 6 | 2026-11-21 | Análise não prevista | Análise do tamanho dos saltos de percentil dos KEV capturados só pela DIN-1 (`mecanismo_saltos_posthoc.json`). | Rotulada como pós-hoc e exploratória; gera hipóteses, não as testa. Incluí-la não mudou nenhum outro arquivo de resultado (hashes conferidos). |
