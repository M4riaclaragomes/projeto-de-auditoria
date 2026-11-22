# Documento de continuidade do projeto: priorização adaptativa de vulnerabilidades (Fases A–D)

Versão de 2026-11-21. Este documento permite retomar o projeto em outra conversa ou com outra ferramenta de IA sem reconstruir o histórico. Ele não contém resultados novos: todos os números abaixo vêm dos arquivos de resultados já gravados e congelados das Fases B e C. Em caso de divergência entre este texto e um arquivo de resultados ou protocolo congelado, vale o arquivo.

> **Atualização de 2026-11-22:** as seções 2 e 5 abaixo (versão de 2026-11-21) dizem que a T1 e a T2 da Fase D ainda não foram executadas. Isso está desatualizado: `results/fase_d/T1/` e `results/fase_d/T2/` já existem. Veja `docs/ATUALIZACAO_FASE_D_2026-11-22.md` para os resultados gravados, as conferências feitas e o que ainda precisa ser verificado (por exemplo, se a T2 foi executada uma única vez, como exige o protocolo).

## 0. Contexto em um parágrafo

O projeto parte da replicação do artigo "Evaluating Vulnerability Prioritization Strategies Based on CVSS and EPSS" (SBSeg 2026, Felipe Curty do Rego Pinto), feita como trabalho da disciplina na UFPE (prof. Jean Carlos T. de Araujo). A extensão investiga a priorização adaptativa de vulnerabilidades. A pergunta é como equilibrar três coisas quando a equipe só consegue corrigir K vulnerabilidades por semana: eficácia (antecipar as CVEs que depois entram no catálogo CISA KEV), estabilidade do plano de trabalho e o próprio orçamento limitado. O trabalho avança em fases. Cada fase é auditada, pré-registrada antes de ver os resultados, reprodutível e preserva as fases anteriores sem modificá-las. Não há aprendizado de máquina em nenhuma fase até agora, por decisão explícita.

## 1. Resumo das Fases A, B e C

### Fase A: auditoria da replicação original

A Fase A auditou o projeto de replicação entregue: os scripts PowerShell e Python de coleta do NVD de 2024, a filtragem, a aplicação do histórico do EPSS e as 13 estratégias por limiar do artigo. O relatório está publicado como artefato (endereço na seção 6). Os dados brutos do NVD de 2024 são 23 páginas da API 2.0, coletadas em 2026-10-26, com 40.704 CVEs publicadas. A coorte "variante" filtrada tem 32.173 CVEs. A Fase A é somente leitura: seus 938 arquivos estão em manifesto com hash e nunca foram alterados.

### Fase B: EST × DIN-1 em 2024

A Fase B comparou duas políticas, sob o mesmo orçamento K de seleções semanais, numa fila sem expiração:

- **EST:** ordena cada CVE pelo percentil do EPSS da semana em que ela entrou na fila e nunca o atualiza.
- **DIN-1:** ordena pelo percentil do EPSS atualizado toda semana.

O desenho do experimento é o seguinte:

- **Decisões:** semanais, às segundas-feiras, de 2024-01-01 a 2025-03-10, num total de 63.
- **Informação disponível:** a decisão do dia t usa apenas informação disponível até c(t) = t − 1.
- **Rótulo:** a CVE ser incluída no KEV em até 365 dias após a publicação, medido no catálogo congelado de 2026-11-20.
- **Conjunto de avaliação A:** as CVEs antecipáveis, isto é, que entram no KEV depois de entrar na fila. Ele se divide em A_T (inclusão no KEV durante a janela de decisões) e A_pós (inclusão depois dela). CVEs que já estavam no KEV ao entrar na fila ("conhecidos na entrada") e as que entraram após 365 dias ("tardios", 12 no total) ficam fora do denominador.

Os principais resultados, com K = 50, foram estes:

- A EST antecipou 15 KEV e a DIN-1 antecipou 27.
- A diferença de recall foi de +14 p.p., com IC bootstrap de 4,7 a 23,3, e o McNemar exato deu p = 0,008.
- A vantagem desaparece em K = 500.
- A hipótese H3 (de que o ganho depende do atraso até o KEV) não é identificável, porque o atraso e o tempo disponível na fila (ω) estão perfeitamente confundidos.
- Achado exploratório: 27 dos 28 acertos da estratégia do artigo com EPSS > 0,5% já estavam no KEV na data de publicação. Ou seja, a estratégia reconhece mais do que antecipa.

As tabelas estão em `results/fase_b_2024/`. Os 10 desvios em relação ao protocolo estão registrados em `docs/REGISTRO_DE_DESVIOS.md`.

### Fase C: DIN-ESTAB, o controle de estabilidade

A auditoria da Fase C começou separando três noções de instabilidade:

- **Mudança contrafactual:** CVEs que seriam selecionadas sem a atualização e foram deslocadas por ela. Com K = 50, foram 1.229 deslocamentos envolvendo 806 CVEs únicas. 68% dessas CVEs foram selecionadas depois, com atraso mediano de 1 semana. Portanto, deslocamentos não são cancelamentos.
- **Revisões do plano (ΣR):** CVEs planejadas para a semana seguinte que continuavam elegíveis e não foram executadas. Essa medida se divide em revisões causadas pela atualização do score e revisões por outras causas.
- **Trabalho comprometido e depois cancelado:** não é modelado.

Com K = 50, a DIN-1 teve ΣR = 1.730 e a EST teve ΣR = 1.090.

A DIN-ESTAB soma um bônus λ ao score das CVEs que estavam no plano da semana anterior (posições K+1 a 2K do ranking). A grade testada foi λ ∈ {0; 0,001; 0,003; 0,01; 0,03; 0,1; 0,3; ∞}. O valor λ = ∞ foi implementado como λ = 2 e equivale a travar o plano com uma semana de antecedência. Com λ = 0, a DIN-ESTAB reproduz a DIN-1, o que foi verificado por teste.

Os resultados com K = 50 foram estes:

- Para λ ≤ 0,3, a DIN-ESTAB mantém os mesmos 27 KEV da DIN-1. Com λ = 0,3, ΣR cai para 364, uma redução de 79%.
- Com λ = ∞, ela antecipa 25 KEV com ΣR = 0. As duas perdas são CVE-2024-36401 e CVE-2024-6670, ambas selecionadas uma semana mais tarde. O número de KEV com folga de pelo menos 30 dias cai de 19 para 16.
- A fronteira de Pareto em (N, ΣR) tem dois pontos: λ = 0,3 e λ = ∞.
- A regra de seleção pré-registrada escolheu λ = ∞. O valor λ = 0,3 só pode ser tratado como escolha pós-hoc.

Uma ressalva: o bônus não foi aplicado à EST na Fase C. Os resultados estão em `results/fase_c_2024/` e os 6 desvios em `docs/REGISTRO_DE_DESVIOS_FASE_C.md`.

## 2. Estado atual da Fase D

O objetivo da Fase D é confirmar, numa coorte independente de 2025 com EPSS v4, se o plano travado (λ = ∞) preserva a eficácia da atualização semanal. Ela também testa se o plano travado é pelo menos tão bom quanto simplesmente atualizar com menos frequência (DIN-4).

O que já foi feito:

- **Protocolo congelado.** O arquivo `freeze/protocolo_fase_d.md` tem SHA-256 `dca72aebe9b048a722cb558f32b67a4b7a4d6c4b57fe60b7455abfd326d3bb4d` (2026-11-21T23:16:45Z) e está protegido contra escrita. Ele define:
  - **Coorte S:** CVEs publicadas na janela, não `Rejected` e com EPSS, sem filtro de status.
  - **Calendário:** T2 confirmatória, publicação de 2025-03-17 a 2025-11-19 e 65 decisões de 2025-03-24 a 2026-06-15. T1 descritiva, com 11 decisões. Ponte 2024-S exploratória.
  - **Fila:** começa vazia, sem backlog de períodos anteriores.
  - **Políticas:** sete (EST, DIN-1, λ = ∞, λ = 0,3, DIN-4, DIN-2, EST-travada), com o calendário de releitura da DIN-Δ.
  - **Hipóteses:** H-D1 e H-D2 com regras de decisão fechadas (seção 4 deste documento).
  - **Regras gerais:** tratamento de poucos eventos, testes obrigatórios e ordem de execução.
- **Cópia de leitura do protocolo** publicada como documento (seção 6).
- **Script `scripts/coleta_nvd.py`.** Coleta a API 2.0 do NVD em janelas de até 120 dias e páginas de 2.000 registros. Pode ser retomado, nunca sobrescreve arquivos, repete requisições que falham e valida `totalResults`, IDs únicos e datas de publicação dentro da janela. Grava um manifesto com o SHA-256 de cada página.
- **Módulo `src/vulnprio/coorte_s.py`.** Constrói a coorte S a partir das páginas brutas e conta exclusões por motivo.
- **Testes offline em `tests/test_fase_d_coleta.py`:** 13 testes, que usam as páginas de 2024 da Fase A como respostas simuladas da API. Eles verificaram o seguinte:
  - a coleta simulada reproduz byte a byte as 23 páginas da Fase A;
  - uma coleta interrompida retoma só as páginas que faltam;
  - inconsistências na coleta são recusadas;
  - a coorte S de 2024 tem 40.704 publicadas, 751 rejeitadas e 39.953 restantes antes do filtro de EPSS, e contém todas as 32.173 CVEs da variante.
- **Suíte completa:** 48 testes passam e 2 são pulados (EST+30 e fila obrigatória, fora de escopo desde a Fase B).
- **Manifesto** desta preparação em `freeze/fase_d_preparacao_manifest.json`.

O que ainda não foi feito: nenhuma simulação da Fase D foi executada, nem em 2024 nem em 2025. As políticas DIN-Δ e EST-travada estão especificadas no protocolo, mas ainda não foram implementadas no código.

## 3. Estrutura de arquivos, dependências e reprodução

A raiz da extensão é `extensao/`. A Fase A fica num diretório irmão, `projeto/`, que é somente leitura. Esse caminho pode ser trocado pela variável de ambiente `FASE_A_DIR`.

| Caminho | Conteúdo |
|---|---|
| `../projeto/` | Fase A original: scripts `fetch_nvd_2024.ps1`, `filter_nvd_2024.ps1`, `apply_epss_history_2024.py`, `build_variant_corpus.py`, `analyze_nvd_strategies.py`, `compare_versions.py`; dados `data/nvd-2024-raw/` (23 páginas e manifesto) e `data/nvd-2024-filtered-variant.jsonl`. Não modificar. |
| `freeze/` | Protocolos congelados e manifestos: `fase_a_manifest.json` (938 arquivos), `protocolo_fase_b_congelado.md`, `fase_b_manifest.json` (40), `protocolo_fase_c_preregistro.md`, `fase_c_manifest.json` (21), `protocolo_fase_d.md`, `fase_d_preparacao_manifest.json`, cada protocolo com seu `.sha256`. |
| `src/vulnprio/` | Fase B: `config.py` (constantes), `dados.py` (coorte e matrizes de EPSS), `estado.py` (única fonte de informação das políticas), `rotulos.py`, `politicas.py`, `simulador.py`, `metricas.py`, `estrategias_artigo.py`, `experimentos.py`, `graficos.py`. Fase C: `politicas_c.py`, `simulador_c.py`, `experimentos_c.py`, `graficos_c.py`. Fase D: `coorte_s.py`. |
| `scripts/` | `coleta_epss_diario.py`, `coleta_kev.py`, `coleta_nvd.py`. |
| `tests/` | `test_integridade.py` (Fase B), `test_fase_c.py`, `test_fase_d_coleta.py`. |
| `data/raw/` | `epss_daily/` (440 arquivos diários e manifesto; falta 2024-12-01) e `kev/` (catálogo 2026.11.20 e `.sha256`). Cerca de 660 MB, recriáveis pelos scripts. |
| `data/derived/` | `coorte_2024.csv.gz`, `epss_diario.npz`, `epss_semanal.npz` (gerados por `dados.py`). |
| `results/` | `fase_b_2024/` e `fase_c_2024/`, com tabelas, logs semanais, sementes, figuras e `ambiente.json`. |
| `docs/` | Registros de desvios das Fases B e C. |
| Raiz | `README.md` (Fase B), `README_FASE_C.md`, `README_FASE_D.md`, `rodar_tudo.sh`, `rodar_fase_c.sh`, `requirements.txt`, este `CONTINUIDADE.md`. |

**Dependências:** Python 3.13 com numpy 2.5.3, pandas 3.0.5, scipy 1.18.1, matplotlib 3.11.2 e pytest 9.1.1 (`pip install -r requirements.txt`).

**Comandos**, executados a partir de `extensao/`:

```bash
# conferir que nada congelado mudou
sha256sum -c freeze/protocolo_fase_b_congelado.sha256 freeze/protocolo_fase_c_preregistro.sha256 freeze/protocolo_fase_d.sha256
# testes (todas as fases)
PYTHONPATH=src python -m pytest -q -rs tests          # esperado: 48 passed, 2 skipped
# dados brutos, se faltarem
python scripts/coleta_epss_diario.py --inicio 2024-01-01 --fim 2025-03-16
python scripts/coleta_kev.py
# reproduzir Fase B e depois Fase C
bash rodar_tudo.sh
bash rodar_fase_c.sh
# Fase D: coleta do NVD 2025 (rodar localmente; a API não é acessível do ambiente de análise)
python scripts/coleta_nvd.py --inicio 2025-01-01 --fim 2025-11-19 --saida data/raw/nvd-2025
python scripts/coleta_nvd.py --inicio 2025-01-01 --fim 2025-11-19 --saida data/raw/nvd-2025 --verificar
```

A reprodutibilidade das Fases B e C foi verificada numa cópia limpa do projeto.

## 4. Hipóteses, decisões metodológicas e limitações

### Hipóteses confirmatórias da Fase D (fixadas no protocolo congelado)

**H-D1.** O plano travado preserva pelo menos 75% da vantagem da DIN-1 sobre a EST na coorte T2. A razão de preservação é ρ = (N∞ − N_EST)/(N_DIN1 − N_EST). A inferência usa a forma aditiva D = Σ(a∞ − 0,25·aEST − 0,75·aDIN1), com bootstrap sobre os eventos de A (B = 10.000, semente 20261121) e teste unilateral a 5%. As regras são aplicadas nesta ordem:

1. Se o denominador for ≤ 0, a hipótese é "não avaliável".
2. Se houver menos de 5 KEV de vantagem da DIN-1, |A| < 30 ou menos de 10 pares discordantes, o resultado é "inconclusivo por poucos eventos".
3. Fora desses casos, as classes são:
   - **sustentada:** limite inferior de D maior que 0;
   - **descritivamente atingida, mas inconclusiva:** D ≥ 0 com limite inferior ≤ 0;
   - **refutada:** limite superior de D menor que 0;
   - **não atingida, inconclusiva:** os demais casos.

**H-D2.** O plano travado não é inferior à DIN-4. A margem de não inferioridade é δ = max(2; ⌈0,03·|A|⌉). A H-D2 só é testada se a H-D1 for sustentada (teste em sequência fixa). Contagens iguais não contam como evidência de não inferioridade. A análise também cobre a folga de pelo menos 30 dias e os ganhos e perdas evento a evento.

### Decisões metodológicas estáveis

- **Informação disponível:** a decisão do dia t usa apenas o que existia em c(t) = t − 1.
- **Fila:** sem expiração e com desempate determinístico pelo SHA-256 do identificador da CVE.
- **Rótulo:** inclusão no KEV em até 365 dias, no catálogo congelado de 2026-11-20. Conhecidos na entrada e tardios ficam fora do denominador.
- **Orçamento primário:** K = 50.
- **Incerteza:** 20 sementes de desempate como verificação de robustez e bootstrap por eventos.
- **Critério de sucesso:** significância estatística não é critério de sucesso, por pedido explícito. Os efeitos e os eventos individuais são reportados.
- **Escopo:** sem aprendizado de máquina.
- **Fonte de dados:** o NVD não é substituído pelo CVEProject/cvelistV5.
- **Calendário do EPSS:** última versão v3 em 2025-03-16, v4 de 2025-03-17 a 2026-06-14, nova versão a partir de 2026-06-15.

### Limitações ainda existentes

- **Poucos eventos.** Em 2024 houve dezenas de KEV antecipáveis, e a T2 também deve ter poucos. Por isso muitos resultados podem sair inconclusivos.
- **H3 não identificável.** O atraso até o KEV e ω continuam confundidos.
- **Fila restrita à coorte.** Não há backlog real nem trabalho obrigatório consumindo o orçamento.
- **Instabilidade incompleta.** O trabalho comprometido e depois cancelado não é modelado.
- **Status `Rejected`.** É lido no momento da coleta, ou seja, é informação posterior às decisões.
- **Bônus na EST.** Não foi testado na Fase C. Por isso a EST-travada entra na Fase D.
- **Mudança do EPSS.** A passagem de v3 para v4 muda a escala do score; os efeitos de magnitude, como λ = 0,3, ficam exploratórios.
- **Coorte da ponte.** A coorte S de 2024 ainda não tem o filtro de EPSS calculado, porque as matrizes atuais cobrem só as 32.173 CVEs da variante.
- **Dados.** Falta o arquivo diário do EPSS de 2024-12-01.
- **Dependência do KEV.** A dependência de um único catálogo e o bootstrap condicional à fila realizada limitam a generalização.

## 5. Próximas atividades, por prioridade

1. **Preservação (agora):** guardar o pacote completo e este documento fora deste ambiente. Os dados brutos podem ser recriados pelos scripts.
2. **Coleta do NVD de 2025 (equipe, localmente):** o comando está na seção 3. É o único bloqueio externo para a T2.
3. **Implementar DIN-Δ e EST-travada** em módulos novos, sem tocar nos das Fases B e C, junto com os testes exigidos pelo protocolo (DIN-Δ com Δ = 1 idêntica à DIN-1, score que só muda nas releituras, ΣR = 0 nas políticas travadas, ausência de vazamento de informação futura).
4. **Exploratório em 2024:** rodar DIN-2 e DIN-4 na coorte variante.
5. **Ponte 2024-S:** estender as matrizes de EPSS para as 39.953 CVEs, aplicar o filtro de EPSS e rodar as sete políticas, com contagens por motivo e a sensibilidade que inclui as rejeitadas.
6. **Coleta do EPSS diário** de 2025-01-01 a 2026-06-14, com verificação de `model_version`.
7. **Construir T1 e T2** e produzir o relatório descritivo de comparabilidade das coortes (seção 7 do protocolo).
8. **Executar T2 (confirmatória) e T1 (descritiva) uma única vez** e escrever o relatório da Fase D.
9. **Escrever o artigo** (seção 7 deste documento).

## 6. Como retomar em outra conversa ou ferramenta

Comece fornecendo à nova sessão este arquivo, o pacote do projeto e o protocolo `freeze/protocolo_fase_d.md`. Peça que ela leia primeiro este documento e o protocolo, e depois `README_FASE_D.md`. Antes de qualquer trabalho, peça que confira os hashes e rode os testes. Os números esperados estão na seção 3.

Regras para quem retomar:

- Não modificar a Fase A nem nenhum arquivo listado nos manifestos.
- Gravar resultados novos em pastas novas (`results/fase_d/`).
- Registrar todo desvio do protocolo, com data e motivo, num `docs/REGISTRO_DE_DESVIOS_FASE_D.md`.
- Não alterar nenhuma hipótese, limiar ou parâmetro depois de ver dados da T2.
- Não usar informação posterior a c(t) nas políticas: elas leem os dados apenas por `estado.py`.
- Não introduzir aprendizado de máquina sem decisão explícita da pesquisadora.

Uma frase de abertura sugerida para a nova sessão:

> "Leia CONTINUIDADE.md e freeze/protocolo_fase_d.md; confira os hashes e rode os testes; depois implemente o passo 3 da seção 5 sem alterar arquivos congelados."

Documentos publicados nesta conversa (privados até serem compartilhados):

- Auditoria da Fase A: https://claude.ai/artifact/Q7cBguntC6JDkHTZrngs3f
- Protocolo da Fase B: https://claude.ai/artifact/UReMP9rz4k77QJWHyXc6H3
- Relatório da Fase B: https://claude.ai/artifact/8iDmfX6XACzHkHp9TwWwjE
- Protocolo da Fase C: https://claude.ai/artifact/HDg9a6bD55PPsqAsgYTwca
- Relatório da Fase C: https://claude.ai/artifact/FAT4RvkndeXtPWGHn4Tj5y
- Protocolo da Fase D (cópia de leitura): https://claude.ai/artifact/Cr2fTCj6sCCpEP33aXiWnm

## 7. Arquivos essenciais para o artigo científico

| Parte do artigo | Arquivos |
|---|---|
| Método e pré-registro | `freeze/protocolo_fase_b_congelado.md`, `freeze/protocolo_fase_c_preregistro.md`, `freeze/protocolo_fase_d.md` e os `.sha256`; registros de desvios em `docs/` |
| Replicação e crítica ao artigo original | relatório de auditoria da Fase A; `results/fase_b_2024/acertos_artigo_reconhecer_vs_antecipar.csv` |
| Resultado EST × DIN-1 | `results/fase_b_2024/resumo_por_politica_K.csv`, `comparacao_EST_DIN_por_K.csv`, `estatistica_mcnemar_bootstrap.csv`, `eventos_A_por_K.csv`, `sementes_20_resumo.csv`, `figuras/` |
| Contexto da coorte | `results/fase_b_2024/descritivo.json`, `chegadas_por_semana.csv`, `perfil_A_T_vs_A_pos.csv`, `h3_atraso_omega.csv` |
| Estabilidade e Pareto | `results/fase_c_2024/resumo_configuracoes_K50.csv`, `comparacoes_mcnemar_bootstrap.csv`, `kev_discordantes_vs_DIN1.csv`, `hipoteses_e_regra.json`, `sementes_20.csv`, `figuras/fc1_pareto_K50.png`; `mecanismo_saltos_posthoc.json` apenas como análise pós-hoc |
| Reprodutibilidade | `requirements.txt`, `results/*/ambiente.json`, manifestos em `freeze/`, scripts de coleta, `rodar_tudo.sh`, `rodar_fase_c.sh`, suíte de testes |
| Ameaças à validade | seção 4 deste documento; registros de desvios; tabela de riscos do protocolo da Fase D |
| Validação temporal | protocolo da Fase D e, quando existir, `results/fase_d/` |

Para a redação, o artigo pode ser organizado em três contribuições, apoiadas nos resultados já obtidos. A primeira é que a estratégia por limiar do artigo original reconhece mais do que antecipa. A segunda é que a atualização semanal do EPSS aumenta a antecipação com orçamento apertado, mas o ganho some com orçamento folgado. A terceira é que é possível obter boa parte dessa eficácia com um plano estável. Essa terceira contribuição continua condicionada à confirmação na T2.
