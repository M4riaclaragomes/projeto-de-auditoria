# Projeto de Auditoria: priorização adaptativa de vulnerabilidades

Replicação, auditoria e **extensão** do artigo *Evaluating Vulnerability Prioritization Strategies Based on CVSS
and EPSS* (SBSeg 2026), feita como trabalho da disciplina na UFPE.

* **Parte 1, a replicação** (pasta `projeto/`): refizemos o experimento do artigo com dados públicos. As conclusões
  do artigo se mantiveram.
* **Parte 2, a extensão** (pasta `extensao/`): o que fizemos de novo. Em vez de uma foto da nota do EPSS, simulamos
  a fila de correção **semana a semana**, com limite de correções, e comparamos jeitos de montar a fila, inclusive
  um **plano travado** que não muda toda semana. Validamos numa base nova, de 2025.

## Consigo rodar? Sim, em três níveis

Não é preciso baixar nada para os níveis 1 e 2: os dados necessários estão no repositório.

| Nível | O que faz | Comando | Tempo | Internet |
|---|---|---|---|---|
| **0. Ler** | Ver resultados, tabelas e figuras já gerados | abrir `extensao/results/` | 0 | não |
| **1. Verificar** | Confere ambiente, protocolos congelados (SHA-256), manifestos e roda os testes | `python verificar.py` | 1 a 3 min | não |
| **2. Reproduzir** | **Refaz os resultados das Fases A, B, C e D** numa pasta temporária e compara com os versionados | `python verificar.py --reproduzir --rapido` (sem as 20 sementes) ou `--reproduzir` (completo) | ~8 min / ~20 min | não |
| **3. Do zero** | Baixa o EPSS diário (~1,5 GB) e reconstrói os dados derivados | ver `extensao/data/raw/LEIAME.md` | horas | sim |

O nível 3 é opcional: serve para auditar a construção dos dados derivados. Os níveis 1 e 2 já mostram que o código roda,
que os testes passam e que os números publicados saem do código.

### Passo a passo

Requer **Python 3.12 ou 3.13** e `git`. O repositório é privado: é preciso ter acesso à conta.

```bash
git clone https://github.com/M4riaclaragomes/projeto-de-auditoria.git
cd projeto-de-auditoria

python -m venv .venv
# Windows (PowerShell):   .venv\Scripts\Activate.ps1
# Linux / macOS:          source .venv/bin/activate
python -m pip install -r requirements.txt

python verificar.py --preparar-dados      # descompacta os dados do NVD e confere o SHA-256 de cada um (5 s)
python verificar.py                       # nível 1  (~3 min)
python verificar.py --reproduzir --rapido # nível 2  (~8 min). Sem --rapido, refaz também as 20 sementes (~20 min)
```

Ao final, o script imprime `Tudo certo` (código de saída 0) ou lista cada problema. Rode `--preparar-dados` antes do
nível 2: sem ele, a reprodução da Fase A é pulada, com um aviso.

### O que é normal aparecer

* **Quatro testes são "pulados" (skipped), não falham.** Um depende dos arquivos diários do EPSS (nível 3), um confere
  o ambiente virtual (`.venv`) que a Fase A tinha na época, e dois foram adiados pelo próprio protocolo. O motivo
  de cada um é impresso. Se você ainda não rodou `--preparar-dados`, mais nove testes (que usam os dados do NVD)
  também são pulados, com a instrução de como habilitá-los.
* **Avisos sobre o manifesto do EPSS v4:** um hash do manifesto da Fase D não bate com o arquivo atual. É uma divergência
  que já veio no material recebido; está explicada na saída e em `extensao/docs/ATUALIZACAO_FASE_D_2026-11-22.md`.
* **Windows:** o `verificar.py` já ativa o modo UTF-8 do Python. Se você rodar os módulos à mão, faça antes
  `$env:PYTHONUTF8 = "1"`; sem isso o Python grava arquivos com o caractere "λ" usando a codificação do Windows e falha.

## Mapa do repositório

```
README.md                  este arquivo
verificar.py               verificação e reprodução em um comando
requirements.txt           dependências (versões fixadas)
dados_compactados/         dados do NVD (2024 e 2025) em .gz, conferidos por SHA-256
projeto/                   PARTE 1 · Fase A: replicação do artigo (somente leitura)  → LEIAME.md
extensao/                  PARTE 2 · Fases B, C e D: a extensão
  src/vulnprio/              código: políticas, simulador, métricas e experimentos
  tests/                     testes de integridade e regressão
  results/                   RESULTADOS: fase_b_2024/, fase_c_2024/, fase_d/ (T1, T2 e exploratórios)
  freeze/                    protocolos congelados e manifestos SHA-256 (não alterar)
  docs/                      registros de desvios e a nota de atualização da Fase D
  data/derived/              dados derivados (entrada dos experimentos)
  data/raw/                  dados brutos: KEV congelado e manifestos            → LEIAME.md
  scripts/                   coleta de EPSS, KEV e NVD
  auditoria_final/           pacote de auditoria da Fase D (T1 e T2)
  CONTINUIDADE.md            histórico completo, decisões e próximos passos
  README*.md                 detalhes de cada fase
```

### Onde achar cada coisa

| Quero ver... | Está em |
|---|---|
| O que foi decidido e por quê | `extensao/freeze/protocolo_fase_b_congelado.md`, `protocolo_fase_c_preregistro.md`, `protocolo_fase_d.md` |
| Resultados da replicação | `projeto/data/nvd-2024-replication-report*.md` e `nvd-2024-comparison.md` |
| EST × DIN-1 em 2024 | `extensao/results/fase_b_2024/` (`comparacao_EST_DIN_por_K.csv`, `estatistica_mcnemar_bootstrap.csv`, `figuras/`) |
| Plano travado (estabilidade) | `extensao/results/fase_c_2024/` |
| Validação em 2025 (T2) | `extensao/results/fase_d/T2/` e `extensao/results/fase_d/RELATORIO_FASE_D.md` |
| Estado atual e próximos passos | `extensao/CONTINUIDADE.md` e `extensao/docs/ATUALIZACAO_FASE_D_2026-11-22.md` |
| Desvios do protocolo | `extensao/docs/REGISTRO_DE_DESVIOS*.md` |

## Resultados em resumo

Com limite de 50 correções por semana:

* **2024:** a fila atualizada toda semana (DIN-1) antecipou **27** das 86 falhas que depois entraram na lista KEV,
  contra **15** da fila fixa (EST). A vantagem some quando o limite é folgado (K = 500).
* **Plano travado:** antecipa 25 (2 a menos que a DIN-1) e elimina as mudanças no plano (de 1.730 para 0).
* **2025 (T2, base nova):** a vantagem da fila semanal diminuiu para **+3** (29 contra 26, de 79). A hipótese principal
  da Fase D ficou **inconclusiva por poucos eventos**.

Resultados preliminares: poucos eventos e um único catálogo KEV. Em caso de divergência entre este texto e um arquivo
de resultados ou protocolo congelado, **vale o arquivo**.

## Limitações a ter em mente

* O **EPSS diário (~1,5 GB)** não está no Git. É público e tem manifestos com SHA-256 (nível 3).
* O NVD muda com o tempo: por isso os dados de 2024 e 2025 usados estão preservados em `dados_compactados/`.
* Ainda falta **registrar formalmente** como e quando a T2 foi executada (data, comando, execução única).
  Ver `extensao/docs/ATUALIZACAO_FASE_D_2026-11-22.md`.
* Testado com Python 3.12 (Windows). Os resultados originais foram gerados com Python 3.13 (Linux). A reprodução
  completa deu resultados idênticos (tabelas, JSON e logs descompactados), exceto quebras de linha e o
  `ambiente.json`, que só registra a máquina.

## Regras do projeto

* Não modificar a Fase A nem nenhum arquivo listado nos manifestos de `extensao/freeze/`.
* Resultados novos vão para pastas novas; todo desvio do protocolo é registrado, com data e motivo, em `extensao/docs/`.
* Não alterar hipóteses, limiares ou parâmetros depois de ver dados da coorte confirmatória (T2).
* As políticas só leem dados por `estado.py`, usando apenas informação disponível até o dia anterior à decisão.
* Não há aprendizado de máquina sem decisão explícita da pesquisadora.
* O `.gitattributes` usa `-text`: não converta quebras de linha, pois os hashes SHA-256 dependem dos bytes exatos.
