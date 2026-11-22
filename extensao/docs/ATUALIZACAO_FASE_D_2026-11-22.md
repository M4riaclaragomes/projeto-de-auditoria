# Fase D — Nota de atualização (2026-11-22)

Esta nota **complementa, sem alterar**, `README_FASE_D.md`, `results/fase_d/RELATORIO_FASE_D.md` e
`docs/REGISTRO_DE_DESVIOS_FASE_D.md`. Esses três arquivos constam em manifestos de `freeze/` (hash SHA-256) e, pela
regra do projeto, não são modificados. Em caso de divergência entre eles e esta nota ou os arquivos de resultados,
vale o arquivo de resultados.

## O que está desatualizado

Os três documentos acima (e a versão de 2026-11-21 do `CONTINUIDADE.md`) dizem que a T1 e a T2 **não foram
executadas** (item 9 do registro de desvios: NVD 2025 inacessível a partir do ambiente de análise). Mas o repositório
contém:

- os dados brutos do NVD 2025 coletados localmente (`data/raw/nvd-2025`, fora do Git) e o EPSS diário v4;
- os resultados de T1 e T2 em `results/fase_d/T1/` e `results/fase_d/T2/`. A data de execução **não é conhecida**:
  todos os arquivos do pacote recebido têm a mesma data de modificação (extração do pacote), então ela não serve de
  prova. Como o manifesto `freeze/fase_d_execucao_parcial_manifest.json` (2026-11-22T01:25Z) ainda os listava como
  pendentes e não inclui esses arquivos, a inferência é que foram gerados depois dele;
- o pacote `auditoria_final/`, com cópia dos mesmos resultados e `manifesto_sha256.csv`.

**Conferências feitas ao importar o projeto para o GitHub:**

- `results/fase_d/T1|T2` são idênticos byte a byte aos de `auditoria_final/T1|T2`.
- Os 53 hashes de `auditoria_final/manifesto_sha256.csv` conferem com os arquivos atuais. Desses, 26 apontavam para
  cópias aninhadas (`T1/T1/`, `T2/T2/`) idênticas às cópias principais; elas foram removidas na importação por serem
  duplicatas.

## Resultados gravados da T2 (confirmatória) e da T1 (descritiva)

Fonte: `results/fase_d/T2/hipoteses.json`, `descritivo.json` e `resumo_politicas_K50.csv`; K = 50.

**Coorte T2:** 33.472 CVEs publicadas de 2025-03-17 a 2025-11-19; 1.325 rejeitadas e 1 sem EPSS excluídas; 32.146
incluídas. EPSS v2025.03.14 (v4). 65 decisões, de 2025-03-24 a 2026-06-15. 123 KEV no catálogo, 39 já conhecidos na
entrada, 5 tardios, **|A| = 79** (A_T = 78, A_pós = 1).

| Política | KEV antecipados (de 79) | KEV com folga ≥ 30 d | Revisões do plano (ΣR) |
|---|---|---|---|
| EST | 26 | 15 | 1.437 |
| DIN-1 | 29 | 17 | 2.311 |
| DIN-ESTAB λ = ∞ (plano travado) | 24 | 17 | 0 |
| DIN-ESTAB λ = 0,3 (pós-hoc) | 26 | 17 | 421 |
| DIN-4 | 27 | 16 | 1.443 |
| DIN-2 | 28 | 17 | 1.807 |
| EST-travada | 17 | 14 | 0 |

- **DIN-1 × EST:** 9 KEV só da DIN-1 e 6 só da EST; McNemar exato p = 0,61.
- **H-D1:** *inconclusivo por poucos eventos* (N_DIN-1 − N_EST = 3 < 5). A razão de preservação observada (−0,67) não
  é interpretável com esse denominador.
- **H-D2** (avaliada só de forma descritiva, pois a H-D1 não foi sustentada), margem δ = 3:
  - todos os KEV: inconclusiva (E = −3; o plano travado ganha 3 e perde 6 eventos em relação à DIN-4);
  - KEV com folga ≥ 30 dias: não inferioridade sustentada (E = +1; ganha 1 e perde 0).
- **Controle:** a EST-travada antecipa 17 contra 24 do plano travado, ou seja, atualizar o EPSS ainda rende 7 KEV a
  mais sob o mesmo travamento.

**T1 (descritiva):** |A| = 26; antecipados: EST 3, DIN-1 2, λ = ∞ 1, λ = 0,3 2, DIN-4 2, DIN-2 2, EST-travada 1.
H-D1 "não avaliável" (denominador −1). Com tão poucos eventos, nada pode ser concluído.

## O que não foi possível verificar

- Se a T2 foi executada **uma única vez** e com o comando confirmatório (`experimentos_d T2 --confirmatoria`), como
  exige o protocolo. Os arquivos não registram quantas execuções houve nem quem as fez.
- Não há registro em `docs/` de que a T1/T2 foram executadas depois da nota original (item 9 segue dizendo o
  contrário). Recomenda-se criar um `docs/REGISTRO_DE_DESVIOS_FASE_D_ADENDO.md` com data, autoria, comando usado e
  número de execuções, antes de citar a T2 como confirmatória no artigo.
- Se a suíte de testes foi reexecutada depois da T1/T2. O único registro, `results/fase_d/testes_saida.txt`
  (57 aprovados e 2 pulados), coincide com o do relatório parcial, que é anterior à T1/T2. A suíte também não foi
  rodada na cópia importada para o GitHub.
- A T2 depende de os dados brutos do NVD 2025 serem os mesmos usados na execução; eles não estão no Git (ver `README.md`
  da raiz). Guarde o backup original.

## Efeito sobre o resto do projeto

Os resultados confirmam o que o relatório parcial já antecipava: a T2 teria pouco poder para sustentar a H-D1. Em 2025
a vantagem da DIN-1 sobre a EST é de +3 KEV (contra +12 em 2024), então a terceira contribuição do artigo (plano
estável com boa eficácia) segue como hipótese **não confirmada**.
