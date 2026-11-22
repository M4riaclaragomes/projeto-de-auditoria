# Fase D — estado atual (2026-11-21)

Protocolo congelado: `freeze/protocolo_fase_d.md`
SHA-256 `dca72aebe9b048a722cb558f32b67a4b7a4d6c4b57fe60b7455abfd326d3bb4d` (2026-11-21T23:16:45Z).
Os dois arquivos estão sem permissão de escrita. Conferir com `sha256sum -c freeze/protocolo_fase_d.sha256`.

## O que já foi feito

1. Protocolo escrito, auditado e congelado. A auditoria conferiu o calendário (63 decisões em 2024, igual à
   Fase B; 11 na T1; 65 na T2; primeira releitura da DIN-4 depois de 2025-03-24 em 2025-04-21), as datas de
   transição do EPSS e o horizonte sem censura (2025-11-19 + 365 = 2026-11-19). Antes do hash, a regra de baixa
   informação da H-D1 foi esclarecida (não declara sustentada nem refutada, e a H-D2 fica descritiva).
2. Manifestos das Fases A (938 arquivos), B (40) e C (21) reconferidos: nenhuma divergência.
3. `scripts/coleta_nvd.py`: coleta da API 2.0 com janelas de até 120 dias, paginação de 2.000, retomada,
   gravação sem sobrescrita, retentativas, validação de integridade e manifesto com SHA-256 por página.
4. `src/vulnprio/coorte_s.py`: construtor da coorte S (publicada na janela, não Rejected, com EPSS), com
   contagens por motivo e comparação com a coorte variante. Módulo novo; nenhum módulo das Fases B e C mudou.
5. `tests/test_fase_d_coleta.py`: 13 testes offline, usando as páginas de 2024 da Fase A como respostas
   simuladas da API. A suíte completa tem 48 testes aprovados e 2 pulados (os mesmos 2 de antes).

Resultados dos testes que valem como verificação:

* a coleta simulada de 2024 reproduz byte a byte as 23 páginas da Fase A (40.704 CVEs, mesmas janelas);
* uma coleta interrompida na 10ª página retoma baixando só as 14 que faltavam, sem tocar nas 9 gravadas;
* `totalResults` alterado no meio da paginação, ID repetido, `published` fora da janela e página ausente
  são recusados, sem gravar manifesto;
* a coorte S de 2024 tem 40.704 publicadas, 751 rejeitadas e 39.953 restantes antes do filtro de EPSS;
  ela contém todas as 32.173 CVEs da coorte variante.

## Como coletar o NVD de 2025 (rodar localmente)

A API do NVD não é acessível do ambiente de análise. Na máquina da equipe:

```bash
export NVD_API_KEY=...        # opcional; sem chave a coleta é mais lenta (6,5 s por página)
python scripts/coleta_nvd.py --inicio 2025-01-01 --fim 2025-11-19 --saida data/raw/nvd-2025
python scripts/coleta_nvd.py --inicio 2025-01-01 --fim 2025-11-19 --saida data/raw/nvd-2025 --verificar
```

Se cair no meio, rode o mesmo comando de novo: as páginas gravadas são aproveitadas. Se o script acusar
`totalResults mudou`, mova para outra pasta só as páginas da janela indicada e rode de novo. Depois, envie a
pasta `data/raw/nvd-2025` inteira (páginas e manifesto).

## Próximos passos, na ordem do protocolo

3. DIN-2 e DIN-4 na coorte variante de 2024 (exploratório).
4. Ponte 2024-S com as sete políticas (exploratório). Exige estender as matrizes de EPSS diário das 32.173 CVEs
   da variante para as 39.953 da coorte S, a partir dos arquivos diários já baixados.
5. Coleta do NVD 2025 (equipe) e do EPSS diário de 2025-01-01 a 2026-06-14 (daqui).
6. Construção de T1 e T2, testes e relatório descritivo das coortes.
7. T2 (confirmatória) e T1 (descritiva), uma única vez.
