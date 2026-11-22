# Fase C — DIN-ESTAB (priorização dinâmica com controle de estabilidade)

Pré-registro: `freeze/protocolo_fase_c_preregistro.md` (+ `.sha256`), gravado antes da primeira execução.
Manifesto da Fase B (verificado pelos testes): `freeze/fase_b_manifest.json`.

Arquivos novos (nenhum arquivo da Fase A ou da Fase B foi alterado):
- `src/vulnprio/politicas_c.py`, `src/vulnprio/simulador_c.py` — políticas e simulador com bônus de plano e
  revisões do plano; com lambda = 0 reproduzem exatamente EST e DIN-1 da Fase B;
- `src/vulnprio/experimentos_c.py`, `src/vulnprio/graficos_c.py` — grade pré-registrada, K = 50;
- `tests/test_fase_c.py` — 16 testes (equivalência, plano travado, orçamento, vazamento, decomposição, determinismo);
- `results/fase_c_2024/` — resultados, figura `figuras/fc1_pareto_K50.png`, saída dos testes;
- `docs/REGISTRO_DE_DESVIOS_FASE_C.md`.

Reproduzir (depois de `rodar_tudo.sh` da Fase B): `bash rodar_fase_c.sh` (cerca de 2 minutos).

| Arquivo em results/fase_c_2024 | Conteúdo |
|---|---|
| `resumo_configuracoes_K50.csv` | Eficácia, instabilidade (ΣR e decomposição, α, contrafactuais, Kendall), Pareto, sementes |
| `comparacoes_mcnemar_bootstrap.csv` | Ganhos/perdas vs DIN-1 e vs EST, McNemar exato, IC 95% de ΔN |
| `kev_discordantes_vs_DIN1.csv` | KEV que cada configuração ganha ou perde em relação à DIN-1 |
| `sementes_20.csv` | 20 sementes de desempate por configuração |
| `hipoteses_e_regra.json` | Avaliação de H1–H3 e regra de escolha pré-registradas |
| `mecanismo_saltos_posthoc.json` | Análise pós-hoc dos saltos de percentil |
| `log_semanal_K50.csv.gz` | Log semanal de todas as configurações |
