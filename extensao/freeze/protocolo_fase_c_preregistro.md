# Fase C — Pré-registro (gravado antes de qualquer execução da DIN-ESTAB)

Documento completo: https://claude.ai/artifact/HDg9a6bD55PPsqAsgYTwca (revisão 7, 2026-11-21).
Este arquivo fixa as decisões que não podem mudar depois de ver resultados. Em caso de conflito, vale este arquivo.

## Desenho herdado da Fase B (sem alteração)
Coorte 2024 (corpus variante, 32.173 CVEs); EPSS v3; decisões semanais às segundas de 2024-01-01 a 2025-03-10;
c(t) = t − 1; fila sem expiração; KEV conhecido sai da fila e fica fora do orçamento; desempate = SHA-256 do
identificador; rótulo: KEV em até 365 dias, catálogo congelado 2026-11-20; denominador A = 86 KEV antecipáveis.
Orçamento primário K = 50 (único K desta execução).

## Política DIN-ESTAB
score_i(t) = percentil_EPSS_i(c(t)) + λ · 1[i ∈ Plan_{t−1}]; S_t = top-K por (score, desempate);
Plan_t = posições K+1..2K do mesmo ranking ajustado. λ = 0 ≡ DIN-1. λ = ∞ implementado como λ = 2 (plano travado
uma semana à frente). A política usa só o percentil em c(t) e o próprio plano anterior.

## Grade de λ (fixada antes de rodar)
{0; 0,001; 0,003; 0,01; 0,03; 0,1; 0,3; ∞}. Valor "moderado" das hipóteses: λ = 0,01.

## Métricas
Eficácia: N antecipados (s_i < k_i) sobre A; recall; N com folga ≥ 30 e ≥ 90 dias; folga mediana.
Instabilidade (primária): ΣR = revisões do plano (CVEs de Plan_{t−1} ainda elegíveis e não selecionadas),
com ΣR^atual (teriam sido executadas com percentis congelados em t−1) e ΣR^outras = ΣR − ΣR^atual.
Secundárias: α médio; Σ|S_t \ S'_t| (mudanças contrafactuais por atualização); Kendall no top-4K; saídas forçadas.
Cancelamento de trabalho comprometido: não modelado, não medido.
Dominância de Pareto em (N, ΣR) e em (N_folga≥30, ΣR).

## Hipóteses (K = 50, desempate determinístico; conferidas nas 20 sementes)
- H1: ΣR(λ = 0,01) ≤ 0,75 · ΣR(DIN-1). Refutada se a redução for < 25%.
- H2: N(λ = 0,01) ≥ 24. Refutada se N ≤ 23.
- H3: N(λ = ∞) ≤ N(DIN-1) − 5 e recall com folga ≥ 30 d menor que o da DIN-1. Refutada se N(∞) ≥ N(DIN-1) − 2;
  perdas de 3 ou 4 KEV: inconclusivo.

## Incerteza (exploratória)
20 sementes de desempate (SHA-256 de "semente:identificador"); pares discordantes vs DIN-1 e vs EST com atraso e ω;
McNemar exato vs DIN-1; bootstrap por eventos (B = 10.000, semente 20261121) de ΔN vs DIN-1.

## Regra de escolha para confirmação temporal (Fase D)
Entre λ > 0 com N(λ) ≥ N(DIN-1) − 2 no desempate determinístico E na média das 20 sementes, escolher o de menor
ΣR; empate → menor λ. Se nenhum satisfizer, nenhuma DIN-ESTAB é levada adiante (resultado negativo).
O λ escolhido será avaliado sem recalibração nas coortes de 2025 (T1 sob v3, T2 sob v4).

## Preservação
Fase A: freeze/fase_a_manifest.json. Fase B: freeze/fase_b_manifest.json (gravado antes de qualquer arquivo novo).
Resultados da Fase C em results/fase_c_2024/.
