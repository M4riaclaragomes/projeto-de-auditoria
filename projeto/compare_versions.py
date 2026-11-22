import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
ORIGINAL_METRICS_PATH = DATA_DIR / "nvd-2024-strategy-metrics.json"
VARIANT_METRICS_PATH = DATA_DIR / "nvd-2024-strategy-metrics-variant.json"
ORIGINAL_SUMMARY_PATH = DATA_DIR / "nvd-2024-filter-summary.json"
VARIANT_SUMMARY_PATH = DATA_DIR / "nvd-2024-filter-summary-variant.json"
OUTPUT_PATH = DATA_DIR / "nvd-2024-comparison.md"

ARTICLE_FUNNEL = [
    ("Publicadas em 2024", "startingRecords"),
    ("Após remover Rejected", "afterRejectedStatus"),
    ("Após remover análise incompleta", "afterIncompleteAnalysisStatus"),
    ("Após exigir CVSS", "afterMissingCvss"),
    ("Após exigir EPSS", "afterMissingEpss"),
]


def read_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f"Required input file not found: {path}")
    return json.loads(path.read_text(encoding="utf-8-sig"))


def percent(value: float) -> str:
    return f"{value * 100:.2f}%"


def format_count(value: Any) -> str:
    return f"{value:,}" if isinstance(value, int) else str(value)


def strategy_table(original: dict[str, Any], variant: dict[str, Any]) -> list[str]:
    original_strategies = {
        result["strategy"]: result for result in original.get("strategies", [])
    }
    variant_strategies = {
        result["strategy"]: result for result in variant.get("strategies", [])
    }
    if original_strategies.keys() != variant_strategies.keys():
        raise ValueError("Original and variant strategy sets do not match.")

    rows = [
        "| Estratégia | Condição | Artigo (TP / total / F2) | Original (TP / total / F2) | Variante (TP / total / F2) |",
        "|---|---|---:|---:|---:|",
    ]
    for strategy_name, original_result in original_strategies.items():
        variant_result = variant_strategies[strategy_name]
        article = original_result["article"]
        rows.append(
            f"| {strategy_name} | `{original_result['condition']}` "
            f"| {article['tp']} / {article['prioritizedTotal']:,} / {percent(article['f2'])} "
            f"| {original_result['tp']} / {original_result['prioritizedTotal']:,} / {percent(original_result['f2'])} "
            f"| {variant_result['tp']} / {variant_result['prioritizedTotal']:,} / {percent(variant_result['f2'])} |"
        )
    return rows


def funnel_table(
    original_summary: dict[str, Any],
    variant_summary: dict[str, Any],
) -> list[str]:
    article_counts = original_summary.get("expectedArticleCounts", {})
    original_counts = original_summary.get("counts", {})
    variant_counts = variant_summary.get("counts", {})

    rows = [
        "| Etapa | Artigo | Original | Variante |",
        "|---|---:|---:|---:|",
    ]
    for label, key in ARTICLE_FUNNEL:
        rows.append(
            f"| {label} | {format_count(article_counts.get(key, '—'))} "
            f"| {format_count(original_counts.get(key, '—'))} "
            f"| — |"
        )

    rows.extend(
        [
            f"| Entrada da variante (corpus original filtrado) | — "
            f"| — | {format_count(variant_counts.get('startingRecords', '—'))} |",
            f"| Após remover `Deferred` | {format_count(article_counts.get('afterIncompleteAnalysisStatus', '—'))} "
            f"| — | {format_count(variant_counts.get('afterDeferred', '—'))} |",
            f"| Após recalcular CVSS / remover sem CVSS | {format_count(article_counts.get('afterMissingCvss', '—'))} "
            f"| {format_count(original_counts.get('afterMissingCvss', '—'))} "
            f"| {format_count(variant_counts.get('finalRecords', '—'))} |",
            f"| Após exigir EPSS / corpus final | {format_count(article_counts.get('afterMissingEpss', '—'))} "
            f"| {format_count(original_counts.get('afterMissingEpss', '—'))} "
            f"| {format_count(variant_counts.get('finalRecords', '—'))} |",
        ]
    )
    return rows


def main() -> None:
    original_metrics = read_json(ORIGINAL_METRICS_PATH)
    variant_metrics = read_json(VARIANT_METRICS_PATH)
    original_summary = read_json(ORIGINAL_SUMMARY_PATH)
    variant_summary = read_json(VARIANT_SUMMARY_PATH)

    lines = [
        "# Comparação das versões da replicação CVSS × EPSS",
        "",
        f"Corpus original: **{original_metrics['corpusRecords']:,}** registros, "
        f"**{original_metrics['kevRecords']} KEVs**.",
        f"Variante: **{variant_metrics['corpusRecords']:,}** registros, "
        f"**{variant_metrics['kevRecords']} KEVs**.",
        "",
        "A variante exclui `Deferred` e recalcula CVSS pela versão mais recente, "
        "preferindo `Secondary` (CNA). A escolha da fonte `Secondary` é uma inferência "
        "metodológica, pois o artigo não especifica a fonte.",
        "",
        "## Estratégias",
        "",
        *strategy_table(original_metrics, variant_metrics),
        "",
        "## Funil de filtros",
        "",
        "A variante parte do corpus original já filtrado e com EPSS associado; por isso, "
        "as etapas iniciais do artigo não são repetidas. As linhas de entrada e exclusão "
        "de `Deferred` mostram as etapas adicionais da variante.",
        "",
        *funnel_table(original_summary, variant_summary),
        "",
        "## Interpretação",
        "",
        "A comparação torna explícitas as diferenças entre o artigo, a versão original e "
        "a variante; não implica que os snapshots atuais reproduzam os dados históricos "
        "usados no estudo.",
        "",
    ]
    OUTPUT_PATH.write_text("\n".join(lines), encoding="utf-8")
    print(f"Comparison report: {OUTPUT_PATH}")
    print(f"Original corpus: {original_metrics['corpusRecords']:,}")
    print(f"Variant corpus: {variant_metrics['corpusRecords']:,}")


if __name__ == "__main__":
    main()
