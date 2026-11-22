import argparse
import csv
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
CORPUS_PATH = DATA_DIR / "nvd-2024-filtered.jsonl"
STRATEGIES = [
    {
        "name": "CVSS 5.0",
        "condition": "cvss >= 5",
        "article_tp": 155,
        "article_prioritized": 27715,
        "article_f2_percent": 2.73,
        "predicate": lambda cvss, epss: cvss >= 5,
    },
    {
        "name": "CVSS 7.0",
        "condition": "cvss >= 7",
        "article_tp": 130,
        "article_prioritized": 13532,
        "article_f2_percent": 4.59,
        "predicate": lambda cvss, epss: cvss >= 7,
    },
    {
        "name": "CVSS 9.0",
        "condition": "cvss >= 9",
        "article_tp": 64,
        "article_prioritized": 2714,
        "article_f2_percent": 9.59,
        "predicate": lambda cvss, epss: cvss >= 9,
    },
    {
        "name": "CVSS 10.0",
        "condition": "cvss == 10",
        "article_tp": 7,
        "article_prioritized": 132,
        "article_f2_percent": 4.63,
        "predicate": lambda cvss, epss: cvss == 10,
    },
    {
        "name": "EPSS 0.05%",
        "condition": "epss > 0.0005",
        "article_tp": 62,
        "article_prioritized": 3740,
        "article_f2_percent": 7.10,
        "predicate": lambda cvss, epss: epss > 0.0005,
    },
    {
        "name": "EPSS 0.10%",
        "condition": "epss > 0.001",
        "article_tp": 41,
        "article_prioritized": 309,
        "article_f2_percent": 21.97,
        "predicate": lambda cvss, epss: epss > 0.001,
    },
    {
        "name": "EPSS 0.50%",
        "condition": "epss > 0.005",
        "article_tp": 28,
        "article_prioritized": 44,
        "article_f2_percent": 20.96,
        "predicate": lambda cvss, epss: epss > 0.005,
    },
    {
        "name": "EPSS 1.00%",
        "condition": "epss > 0.01",
        "article_tp": 21,
        "article_prioritized": 26,
        "article_f2_percent": 16.15,
        "predicate": lambda cvss, epss: epss > 0.01,
    },
    {
        "name": "EPSS 5.00%",
        "condition": "epss > 0.05",
        "article_tp": 4,
        "article_prioritized": 5,
        "article_f2_percent": 3.18,
        "predicate": lambda cvss, epss: epss > 0.05,
    },
    {
        "name": "CVSS 7.0 AND EPSS 0.50%",
        "condition": "cvss >= 7 and epss > 0.005",
        "article_tp": 21,
        "article_prioritized": 36,
        "article_f2_percent": 15.91,
        "predicate": lambda cvss, epss: cvss >= 7 and epss > 0.005,
    },
    {
        "name": "CVSS 9.0 AND EPSS 0.50%",
        "condition": "cvss >= 9 and epss > 0.005",
        "article_tp": 8,
        "article_prioritized": 19,
        "article_f2_percent": 6.22,
        "predicate": lambda cvss, epss: cvss >= 9 and epss > 0.005,
    },
    {
        "name": "CVSS 9.0 OR EPSS 0.50%",
        "condition": "cvss >= 9 or epss > 0.005",
        "article_tp": 84,
        "article_prioritized": 2739,
        "article_f2_percent": 12.49,
        "predicate": lambda cvss, epss: cvss >= 9 or epss > 0.005,
    },
    {
        "name": "CVSS 10.0 OR EPSS 0.50%",
        "condition": "cvss == 10 or epss > 0.005",
        "article_tp": 35,
        "article_prioritized": 175,
        "article_f2_percent": 21.90,
        "predicate": lambda cvss, epss: cvss == 10 or epss > 0.005,
    },
]


def load_corpus(corpus_path: Path) -> list[dict]:
    if not corpus_path.is_file():
        raise FileNotFoundError(f"Final corpus not found: {corpus_path}")
    records = []
    with corpus_path.open(encoding="utf-8") as source:
        for line_number, line in enumerate(source, start=1):
            if not line.strip():
                continue
            record = json.loads(line)
            if record.get("cvssBaseScore") is None:
                raise ValueError(f"Missing CVSS score on corpus row {line_number}.")
            if record.get("epssScore") is None:
                raise ValueError(f"Missing EPSS score on corpus row {line_number}.")
            records.append(record)
    if not records:
        raise ValueError(f"Final corpus is empty: {CORPUS_PATH}")
    return records


def calculate_metrics(records: list[dict], corpus_name: str) -> dict:
    results = []
    total_kev = sum(record.get("cisaExploitAdd") is not None for record in records)
    reference_precision = 64 / 2714
    reference_recall = 64 / 156
    reference_f2 = (
        5 * reference_precision * reference_recall
        / (4 * reference_precision + reference_recall)
    )
    if round(reference_f2 * 100, 2) != 9.59:
        raise AssertionError("F2 calculation does not match the article's CVSS 9.0 check.")

    for strategy in STRATEGIES:
        tp = fp = fn = tn = 0
        for record in records:
            cvss = float(record["cvssBaseScore"])
            epss = float(record["epssScore"])
            is_kev = record.get("cisaExploitAdd") is not None
            prioritized = strategy["predicate"](cvss, epss)
            if prioritized and is_kev:
                tp += 1
            elif prioritized:
                fp += 1
            elif is_kev:
                fn += 1
            else:
                tn += 1

        prioritized_total = tp + fp
        precision = tp / prioritized_total if prioritized_total else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = (
            2 * precision * recall / (precision + recall)
            if precision + recall
            else 0.0
        )
        f2 = (
            5 * precision * recall / (4 * precision + recall)
            if 4 * precision + recall
            else 0.0
        )
        if tp + fp != prioritized_total or tp + fn != total_kev:
            raise AssertionError(f"Confusion matrix totals are inconsistent for {strategy['name']}.")

        result = {
            "strategy": strategy["name"],
            "condition": strategy["condition"],
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "prioritizedTotal": prioritized_total,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "f2": f2,
            "article": {
                "tp": strategy["article_tp"],
                "prioritizedTotal": strategy["article_prioritized"],
                "f2": strategy["article_f2_percent"] / 100,
            },
        }
        result["comparison"] = {
            "tpMatchesArticle": tp == result["article"]["tp"],
            "prioritizedTotalMatchesArticle": (
                prioritized_total == result["article"]["prioritizedTotal"]
            ),
            "f2DifferencePercentagePoints": (
                f2 * 100 - strategy["article_f2_percent"]
            ),
        }
        results.append(result)

    return {
        "corpus": corpus_name,
        "corpusRecords": len(records),
        "kevDefinition": "cisaExploitAdd is not null",
        "kevRecords": total_kev,
        "metrics": "P=TP/(TP+FP); R=TP/(TP+FN); F1=2PR/(P+R); F2=5PR/(4P+R)",
        "epssThresholdsAreStrict": True,
        "combinedStrategiesUseEpssThreshold": 0.005,
        "cvss10UsesExactEquality": True,
        "strategies": results,
    }


def write_outputs(report: dict, json_output_path: Path, csv_output_path: Path) -> None:
    json_output_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    fieldnames = [
        "strategy",
        "condition",
        "tp",
        "fp",
        "fn",
        "tn",
        "prioritizedTotal",
        "precision",
        "recall",
        "f1",
        "f2",
        "articleTp",
        "articlePrioritizedTotal",
        "articleF2",
        "tpMatchesArticle",
        "prioritizedTotalMatchesArticle",
        "f2DifferencePercentagePoints",
    ]
    with csv_output_path.open("w", encoding="utf-8", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        for result in report["strategies"]:
            writer.writerow(
                {
                    **{
                        key: result[key]
                        for key in fieldnames
                        if key in result
                    },
                    "articleTp": result["article"]["tp"],
                    "articlePrioritizedTotal": result["article"][
                        "prioritizedTotal"
                    ],
                    "articleF2": result["article"]["f2"],
                    "tpMatchesArticle": result["comparison"]["tpMatchesArticle"],
                    "prioritizedTotalMatchesArticle": result["comparison"][
                        "prioritizedTotalMatchesArticle"
                    ],
                    "f2DifferencePercentagePoints": result["comparison"][
                        "f2DifferencePercentagePoints"
                    ],
                }
            )


def write_markdown_report(
    report: dict,
    filter_summary_path: Path,
    report_output_path: Path,
    corpus_path: Path,
    suffix: str,
) -> None:
    filter_summary = json.loads(filter_summary_path.read_text(encoding="utf-8-sig"))
    is_variant = bool(suffix)
    article_summary = filter_summary
    if is_variant:
        article_summary = json.loads(
            (DATA_DIR / "nvd-2024-filter-summary.json").read_text(
                encoding="utf-8-sig"
            )
        )
    corpus_link = corpus_path.name
    json_link = f"nvd-2024-strategy-metrics{suffix}.json"
    csv_link = f"nvd-2024-strategy-metrics{suffix}.csv"
    summary_link = f"nvd-2024-filter-summary{suffix}.json"
    article_counts = article_summary.get("expectedArticleCounts", {})
    current_counts = filter_summary.get("counts", {})
    if is_variant:
        status_note = (
            "Nesta variante, os registros `Deferred` foram excluídos como aproximação "
            "do backlog de análise descrito no artigo."
        )
        cvss_note = (
            "A variante recalcula CVSS pela versão mais recente disponível e prioriza "
            "a nota `Secondary` (CNA), recorrendo a `Primary` e depois à primeira métrica "
            "válida. Essa preferência por `Secondary` é uma inferência nossa: o artigo "
            "não especifica qual fonte de CVSS foi usada."
        )
        cvss_selection_report = (
            "- **Fonte CVSS:** notas podem ser revisadas; nesta variante selecionamos a "
            "versão mais recente disponível e priorizamos `Secondary` (CNA). Essa escolha "
            "é uma inferência metodológica nossa, não explicitada pelo artigo."
        )
        funnel_rows = [
            f"| Entrada (corpus original filtrado) | — | {current_counts.get('startingRecords', 0):,} |",
            f"| Após excluir `Deferred` | {article_counts.get('afterIncompleteAnalysisStatus', 0):,} | {current_counts.get('afterDeferred', 0):,} |",
            f"| Após exigir/recalcular CVSS | {article_counts.get('afterMissingCvss', 0):,} | {current_counts.get('finalRecords', 0):,} |",
        ]
    else:
        status_note = (
            "A filtragem original remove `Rejected`, `Awaiting Analysis` e "
            "`Undergoing Analysis`; os demais status são mantidos."
        )
        cvss_note = (
            "A análise usa o CVSS armazenado no corpus original, selecionado pela "
            "versão mais recente disponível e com `Primary` preferida."
        )
        cvss_selection_report = (
            "- **CVSS pode ser revisado:** avaliações de CNA/NVD podem mudar; a replicação "
            "seleciona a versão de CVSS mais recente disponível pela ordem 4.0, 3.1, 3.0, 2.0 "
            "e prioriza `Primary`."
        )
        funnel_rows = [
            f"| Publicadas em 2024 | {article_counts.get('startingRecords', 0):,} | {current_counts.get('startingRecords', 0):,} |",
            f"| Após `Rejected` | {article_counts.get('afterRejectedStatus', 0):,} | {current_counts.get('afterRejectedStatus', 0):,} |",
            f"| Após análise incompleta | {article_counts.get('afterIncompleteAnalysisStatus', 0):,} | {current_counts.get('afterIncompleteAnalysisStatus', 0):,} |",
            f"| Após CVSS disponível | {article_counts.get('afterMissingCvss', 0):,} | {current_counts.get('afterMissingCvss', 0):,} |",
            f"| Após EPSS disponível | {article_counts.get('afterMissingEpss', 0):,} | {current_counts.get('afterMissingEpss', 0):,} |",
        ]
    lines = [
        "# Replicação CVSS × EPSS — artigo vs. dados atuais",
        "",
        "## Estratégias e métricas",
        "",
        "O total priorizado corresponde a TP + FP. CVSS usa `>=` (exceto CVSS 10.0, que usa `==`); "
        "EPSS usa `>` e os limites das estratégias combinadas são 0,50% (`0.005`). "
        "KEV é definido por `cisaExploitAdd` não nulo.",
        "",
        "| Estratégia | Condição | Artigo TP / total / F2 | Replicação TP / FP / FN / total | P | R | F1 | F2 | Δ F2 (p.p.) |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for result in report["strategies"]:
        article = result["article"]
        lines.append(
            f"| {result['strategy']} | `{result['condition']}` "
            f"| {article['tp']} / {article['prioritizedTotal']:,} / {article['f2'] * 100:.2f}% "
            f"| {result['tp']} / {result['fp']:,} / {result['fn']} / {result['prioritizedTotal']:,} "
            f"| {result['precision'] * 100:.2f}% "
            f"| {result['recall'] * 100:.2f}% "
            f"| {result['f1'] * 100:.2f}% "
            f"| {result['f2'] * 100:.2f}% "
            f"| {result['comparison']['f2DifferencePercentagePoints']:+.2f} |"
        )

    lines.extend(
        [
            "",
            "## Corpus e checklist de filtros",
            "",
            f"O corpus usado tem **{report['corpusRecords']:,} registros**, dos quais "
            f"**{report['kevRecords']}** têm `cisaExploitAdd` preenchido.",
            "",
            *([status_note, "", cvss_note, ""] if is_variant else []),
            "| Etapa | Artigo: restantes | Replicação: restantes |",
            "|---|---:|---:|",
            *funnel_rows,
            "",
            "## Ameaças à validade e interpretação",
            "",
            "- **Status NVD mudam com o tempo:** o campo `vulnStatus` foi consultado na versão atual da API, "
            "não em um snapshot de 2024. CVEs anteriormente `Awaiting Analysis` podem agora estar "
            "`Analyzed` ou em outro status. Por isso, a filtragem atual não recompõe exatamente o corpus do artigo.",
            "- **KEV é dinâmico:** `cisaExploitAdd` reflete o catálogo conhecido no momento da resposta do NVD. "
            "Entradas posteriores no KEV alteram positivos verdadeiros e falsos negativos.",
            cvss_selection_report,
            "- **EPSS é temporal e tem mudanças de modelo:** foram usados arquivos históricos diários, "
            "selecionando para cada CVE o primeiro score na data ou após sua publicação. "
            "A série usada termina em "
            f"{article_summary.get('epssDateRangeScanned', {}).get('endDate', 'data indisponível')}.",
            "- **Diferenças não são erro de fórmula:** TP, FP, FN, precisão, recall, F1 e F2 são "
            "recalculados sobre o corpus disponível. O F2 de referência do artigo para CVSS 9.0 "
            "(64 TP, total 2.714, 156 KEVs) foi validado em 9,59%; diferenças na tabela são "
            "apresentadas lado a lado, não corrigidas artificialmente.",
            "",
            "Para se aproximar dos valores originais, seriam necessários os snapshots e o pacote de "
            "replicação do estudo. Se o pacote estiver indisponível por revisão cega, os dados podem "
            "ser solicitados ao autor identificado no artigo; esta execução não contatou o autor.",
            "",
            "## Arquivos de dados",
            "",
            f"- Corpus: [`{corpus_link}`](./{corpus_link})",
            f"- Métricas completas: [`{json_link}`](./{json_link})",
            f"- Métricas tabulares: [`{csv_link}`](./{csv_link})",
            f"- Contagens e metodologia: [`{summary_link}`](./{summary_link})",
            "",
        ]
    )
    report_output_path.write_text("\n".join(lines), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Analyze CVSS and EPSS prioritization strategies.")
    parser.add_argument(
        "--corpus",
        type=Path,
        default=DATA_DIR / "nvd-2024-filtered.jsonl",
        help="Input JSONL corpus (default: data/nvd-2024-filtered.jsonl).",
    )
    parser.add_argument(
        "--suffix",
        default="",
        help="Suffix appended to metrics, report, and summary filenames.",
    )
    arguments = sys.argv[1:]
    if "--suffix" in arguments:
        index = arguments.index("--suffix")
        if index + 1 < len(arguments) and arguments[index + 1].startswith("-"):
            arguments[index : index + 2] = [f"--suffix={arguments[index + 1]}"]
    return parser.parse_args(arguments)


def main() -> None:
    args = parse_args()
    corpus_path = args.corpus if args.corpus.is_absolute() else ROOT / args.corpus
    corpus_path = corpus_path.resolve()
    json_output_path = DATA_DIR / f"nvd-2024-strategy-metrics{args.suffix}.json"
    csv_output_path = DATA_DIR / f"nvd-2024-strategy-metrics{args.suffix}.csv"
    report_output_path = DATA_DIR / f"nvd-2024-replication-report{args.suffix}.md"
    filter_summary_path = DATA_DIR / f"nvd-2024-filter-summary{args.suffix}.json"
    try:
        corpus_name = corpus_path.relative_to(ROOT).as_posix()
    except ValueError:
        corpus_name = str(corpus_path)
    report = calculate_metrics(load_corpus(corpus_path), corpus_name)
    write_outputs(report, json_output_path, csv_output_path)
    write_markdown_report(
        report,
        filter_summary_path,
        report_output_path,
        corpus_path,
        args.suffix,
    )
    print(
        "Strategy metrics: "
        f"{len(report['strategies'])} strategies, "
        f"{report['corpusRecords']} corpus records, "
        f"{report['kevRecords']} KEV records."
    )
    print(f"JSON: {json_output_path}")
    print(f"CSV: {csv_output_path}")
    print(f"Report: {report_output_path}")
    print()
    print(
        f"{'Strategy':34} {'TP':>4} {'FP':>6} {'FN':>4} "
        f"{'Total':>7} {'P':>8} {'R':>8} {'F1':>8} {'F2':>8}"
    )
    for result in report["strategies"]:
        print(
            f"{result['strategy']:34} {result['tp']:4} {result['fp']:6} "
            f"{result['fn']:4} {result['prioritizedTotal']:7} "
            f"{result['precision'] * 100:7.2f}% "
            f"{result['recall'] * 100:7.2f}% "
            f"{result['f1'] * 100:7.2f}% "
            f"{result['f2'] * 100:7.2f}%"
        )


if __name__ == "__main__":
    main()
