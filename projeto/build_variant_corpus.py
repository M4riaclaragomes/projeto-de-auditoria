import json
import os
import tempfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
INPUT_PATH = DATA_DIR / "nvd-2024-filtered.jsonl"
OUTPUT_PATH = DATA_DIR / "nvd-2024-filtered-variant.jsonl"
SUMMARY_PATH = DATA_DIR / "nvd-2024-filter-summary-variant.json"
ORIGINAL_SUMMARY_PATH = DATA_DIR / "nvd-2024-filter-summary.json"
CVSS_METRIC_PREFERENCE = (
    "cvssMetricV40",
    "cvssMetricV31",
    "cvssMetricV30",
    "cvssMetricV2",
)


def select_cvss_metric(nvd_cve: dict[str, Any]) -> dict[str, Any] | None:
    metrics = nvd_cve.get("metrics")
    if not isinstance(metrics, dict):
        return None

    for metric_name in CVSS_METRIC_PREFERENCE:
        entries = metrics.get(metric_name)
        if not isinstance(entries, list):
            continue
        available = []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            cvss_data = entry.get("cvssData")
            if not isinstance(cvss_data, dict) or cvss_data.get("baseScore") is None:
                continue
            available.append(entry)
        if not available:
            continue

        for preferred_type in ("Secondary", "Primary"):
            for entry in available:
                if entry.get("type") == preferred_type:
                    return entry
        return available[0]
    return None


def write_jsonl_record(output: Any, record: dict[str, Any]) -> None:
    output.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")))
    output.write("\n")


def main() -> None:
    for required_path in (INPUT_PATH, ORIGINAL_SUMMARY_PATH):
        if not required_path.is_file():
            raise FileNotFoundError(f"Required input file not found: {required_path}")
    counts = {
        "startingRecords": 0,
        "removedDeferred": 0,
        "afterDeferred": 0,
        "removedWithoutCvss": 0,
        "finalRecords": 0,
        "kevRecords": 0,
    }
    output_temp_path: Path | None = None
    summary_temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            prefix=".nvd-2024-filtered-variant-",
            suffix=".tmp",
            dir=DATA_DIR,
            delete=False,
        ) as output:
            output_temp_path = Path(output.name)
            with INPUT_PATH.open(encoding="utf-8") as source:
                for line_number, line in enumerate(source, start=1):
                    if not line.strip():
                        continue
                    record = json.loads(line)
                    if not isinstance(record, dict):
                        raise ValueError(
                            f"Expected a JSON object on input row {line_number}."
                        )
                    counts["startingRecords"] += 1

                    if record.get("vulnStatus") == "Deferred":
                        counts["removedDeferred"] += 1
                        continue
                    counts["afterDeferred"] += 1

                    nvd_cve = record.get("nvdCve")
                    if not isinstance(nvd_cve, dict):
                        metric = None
                    else:
                        metric = select_cvss_metric(nvd_cve)
                    if metric is None:
                        counts["removedWithoutCvss"] += 1
                        continue

                    cvss_data = metric["cvssData"]
                    record["cvssBaseScore"] = cvss_data["baseScore"]
                    record["cvssVersion"] = cvss_data.get("version")
                    record["cvssType"] = metric.get("type")
                    record["cvssSource"] = metric.get("source")
                    counts["finalRecords"] += 1
                    if record.get("cisaExploitAdd") is not None:
                        counts["kevRecords"] += 1
                    write_jsonl_record(output, record)

        original_summary = json.loads(
            ORIGINAL_SUMMARY_PATH.read_text(encoding="utf-8-sig")
        )
        summary = {
            "inputCorpus": "nvd-2024-filtered.jsonl",
            "outputCorpus": "nvd-2024-filtered-variant.jsonl",
            "expectedArticleCounts": original_summary.get(
                "expectedArticleCounts", {}
            ),
            "epssDateRangeScanned": original_summary.get(
                "epssDateRangeScanned", {}
            ),
            "epssSelectionRule": original_summary.get("epssSelectionRule"),
            "method": {
                "excludedVulnStatus": "Deferred",
                "cvssMetricVersionPreference": list(CVSS_METRIC_PREFERENCE),
                "cvssTypePreference": ["Secondary", "Primary", "first available"],
                "cvssEntriesRequireDictionary": True,
                "cvssEntriesRequireBaseScore": True,
            },
            "counts": counts,
        }
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            prefix=".nvd-2024-filter-summary-variant-",
            suffix=".tmp",
            dir=DATA_DIR,
            delete=False,
        ) as summary_file:
            summary_temp_path = Path(summary_file.name)
            json.dump(summary, summary_file, ensure_ascii=False, indent=2)
            summary_file.write("\n")

        os.replace(output_temp_path, OUTPUT_PATH)
        output_temp_path = None
        os.replace(summary_temp_path, SUMMARY_PATH)
        summary_temp_path = None
    finally:
        for temporary_path in (output_temp_path, summary_temp_path):
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)

    print(f"Initial records: {counts['startingRecords']:,}")
    print(f"Removed as Deferred: {counts['removedDeferred']:,}")
    print(f"Removed without CVSS: {counts['removedWithoutCvss']:,}")
    print(f"Final records: {counts['finalRecords']:,}")
    print(f"KEV records: {counts['kevRecords']:,}")
    print(f"Corpus: {OUTPUT_PATH}")
    print(f"Summary: {SUMMARY_PATH}")


if __name__ == "__main__":
    main()
