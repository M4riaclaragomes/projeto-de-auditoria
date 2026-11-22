import argparse
import csv
import gzip
import json
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import date, timedelta
from pathlib import Path


ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
EPSS_DIR = DATA_DIR / "epss"
CANDIDATE_PATH = DATA_DIR / "nvd-2024-filtered.jsonl"
OUTPUT_PATH = DATA_DIR / "nvd-2024-filtered.jsonl"
SUMMARY_PATH = DATA_DIR / "nvd-2024-filter-summary.json"
CHECKPOINT_PATH = EPSS_DIR / "history-checkpoint.json"
TEMP_GZIP_PATH = EPSS_DIR / "epss-history-current.csv.gz"
ARCHIVE_URL = "https://raw.githubusercontent.com/empiricalsec/epss_scores/main"
CHECKPOINT_INTERVAL_DAYS = 30


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Join each NVD CVE to its first EPSS score on or after publication."
    )
    parser.add_argument("--start-date", default="2024-01-01")
    parser.add_argument("--end-date", default="2025-04-30")
    return parser.parse_args()


def atomic_write_json(path: Path, data: object) -> None:
    temporary_path = path.with_suffix(path.suffix + ".tmp")
    with temporary_path.open("w", encoding="utf-8", newline="\n") as output:
        json.dump(data, output, ensure_ascii=False, separators=(",", ":"))
        output.write("\n")
    temporary_path.replace(path)


def download_archive(url: str, destination: Path) -> bool:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "nvd-epss-historical-join/1.0"},
    )
    last_error: Exception | None = None
    for attempt in range(1, 5):
        try:
            with urllib.request.urlopen(request, timeout=180) as response:
                with destination.open("wb") as output:
                    while chunk := response.read(1024 * 1024):
                        output.write(chunk)
            return True
        except urllib.error.HTTPError as error:
            destination.unlink(missing_ok=True)
            if error.code == 404:
                return False
            last_error = error
            if attempt < 4:
                time.sleep(5 * attempt)
        except (OSError, urllib.error.URLError) as error:
            last_error = error
            destination.unlink(missing_ok=True)
            if attempt < 4:
                time.sleep(5 * attempt)
    raise RuntimeError(f"Failed to download {url}: {last_error}") from last_error


def load_candidates() -> tuple[list[dict], dict[str, dict]]:
    if not CANDIDATE_PATH.is_file():
        raise FileNotFoundError(
            f"Filtered NVD candidates not found at {CANDIDATE_PATH}; "
            "run filter_nvd_2024.ps1 first."
        )
    candidates: list[dict] = []
    candidate_by_id: dict[str, dict] = {}
    with CANDIDATE_PATH.open(encoding="utf-8") as source:
        for line_number, line in enumerate(source, start=1):
            if not line.strip():
                continue
            record = json.loads(line)
            cve_id = record.get("cveId")
            published = record.get("published")
            if not cve_id or not published:
                raise ValueError(
                    f"Candidate row {line_number} is missing cveId or published."
                )
            if cve_id in candidate_by_id:
                raise ValueError(f"Duplicate candidate CVE ID: {cve_id}")
            record["_publication_date"] = date.fromisoformat(published[:10])
            candidates.append(record)
            candidate_by_id[cve_id] = record
    if not candidates:
        raise ValueError(f"No candidate records found in {CANDIDATE_PATH}.")
    return candidates, candidate_by_id


def load_checkpoint(start_date: str, end_date: str) -> tuple[date, dict[str, dict]]:
    if not CHECKPOINT_PATH.is_file():
        return date.fromisoformat(start_date), {}
    checkpoint = json.loads(CHECKPOINT_PATH.read_text(encoding="utf-8-sig"))
    if checkpoint.get("startDate") != start_date or checkpoint.get("endDate") != end_date:
        raise ValueError(
            "The EPSS checkpoint uses a different date range. "
            f"Move or remove {CHECKPOINT_PATH} before changing the range."
        )
    last_scanned = date.fromisoformat(checkpoint["lastScannedDate"])
    selected = {
        row["cve"]: {
            "date": row["date"],
            "epss": row["epss"],
            "percentile": row["percentile"],
        }
        for row in checkpoint.get("selectedScores", [])
    }
    print(
        f"Resuming after {last_scanned}; "
        f"{len(selected)} historical scores already checkpointed."
    )
    return last_scanned + timedelta(days=1), selected


def scan_daily_archive(
    score_date: date,
    candidate_by_id: dict[str, dict],
    unmatched: set[str],
    selected: dict[str, dict],
) -> None:
    date_text = score_date.isoformat()
    url = (
        f"{ARCHIVE_URL}/{score_date.year}/"
        f"epss_scores-{date_text}.csv.gz"
    )
    if not download_archive(url, TEMP_GZIP_PATH):
        print(f"No EPSS archive was published for {date_text}; skipping this date.")
        return
    try:
        with gzip.open(TEMP_GZIP_PATH, "rt", encoding="utf-8", newline="") as source:
            metadata = source.readline().strip()
            score_date_match = re.search(r"score_date:(\d{4}-\d{2}-\d{2})", metadata)
            if not score_date_match or score_date_match.group(1) != date_text:
                raise ValueError(
                    f"EPSS archive metadata date does not match {date_text}: {metadata}"
                )
            reader = csv.reader(source)
            if next(reader, None) != ["cve", "epss", "percentile"]:
                raise ValueError(f"Unexpected EPSS CSV header for {date_text}.")

            for row in reader:
                if not row:
                    continue
                cve_id = row[0]
                if cve_id not in unmatched:
                    continue
                if candidate_by_id[cve_id]["_publication_date"] > score_date:
                    continue
                if len(row) != 3:
                    raise ValueError(
                        f"Malformed EPSS row for {cve_id} in archive {date_text}."
                    )
                selected[cve_id] = {
                    "date": date_text,
                    "epss": row[1],
                    "percentile": row[2],
                }
                unmatched.remove(cve_id)
    finally:
        TEMP_GZIP_PATH.unlink(missing_ok=True)


def write_final_corpus(
    candidates: list[dict], selected: dict[str, dict]
) -> tuple[int, int]:
    temporary_path = OUTPUT_PATH.with_suffix(OUTPUT_PATH.suffix + ".tmp")
    final_count = 0
    kev_count = 0
    with temporary_path.open("w", encoding="utf-8", newline="\n") as output:
        for record in candidates:
            score = selected.get(record["cveId"])
            if score is None:
                continue
            record["epssScore"] = float(score["epss"])
            record["epssPercentile"] = float(score["percentile"])
            record["epssDate"] = score["date"]
            record.pop("_publication_date", None)
            if record.get("cisaExploitAdd") is not None:
                kev_count += 1
            output.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")))
            output.write("\n")
            final_count += 1
    temporary_path.replace(OUTPUT_PATH)
    return final_count, kev_count


def main() -> int:
    args = parse_args()
    try:
        start_date = date.fromisoformat(args.start_date)
        end_date = date.fromisoformat(args.end_date)
    except ValueError as error:
        raise ValueError("Dates must use YYYY-MM-DD format.") from error
    if start_date > end_date:
        raise ValueError("--start-date must not be after --end-date.")

    EPSS_DIR.mkdir(parents=True, exist_ok=True)
    candidates, candidate_by_id = load_candidates()
    scan_date, selected = load_checkpoint(args.start_date, args.end_date)
    if scan_date < start_date:
        raise ValueError("Checkpoint date precedes the requested date range.")
    selected = {
        cve_id: score
        for cve_id, score in selected.items()
        if cve_id in candidate_by_id
    }
    unmatched = set(candidate_by_id).difference(selected)
    last_scanned_date = scan_date - timedelta(days=1)
    scanned_days = 0

    while scan_date <= end_date and unmatched:
        print(
            f"Scanning EPSS archive {scan_date.isoformat()} "
            f"({len(unmatched)} corpus CVEs still unmatched)"
        )
        scan_daily_archive(scan_date, candidate_by_id, unmatched, selected)
        last_scanned_date = scan_date
        scanned_days += 1

        if (
            scanned_days % CHECKPOINT_INTERVAL_DAYS == 0
            or scan_date == end_date
            or not unmatched
        ):
            atomic_write_json(
                CHECKPOINT_PATH,
                {
                    "startDate": args.start_date,
                    "endDate": args.end_date,
                    "lastScannedDate": last_scanned_date.isoformat(),
                    "selectedScores": [
                        {"cve": cve_id, **score}
                        for cve_id, score in selected.items()
                    ],
                },
            )
            print(
                f"Checkpoint saved through {last_scanned_date}: "
                f"{len(selected)} matched; {len(unmatched)} remain."
            )
        scan_date += timedelta(days=1)

    final_count, kev_count = write_final_corpus(candidates, selected)
    summary = json.loads(SUMMARY_PATH.read_text(encoding="utf-8-sig"))
    expected_counts = summary.get("expectedArticleCounts", {})
    summary["epssSource"] = (
        "FIRST EPSS daily historical CSV archive "
        "(https://github.com/empiricalsec/epss_scores)"
    )
    summary["epssSnapshot"] = None
    summary.pop("epssScoreDate", None)
    summary["epssSelectionRule"] = (
        "For each CVE, select the first daily EPSS score whose score date "
        "is on or after the CVE publication date."
    )
    summary["epssDateRangeScanned"] = {
        "startDate": args.start_date,
        "endDate": last_scanned_date.isoformat(),
    }
    summary["epssMatched"] = len(selected)
    summary["epssMissing"] = len(unmatched)
    summary["finalCorpusCount"] = final_count
    summary["kevCount"] = kev_count
    summary["historicalEpssMatchesArticleCount"] = len(unmatched) == 375
    summary["matchesArticleChecklist"] = all(
        summary.get("counts", {}).get(key) == value
        for key, value in expected_counts.items()
    )
    if "counts" in summary:
        summary["counts"]["afterMissingEpss"] = final_count
    if "removed" in summary:
        summary["removed"]["missingEpss"] = len(unmatched)
    atomic_write_json(SUMMARY_PATH, summary)

    print(
        f"Historical EPSS complete: matched {len(selected)}/{len(candidates)}; "
        f"{len(unmatched)} lack a score by {last_scanned_date}."
    )
    print(f"Final corpus: {final_count}; KEV cisaExploitAdd count: {kev_count}.")
    print(f"Output: {OUTPUT_PATH}")
    print(f"Summary: {SUMMARY_PATH}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(1)
