$ErrorActionPreference = "Stop"

$dataDirectory = Join-Path $PSScriptRoot "data"
$rawDirectory = Join-Path $dataDirectory "nvd-2024-raw"
$epssPath = Join-Path $dataDirectory "epss\epss_scores-current.csv.gz"
$outputPath = Join-Path $dataDirectory "nvd-2024-filtered.jsonl"
$summaryPath = Join-Path $dataDirectory "nvd-2024-filter-summary.json"
$cvssPreference = @("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")

if (-not (Test-Path -LiteralPath $rawDirectory -PathType Container)) {
    throw "NVD raw data directory not found: $rawDirectory"
}
if (-not (Test-Path -LiteralPath $epssPath -PathType Leaf)) {
    throw "EPSS snapshot not found: $epssPath"
}

$epssScores = @{}
$epssPercentiles = @{}
$fileStream = [System.IO.File]::OpenRead($epssPath)
$gzipStream = [System.IO.Compression.GzipStream]::new(
    $fileStream,
    [System.IO.Compression.CompressionMode]::Decompress
)
$reader = [System.IO.StreamReader]::new($gzipStream)
try {
    $metadataLine = $reader.ReadLine()
    $headerLine = $reader.ReadLine()
    if ($headerLine -ne "cve,epss,percentile") {
        throw "Unexpected EPSS CSV header: $headerLine"
    }
    $epssDateMatch = [regex]::Match($metadataLine, "score_date:([^,]+)")
    if (-not $epssDateMatch.Success) {
        throw "EPSS snapshot does not declare score_date."
    }
    $epssDate = $epssDateMatch.Groups[1].Value
    while ($null -ne ($line = $reader.ReadLine())) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }
        $columns = $line.Split(",")
        if ($columns.Count -lt 3) {
            throw "Malformed EPSS CSV row: $line"
        }
        $epssScores[$columns[0]] = $columns[1]
        $epssPercentiles[$columns[0]] = $columns[2]
    }
} finally {
    $reader.Dispose()
    $gzipStream.Dispose()
    $fileStream.Dispose()
}

$counts = [ordered]@{
    startingRecords = 0
    afterRejectedStatus = 0
    afterIncompleteAnalysisStatus = 0
    afterMissingCvss = 0
    afterMissingEpss = 0
}
$statusCounts = @{}
$kevCount = 0
$removed = [ordered]@{
    rejectedStatus = 0
    incompleteAnalysisStatus = 0
    missingCvss = 0
    missingEpss = 0
}
$outputWriter = [System.IO.StreamWriter]::new(
    $outputPath,
    $false,
    [System.Text.UTF8Encoding]::new($false),
    1048576
)
try {
    foreach ($file in (Get-ChildItem -LiteralPath $rawDirectory -Filter "*.json" | Where-Object { $_.Name -ne "manifest.json" } | Sort-Object Name)) {
        $page = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json
        foreach ($item in $page.vulnerabilities) {
            $cve = $item.cve
            $counts.startingRecords++
            $status = [string]$cve.vulnStatus
            if (-not $statusCounts.ContainsKey($status)) {
                $statusCounts[$status] = 0
            }
            $statusCounts[$status]++

            if ($status -eq "Rejected") {
                $removed.rejectedStatus++
                continue
            }
            $counts.afterRejectedStatus++

            if ($status -eq "Awaiting Analysis" -or $status -eq "Undergoing Analysis") {
                $removed.incompleteAnalysisStatus++
                continue
            }
            $counts.afterIncompleteAnalysisStatus++

            $selectedMetric = $null
            $selectedVersion = $null
            foreach ($metricName in $cvssPreference) {
                $metricProperty = $cve.metrics.PSObject.Properties[$metricName]
                if ($null -eq $metricProperty) {
                    continue
                }
                $candidates = @($metricProperty.Value | Where-Object {
                    $null -ne $_.cvssData -and $null -ne $_.cvssData.baseScore
                })
                if ($candidates.Count -eq 0) {
                    continue
                }
                $selectedMetric = $candidates | Where-Object { $_.type -eq "Primary" } | Select-Object -First 1
                if ($null -eq $selectedMetric) {
                    $selectedMetric = $candidates[0]
                }
                $selectedVersion = $selectedMetric.cvssData.version
                break
            }
            if ($null -eq $selectedMetric) {
                $removed.missingCvss++
                continue
            }
            $counts.afterMissingCvss++

            $cveId = [string]$cve.id
            if (-not $epssScores.ContainsKey($cveId)) {
                $removed.missingEpss++
                continue
            }
            $counts.afterMissingEpss++
            if ($null -ne $cve.cisaExploitAdd) {
                $kevCount++
            }

            $record = [ordered]@{
                cveId = $cveId
                published = $cve.published
                vulnStatus = $cve.vulnStatus
                cisaExploitAdd = $cve.cisaExploitAdd
                cvssVersion = $selectedVersion
                cvssBaseScore = $selectedMetric.cvssData.baseScore
                cvssType = $selectedMetric.type
                cvssSource = $selectedMetric.source
                epssScore = [double]$epssScores[$cveId]
                epssPercentile = [double]$epssPercentiles[$cveId]
                epssDate = $epssDate
                nvdCve = $cve
            }
            $outputWriter.WriteLine(($record | ConvertTo-Json -Depth 100 -Compress))
        }
    }
} finally {
    $outputWriter.Dispose()
}

$expectedCounts = [ordered]@{
    startingRecords = 40704
    afterRejectedStatus = 39959
    afterIncompleteAnalysisStatus = 32181
    afterMissingCvss = 32154
    afterMissingEpss = 31779
}
$summary = [ordered]@{
    nvdRawDirectory = "nvd-2024-raw"
    epssSnapshot = "epss/epss_scores-current.csv.gz"
    epssSource = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
    epssScoreDate = $epssDate
    outputFile = "nvd-2024-filtered.jsonl"
    cvssVersionPreference = $cvssPreference
    cvssSelectionRule = "Within the highest-preference version with a baseScore, select type Primary; if none exists, use the first available metric."
    counts = $counts
    removed = $removed
    observedNvdStatusCounts = $statusCounts
    expectedArticleCounts = $expectedCounts
    matchesArticleChecklist = (($counts | ConvertTo-Json -Compress) -eq ($expectedCounts | ConvertTo-Json -Compress))
    kevCount = $kevCount
}

$summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $summaryPath -Encoding UTF8
Write-Host "Sequential filter counts:"
foreach ($name in $counts.Keys) {
    Write-Host ("  {0}: {1} (expected {2})" -f $name, $counts[$name], $expectedCounts[$name])
}
Write-Host ("  Removed via CISA KEV field: {0} records have cisaExploitAdd" -f $summary.kevCount)
Write-Host "Output: $outputPath"
Write-Host "Summary: $summaryPath"
