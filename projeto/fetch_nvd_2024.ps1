$ErrorActionPreference = "Stop"

$baseUrl = "https://services.nvd.nist.gov/rest/json/cves/2.0"
$outputDirectory = Join-Path $PSScriptRoot "data\nvd-2024-raw"
$resultsPerPage = 2000
$apiKey = $env:NVD_API_KEY
$windows = @(
    @{ Start = "2024-01-01T00:00:00.000Z"; End = "2024-04-29T23:59:59.999Z" },
    @{ Start = "2024-04-30T00:00:00.000Z"; End = "2024-08-27T23:59:59.999Z" },
    @{ Start = "2024-08-28T00:00:00.000Z"; End = "2024-12-25T23:59:59.999Z" },
    @{ Start = "2024-12-26T00:00:00.000Z"; End = "2024-12-31T23:59:59.999Z" }
)

New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
$manifest = [System.Collections.Generic.List[object]]::new()
$requestCount = 0

foreach ($window in $windows) {
    $windowLabel = $window.Start.Substring(0, 10) + "_" + $window.End.Substring(0, 10)
    $startIndex = 0
    $totalResults = $null

    do {
        if ($requestCount -gt 0 -and -not $apiKey) {
            Start-Sleep -Seconds 7
        }

        $query = "pubStartDate=$([uri]::EscapeDataString($window.Start))" +
            "&pubEndDate=$([uri]::EscapeDataString($window.End))" +
            "&resultsPerPage=$resultsPerPage&startIndex=$startIndex"
        $uri = "$baseUrl`?$query"
        if ($apiKey) {
            $headers = @{ apiKey = $apiKey }
        } else {
            $headers = @{}
        }

        $attempt = 0
        while ($true) {
            try {
                $response = Invoke-WebRequest -Uri $uri -Headers $headers -UseBasicParsing -TimeoutSec 120
                break
            } catch {
                $attempt++
                if ($attempt -ge 5) {
                    throw "NVD request failed after $attempt attempts (window $windowLabel, startIndex $startIndex): $($_.Exception.Message)"
                }
                Start-Sleep -Seconds ([Math]::Min(60, 10 * $attempt))
            }
        }
        $requestCount++

        $rawJson = $response.Content
        $totalMatch = [regex]::Match($rawJson, '"totalResults"\s*:\s*(\d+)')
        if (-not $totalMatch.Success) {
            throw "NVD response did not include totalResults (window $windowLabel, startIndex $startIndex)."
        }
        $pageTotal = [int]$totalMatch.Groups[1].Value
        if ($null -eq $totalResults) {
            $totalResults = $pageTotal
        } elseif ($pageTotal -ne $totalResults) {
            throw "NVD totalResults changed during pagination for window $windowLabel."
        }

        $fileName = "{0}_start-{1:D6}.json" -f $windowLabel, $startIndex
        $filePath = Join-Path $outputDirectory $fileName
        [System.IO.File]::WriteAllText($filePath, $rawJson, [System.Text.UTF8Encoding]::new($false))
        Write-Host ("Saved {0} ({1}/{2} records in window)" -f $fileName, [Math]::Min($startIndex + $resultsPerPage, $totalResults), $totalResults)

        $startIndex += $resultsPerPage
    } while ($startIndex -lt $totalResults)

    $manifest.Add([pscustomobject]@{
        pubStartDate = $window.Start
        pubEndDate = $window.End
        totalResults = $totalResults
        pages = [Math]::Ceiling($totalResults / $resultsPerPage)
    })
}

$manifestPath = Join-Path $outputDirectory "manifest.json"
$manifestData = [pscustomobject]@{
    api = $baseUrl
    resultsPerPage = $resultsPerPage
    totalResults = ($manifest | Measure-Object -Property totalResults -Sum).Sum
    retrievedAtUtc = [DateTime]::UtcNow.ToString("o")
    windows = $manifest
}
$manifestData | ConvertTo-Json -Depth 5 | Set-Content -Path $manifestPath -Encoding UTF8
Write-Host ("Finished: {0} total CVE records saved under {1}" -f $manifestData.totalResults, $outputDirectory)
