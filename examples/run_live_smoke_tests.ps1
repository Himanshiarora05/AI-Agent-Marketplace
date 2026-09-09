$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$reports = Join-Path $PSScriptRoot "reports"
New-Item -ItemType Directory -Force -Path $reports | Out-Null

# Never ship stale/canned JSON from a previous run. Reports are generated fresh
# by the actual entrypoint when this smoke test is executed.
Get-ChildItem -Path $reports -Filter "*.json" -File -ErrorAction SilentlyContinue |
  Remove-Item -Force

$sites = @(
  "https://www.adobe.com",
  "https://www.microsoft.com",
  "https://www.shopify.com"
)

$runner = Join-Path $root "skills/audit-orchestrator/scripts/run_audit.py"
$limit = 240

foreach ($site in $sites) {
  $host = ([uri]$site).Host
  $safe = $host -replace '[^A-Za-z0-9.-]', '_'
  $out = Join-Path $reports ("{0}.json" -f $safe)

  Write-Host ""
  Write-Host "=== Auditing $site ==="
  $sw = [System.Diagnostics.Stopwatch]::StartNew()

  python $runner $site --max-pages 3 --stage-timeout 60 --runtime-limit $limit --output $out

  $sw.Stop()
  if ($LASTEXITCODE -ne 0) {
    throw "Audit failed for $site"
  }
  if (-not (Test-Path $out)) {
    throw "No report was produced for $site"
  }

  $report = Get-Content $out -Raw | ConvertFrom-Json
  if ($report.site -ne $site) {
    throw "Report site mismatch: expected $site, got $($report.site)"
  }
  if ($null -eq $report.execution.runtime_seconds) {
    throw "Runtime metadata missing from $out"
  }

  $runtime = [double]$report.execution.runtime_seconds
  Write-Host ("Completed in {0:N3}s (pipeline limit {1}s)" -f $runtime, $limit)

  if ($runtime -gt $limit) {
    throw "Runtime limit exceeded for $site"
  }
}

Write-Host ""
Write-Host "Fresh live smoke tests complete."
Write-Host "Inspect the newly generated JSON files under examples/reports/."
