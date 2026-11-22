<#
.SYNOPSIS
Runs the libFuzzer targets of a 'fuzz' preset build, one after another.

.DESCRIPTION
Each target fuzzes for -Seconds starting from its committed seed corpus
(fuzz/corpus/<target>, read-only here) plus a work corpus under -Work that
collects the inputs it discovers, with its dictionary (fuzz/dict/<target>.dict)
when there is one. Crashes, leaks, timeouts and OOMs are written to
-Artifacts/<target>/. Exits non-zero if any target failed.

.EXAMPLE
powershell -NoProfile -File fuzz\run.ps1 -Seconds 600 -Targets url,robots
#>
param(
    [int]$Seconds = 60,
    [string[]]$Targets = @(),
    [string]$Build = "build/fuzz",
    [string]$Work = "build/fuzz/corpus-work",
    [string]$Artifacts = "build/fuzz/artifacts",
    [int]$Timeout = 10,
    # Extra libFuzzer flags, e.g. -Extra '-jobs=4','-workers=4'
    [string[]]$Extra = @()
)

$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

# `-File` passes "a,b" as one string; accept both forms.
$Targets = @($Targets | ForEach-Object { $_ -split ',' } | Where-Object { $_ })
if ($Targets.Count -eq 0) {
    $Targets = Get-ChildItem -Directory "fuzz/corpus" | ForEach-Object { $_.Name } | Sort-Object
}

$failed = @()
foreach ($t in $Targets) {
    $exe = Join-Path $Build "bin/fuzz_$t.exe"
    if (-not (Test-Path $exe)) {
        Write-Host "::error::$exe not found (build the 'fuzz' preset first)"
        $failed += $t
        continue
    }
    $work = Join-Path $Work $t
    $art = Join-Path $Artifacts $t
    New-Item -ItemType Directory -Force -Path $work, $art | Out-Null

    $flags = @($work, "fuzz/corpus/$t", "-max_total_time=$Seconds", "-timeout=$Timeout",
               "-artifact_prefix=$art/", "-print_final_stats=1")
    $dict = "fuzz/dict/$t.dict"
    if (Test-Path $dict) { $flags += "-dict=$dict" }
    $flags += $Extra

    Write-Host "=== fuzz_$t ($Seconds s)"
    # libFuzzer logs to stderr; keep it as plain text.
    & $exe @flags 2>&1 | ForEach-Object { "$_" }
    $code = $LASTEXITCODE
    if ($code -ne 0) {
        Write-Host "::error::fuzz_$t exited with $code; artifacts in $art"
        $failed += $t
    }
}

if ($failed.Count -ne 0) {
    Write-Host "failed: $($failed -join ', ')"
    exit 1
}
Write-Host "all targets passed: $($Targets -join ', ')"
