<#
.SYNOPSIS
    Configures an out-of-source CMake build (x64 - Release),
    compiles it with MSBuild and immediately launches the crawler.

.NOTES
    • Requires CMake and a VS 2022 Developer PowerShell.
    • The working directory can be the repo root or anywhere else.
#>

$rootDir = $PSScriptRoot
$buildDir = Join-Path $rootDir "build"

# --- Configure ----------------------------------------------------------------
if (-not (Test-Path $buildDir)) { New-Item -ItemType Directory $buildDir | Out-Null }

cmake -S $rootDir -B $buildDir -A x64 -DCMAKE_BUILD_TYPE=Release

# --- Build --------------------------------------------------------------------
cmake --build $buildDir --config Release

# --- Run ----------------------------------------------------------------------
& "$rootDir\run_script.ps1"

