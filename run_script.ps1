YNOPSIS
    Launches the release build of WinSock-Crawler with a 100-thread
    workload against the sample 100-URL list.

.DESCRIPTION
    Expects the standard out-of-tree CMake layout:

        /build/x64/Release/wincrawl.exe
        /sample_urls/URL-input-100.txt

    The script can be placed anywhere, but is intended to sit
    at the repository root.
#>

$exe   = Join-Path -Path $PSScriptRoot -ChildPath "build\x64\Release\wincrawl.exe"
$urls  = Join-Path -Path $PSScriptRoot -ChildPath "sample_urls\URL-input-100.txt"

if (-not (Test-Path $exe))  { throw "Executable not found: $exe"  }
if (-not (Test-Path $urls)) { throw "Seed list not found: $urls" }

& $exe 100 $urls

