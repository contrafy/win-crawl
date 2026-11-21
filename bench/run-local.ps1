<#
.SYNOPSIS
  Runs wincrawl (and optionally the legacy threaded crawler) against the local
  benchmark rig (wincrawl-benchd) and writes a markdown results table to
  bench/results/local/<timestamp>.md.

.DESCRIPTION
  Builds nothing. Starts `wincrawl-benchd serve` with a named latency profile,
  generates the URL files, runs
    wincrawl --dns 127.0.0.1:<DnsPort> -c <C> --json <file> --quiet <urls>
  for every -Concurrency value, and the legacy crawler (`<exe> <threads> <urls>`)
  on an IP-literal URL file for every -LegacyThreads value. benchd is always
  stopped on exit.

.EXAMPLE
  bench\run-local.ps1 -Wincrawl build\release\apps\wincrawl\wincrawl.exe -Profile wan
.EXAMPLE
  bench\run-local.ps1 -Legacy build\release\wincrawl_legacy.exe -LegacyCount 20000 -LegacyThreads 500,2000
#>
[CmdletBinding()]
param(
    [string]$Wincrawl,
    [string]$Legacy,
    [string]$Benchd,
    [ValidateSet('lan', 'wan')][string]$Profile = 'lan',
    [int]$Count = 200000,                 # URLs for wincrawl
    [int]$LegacyCount = 0,                # URLs for the legacy crawler (0 = -Count)
    # Strings, not [int[]]: under `powershell -File` "500,2000" arrives as one
    # string and [int] conversion would read it as 5002000 (thousands separator).
    [string[]]$Concurrency = @('500', '2000', '8000'),
    [string[]]$LegacyThreads = @('500', '2000'),
    [int]$Threads = 0,                    # wincrawl -t (0 = its default)
    [int]$ServerThreads = 4,              # benchd HTTP worker loops
    [int]$HttpPort = 8080,
    [int]$DnsPort = 5300,                 # not 5353: mDNS (Chrome, DNS Client) holds it
    [string[]]$ServeArgs = @(),           # extra `serve` options, e.g. '--page-kb','64'
    [string[]]$CrawlArgs = @(),           # extra wincrawl options
    [int]$RunTimeoutSec = 1800,
    # Before each run, wait up to this long for TIME_WAIT sockets on the HTTP
    # port (left by close-per-request clients such as the legacy crawler) to
    # drain: a large TIME_WAIT population slows every new loopback connection.
    [int]$SettleSec = 150,
    [string]$OutDir
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repo = Split-Path -Parent $PSScriptRoot
if (-not $Benchd) { $Benchd = Join-Path $repo 'build\release\apps\benchd\wincrawl-benchd.exe' }
if (-not $OutDir) { $OutDir = Join-Path $PSScriptRoot 'results\local' }
if (-not $Wincrawl -and -not $Legacy) { throw 'give -Wincrawl and/or -Legacy' }
foreach ($exe in @($Benchd, $Wincrawl, $Legacy)) {
    if ($exe -and -not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw "not found: $exe" }
}
$Benchd = (Resolve-Path -LiteralPath $Benchd).Path
if ($Wincrawl) { $Wincrawl = (Resolve-Path -LiteralPath $Wincrawl).Path }
if ($Legacy) { $Legacy = (Resolve-Path -LiteralPath $Legacy).Path }
if ($LegacyCount -le 0) { $LegacyCount = $Count }

# --- ports must be free --------------------------------------------------------
if (Get-NetTCPConnection -LocalPort $HttpPort -State Listen -ErrorAction SilentlyContinue) {
    throw "TCP port $HttpPort is already listening (another benchd?)"
}
if (Get-NetUDPEndpoint -LocalPort $DnsPort -ErrorAction SilentlyContinue) {
    throw "UDP port $DnsPort is already in use"
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$work = Join-Path $OutDir $stamp
New-Item -ItemType Directory -Force -Path $work | Out-Null
$report = Join-Path $OutDir "$stamp.md"

function Quote([string]$a) { if ($a -match '[\s"]') { '"' + ($a -replace '"', '\"') + '"' } else { $a } }

# "500,2000" / "500 2000" / @('500','2000') -> 500, 2000
function Split-IntList([string[]]$values) {
    @($values | ForEach-Object { $_ -split '[,\s]+' } | Where-Object { $_ } | ForEach-Object { [int]$_ })
}

# Runs an executable to completion; returns wall seconds, CPU seconds, exit code and stdout.
function Invoke-Measured([string]$exe, [string[]]$argv, [string]$tag) {
    $out = Join-Path $work "$tag.out.txt"
    $err = Join-Path $work "$tag.err.txt"
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $p = Start-Process -FilePath $exe -ArgumentList (($argv | ForEach-Object { Quote $_ }) -join ' ') `
        -RedirectStandardOutput $out -RedirectStandardError $err -NoNewWindow -PassThru
    $null = $p.Handle  # keep the process handle so ExitCode/TotalProcessorTime survive exit
    if (-not $p.WaitForExit($RunTimeoutSec * 1000)) {
        Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
        $p.WaitForExit()
        Write-Warning "$tag timed out after $RunTimeoutSec s"
    }
    $sw.Stop()
    [pscustomobject]@{
        Wall   = $sw.Elapsed.TotalSeconds
        Cpu    = $p.TotalProcessorTime.TotalSeconds
        Exit   = $p.ExitCode
        Stdout = (Get-Content -Raw -LiteralPath $out -ErrorAction SilentlyContinue)
    }
}

# netstat is O(seconds) with 10^5 entries; Get-NetTCPConnection takes minutes.
function Get-TimeWaitCount {
    @(@(netstat -an -p TCP) -match 'TIME_WAIT' -match ":$HttpPort\s").Count
}

function Wait-Settled {
    if ($SettleSec -le 0) { return }
    $deadline = (Get-Date).AddSeconds($SettleSec)
    while (($n = Get-TimeWaitCount) -gt 1000 -and (Get-Date) -lt $deadline) {
        Write-Host "  waiting for $n TIME_WAIT sockets on :$HttpPort to expire ..."
        Start-Sleep -Seconds 10
    }
}

function Get-ServerCpu($proc) { $proc.Refresh(); $proc.TotalProcessorTime.TotalSeconds }

function Fmt($v, [int]$digits = 0) { if ($null -eq $v) { '-' } else { [math]::Round([double]$v, $digits).ToString("N$digits") } }

$serveArgs = @('serve', '--profile', $Profile, '--dns', "127.0.0.1:$DnsPort", '--http', "0.0.0.0:$HttpPort",
    '-t', "$ServerThreads", '--stats-interval', '5000') + $ServeArgs
$benchdLog = Join-Path $work 'benchd.out.txt'
$benchdErr = Join-Path $work 'benchd.err.txt'
$server = $null
$rows = @()
$legacyRows = @()
try {
    # --- inputs ------------------------------------------------------------------
    $urls = Join-Path $work 'urls.txt'
    $ipUrls = Join-Path $work 'urls-ip.txt'
    $genOut = @()
    if ($Wincrawl) {
        $genOut += & $Benchd gen --count $Count --out $urls --port $HttpPort
        if ($LASTEXITCODE -ne 0) { throw 'url generation failed' }
    }
    if ($Legacy) {
        $genOut += & $Benchd gen --count $LegacyCount --out $ipUrls --port $HttpPort --ip-literal
        if ($LASTEXITCODE -ne 0) { throw 'ip-literal url generation failed' }
    }
    $genOut | ForEach-Object { Write-Host $_ }

    # --- server ------------------------------------------------------------------
    $server = Start-Process -FilePath $Benchd -ArgumentList (($serveArgs | ForEach-Object { Quote $_ }) -join ' ') `
        -RedirectStandardOutput $benchdLog -RedirectStandardError $benchdErr -NoNewWindow -PassThru
    $null = $server.Handle
    $deadline = (Get-Date).AddSeconds(15)
    while ($true) {
        if ($server.HasExited) { throw "benchd exited: $(Get-Content -Raw $benchdErr)" }
        if ((Test-Path $benchdLog) -and (Select-String -Quiet -Pattern '^ready' -LiteralPath $benchdLog)) { break }
        if ((Get-Date) -gt $deadline) { throw 'benchd did not become ready within 15 s' }
        Start-Sleep -Milliseconds 100
    }
    Write-Host "benchd ready (profile $Profile, pid $($server.Id))"

    # --- wincrawl sweep -------------------------------------------------------------
    if ($Wincrawl) {
        foreach ($c in (Split-IntList $Concurrency)) {
            $json = Join-Path $work "wincrawl-c$c.json"
            $argv = @('--dns', "127.0.0.1:$DnsPort", '-c', "$c", '--json', $json, '--quiet')
            if ($Threads -gt 0) { $argv += @('-t', "$Threads") }
            $argv += $CrawlArgs
            $argv += $urls
            Wait-Settled
            Write-Host "wincrawl -c $c ..."
            $cpu0 = Get-ServerCpu $server
            $r = Invoke-Measured $Wincrawl $argv "wincrawl-c$c"
            $serverCpu = (Get-ServerCpu $server) - $cpu0
            $s = $null
            if (Test-Path $json) { $s = Get-Content -Raw $json | ConvertFrom-Json }
            $elapsed = if ($s) { [double]$s.elapsed_s } else { $r.Wall }
            $rows += [pscustomobject]@{
                C = $c; Exit = $r.Exit; Elapsed = $elapsed; Wall = $r.Wall; S = $s
                Cpu = $r.Cpu; ServerCpu = $serverCpu; TimeWait = Get-TimeWaitCount
            }
            if (-not $s) { Write-Warning "wincrawl -c $c produced no JSON (exit $($r.Exit))" }
        }
    }

    # --- legacy sweep -----------------------------------------------------------
    if ($Legacy) {
        foreach ($t in (Split-IntList $LegacyThreads)) {
            Wait-Settled
            Write-Host "legacy $t threads ..."
            $cpu0 = Get-ServerCpu $server
            $r = Invoke-Measured $Legacy @("$t", $ipUrls) "legacy-t$t"
            $serverCpu = (Get-ServerCpu $server) - $cpu0
            $o = $r.Stdout
            function Grab([string]$pattern) { if ($o -match $pattern) { [double]$Matches[1] } else { $null } }
            $codes = if ($o -match 'HTTP codes: 2xx = (\d+), 3xx = (\d+), 4xx = (\d+), 5xx = (\d+), other = (\d+)') {
                "$($Matches[1])/$($Matches[2])/$($Matches[3])/$($Matches[4])/$($Matches[5])"
            } else { '-' }
            $legacyRows += [pscustomobject]@{
                Threads = $t; Exit = $r.Exit; Wall = $r.Wall; Cpu = $r.Cpu; ServerCpu = $serverCpu
                Urls = Grab 'Extracted (\d+) URLs'; Hosts = Grab 'Looked up (\d+) DNS'
                Robots = Grab 'Attempted (\d+) site robots'; Pages = Grab 'Crawled (\d+) pages'
                MB = Grab 'pages @ \d+/s \(([\d.]+) MB\)'; Links = Grab 'Parsed (\d+) links'
                Codes = $codes; TimeWait = Get-TimeWaitCount
            }
        }
    }
}
finally {
    if ($server -and -not $server.HasExited) {
        Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
        $server.WaitForExit(5000) | Out-Null
    }
}

# --- report -----------------------------------------------------------------------
$cpuName = (Get-CimInstance Win32_Processor | Select-Object -First 1).Name.Trim()
$os = (Get-CimInstance Win32_OperatingSystem).Caption
$md = [System.Collections.Generic.List[string]]::new()
$md.Add("# wincrawl local benchmark $stamp")
$md.Add('')
$md.Add("- Machine: $cpuName, $([Environment]::ProcessorCount) logical CPUs, $os")
$md.Add("- Profile: **$Profile**; benchd: ``$($serveArgs -join ' ')``")
$md.Add("- Inputs: $($genOut -join '; ')")
$md.Add("- Files: ``$work``")
$md.Add('')
if ($rows.Count -gt 0) {
    $md.Add('## wincrawl')
    $md.Add('')
    $md.Add('| -c | exit | elapsed s | URLs/s | DNS ok/fail | unique IPs | robots 4xx/attempted | pages ok | pages/s | 2xx/3xx/4xx/5xx | links | MB | timeouts | conn fail | peak inflight | crawler CPU s | server CPU s | TIME_WAIT |')
    $md.Add('|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|')
    foreach ($r in $rows) {
        $s = $r.S
        if ($s) {
            $md.Add("| $($r.C) | $($r.Exit) | $(Fmt $r.Elapsed 1) | $(Fmt ($s.urls_read / $r.Elapsed)) | $(Fmt $s.dns_ok)/$(Fmt $s.dns_fail) | $(Fmt $s.unique_ips) | $(Fmt $s.robots_passed)/$(Fmt $s.robots_attempted) | $(Fmt $s.pages_ok) | $(Fmt ($s.pages_ok / $r.Elapsed)) | $($s.http_2xx)/$($s.http_3xx)/$($s.http_4xx)/$($s.http_5xx) | $(Fmt $s.links) | $(Fmt ($s.bytes_received / 1MB) 1) | $(Fmt $s.timeouts) | $(Fmt $s.connect_fail) | $(Fmt $s.peak_inflight) | $(Fmt $r.Cpu 1) | $(Fmt $r.ServerCpu 1) | $($r.TimeWait) |")
        } else {
            $md.Add("| $($r.C) | $($r.Exit) | $(Fmt $r.Wall 1) | - | - | - | - | - | - | - | - | - | - | - | - | $(Fmt $r.Cpu 1) | $(Fmt $r.ServerCpu 1) | $($r.TimeWait) |")
        }
    }
    $md.Add('')
}
if ($legacyRows.Count -gt 0) {
    $md.Add("## legacy (thread per URL, system DNS, IP-literal URLs, $LegacyCount URLs)")
    $md.Add('')
    $md.Add('| threads | exit | elapsed s | URLs/s | unique hosts | robots attempted | pages | pages/s | 2xx/3xx/4xx/5xx/other | links | MB | crawler CPU s | server CPU s | TIME_WAIT |')
    $md.Add('|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|')
    foreach ($r in $legacyRows) {
        $urlsPerSec = if ($r.Urls) { $r.Urls / $r.Wall } else { $null }
        $pagesPerSec = if ($r.Pages) { $r.Pages / $r.Wall } else { $null }
        $md.Add("| $($r.Threads) | $($r.Exit) | $(Fmt $r.Wall 1) | $(Fmt $urlsPerSec) | $(Fmt $r.Hosts) | $(Fmt $r.Robots) | $(Fmt $r.Pages) | $(Fmt $pagesPerSec) | $($r.Codes) | $(Fmt $r.Links) | $(Fmt $r.MB 1) | $(Fmt $r.Cpu 1) | $(Fmt $r.ServerCpu 1) | $($r.TimeWait) |")
    }
    $md.Add('')
}
$md.Add('URLs/s and pages/s are over the whole run (input read to exit). TIME_WAIT counts sockets on the HTTP port right after each run.')
Set-Content -LiteralPath $report -Value $md -Encoding utf8
Write-Host "report: $report"
Get-Content -LiteralPath $report | Write-Host
