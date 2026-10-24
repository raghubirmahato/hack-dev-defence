#Requires -Version 5.1
<#
.SYNOPSIS
    HDD HK1 demo attack script - SQL injection on a login form (lab/rehearsal only).

.DESCRIPTION
    Sends the twelve demo payloads from lab/demo/payloads.tsv (the six mandated
    SQL-injection payloads M1-M6 of docs/SPEC.md C4.1/E1.1 plus the six
    auth-bypass forms named in docs/COLLAB.md) to ONE login endpoint:

      * as an urlencoded login POST (username=<payload>, password=<payload>), and
      * as a GET query string (username=<payload>&password=<payload>).

    It prints every request with its HTTP status, says whether the response looks
    like the admin page and prints a final "reached admin / blocked yes/no per
    payload" table. Rate is capped at 2 requests per second (500 ms spacing).

    SAFETY (hard-coded):
      * the target host must be loopback (127.0.0.0/8, ::1, localhost), which is
        always allowed for the local rehearsal, OR be listed in the operator-created
        lab/demo/targets.allow (one host per line); otherwise the script refuses
        BEFORE sending anything;
      * only the login path is requested; no scanning, no other paths, no other
        attack classes, never a third-party host;
      * if the target or the operator is not authorised, do not run this script.

    This app/script pair is lab-only and is not shipped. It demonstrates a real
    SQL injection; it is not a security product and makes no protection claim.

.PARAMETER TargetUrl
    Base URL of the target: http(s)://host[:port][/path]. Default from
    HDD_ATTACK_TARGET or http://127.0.0.1:8080 (the local HDD proxy). For the
    "before" comparison use http://127.0.0.1:8082 (the direct lab shop origin; the
    older Python lab app is on 8081).

.PARAMETER LoginPath
    Login endpoint path. Default: the target URL path when it is not "/", else
    /admin/login (the lab shop admin login; use -LoginPath /login for the older
    Python lab app).

.PARAMETER UserField
    Login form username field name (default username).

.PARAMETER PassField
    Login form password field name (default password).

.PARAMETER Kind
    auto | direct | proxy | target. auto detects the local rehearsal ports
    (8082/8081 = direct lab origin, 8080 = through HDD). direct prints "reached admin",
    proxy prints "blocked" with Ray IDs, target prints both.

.PARAMETER DashboardUrl
    Optional URL of the HDD dashboard/admin listener, printed at the end of a
    through-HDD run so the operator can find the events and bans. The npm wrapper
    passes the admin URL of the run; without it a generic hint is printed.

.PARAMETER Help
    Print this usage and exit.

.NOTES
    Requires Windows PowerShell 5.1+ and curl.exe (ships with Windows 10 1803+
    and Windows Server 2019+; otherwise install curl). The bash twin is
    lab/demo/attack.sh. Exit codes: 0 ran, 2 usage/prerequisite, 3 refused by
    allowlist, 4 refused by target validation.
#>
[CmdletBinding()]
param(
    [string]$TargetUrl = $(if ($env:HDD_ATTACK_TARGET) { $env:HDD_ATTACK_TARGET } else { 'http://127.0.0.1:8080' }),
    [string]$LoginPath = '/admin/login',
    [string]$UserField = 'username',
    [string]$PassField = 'password',
    [ValidateSet('auto', 'direct', 'proxy', 'target')]
    [string]$Kind = 'auto',
    [string]$DashboardUrl = '',
    [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ExitUsage = 2
$script:ExitRefused = 3
$script:ExitTarget = 4

function Write-Section([string]$Text) {
    Write-Output ''
    Write-Output ('=' * 104)
    Write-Output $Text
    Write-Output ('=' * 104)
}

function Stop-Script([int]$Code, [string]$Message) {
    Write-Output ''
    Write-Output ('ERROR: ' + $Message)
    exit $Code
}

function Write-Usage {
    Write-Output @'
HDD HK1 demo attack script (lab/rehearsal only) - SQL injection on one login form.

Usage (Windows PowerShell 5.1+):
  powershell -NoProfile -ExecutionPolicy Bypass -File lab/demo/attack.ps1 [-TargetUrl URL]
      [-LoginPath /admin/login] [-UserField username] [-PassField password] [-DashboardUrl URL]
      [-Kind auto|direct|proxy|target]

Examples:
  # direct lab shop origin (POST /admin/login): several payloads reach the admin dashboard
  pwsh -File lab/demo/attack.ps1 -TargetUrl http://127.0.0.1:8082
  # through HDD in block mode: expected 403 + Ray ID and a ban for all twelve
  pwsh -File lab/demo/attack.ps1 -TargetUrl http://127.0.0.1:8080
  # remediation state: SHOP_VULN=0 on the shop; the same payloads no longer reach the dashboard

Safety: the target host must be loopback or listed in lab/demo/targets.allow
(one operator-authorised host per line). Only the login endpoint is requested;
the script never scans and never touches a third-party host. Never run it on a
site you are not authorised to test. This is a lab demo, not a security product.
'@
}

if ($Help) {
    Write-Usage
    exit 0
}

# --- paths -------------------------------------------------------------------
$ScriptDir = $PSScriptRoot
if ([string]::IsNullOrEmpty($ScriptDir)) {
    $ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
}
$PayloadFile = Join-Path $ScriptDir 'payloads.tsv'
$AllowFile = Join-Path $ScriptDir 'targets.allow'

# --- helpers -----------------------------------------------------------------
function Test-LoopbackHost([string]$HostName) {
    if ([string]::IsNullOrEmpty($HostName)) { return $false }
    if ($HostName -ieq 'localhost') { return $true }
    $address = $null
    if ([System.Net.IPAddress]::TryParse($HostName, [ref]$address)) {
        return [System.Net.IPAddress]::IsLoopback($address)
    }
    return $false
}

function Find-Curl {
    $command = Get-Command -Name 'curl.exe' -CommandType Application -ErrorAction SilentlyContinue
    if ($null -ne $command) { return $command.Source }
    return $null
}

function Read-AllowFileHosts([string]$Path) {
    $hosts = New-Object System.Collections.Generic.List[string]
    if (-not (Test-Path -LiteralPath $Path)) { return $hosts }
    foreach ($rawLine in [System.IO.File]::ReadAllLines($Path)) {
        $line = $rawLine
        $comment = $line.IndexOf('#')
        if ($comment -ge 0) { $line = $line.Substring(0, $comment) }
        $line = $line.Trim()
        if ($line.Length -gt 0) { $hosts.Add($line) }
    }
    return $hosts
}

function Read-Payloads([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        Stop-Script $script:ExitUsage ("payload catalogue not found: " + $Path)
    }
    $rows = New-Object System.Collections.Generic.List[object]
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'
    $lineNumber = 0
    foreach ($rawLine in [System.IO.File]::ReadAllLines($Path)) {
        $lineNumber++
        if ($rawLine.Trim().Length -eq 0) { continue }
        if ($rawLine.TrimStart().StartsWith('#')) { continue }
        $parts = $rawLine -split "`t"
        if ($parts.Count -ne 3) {
            Stop-Script $script:ExitUsage ("malformed payload line {0} in {1}: expected id<TAB>group<TAB>payload" -f $lineNumber, $Path)
        }
        $id = $parts[0].Trim()
        $group = $parts[1].Trim()
        $payload = $parts[2]
        if ($id -notmatch '^[MB][1-6]$') {
            Stop-Script $script:ExitUsage ("malformed payload id '{0}' on line {1} of {2}" -f $id, $lineNumber, $Path)
        }
        if ($payload.Length -eq 0) {
            Stop-Script $script:ExitUsage ("empty payload on line {0} of {1}" -f $lineNumber, $Path)
        }
        if (-not $seen.Add($id)) {
            Stop-Script $script:ExitUsage ("duplicate payload id '{0}' on line {1} of {2}" -f $id, $lineNumber, $Path)
        }
        $rows.Add([pscustomobject]@{ Id = $id; Group = $group; Payload = $payload })
    }
    return $rows
}

function Test-AdminPage([string]$Body) {
    if ([string]::IsNullOrEmpty($Body)) { return $false }
    # Lab shop admin dashboard markers (CoreByte): the dashboard has "Demo data only"
    # and the admin shell title "Dashboard | CoreByte Admin"; the login page has
    # neither. The older Python lab page markers are kept for stack: python profiles.
    if ($Body -match '(?i)Demo data only') { return $true }
    if ($Body -match '(?i)<title>Dashboard \| CoreByte Admin</title>') { return $true }
    if ($Body -match '(?i)data-page="admin"') { return $true }
    if ($Body -match '(?i)<h1>\s*admin panel\s*</h1>') { return $true }
    return $false
}

function Test-BlockPage([string]$Body) {
    if ([string]::IsNullOrEmpty($Body)) { return $false }
    return (($Body -match '(?i)access denied') -or
        ($Body -match '(?i)your request looked like an attack') -or
        ($Body -match '(?i)blocked by hdd'))
}

function Get-RayId([string]$Body) {
    if ([string]::IsNullOrEmpty($Body)) { return '' }
    if ($Body -match '([0-9a-f]{16}-HDD1)') { return $Matches[1] }
    return ''
}

function Get-ShortText([string]$Text, [int]$Width) {
    if ($Text.Length -le $Width) { return $Text }
    return $Text.Substring(0, $Width - 1) + '~'
}

function Invoke-CurlRequest {
    param(
        [string]$Method,
        [string]$Url,
        [string]$Data,
        [string]$BodyFile,
        [string]$ErrorFile,
        [string]$CookieJar,
        [string]$CurlPath
    )
    $arguments = @(
        '-sS', '-o', $BodyFile, '-w', '%{http_code}', '-L', '--max-redirs', '5',
        '-c', $CookieJar, '-b', $CookieJar, '-m', '15',
        '-H', 'Accept: text/html', '-A', 'hdd-hk1-demo-attack/1.0'
    )
    if ($Method -eq 'POST') { $arguments += @('--data', $Data) }
    $arguments += $Url
    $statusText = & $CurlPath @arguments 2>$ErrorFile
    $exitCode = $LASTEXITCODE
    $status = -1
    $joined = ''
    if ($null -ne $statusText) {
        $joined = (($statusText | ForEach-Object { [string]$_ }) -join '').Trim()
        [void][int]::TryParse($joined, [ref]$status)
    }
    $body = ''
    if (Test-Path -LiteralPath $BodyFile) {
        $body = [System.IO.File]::ReadAllText($BodyFile, [System.Text.Encoding]::UTF8)
    }
    $curlError = ''
    if (Test-Path -LiteralPath $ErrorFile) {
        $curlError = ([System.IO.File]::ReadAllText($ErrorFile)).Trim()
    }
    return [pscustomobject]@{
        ExitCode = $exitCode
        Status   = $status
        Body     = $body
        Error    = $curlError
    }
}

function Get-TableCell([object]$Record, [string]$RequestedKind) {
    if ($null -eq $Record) { return 'n/a' }
    if ($Record.Status -lt 0) { return 'no (request error)' }
    if ($RequestedKind -eq 'direct') {
        if ($Record.Admin) { return 'YES' }
        if ($Record.Status -eq 500) { return 'no (500 SQL error)' }
        if ($Record.Status -eq 401) { return 'no (401 rejected)' }
        if ($Record.BlockPage) { return 'no (block page)' }
        return ('no (HTTP ' + $Record.Status + ')')
    }
    if ($RequestedKind -eq 'proxy') {
        if ($Record.Admin) { return 'NO - ADMIN REACHED' }
        if (($Record.Status -eq 403) -or ($Record.Status -eq 429)) { return ('YES (' + $Record.Status + ')') }
        return ('no (HTTP ' + $Record.Status + ')')
    }
    # generic target: report whatever the response shows, honestly
    if ($Record.Admin) { return 'ADMIN REACHED' }
    if (($Record.Status -eq 403) -or ($Record.Status -eq 429)) { return ('blocked (' + $Record.Status + ')') }
    return ('no (HTTP ' + $Record.Status + ')')
}

function Get-KindDescription([string]$RequestedKind, [string]$ResolvedKind) {
    if ($RequestedKind -ne 'auto') { return 'explicit -Kind ' + $RequestedKind }
    switch ($ResolvedKind) {
        'direct' { return 'auto: loopback port 8081 -> direct lab origin' }
        'proxy' { return 'auto: loopback port 8080 -> through HDD' }
        default { return 'auto: not a local rehearsal port -> generic target' }
    }
}

# --- 1. validate the target URL before doing anything ------------------------
$TargetUrl = $TargetUrl.Trim()
$uri = $null
if ([string]::IsNullOrWhiteSpace($TargetUrl)) {
    Stop-Script $script:ExitTarget 'no target URL given (use -TargetUrl or HDD_ATTACK_TARGET).'
}
if (-not [System.Uri]::TryCreate($TargetUrl, [System.UriKind]::Absolute, [ref]$uri)) {
    Stop-Script $script:ExitTarget ("target URL is not an absolute http(s) URL: '" + $TargetUrl + "'")
}
if (($uri.Scheme -ne 'http') -and ($uri.Scheme -ne 'https')) {
    Stop-Script $script:ExitTarget ("target URL scheme must be http or https, got '" + $uri.Scheme + "'.")
}
if (-not [string]::IsNullOrEmpty($uri.UserInfo)) {
    Stop-Script $script:ExitTarget 'target URL must not contain embedded credentials (no secrets in URLs).'
}
$hostName = $uri.DnsSafeHost
$port = $uri.Port
$isLoopback = Test-LoopbackHost $hostName

# --- 2. resolve the mode (direct origin vs through HDD) ---------------------
$resolvedKind = $Kind
if ($Kind -eq 'auto') {
    if ($isLoopback -and (($port -eq 8082) -or ($port -eq 8081))) { $resolvedKind = 'direct' }
    elseif ($isLoopback -and ($port -eq 8080)) { $resolvedKind = 'proxy' }
    else { $resolvedKind = 'target' }
}

# --- 3. allowlist gate: refuse before the first request ---------------------
$allowNote = ''
if ($isLoopback) {
    $allowNote = 'loopback host -> always allowed (no lab/demo/targets.allow entry needed)'
}
else {
    $allowedHosts = Read-AllowFileHosts $AllowFile
    $matched = $false
    foreach ($allowed in $allowedHosts) {
        if ($allowed -ieq $hostName) { $matched = $true; break }
    }
    if (-not $matched) {
        Write-Output ''
        Write-Output ("REFUSED: target host '" + $hostName + "' is not loopback and is not listed in:")
        Write-Output ('  ' + $AllowFile)
        Write-Output '  Create that file with one operator-authorised host per line, for example:'
        Write-Output ('    ' + $hostName)
        Write-Output '  (see lab/demo/targets.allow.example). Loopback hosts are always allowed.'
        Write-Output '  No request was sent.'
        exit $script:ExitRefused
    }
    $allowNote = ("host listed in " + $AllowFile)
}

# --- 4. resolve the login endpoint and field names --------------------------
if ($UserField -notmatch '^[A-Za-z0-9_\-\[\]]+$') {
    Stop-Script $script:ExitUsage ("invalid -UserField '" + $UserField + "' (letters, digits, _ - [ ] only).")
}
if ($PassField -notmatch '^[A-Za-z0-9_\-\[\]]+$') {
    Stop-Script $script:ExitUsage ("invalid -PassField '" + $PassField + "' (letters, digits, _ - [ ] only).")
}
$resolvedLoginPath = ''
if (-not [string]::IsNullOrWhiteSpace($LoginPath)) {
    $resolvedLoginPath = $LoginPath.Trim()
}
elseif (($uri.AbsolutePath -ne '/') -and ($uri.AbsolutePath.Length -gt 0)) {
    $resolvedLoginPath = $uri.AbsolutePath
}
else {
    $resolvedLoginPath = '/admin/login'
}
if (-not $resolvedLoginPath.StartsWith('/')) { $resolvedLoginPath = '/' + $resolvedLoginPath }
$authority = $uri.GetLeftPart([System.UriPartial]::Authority)
$loginUrl = $authority + $resolvedLoginPath

# --- 5. load the payload catalogue and the HTTP client ----------------------
$payloads = Read-Payloads $PayloadFile
$mandated = @($payloads | Where-Object { $_.Group -eq 'mandated' }).Count
$bypass = @($payloads | Where-Object { $_.Group -eq 'auth-bypass' }).Count
if (($mandated -ne 6) -or ($bypass -ne 6)) {
    Stop-Script $script:ExitUsage ("payload catalogue must hold 6 mandated + 6 auth-bypass rows; found {0} + {1} in {2}" -f $mandated, $bypass, $PayloadFile)
}
$curlPath = Find-Curl
if ($null -eq $curlPath) {
    Stop-Script $script:ExitUsage 'curl.exe not found. It ships with Windows 10 1803+ and Windows Server 2019+; install curl (winget install curl.curl) or run lab/demo/attack.sh on Linux/macOS.'
}

# --- 6. print exactly what will happen -------------------------------------
Write-Section 'HDD HK1 demo attack script - SQL injection on a login form (lab/rehearsal only)'
Write-Output 'Only the 12 payloads below, only the login endpoint, only an operator-authorised host.'
Write-Output 'No scanning. No other paths. No other attack classes. Rate capped at 2 requests/second.'
Write-Output ''
Write-Output ('target:    ' + $TargetUrl)
Write-Output ('kind:      ' + $resolvedKind + ' (' + (Get-KindDescription $Kind $resolvedKind) + ')')
Write-Output ('login:     ' + $loginUrl + '  fields: ' + $UserField + '/' + $PassField)
Write-Output ('allowlist: ' + $allowNote)
Write-Output ('payloads:  ' + $payloads.Count + ' (' + $mandated + ' mandated M1-M6 + ' + $bypass + ' auth-bypass B1-B6) x 2 shapes = ' + ($payloads.Count * 2) + ' requests')
Write-Output 'rate:      2 requests/second maximum (500 ms minimum spacing between requests)'
Write-Output ('script:    ' + $PSCommandPath)
Write-Output ('catalogue: ' + $PayloadFile)

$tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ('hdd-attack-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tempDir | Out-Null

$results = @{}
foreach ($entry in $payloads) {
    $results[$entry.Id] = @{ POST = $null; GET = $null }
}

$totalRequests = $payloads.Count * 2
$requestNumber = 0
$transportErrors = 0
$nextRequestAt = [DateTime]::UtcNow
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

try {
    foreach ($shape in @('POST', 'GET')) {
        Write-Output ''
        Write-Output ('--- ' + $shape + ' login attempts ---')
        foreach ($entry in $payloads) {
            $requestNumber++
            $requested = [DateTime]::UtcNow
            if ($requested -lt $nextRequestAt) {
                Start-Sleep -Milliseconds ([int]($nextRequestAt - $requested).TotalMilliseconds)
            }
            $nextRequestAt = [DateTime]::UtcNow.AddMilliseconds(500)

            $encoded = [System.Uri]::EscapeDataString($entry.Payload)
            $encodedForm = $UserField + '=' + $encoded + '&' + $PassField + '=' + $encoded
            $bodyFile = Join-Path $tempDir ('body-' + $requestNumber + '.html')
            $errorFile = Join-Path $tempDir ('error-' + $requestNumber + '.txt')
            $cookieJar = Join-Path $tempDir ('cookies-' + $requestNumber + '.txt')
            $requestUrl = $loginUrl
            if ($shape -eq 'POST') {
                $response = Invoke-CurlRequest -Method 'POST' -Url $requestUrl -Data $encodedForm `
                    -BodyFile $bodyFile -ErrorFile $errorFile -CookieJar $cookieJar -CurlPath $curlPath
            }
            else {
                $response = Invoke-CurlRequest -Method 'GET' -Url ($requestUrl + '?' + $encodedForm) -Data '' `
                    -BodyFile $bodyFile -ErrorFile $errorFile -CookieJar $cookieJar -CurlPath $curlPath
            }
            if ($response.Status -lt 0) {
                $transportErrors++
                $firstError = ''
                if ($response.Error.Length -gt 0) {
                    $firstError = ($response.Error -split "`n")[0].Trim()
                }
                $detail = 'request failed (curl exit ' + $response.ExitCode + ')'
                if ($firstError.Length -gt 0) { $detail += ': ' + $firstError }
                Write-Output ('[{0,2}/{1}] {2,-4} {3,-3} {4} -> {5}' -f $requestNumber, $totalRequests, $shape, $entry.Id, ('"' + $entry.Payload + '"'), $detail)
                $results[$entry.Id][$shape] = [pscustomobject]@{
                    Status = -1; Admin = $false; Ray = ''; BlockPage = $false; Error = $detail
                }
                continue
            }
            $admin = Test-AdminPage $response.Body
            $blockPage = Test-BlockPage $response.Body
            $ray = Get-RayId $response.Body
            $suffix = ''
            if ($admin) { $suffix = '  ->  admin page: YES' }
            elseif ($ray.Length -gt 0) { $suffix = '  ->  Ray ID: ' + $ray }
            elseif ($blockPage) { $suffix = '  ->  HDD block page text: YES (no Ray ID parsed)' }
            elseif ($response.Status -eq 500) { $suffix = '  ->  SQL error (dialect/syntax)' }
            Write-Output ('[{0,2}/{1}] {2,-4} {3,-3} {4} -> HTTP {5}{6}' -f $requestNumber, $totalRequests, $shape, $entry.Id, ('"' + $entry.Payload + '"'), $response.Status, $suffix)
            $results[$entry.Id][$shape] = [pscustomobject]@{
                Status = $response.Status; Admin = $admin; Ray = $ray; BlockPage = $blockPage; Error = ''
            }
        }
    }
}
finally {
    $stopwatch.Stop()
    if (Test-Path -LiteralPath $tempDir) {
        Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# --- 7. final yes/no table ---------------------------------------------------
switch ($resolvedKind) {
    'direct' { $title = 'direct origin: reached admin yes/no per payload' }
    'proxy' { $title = 'through HDD: blocked yes/no per payload' }
    default { $title = 'target: outcome per payload (admin reached or blocked, honestly as observed)' }
}
Write-Section $title
$rowFormat = '{0,-3} {1,-11} {2,-30} {3,-24} {4,-24}'
Write-Output ($rowFormat -f 'id', 'group', 'payload', 'POST', 'GET')
Write-Output ('-' * 104)
foreach ($entry in $payloads) {
    $postCell = Get-TableCell $results[$entry.Id]['POST'] $resolvedKind
    $getCell = Get-TableCell $results[$entry.Id]['GET'] $resolvedKind
    Write-Output ($rowFormat -f $entry.Id, $entry.Group, (Get-ShortText $entry.Payload 30), $postCell, $getCell)
}
Write-Output ('-' * 104)

$postAdmin = @($payloads | Where-Object { $results[$_.Id]['POST'].Admin -eq $true }).Count
$getAdmin = @($payloads | Where-Object { $results[$_.Id]['GET'].Admin -eq $true }).Count
$postBlocked = @($payloads | Where-Object {
        ($results[$_.Id]['POST'].Status -eq 403) -or ($results[$_.Id]['POST'].Status -eq 429)
    }).Count
$getBlocked = @($payloads | Where-Object {
        ($results[$_.Id]['GET'].Status -eq 403) -or ($results[$_.Id]['GET'].Status -eq 429)
    }).Count
$rayIds = New-Object System.Collections.Generic.HashSet[string]
foreach ($entry in $payloads) {
    foreach ($shape in @('POST', 'GET')) {
        $ray = $results[$entry.Id][$shape].Ray
        if (-not [string]::IsNullOrEmpty($ray)) { [void]$rayIds.Add($ray) }
    }
}
$seconds = [Math]::Round($stopwatch.Elapsed.TotalSeconds, 1)
$rateNote = '500 ms minimum spacing between request starts (at most 2 starts in any second)'

Write-Output ''
if ($resolvedKind -eq 'direct') {
    Write-Output ('direct origin: reached admin POST {0}/{1}, GET {2}/{3} ({4} requests in {5} s; {6})' -f $postAdmin, $payloads.Count, $getAdmin, $payloads.Count, $requestNumber, $seconds, $rateNote)
    if (($postAdmin + $getAdmin) -gt 0) {
        Write-Output 'Interpretation: at least one payload reached the admin page WITHOUT HDD. That is the vulnerability the demo is about.'
    }
    else {
        Write-Output 'Interpretation: no payload reached the admin page. Check the target is the vulnerable origin and the field names are right.'
    }
    if (($postAdmin + $getAdmin) -lt ($payloads.Count * 2)) {
        Write-Output "Note: the remaining payloads fail here for engine/query-shape reasons, not because of HDD (the lab shop hashes the password, so M2's separate-field tautology does not match; M4 and B4 use a hash comment that SQLite does not support; B3 has parentheses this query does not have; B5 runs but does not bypass)."
        Write-Output '      docs/SPEC.md E1.1 and P28 record that mandated payloads differ in dialect validity on a given endpoint;'
        Write-Output '      that is expected and is recorded here, not hidden. HDD must still block all twelve by intent.'
    }
    Write-Output ''
    Write-Output 'Next (the comparison): start the stack and run the same payloads through HDD:'
    Write-Output '  npm run dev            # in another terminal'
    Write-Output '  npm run attack            # uses the proxy URL printed by npm run dev'
}
elseif ($resolvedKind -eq 'proxy') {
    Write-Output ('through HDD: blocked POST {0}/{1}, GET {2}/{3} ({4} requests in {5} s; {6})' -f $postBlocked, $payloads.Count, $getBlocked, $payloads.Count, $requestNumber, $seconds, $rateNote)
    Write-Output ('Ray IDs seen: ' + $rayIds.Count)
    if (($postAdmin + $getAdmin) -gt 0) {
        Write-Output 'WARNING: at least one payload reached the admin page THROUGH HDD. The site is not protected on this path (R-34); do not claim protection.'
    }
    else {
        Write-Output 'Interpretation: no payload reached the admin page through HDD. Bans persist for the configured TTL; unban from the dashboard or wait.'
    }
    Write-Output ''
    if ([string]::IsNullOrEmpty($DashboardUrl)) {
        Write-Output 'Dashboard (bans + events): the admin listener URL printed by npm run dev (9090 by default)'
    }
    else {
        Write-Output ('Dashboard (bans + events): ' + $DashboardUrl)
    }
}
else {
    Write-Output ('target: admin reached POST {0}/{1}, GET {2}/{3}; blocked (403/429) POST {4}/{1}, GET {5}/{3} ({6} requests in {7} s; {8})' -f $postAdmin, $payloads.Count, $getAdmin, $payloads.Count, $postBlocked, $getBlocked, $requestNumber, $seconds, $rateNote)
    Write-Output 'Interpretation: confirm whether this target is the direct origin or the HDD-protected entry point;'
    Write-Output '      use -Kind direct or -Kind proxy to get the matching yes/no interpretation explicitly.'
}
if ($rayIds.Count -gt 0) {
    $rayList = @($rayIds)
    Write-Output ('first Ray ID observed: ' + $rayList[0])
}
if ($transportErrors -gt 0) {
    Write-Output ('Transport errors: ' + $transportErrors + '. Check the URL, the port and that the service is running.')
}
Write-Output 'No scanning was performed: only the login endpoint above was requested.'
if ($transportErrors -eq $requestNumber) { exit 1 }
exit 0
