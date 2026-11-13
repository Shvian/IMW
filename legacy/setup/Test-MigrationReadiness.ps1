<#
.SYNOPSIS
    Readiness checker for the Delinea -> CyberArk Privilege Cloud migration server.

.DESCRIPTION
    Run this on the migration server before any rehearsal or migration. It checks:

      SOFTWARE      PowerShell, Python 3.8+ and its modules, migration files and config,
                    ssh-keygen (rehearsals), time sync
      CONNECTIVITY  DNS, TCP 443, TLS (protocol and certificate), HTTPS through the proxy,
                    and HTTPS from Python itself, for every endpoint in phase2_config.json;
                    optional sign-in test for both APIs (-TestAuth)
      PERMISSIONS   who runs the tool, working folder ACLs and location, persisted
                    credentials, state folder write access, and optionally the Phase 2
                    read-only preflight against the real tenant (-RunPreflight)
      SECURITY      a CIS Microsoft Windows Server Benchmark (Level 1) aligned subset
                    that matters for a machine handling privileged credentials, plus a few
                    migration-specific items (crash dumps, sync clients, drive redirection)

    Then a resolve menu fixes issues automatically where that is safe, or prints the
    remediation steps. Every action is logged. Nothing in the reports contains secrets.

    This is NOT a full CIS benchmark assessment. Use CIS-CAT or your organisation's
    baseline (e.g. GPO / Intune security baseline) for that.

.PARAMETER Mode
    Resolve (default): check, then open the resolve menu.
    Check: check only, write the report, exit 0 (all pass), 1 (warnings) or 2 (failures).

.PARAMETER MigrationRoot
    Folder holding phase1\, phase2\ and tools\. Defaults to the parent of this script's folder.

.PARAMETER ConfigPath
    Phase 2 config. Defaults to <MigrationRoot>\phase2\phase2_config.json.

.PARAMETER StateDir
    Phase 2 --state-dir that the migration will use. Defaults to <MigrationRoot>\migration_state.

.PARAMETER TestAuth
    Also sign in to CyberArk and Delinea once each (prompts for credentials unless the
    env vars named in the config are set). Tokens are discarded and never displayed.

.PARAMETER RunPreflight
    Also run the Phase 2 read-only preflight against the real CyberArk tenant.

.PARAMETER FixIds
    With -NonInteractive: fix these check IDs (e.g. SEC-06,PERM-04) without the menu.

.PARAMETER Force
    Do not ask for confirmation before each fix.

.EXAMPLE
    .\Test-MigrationReadiness.ps1
.EXAMPLE
    .\Test-MigrationReadiness.ps1 -Mode Check -TestAuth -RunPreflight
.EXAMPLE
    # As Administrator, non-interactive fix of two items
    .\Test-MigrationReadiness.ps1 -NonInteractive -FixIds SEC-06,SEC-16 -Force
#>
[CmdletBinding()]
param(
    [ValidateSet('Resolve', 'Check')]
    [string]$Mode = 'Resolve',
    [string]$MigrationRoot,
    [string]$ConfigPath,
    [string]$StateDir,
    [string]$ReportDir,
    [switch]$TestAuth,
    [switch]$RunPreflight,
    [switch]$NonInteractive,
    [string[]]$FixIds,
    [switch]$Force
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ScriptVersion = '1.0.0'

# --------------------------------------------------------------------------- #
# Paths, logging, environment
# --------------------------------------------------------------------------- #
if (-not $MigrationRoot) { $MigrationRoot = Split-Path -Parent $PSScriptRoot }
$MigrationRoot = (Resolve-Path -LiteralPath $MigrationRoot).Path
if (-not $ConfigPath) { $ConfigPath = Join-Path $MigrationRoot 'phase2\phase2_config.json' }
if (-not $StateDir) { $StateDir = Join-Path $MigrationRoot 'migration_state' }
if (-not $ReportDir) { $ReportDir = Join-Path $MigrationRoot 'readiness' }
New-Item -ItemType Directory -Force -Path $ReportDir | Out-Null

$Stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$LogPath = Join-Path $ReportDir "readiness_$Stamp.log"

$OnWindows = ($PSVersionTable.PSEdition -eq 'Desktop') -or ((Get-Variable -Name IsWindows -ErrorAction SilentlyContinue) -and $IsWindows)

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $line = '{0} {1,-5} {2}' -f (Get-Date -Format 's'), $Level, $Message
    Add-Content -LiteralPath $LogPath -Value $line -Encoding UTF8
}

function Test-IsAdmin {
    if (-not $OnWindows) { return $false }
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
$IsAdmin = Test-IsAdmin

# TLS 1.2 for this PowerShell session's own web calls (PS 5.1 defaults can be older).
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }

Write-Log "Test-MigrationReadiness $ScriptVersion started by $([Environment]::UserDomainName)\$([Environment]::UserName) on $([Environment]::MachineName); admin=$IsAdmin; root=$MigrationRoot"

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
function Get-Reg {
    param([string]$Path, [string]$Name)
    try { return (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name } catch { return $null }
}

function Set-Reg {
    param([string]$Path, [string]$Name, $Value, [string]$Type = 'DWord')
    if (-not (Test-Path -LiteralPath $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
    Write-Log "Registry set: $Path\$Name = $Value ($Type)" 'FIX'
}

function New-Outcome {
    param([ValidateSet('Pass', 'Warn', 'Fail', 'Info', 'Skipped')] [string]$Status, [string]$Detail)
    return [pscustomobject]@{ Status = $Status; Detail = $Detail }
}

$Script:Python = $null
function Get-Python {
    if ($Script:Python) { return $Script:Python }
    $candidates = @(@('py', '-3'), @('python'), @('python3'))
    foreach ($c in $candidates) {
        $exe = $c[0]
        if (-not (Get-Command $exe -ErrorAction SilentlyContinue)) { continue }
        $pre = @()
        if ($c.Count -gt 1) { $pre = $c[1..($c.Count - 1)] }
        try {
            $out = & $exe @pre '--version' 2>&1 | Out-String
            if ($out -match 'Python (\d+)\.(\d+)\.(\d+)') {
                $Script:Python = [pscustomobject]@{
                    Exe = $exe; PreArgs = $pre
                    Version = [version]"$($Matches[1]).$($Matches[2]).$($Matches[3])"
                }
                return $Script:Python
            }
        } catch { }
    }
    return $null
}

function Invoke-PythonSnippet {
    # Writes the code to a temp file (avoids Windows native-argument quoting problems).
    param([string]$Code, [string[]]$Arguments = @(), [int]$TimeoutSec = 60)
    $py = Get-Python
    if (-not $py) { throw 'Python not found' }
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("mig_{0}.py" -f [guid]::NewGuid().ToString('N'))
    Set-Content -LiteralPath $tmp -Value $Code -Encoding UTF8
    try {
        $all = @($py.PreArgs) + @('-I', $tmp) + $Arguments
        $out = & $py.Exe @all 2>&1 | Out-String
        return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $out.Trim() }
    } finally {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    }
}

function Read-Config {
    if (-not (Test-Path -LiteralPath $ConfigPath)) { return $null }
    try { return Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json } catch { return $null }
}

function Get-Endpoints {
    $cfg = Read-Config
    $list = New-Object System.Collections.ArrayList
    if (-not $cfg) { return $list }
    $pairs = @(
        @('CyberArk Identity', $cfg.cyberark.token_url),
        @('Privilege Cloud API', $cfg.cyberark.api_base_url),
        @('Delinea Secret Server', $cfg.delinea.base_url)
    )
    $dTok = $null
    try { $dTok = $cfg.delinea.token_url } catch { }
    if ($dTok) { $pairs += , @('Delinea token', $dTok) }
    $seen = @{}
    foreach ($p in $pairs) {
        if (-not $p[1]) { continue }
        try { $u = [Uri]$p[1] } catch { continue }
        if (-not $u.IsAbsoluteUri) { continue }
        $key = "$($u.Host):$($u.Port)"
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        [void]$list.Add([pscustomobject]@{ Label = $p[0]; Url = $p[1]; Host = $u.Host; Port = $u.Port; Placeholder = ($u.Host -match 'EXAMPLE') })
    }
    return $list
}

function Get-Credential-Plain {
    # Returns a plain string only for the duration of a sign-in test; never logged or shown.
    param([string]$EnvName, [string]$Prompt)
    $v = [Environment]::GetEnvironmentVariable($EnvName, 'Process')
    if ($v) { return $v }
    if ($NonInteractive) { return $null }
    $sec = Read-Host -Prompt $Prompt -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

# --------------------------------------------------------------------------- #
# Check registry
# --------------------------------------------------------------------------- #
$Checks = New-Object System.Collections.ArrayList

function Add-Check {
    param(
        [string]$Id, [string]$Category, [string]$Name,
        [scriptblock]$Test,
        [string]$Remediation,
        [scriptblock]$Fix = $null,
        [string]$FixText = '',
        [ValidateSet('Low', 'Medium', 'High', 'None')] [string]$FixRisk = 'None',
        [switch]$NeedsAdmin, [switch]$NeedsReboot, [switch]$WindowsOnly,
        [string]$Reference = ''
    )
    [void]$Checks.Add([pscustomobject]@{
        Id = $Id; Category = $Category; Name = $Name; Test = $Test; Remediation = $Remediation
        Fix = $Fix; FixText = $FixText; FixRisk = $FixRisk; NeedsAdmin = [bool]$NeedsAdmin
        NeedsReboot = [bool]$NeedsReboot; WindowsOnly = [bool]$WindowsOnly; Reference = $Reference
        Status = 'NotRun'; Detail = ''
    })
}

function Invoke-Check {
    param($Check)
    if ($Check.WindowsOnly -and -not $OnWindows) {
        $Check.Status = 'Skipped'; $Check.Detail = 'Windows-only check'
    } else {
        try {
            $o = & $Check.Test
            $Check.Status = $o.Status; $Check.Detail = $o.Detail
        } catch {
            $Check.Status = 'Fail'; $Check.Detail = "Check could not run: $($_.Exception.Message)"
        }
    }
    Write-Log ("[{0}] {1} {2}: {3}" -f $Check.Status, $Check.Id, $Check.Name, $Check.Detail) 'CHECK'
}

# =========================================================================== #
# SOFTWARE
# =========================================================================== #
Add-Check -Id 'SW-01' -Category 'Software' -Name 'PowerShell 5.1 or later' -Test {
    $v = $PSVersionTable.PSVersion
    if ($v -ge [version]'5.1') { New-Outcome Pass "PowerShell $v" } else { New-Outcome Fail "PowerShell $v" }
} -Remediation 'Install Windows Management Framework 5.1 or PowerShell 7 (https://aka.ms/powershell).'

Add-Check -Id 'SW-02' -Category 'Software' -Name 'Python 3.8 or later' -Test {
    $py = Get-Python
    if (-not $py) { return New-Outcome Fail 'Python not found on PATH (tried py -3, python, python3)' }
    if ($py.Version -lt [version]'3.8') { return New-Outcome Fail "Python $($py.Version) is too old" }
    New-Outcome Pass "Python $($py.Version) via '$($py.Exe) $($py.PreArgs -join ' ')'"
} -Remediation 'Install Python 3.12 for all users from https://www.python.org/downloads/windows/ (tick "Add python.exe to PATH"), or via winget: winget install -e --id Python.Python.3.12 --scope machine. Then open a new PowerShell window.' `
  -Fix {
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) { throw 'winget is not available; install Python manually (see remediation).' }
    & winget install -e --id Python.Python.3.12 --scope machine --silent --accept-package-agreements --accept-source-agreements
    $Script:Python = $null
    $env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('Path', 'User')
  } -FixText 'Install Python 3.12 (machine-wide) with winget' -FixRisk Low -NeedsAdmin

Add-Check -Id 'SW-03' -Category 'Software' -Name 'Python modules: ssl (TLS 1.2+), sqlite3, json, urllib' -Test {
    if (-not (Get-Python)) { return New-Outcome Skipped 'Python not available' }
    $r = Invoke-PythonSnippet -Code @'
import ssl, sqlite3, json, urllib.request, hashlib
ctx = ssl.create_default_context()
ok = bool(getattr(ssl, "HAS_TLSv1_2", True))
print(("OK" if ok else "NOTLS12") + "|" + ssl.OPENSSL_VERSION + "|sqlite " + sqlite3.sqlite_version)
'@
    if ($r.ExitCode -ne 0) { return New-Outcome Fail "Module check failed: $($r.Output)" }
    $parts = $r.Output -split '\|'
    if ($parts[0] -ne 'OK') { return New-Outcome Fail "Python ssl lacks TLS 1.2: $($parts[1])" }
    New-Outcome Pass "$($parts[1]); $($parts[2])"
} -Remediation 'Reinstall Python from python.org (the standard installer includes ssl and sqlite3). Do not use an embedded/minimal distribution.'

Add-Check -Id 'SW-04' -Category 'Software' -Name 'Migration scripts present (with SHA-256 recorded)' -Test {
    $files = @('phase1\delinea_phase1_mapping.py', 'phase2\cyberark_phase2_execute.py')
    $missing = @(); $hashes = @()
    foreach ($f in $files) {
        $p = Join-Path $MigrationRoot $f
        if (Test-Path -LiteralPath $p) {
            $h = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.Substring(0, 16)
            $hashes += "$f sha256:$h..."
        } else { $missing += $f }
    }
    if ($missing) { return New-Outcome Fail ("Missing: " + ($missing -join ', ')) }
    New-Outcome Pass ($hashes -join '; ')
} -Remediation 'Copy the migration package (phase1, phase2, tools, setup folders) to the migration root, then compare the SHA-256 hashes in this report with the approved release.'

Add-Check -Id 'SW-05' -Category 'Software' -Name 'Phase 2 config exists and is filled in' -Test {
    if (-not (Test-Path -LiteralPath $ConfigPath)) { return New-Outcome Fail "Not found: $ConfigPath" }
    $cfg = Read-Config
    if (-not $cfg) { return New-Outcome Fail 'Config is not valid JSON' }
    $problems = @()
    foreach ($ep in (Get-Endpoints)) { if ($ep.Placeholder) { $problems += "$($ep.Label) URL is still a placeholder" } }
    if (-not $cfg.cyberark.client_id) { $problems += 'cyberark.client_id is empty' }
    if ($cfg.delinea.grant_type -eq 'password' -and -not $cfg.delinea.username) { $problems += 'delinea.username is empty' }
    if ($cfg.PSObject.Properties.Name -contains 'verify_tls' -and -not $cfg.verify_tls) { $problems += 'verify_tls is false (must be true for a real migration)' }
    if ($problems) { return New-Outcome Fail ($problems -join '; ') }
    New-Outcome Pass $ConfigPath
} -Remediation 'Generate a starter config with: python phase2\cyberark_phase2_execute.py --write-default-config phase2\phase2_config.json. Then set cyberark.token_url, cyberark.api_base_url, cyberark.client_id, delinea.base_url, delinea.username, directory_map and safe_defaults. Keep verify_tls true.' `
  -Fix {
    if (Test-Path -LiteralPath $ConfigPath) { throw 'Config exists; edit it by hand (see remediation).' }
    $py = Get-Python; if (-not $py) { throw 'Python not available' }
    $all = @($py.PreArgs) + @((Join-Path $MigrationRoot 'phase2\cyberark_phase2_execute.py'), '--write-default-config', $ConfigPath)
    & $py.Exe @all | Out-Null
    Write-Host "  Created $ConfigPath. Edit the URLs and names, then re-run the check." -ForegroundColor Yellow
  } -FixText 'Create a starter phase2_config.json (only if missing)' -FixRisk Low

Add-Check -Id 'SW-06' -Category 'Software' -Name 'ssh-keygen available (rehearsal fake SSH keys)' -Test {
    if (Get-Command ssh-keygen -ErrorAction SilentlyContinue) { New-Outcome Pass 'ssh-keygen found' }
    else { New-Outcome Warn 'Not found: rehearsals will use random text for SSH-key accounts, which the key platform may reject' }
} -Remediation 'Install the OpenSSH client: Settings > Apps > Optional features > OpenSSH Client, or Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0' `
  -Fix { Add-WindowsCapability -Online -Name 'OpenSSH.Client~~~~0.0.1.0' | Out-Null } `
  -FixText 'Install the Windows OpenSSH client capability' -FixRisk Low -NeedsAdmin -WindowsOnly

Add-Check -Id 'SW-07' -Category 'Software' -Name 'Clock in sync (tokens are time-sensitive)' -Test {
    $out = & w32tm /stripchart /computer:time.windows.com /samples:1 /dataonly 2>&1 | Out-String
    if ($out -match '([+-]\d+\.\d+)s') {
        $off = [math]::Abs([double]$Matches[1])
        if ($off -le 5) { return New-Outcome Pass ("Offset {0:N2}s from time.windows.com" -f $off) }
        if ($off -le 60) { return New-Outcome Warn ("Offset {0:N1}s" -f $off) }
        return New-Outcome Fail ("Offset {0:N0}s: token validation may fail" -f $off)
    }
    $st = & w32tm /query /status 2>&1 | Out-String
    if ($st -match 'Last Successful Sync Time:\s*(.+)') { return New-Outcome Info "Could not reach time.windows.com; last sync $($Matches[1].Trim())" }
    New-Outcome Warn 'Could not determine clock offset'
} -Remediation 'Make sure the Windows Time service syncs with your domain hierarchy or an approved NTP source: w32tm /resync /force' `
  -Fix { Start-Service w32time -ErrorAction SilentlyContinue; & w32tm /resync /force | Out-Null } `
  -FixText 'Start Windows Time and force a resync' -FixRisk Low -NeedsAdmin -WindowsOnly

# =========================================================================== #
# CONNECTIVITY (one set of checks per endpoint in the config)
# =========================================================================== #
$endpoints = Get-Endpoints
if (-not $endpoints -or $endpoints.Count -eq 0) {
    Add-Check -Id 'NET-00' -Category 'Connectivity' -Name 'Endpoints to test' -Test {
        New-Outcome Fail 'No endpoint URLs found (config missing or invalid)'
    } -Remediation 'Fix SW-05 first, then re-run the checks.'
}
$i = 0
foreach ($ep in $endpoints) {
    $i++
    $e = $ep
    Add-Check -Id ("NET-{0}A" -f $i) -Category 'Connectivity' -Name "DNS: $($e.Host) ($($e.Label))" -Test ({
        if ($e.Placeholder) { return New-Outcome Skipped 'URL is a placeholder' }
        $ips = [System.Net.Dns]::GetHostAddresses($e.Host) | ForEach-Object { $_.IPAddressToString }
        New-Outcome Pass ($ips -join ', ')
    }.GetNewClosure()) -Remediation "Check DNS on this server resolves $($e.Host) (nslookup $($e.Host)). If outbound DNS is restricted, ask the network team to allow it or add a conditional forwarder."

    Add-Check -Id ("NET-{0}B" -f $i) -Category 'Connectivity' -Name "TCP $($e.Port): $($e.Host)" -Test ({
        if ($e.Placeholder) { return New-Outcome Skipped 'URL is a placeholder' }
        $c = New-Object System.Net.Sockets.TcpClient
        try {
            $ar = $c.BeginConnect($e.Host, $e.Port, $null, $null)
            if (-not $ar.AsyncWaitHandle.WaitOne(5000)) { return New-Outcome Warn 'No direct connection in 5s (fine if all traffic must use the proxy; see the HTTPS check)' }
            $c.EndConnect($ar); New-Outcome Pass 'Direct TCP connection OK'
        } finally { $c.Close() }
    }.GetNewClosure()) -Remediation "Allow outbound TCP $($e.Port) from this server to $($e.Host), or confirm the proxy path works (next checks)."

    Add-Check -Id ("NET-{0}C" -f $i) -Category 'Connectivity' -Name "TLS 1.2+ and certificate: $($e.Host)" -Test ({
        if ($e.Placeholder) { return New-Outcome Skipped 'URL is a placeholder' }
        $tcp = New-Object System.Net.Sockets.TcpClient
        $errs = New-Object System.Collections.ArrayList
        try {
            $ar = $tcp.BeginConnect($e.Host, $e.Port, $null, $null)
            if (-not $ar.AsyncWaitHandle.WaitOne(5000)) { return New-Outcome Skipped 'No direct TCP path (checked through the proxy in the HTTPS checks)' }
            $tcp.EndConnect($ar)
            $cb = [System.Net.Security.RemoteCertificateValidationCallback] { param($s, $cert, $chain, $policyErrors) if ($policyErrors -ne 'None') { [void]$errs.Add($policyErrors.ToString()) }; return $true }
            $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, $cb)
            $protocols = [System.Security.Authentication.SslProtocols]::Tls12
            try { $protocols = $protocols -bor [System.Security.Authentication.SslProtocols]'Tls13' } catch { }
            $ssl.AuthenticateAsClient($e.Host, $null, $protocols, $true)
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
            $days = [int]($cert.NotAfter - (Get-Date)).TotalDays
            $info = "$($ssl.SslProtocol); issuer '$($cert.Issuer)'; expires $($cert.NotAfter.ToString('yyyy-MM-dd')) ($days days)"
            $ssl.Dispose()
            if ($errs.Count) { return New-Outcome Fail "Certificate not trusted ($($errs -join ', ')): $info" }
            if ($days -lt 14) { return New-Outcome Warn "Certificate expires soon: $info" }
            New-Outcome Pass $info
        } finally { $tcp.Close() }
    }.GetNewClosure()) -Remediation "The server must trust the certificate chain for $($e.Host). If a TLS-inspecting proxy re-signs traffic, install its root CA in the Local Computer > Trusted Root store (Python on Windows uses that store). Never set verify_tls to false."

    Add-Check -Id ("NET-{0}D" -f $i) -Category 'Connectivity' -Name "HTTPS via system proxy: $($e.Label)" -Test ({
        if ($e.Placeholder) { return New-Outcome Skipped 'URL is a placeholder' }
        try {
            $r = Invoke-WebRequest -Uri $e.Url -Method Get -UseBasicParsing -TimeoutSec 20 -MaximumRedirection 0 -ErrorAction Stop
            New-Outcome Pass "HTTP $($r.StatusCode)"
        } catch {
            $resp = $null
            try { $resp = $_.Exception.Response } catch { }
            if ($resp) { return New-Outcome Pass "Reachable (HTTP $([int]$resp.StatusCode) is expected without credentials)" }
            New-Outcome Fail $_.Exception.Message
        }
    }.GetNewClosure()) -Remediation "Allow HTTPS to $($e.Url) through the proxy/firewall. Check the proxy with: netsh winhttp show proxy, and the user proxy under Internet Options."

    Add-Check -Id ("NET-{0}E" -f $i) -Category 'Connectivity' -Name "HTTPS from Python: $($e.Label)" -Test ({
        if ($e.Placeholder) { return New-Outcome Skipped 'URL is a placeholder' }
        if (-not (Get-Python)) { return New-Outcome Skipped 'Python not available' }
        $r = Invoke-PythonSnippet -Arguments @($e.Url) -Code @'
import sys, urllib.request, urllib.error, ssl
try:
    urllib.request.urlopen(urllib.request.Request(sys.argv[1], method="GET"), timeout=20)
    print("OK 200")
except urllib.error.HTTPError as e:
    print("OK %s" % e.code)
except ssl.SSLError as e:
    print("TLS %s" % e)
except Exception as e:
    print("ERR %s" % e)
'@
        if ($r.Output -like 'OK*') { return New-Outcome Pass "Python reached it ($($r.Output))" }
        if ($r.Output -like 'TLS*') { return New-Outcome Fail "Python TLS verification failed: $($r.Output)" }
        New-Outcome Fail "Python could not connect: $($r.Output)"
    }.GetNewClosure()) -Remediation 'Python uses the Windows proxy settings and the Windows certificate store. If PowerShell works but Python does not, set HTTPS_PROXY for the migration session (e.g. $env:HTTPS_PROXY="http://proxy:8080"), and make sure any inspection CA is in the Local Computer Trusted Root store.'
}

Add-Check -Id 'NET-90' -Category 'Connectivity' -Name 'Proxy configuration' -Test {
    $parts = @()
    if ($OnWindows) {
        $wh = (& netsh winhttp show proxy 2>&1 | Out-String) -replace '\s+', ' '
        $parts += "WinHTTP: $($wh.Trim())"
        $ie = Get-Reg 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' 'ProxyServer'
        if ($ie) { $parts += "User proxy: $ie" }
    }
    foreach ($n in 'HTTPS_PROXY', 'HTTP_PROXY', 'NO_PROXY') {
        $v = [Environment]::GetEnvironmentVariable($n)
        if ($v) { $parts += "$n=$v" }
    }
    New-Outcome Info ($parts -join ' | ')
} -Remediation 'Informational. The Python scripts follow HTTPS_PROXY / the Windows user proxy.'

if ($TestAuth) {
    Add-Check -Id 'NET-95' -Category 'Connectivity' -Name 'Sign-in test: CyberArk service user' -Test {
        $cfg = Read-Config
        $secret = Get-Credential-Plain $cfg.cyberark.client_secret_env 'CyberArk client secret (not shown, not stored)'
        if (-not $secret) { return New-Outcome Skipped 'No credential supplied' }
        try {
            $body = @{ grant_type = 'client_credentials'; client_id = $cfg.cyberark.client_id; client_secret = $secret }
            $r = Invoke-RestMethod -Uri $cfg.cyberark.token_url -Method Post -Body $body -ContentType 'application/x-www-form-urlencoded' -TimeoutSec 30
            $hasRefresh = [bool]($r.PSObject.Properties.Name -contains 'refresh_token')
            if ($r.access_token) { New-Outcome Pass "Token issued (valid $($r.expires_in)s; refresh token: $hasRefresh). Token discarded." }
            else { New-Outcome Fail 'No access_token in response' }
        } catch { New-Outcome Fail "Sign-in failed: $($_.Exception.Message)" }
        finally { $secret = $null; $body = $null }
    } -Remediation 'Check cyberark.client_id and the client secret, that the service user is an OAuth confidential client in CyberArk Identity, and that it has the Privilege Cloud Administrators role.'

    Add-Check -Id 'NET-96' -Category 'Connectivity' -Name 'Sign-in test: Delinea API user' -Test {
        $cfg = Read-Config
        $d = $cfg.delinea
        if ($d.base_url -match 'EXAMPLE') { return New-Outcome Skipped 'Delinea URL not configured' }
        $isCC = ($d.grant_type -eq 'client_credentials')
        $envName = $d.password_env; if ($isCC) { $envName = $d.client_secret_env }
        $secret = Get-Credential-Plain $envName 'Delinea API credential (not shown, not stored; ONE attempt to avoid lockout)'
        if (-not $secret) { return New-Outcome Skipped 'No credential supplied' }
        $url = $d.token_url; if (-not $url) { $url = $d.base_url.TrimEnd('/') + '/oauth2/token' }
        try {
            if ($isCC) { $body = @{ grant_type = 'client_credentials'; client_id = $d.client_id; client_secret = $secret } }
            else { $body = @{ grant_type = 'password'; username = $d.username; password = $secret } }
            $r = Invoke-RestMethod -Uri $url -Method Post -Body $body -ContentType 'application/x-www-form-urlencoded' -TimeoutSec 30
            $hasRefresh = [bool]($r.PSObject.Properties.Name -contains 'refresh_token')
            if ($r.access_token) { New-Outcome Pass "Token issued (valid $($r.expires_in)s; refresh token: $hasRefresh). Token discarded." }
            else { New-Outcome Fail 'No access_token in response' }
        } catch { New-Outcome Fail "Sign-in failed: $($_.Exception.Message)" }
        finally { $secret = $null; $body = $null }
    } -Remediation 'Check delinea.username and its password. The account must be a local Secret Server user allowed to use the REST API (Web Services enabled under Admin > Configuration). Wrong passwords count toward lockout.'
}

# =========================================================================== #
# PERMISSIONS
# =========================================================================== #
Add-Check -Id 'PERM-01' -Category 'Permissions' -Name 'Run as a named, non-SYSTEM account' -Test {
    $u = "$([Environment]::UserDomainName)\$([Environment]::UserName)"
    if ($u -match 'SYSTEM$|\$$') { return New-Outcome Fail "Running as $u; the audit log must name a person" }
    if ($IsAdmin) { return New-Outcome Info "$u (elevated; needed only for fixes. Run the migration itself from a non-elevated window.)" }
    New-Outcome Pass "$u (not elevated)"
} -Remediation 'Sign in with your own named admin account. Use an elevated window only for the fixes in this tool, and run the migration scripts non-elevated.'

Add-Check -Id 'PERM-02' -Category 'Permissions' -Name 'Migration folder access limited to you, Administrators and SYSTEM' -Test {
    $acl = Get-Acl -LiteralPath $MigrationRoot
    $broad = @($acl.Access | Where-Object {
        $_.AccessControlType -eq 'Allow' -and (
            $_.IdentityReference -match '(^|\\)(Everyone|Users|Authenticated Users|Domain Users|INTERACTIVE)$')
    } | ForEach-Object { "$($_.IdentityReference):$($_.FileSystemRights)" })
    if ($broad.Count) { return New-Outcome Fail ("Broad access: " + (($broad | Select-Object -Unique) -join '; ')) }
    New-Outcome Pass ("Inheritance protected: {0}" -f $acl.AreAccessRulesProtected)
} -Remediation 'Restrict the migration root so only the operator(s), Administrators and SYSTEM can read it: icacls "<root>" /inheritance:r /grant:r "<you>:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F"' `
  -Fix {
    $me = "$([Environment]::UserDomainName)\$([Environment]::UserName)"
    & icacls $MigrationRoot /inheritance:r /grant:r "${me}:(OI)(CI)F" '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' /T /C /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls exited $LASTEXITCODE" }
  } -FixText 'Remove inherited ACLs on the migration root; grant only you, Administrators and SYSTEM (recursive)' -FixRisk Medium -WindowsOnly

Add-Check -Id 'PERM-03' -Category 'Permissions' -Name 'Migration folder is local, not synced or on a share' -Test {
    $p = $MigrationRoot
    if ($p -match '^\\\\') { return New-Outcome Fail "On a network share: $p" }
    $drive = (Split-Path -Qualifier $p) + '\'
    $di = New-Object System.IO.DriveInfo($drive)
    if ($di.DriveType -eq 'Network') { return New-Outcome Fail "On a mapped network drive: $p" }
    $syncRoots = @($env:OneDrive, $env:OneDriveCommercial, $env:OneDriveConsumer) | Where-Object { $_ }
    foreach ($r in $syncRoots) { if ($p.StartsWith($r, [StringComparison]::OrdinalIgnoreCase)) { return New-Outcome Fail "Inside OneDrive: $p" } }
    if ($p -match '\\(Dropbox|Google Drive|My Drive|Box|iCloudDrive)\\') { return New-Outcome Fail "Inside a sync folder: $p" }
    New-Outcome Pass "$p ($($di.DriveType) drive)"
} -Remediation 'Move the migration root to a local folder on an encrypted fixed drive (e.g. D:\Migration), outside OneDrive/Dropbox/Google Drive and not on a network share.'

Add-Check -Id 'PERM-04' -Category 'Permissions' -Name 'No credentials persisted in env vars or config' -Test {
    $names = @('CYBERARK_CLIENT_SECRET', 'DELINEA_PASSWORD', 'DELINEA_CLIENT_SECRET')
    $cfg = Read-Config
    if ($cfg) { foreach ($k in 'client_secret_env', 'password_env') {
        foreach ($sec in $cfg.cyberark, $cfg.delinea) { if ($sec -and ($sec.PSObject.Properties.Name -contains $k) -and $sec.$k) { $names += $sec.$k } } } }
    $names = $names | Select-Object -Unique
    $found = @()
    foreach ($n in $names) { foreach ($scope in 'User', 'Machine') {
        if ([Environment]::GetEnvironmentVariable($n, $scope)) { $found += "$n ($scope scope)" } } }
    if (Test-Path -LiteralPath $ConfigPath) {
        $raw = Get-Content -LiteralPath $ConfigPath -Raw
        if ($raw -match '"(client_secret|password|secret)"\s*:\s*"[^"]+"') { $found += 'a secret value inside phase2_config.json' }
    }
    if ($found) { return New-Outcome Fail ("Persisted: " + ($found -join '; ')) }
    New-Outcome Pass 'None found (credentials will be prompted for, or set only in the session)'
} -Remediation 'Do not store the CyberArk or Delinea credentials in User/Machine environment variables or in the config. Let the scripts prompt for them (recommended), or set them only for the current session.' `
  -Fix {
    foreach ($n in 'CYBERARK_CLIENT_SECRET', 'DELINEA_PASSWORD', 'DELINEA_CLIENT_SECRET') {
        foreach ($scope in 'User', 'Machine') {
            if ([Environment]::GetEnvironmentVariable($n, $scope)) {
                if ($scope -eq 'Machine' -and -not $IsAdmin) { Write-Host "  $n (Machine) needs an elevated window" -ForegroundColor Yellow; continue }
                [Environment]::SetEnvironmentVariable($n, $null, $scope); Write-Log "Removed persisted env var $n ($scope)" 'FIX'
            }
        }
    }
    Write-Host '  If a secret is inside phase2_config.json, remove it by hand and rotate that credential.' -ForegroundColor Yellow
  } -FixText 'Delete persisted credential env vars (User/Machine scope)' -FixRisk Low

Add-Check -Id 'PERM-05' -Category 'Permissions' -Name 'State folder writable' -Test {
    New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
    $t = Join-Path $StateDir ('.write_test_' + [guid]::NewGuid().ToString('N'))
    Set-Content -LiteralPath $t -Value 'x'; Remove-Item -LiteralPath $t -Force
    New-Outcome Pass $StateDir
} -Remediation 'Give the operator account Modify on the state folder, or choose a different --state-dir.'

Add-Check -Id 'PERM-06' -Category 'Permissions' -Name 'Delinea API account requirements (manual)' -Test {
    New-Outcome Info 'Cannot be verified without Delinea data. Confirm before migration day, then run probe-delinea.'
} -Remediation @'
In Secret Server, the migration API account needs:
  1. View on every folder in scope (and on any secret with broken inheritance).
  2. Exemption from approval, checkout, require-comment and DoubleLock on in-scope secrets
     (or set delinea.field_query accordingly).
  3. REST API / Web Services enabled; account not subject to MFA for API sign-in.
On migration day run: python phase2\cyberark_phase2_execute.py probe-delinea ...
'@

if ($RunPreflight) {
    Add-Check -Id 'PERM-07' -Category 'Permissions' -Name 'CyberArk tenant preflight (read-only)' -Test {
        $py = Get-Python; if (-not $py) { return New-Outcome Skipped 'Python not available' }
        $all = @($py.PreArgs) + @((Join-Path $MigrationRoot 'phase2\cyberark_phase2_execute.py'), 'preflight',
            '--config', $ConfigPath, '--state-dir', (Join-Path $ReportDir 'preflight'))
        $mc = Join-Path $MigrationRoot 'phase1\mapping_config.json'
        if (Test-Path -LiteralPath $mc) { $all += @('--mapping-config', $mc) }
        $out = & $py.Exe @all 2>&1 | Out-String
        $code = $LASTEXITCODE
        Add-Content -LiteralPath $LogPath -Value $out -Encoding UTF8
        $fails = @(($out -split "`n") | Where-Object { $_ -match '\[FAIL' } | ForEach-Object { $_.Trim() })
        if ($code -eq 0) { return New-Outcome Pass 'All preflight checks passed (details in the log)' }
        if ($fails.Count) { return New-Outcome Fail ($fails -join ' | ') }
        New-Outcome Fail "Preflight exited $code; see $LogPath"
    } -Remediation 'Read the preflight lines in the log: each FAIL names the platform, directory, group or right to fix in the CyberArk tenant.'
}

# =========================================================================== #
# SECURITY: CIS Windows Server Benchmark (L1) aligned subset + migration items
# =========================================================================== #
Add-Check -Id 'SEC-01' -Category 'Security' -Name 'BitLocker on the OS drive and the migration drive' -Reference 'CIS: BitLocker Drive Encryption' -WindowsOnly -Test {
    if (-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) { return New-Outcome Warn 'BitLocker cmdlets not available (feature not installed?)' }
    $drives = @($env:SystemDrive, (Split-Path -Qualifier $MigrationRoot)) | Select-Object -Unique
    $bad = @()
    foreach ($d in $drives) {
        $v = Get-BitLockerVolume -MountPoint $d -ErrorAction SilentlyContinue
        if (-not $v -or $v.ProtectionStatus -ne 'On') { $bad += $d }
    }
    if ($bad) { return New-Outcome Fail ("Not protected: " + ($bad -join ', ')) }
    New-Outcome Pass ("Protected: " + ($drives -join ', '))
} -Remediation 'Enable BitLocker (XTS-AES 256) on the OS drive and the drive holding the migration folder, with the recovery key escrowed to AD/Entra ID per your policy. Not automated here because recovery-key handling is an organisational decision.'

Add-Check -Id 'SEC-02' -Category 'Security' -Name 'Microsoft Defender real-time protection on, signatures current' -Reference 'CIS: Microsoft Defender Antivirus' -WindowsOnly -Test {
    if (-not (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)) { return New-Outcome Warn 'Defender cmdlets unavailable (third-party AV?). Confirm your EDR is active.' }
    $s = Get-MpComputerStatus
    $age = ((Get-Date) - $s.AntivirusSignatureLastUpdated).TotalDays
    if (-not $s.RealTimeProtectionEnabled) { return New-Outcome Fail 'Real-time protection is off' }
    if ($age -gt 3) { return New-Outcome Warn ("Signatures are {0:N0} days old" -f $age) }
    New-Outcome Pass ("Real-time on; signatures {0:N1} days old" -f $age)
} -Remediation 'Turn on real-time protection and update signatures, or confirm your third-party EDR is active and current.' `
  -Fix { Set-MpPreference -DisableRealtimeMonitoring $false; Update-MpSignature -ErrorAction SilentlyContinue } `
  -FixText 'Enable Defender real-time protection and update signatures' -FixRisk Low -NeedsAdmin

Add-Check -Id 'SEC-03' -Category 'Security' -Name 'Windows Firewall on for all profiles, inbound blocked by default' -Reference 'CIS: Windows Defender Firewall with Advanced Security' -WindowsOnly -Test {
    $bad = @(Get-NetFirewallProfile | Where-Object { -not $_.Enabled -or $_.DefaultInboundAction -ne 'Block' } | ForEach-Object { "$($_.Name)(enabled=$($_.Enabled), inbound=$($_.DefaultInboundAction))" })
    if ($bad) { return New-Outcome Fail ($bad -join '; ') }
    New-Outcome Pass 'Domain, Private, Public: on, inbound Block'
} -Remediation 'Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block. Existing allow rules (e.g. RDP) keep working.' `
  -Fix { Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True -DefaultInboundAction Block } `
  -FixText 'Enable all firewall profiles with default inbound Block' -FixRisk Medium -NeedsAdmin

Add-Check -Id 'SEC-04' -Category 'Security' -Name 'SMBv1 disabled' -Reference 'CIS: Configure SMB v1 server / client driver' -WindowsOnly -Test {
    $srv = $null
    try { $srv = (Get-SmbServerConfiguration).EnableSMB1Protocol } catch { }
    $feat = $null
    try { $feat = (Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop).State } catch { }
    if ($srv -eq $true -or $feat -eq 'Enabled') { return New-Outcome Fail "SMB1 server=$srv, feature=$feat" }
    New-Outcome Pass "SMB1 server=$srv, feature=$feat"
} -Remediation 'Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force; Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart' `
  -Fix {
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null
  } -FixText 'Disable SMBv1 (server setting and optional feature)' -FixRisk Low -NeedsAdmin -NeedsReboot

$Schannel = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
Add-Check -Id 'SEC-05' -Category 'Security' -Name 'TLS 1.0/1.1 disabled, TLS 1.2 enabled (SCHANNEL)' -Reference 'Hardening baseline (CIS/MS): legacy TLS disabled' -WindowsOnly -Test {
    $bad = @()
    foreach ($p in 'TLS 1.0', 'TLS 1.1') { foreach ($side in 'Client', 'Server') {
        $en = Get-Reg "$Schannel\$p\$side" 'Enabled'
        if ($en -ne 0) { $bad += "$p $side not disabled" } } }
    foreach ($side in 'Client', 'Server') {
        $en = Get-Reg "$Schannel\TLS 1.2\$side" 'Enabled'
        if ($en -eq 0) { $bad += "TLS 1.2 $side disabled" } }
    if ($bad) { return New-Outcome Warn ($bad -join '; ') }
    New-Outcome Pass 'Legacy TLS disabled; TLS 1.2 enabled'
} -Remediation 'Disable TLS 1.0 and 1.1 (Client and Server: Enabled=0, DisabledByDefault=1) and keep TLS 1.2 enabled under the SCHANNEL Protocols registry key. Reboot. Check first that nothing else on this server needs legacy TLS.' `
  -Fix {
    foreach ($p in 'TLS 1.0', 'TLS 1.1') { foreach ($side in 'Client', 'Server') {
        Set-Reg "$Schannel\$p\$side" 'Enabled' 0; Set-Reg "$Schannel\$p\$side" 'DisabledByDefault' 1 } }
    foreach ($side in 'Client', 'Server') { Set-Reg "$Schannel\TLS 1.2\$side" 'Enabled' 1; Set-Reg "$Schannel\TLS 1.2\$side" 'DisabledByDefault' 0 }
  } -FixText 'Disable TLS 1.0/1.1 and enable TLS 1.2 in SCHANNEL' -FixRisk Medium -NeedsAdmin -NeedsReboot

Add-Check -Id 'SEC-06' -Category 'Security' -Name '.NET strong cryptography enabled' -Reference 'Hardening baseline: SchUseStrongCrypto' -WindowsOnly -Test {
    $keys = 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319', 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319'
    $bad = @($keys | Where-Object { (Get-Reg $_ 'SchUseStrongCrypto') -ne 1 })
    if ($bad) { return New-Outcome Warn ('Not set: ' + ($bad -join ', ')) }
    New-Outcome Pass 'SchUseStrongCrypto=1 (64/32-bit)'
} -Remediation 'Set SchUseStrongCrypto=1 and SystemDefaultTlsVersions=1 under both .NETFramework\v4.0.30319 keys.' `
  -Fix {
    foreach ($k in 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319', 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319') {
        Set-Reg $k 'SchUseStrongCrypto' 1; Set-Reg $k 'SystemDefaultTlsVersions' 1 }
  } -FixText 'Set SchUseStrongCrypto and SystemDefaultTlsVersions for .NET' -FixRisk Low -NeedsAdmin

Add-Check -Id 'SEC-07' -Category 'Security' -Name 'Security updates installed in the last 35 days' -Reference 'CIS control: continuous vulnerability management' -WindowsOnly -Test {
    $last = Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
    if (-not $last) { return New-Outcome Warn 'No update history found' }
    $days = ((Get-Date) - $last.InstalledOn).TotalDays
    if ($days -gt 35) { return New-Outcome Fail ("Last update {0} ({1:N0} days ago)" -f $last.HotFixID, $days) }
    New-Outcome Pass ("Last update {0} on {1:yyyy-MM-dd}" -f $last.HotFixID, $last.InstalledOn)
} -Remediation 'Install the latest cumulative update through your patching process (WSUS/Intune/SCCM) and reboot before the migration window.'

$CrashKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl'
Add-Check -Id 'SEC-08' -Category 'Security' -Name 'No memory dumps (secrets pass through process memory)' -Reference 'Migration-specific' -WindowsOnly -Test {
    $v = Get-Reg $CrashKey 'CrashDumpEnabled'
    $pf = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' 'ClearPageFileAtShutdown'
    $msg = "CrashDumpEnabled=$v; ClearPageFileAtShutdown=$pf"
    if ($v -ne 0) { return New-Outcome Warn "$msg (a crash dump could hold secrets)" }
    if ($pf -ne 1) { return New-Outcome Warn "$msg (pagefile kept at shutdown)" }
    New-Outcome Pass $msg
} -Remediation 'For the migration window, disable crash dumps (CrashDumpEnabled=0) and clear the pagefile at shutdown (ClearPageFileAtShutdown=1). Revert after the migration if your support process needs dumps.' `
  -Fix {
    Set-Reg $CrashKey 'CrashDumpEnabled' 0
    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' 'ClearPageFileAtShutdown' 1
  } -FixText 'Disable crash dumps and clear the pagefile at shutdown' -FixRisk Medium -NeedsAdmin -NeedsReboot

$TS = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
Add-Check -Id 'SEC-09' -Category 'Security' -Name 'RDP requires Network Level Authentication' -Reference 'CIS: Require user authentication for remote connections by using NLA' -WindowsOnly -Test {
    $v = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication'
    $p = Get-Reg $TS 'UserAuthentication'
    if ($v -eq 1 -or $p -eq 1) { return New-Outcome Pass 'NLA required' }
    New-Outcome Fail 'NLA not required'
} -Remediation 'Require NLA for RDP (System Properties > Remote, or GPO: Require user authentication for remote connections by using Network Level Authentication).' `
  -Fix { Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication' 1 } `
  -FixText 'Require NLA for RDP' -FixRisk Low -NeedsAdmin

Add-Check -Id 'SEC-10' -Category 'Security' -Name 'RDP drive redirection disabled (no copying data off)' -Reference 'CIS: Do not allow drive redirection' -WindowsOnly -Test {
    if ((Get-Reg $TS 'fDisableCdm') -eq 1) { return New-Outcome Pass 'Drive redirection disabled' }
    New-Outcome Warn 'Drive redirection allowed'
} -Remediation 'GPO: Remote Desktop Session Host > Device and Resource Redirection > Do not allow drive redirection = Enabled.' `
  -Fix { Set-Reg $TS 'fDisableCdm' 1 } -FixText 'Disable RDP drive redirection' -FixRisk Low -NeedsAdmin

$AuditSubs = [ordered]@{
    'Credential Validation' = @('{0CCE923F-69AE-11D9-BED3-505054503030}', 'Success and Failure')
    'Logon'                 = @('{0CCE9215-69AE-11D9-BED3-505054503030}', 'Success and Failure')
    'Process Creation'      = @('{0CCE922B-69AE-11D9-BED3-505054503030}', 'Success')
}
Add-Check -Id 'SEC-11' -Category 'Security' -Name 'Audit policy: credential validation, logon, process creation' -Reference 'CIS: Advanced Audit Policy Configuration' -WindowsOnly -Test {
    $bad = @()
    foreach ($k in $AuditSubs.Keys) {
        $csv = & auditpol /get /subcategory:"$($AuditSubs[$k][0])" /r 2>$null | ConvertFrom-Csv
        $setting = ($csv | Select-Object -First 1).'Inclusion Setting'
        if (-not $setting) { return New-Outcome Warn 'Could not read audit policy (needs elevation, or non-English OS)' }
        $want = $AuditSubs[$k][1]
        if (($want -eq 'Success and Failure' -and $setting -ne 'Success and Failure') -or
            ($want -eq 'Success' -and $setting -notmatch 'Success')) { $bad += "$k=$setting" }
    }
    if ($bad) { return New-Outcome Fail ($bad -join '; ') }
    New-Outcome Pass 'Required subcategories audited'
} -Remediation 'auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable; same for "Logon"; auditpol /set /subcategory:"Process Creation" /success:enable. Prefer setting these by GPO.' `
  -Fix {
    foreach ($k in $AuditSubs.Keys) {
        $g = $AuditSubs[$k][0]
        if ($AuditSubs[$k][1] -eq 'Success') { & auditpol /set /subcategory:"$g" /success:enable | Out-Null }
        else { & auditpol /set /subcategory:"$g" /success:enable /failure:enable | Out-Null }
    }
  } -FixText 'Enable the three audit subcategories' -FixRisk Low -NeedsAdmin

$SBL = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
Add-Check -Id 'SEC-12' -Category 'Security' -Name 'PowerShell script block logging enabled' -Reference 'CIS: Turn on PowerShell Script Block Logging' -WindowsOnly -Test {
    if ((Get-Reg $SBL 'EnableScriptBlockLogging') -eq 1) {
        return New-Outcome Pass 'Enabled. Never type secrets into a command line: they would be logged. Let the scripts prompt.'
    }
    New-Outcome Warn 'Not enabled'
} -Remediation 'Enable via GPO: Windows PowerShell > Turn on PowerShell Script Block Logging. Because commands are then logged, never put credentials on a command line or in $env: assignments; let the migration scripts prompt.' `
  -Fix { Set-Reg $SBL 'EnableScriptBlockLogging' 1 } -FixText 'Enable PowerShell script block logging' -FixRisk Low -NeedsAdmin

Add-Check -Id 'SEC-13' -Category 'Security' -Name 'Machine inactivity lock at 15 minutes or less' -Reference 'CIS: Interactive logon: Machine inactivity limit' -WindowsOnly -Test {
    $v = Get-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'InactivityTimeoutSecs'
    if ($v -and $v -gt 0 -and $v -le 900) { return New-Outcome Pass "$v seconds" }
    New-Outcome Fail "InactivityTimeoutSecs=$v"
} -Remediation 'Set Interactive logon: Machine inactivity limit to 900 seconds or less (GPO or registry InactivityTimeoutSecs).' `
  -Fix { Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'InactivityTimeoutSecs' 900 } `
  -FixText 'Set the inactivity lock to 900 seconds' -FixRisk Low -NeedsAdmin

Add-Check -Id 'SEC-14' -Category 'Security' -Name 'Guest account disabled' -Reference 'CIS: Accounts: Guest account status' -WindowsOnly -Test {
    $g = Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' } | Select-Object -First 1
    if (-not $g) { return New-Outcome Pass 'No local guest account (domain controller or removed)' }
    if ($g.Enabled) { return New-Outcome Fail "$($g.Name) is enabled" }
    New-Outcome Pass "$($g.Name) disabled"
} -Remediation 'Disable the built-in Guest account.' `
  -Fix { Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' } | Disable-LocalUser } `
  -FixText 'Disable the built-in Guest account' -FixRisk Low -NeedsAdmin

$Lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
Add-Check -Id 'SEC-15' -Category 'Security' -Name 'LSA protection (RunAsPPL)' -Reference 'CIS/MS baseline: Configure LSASS to run as a protected process' -WindowsOnly -Test {
    $v = Get-Reg $Lsa 'RunAsPPL'
    if ($v -eq 1 -or $v -eq 2) { return New-Outcome Pass "RunAsPPL=$v" }
    New-Outcome Warn "RunAsPPL=$v"
} -Remediation 'Set RunAsPPL=1 under HKLM\SYSTEM\CurrentControlSet\Control\Lsa and reboot. Check first that no third-party LSA plug-ins on this server are unsigned.' `
  -Fix { Set-Reg $Lsa 'RunAsPPL' 1 } -FixText 'Enable LSA protection' -FixRisk Medium -NeedsAdmin -NeedsReboot

Add-Check -Id 'SEC-16' -Category 'Security' -Name 'WDigest plaintext credential caching off' -Reference 'CIS: WDigest Authentication (disabling may require KB2871997)' -WindowsOnly -Test {
    $v = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential'
    if ($v -eq 1) { return New-Outcome Fail 'UseLogonCredential=1' }
    New-Outcome Pass "UseLogonCredential=$v (off)"
} -Remediation 'Set HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest UseLogonCredential=0.' `
  -Fix { Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential' 0 } `
  -FixText 'Turn off WDigest credential caching' -FixRisk Low -NeedsAdmin

Add-Check -Id 'SEC-17' -Category 'Security' -Name 'LLMNR disabled' -Reference 'CIS: Turn off multicast name resolution' -WindowsOnly -Test {
    if ((Get-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast') -eq 0) { return New-Outcome Pass 'Disabled' }
    New-Outcome Warn 'LLMNR enabled'
} -Remediation 'GPO: Network > DNS Client > Turn off multicast name resolution = Enabled.' `
  -Fix { Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' 0 } `
  -FixText 'Disable LLMNR' -FixRisk Low -NeedsAdmin

Add-Check -Id 'SEC-18' -Category 'Security' -Name 'Windows Installer never installs elevated' -Reference 'CIS: Always install with elevated privileges = Disabled' -WindowsOnly -Test {
    $m = Get-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated'
    if ($m -eq 1) { return New-Outcome Fail 'AlwaysInstallElevated=1' }
    New-Outcome Pass "AlwaysInstallElevated=$m"
} -Remediation 'Set AlwaysInstallElevated=0 (GPO: Windows Installer > Always install with elevated privileges = Disabled).' `
  -Fix { Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated' 0 } `
  -FixText 'Disable elevated Windows Installer' -FixRisk Low -NeedsAdmin

Add-Check -Id 'SEC-19' -Category 'Security' -Name 'AutoPlay disabled on all drives' -Reference 'CIS: Turn off Autoplay = All drives' -WindowsOnly -Test {
    if ((Get-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun') -eq 255) { return New-Outcome Pass 'Off for all drives' }
    New-Outcome Warn 'AutoPlay not fully disabled'
} -Remediation 'GPO: AutoPlay Policies > Turn off Autoplay = Enabled, All drives.' `
  -Fix { Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun' 255 } `
  -FixText 'Turn off AutoPlay on all drives' -FixRisk Low -NeedsAdmin

Add-Check -Id 'SEC-20' -Category 'Security' -Name 'No file-sync clients running' -Reference 'Migration-specific' -WindowsOnly -Test {
    $names = 'OneDrive', 'Dropbox', 'GoogleDriveFS', 'BoxSync', 'Box', 'iCloudDrive'
    $run = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $names -contains $_.ProcessName } | Select-Object -ExpandProperty ProcessName -Unique)
    if ($run) { return New-Outcome Warn ('Running: ' + ($run -join ', ')) }
    New-Outcome Pass 'None running'
} -Remediation 'Uninstall sync clients from the migration server, or block them by policy. At minimum stop them for the migration window.' `
  -Fix { Get-Process -ErrorAction SilentlyContinue | Where-Object { 'OneDrive', 'Dropbox', 'GoogleDriveFS', 'BoxSync', 'Box', 'iCloudDrive' -contains $_.ProcessName } | Stop-Process -Force } `
  -FixText 'Stop running sync clients (they may restart at next sign-in)' -FixRisk Low

# --------------------------------------------------------------------------- #
# Run, report, resolve
# --------------------------------------------------------------------------- #
$StatusColor = @{ Pass = 'Green'; Warn = 'Yellow'; Fail = 'Red'; Info = 'Cyan'; Skipped = 'DarkGray'; NotRun = 'DarkGray' }
$RebootNeeded = New-Object System.Collections.ArrayList

function Invoke-AllChecks {
    Write-Host ''
    Write-Host "Running $($Checks.Count) checks..." -ForegroundColor Cyan
    foreach ($c in $Checks) { Invoke-Check $c }
}

function Show-Results {
    Write-Host ''
    foreach ($cat in 'Software', 'Connectivity', 'Permissions', 'Security') {
        $items = @($Checks | Where-Object { $_.Category -eq $cat })
        if (-not $items) { continue }
        Write-Host "== $cat ==" -ForegroundColor White
        foreach ($c in $items) {
            $fix = ''
            if ($c.Status -in 'Fail', 'Warn') { if ($c.Fix) { $fix = ' [auto-fix]' } else { $fix = ' [manual]' } }
            Write-Host ("  {0,-8} {1,-7} {2}{3}" -f $c.Id, $c.Status.ToUpper(), $c.Name, $fix) -ForegroundColor $StatusColor[$c.Status]
            if ($c.Status -ne 'Pass' -and $c.Detail) { Write-Host ("                   {0}" -f $c.Detail) -ForegroundColor DarkGray }
        }
    }
    $g = $Checks | Group-Object Status | ForEach-Object { "$($_.Name)=$($_.Count)" }
    Write-Host ''
    Write-Host ("Summary: " + ($g -join '  ')) -ForegroundColor White
}

function Export-Report {
    $rows = $Checks | Select-Object Id, Category, Name, Status, Detail, Reference, FixRisk, NeedsAdmin, NeedsReboot,
        @{ n = 'AutoFix'; e = { [bool]$_.Fix } }, Remediation
    $json = Join-Path $ReportDir "readiness_$Stamp.json"
    $csv = Join-Path $ReportDir "readiness_$Stamp.csv"
    [pscustomobject]@{
        tool = 'Test-MigrationReadiness'; version = $ScriptVersion; generated = (Get-Date).ToString('o')
        host = [Environment]::MachineName; operator = "$([Environment]::UserDomainName)\$([Environment]::UserName)"
        elevated = $IsAdmin; migration_root = $MigrationRoot; reboot_needed = @($RebootNeeded); checks = $rows
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $json -Encoding UTF8
    $rows | Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding UTF8
    Write-Host "Report: $json" -ForegroundColor Cyan
    Write-Host "        $csv" -ForegroundColor Cyan
    Write-Host "Log:    $LogPath" -ForegroundColor Cyan
}

function Get-OpenIssues { @($Checks | Where-Object { $_.Status -in 'Fail', 'Warn' }) }

function Show-Remediation {
    param($List)
    foreach ($c in $List) {
        Write-Host ''
        Write-Host ("[{0}] {1}  ({2})" -f $c.Id, $c.Name, $c.Status.ToUpper()) -ForegroundColor $StatusColor[$c.Status]
        if ($c.Detail) { Write-Host "  Found: $($c.Detail)" -ForegroundColor DarkGray }
        Write-Host '  How to fix:' -ForegroundColor White
        foreach ($l in ($c.Remediation -split "`n")) { Write-Host "    $($l.TrimEnd())" }
        if ($c.Fix) {
            $flags = @("risk $($c.FixRisk)")
            if ($c.NeedsAdmin) { $flags += 'needs Administrator' }
            if ($c.NeedsReboot) { $flags += 'reboot required' }
            Write-Host ("  Auto-fix available: {0} ({1})" -f $c.FixText, ($flags -join ', ')) -ForegroundColor Cyan
        }
        if ($c.Reference) { Write-Host "  Reference: $($c.Reference)" -ForegroundColor DarkGray }
    }
}

function Invoke-Fix {
    param($Check)
    if (-not $Check.Fix) { Write-Host "  $($Check.Id): no automatic fix. Remediation:" -ForegroundColor Yellow; Show-Remediation @($Check); return }
    if ($Check.WindowsOnly -and -not $OnWindows) { Write-Host "  $($Check.Id): Windows only" -ForegroundColor DarkGray; return }
    if ($Check.NeedsAdmin -and -not $IsAdmin) {
        Write-Host "  $($Check.Id): needs an elevated PowerShell (Run as Administrator). Skipped." -ForegroundColor Yellow
        Write-Log "Fix skipped (not elevated): $($Check.Id)" 'FIX'
        return
    }
    $desc = "$($Check.FixText) [risk $($Check.FixRisk)$(if ($Check.NeedsReboot) { ', reboot required' })]"
    if (-not $Force) {
        $a = Read-Host "  Apply fix for $($Check.Id): $desc ? (y/N)"
        if ($a -notmatch '^(y|yes)$') { Write-Log "Fix declined: $($Check.Id)" 'FIX'; return }
    }
    Write-Log "Fix start: $($Check.Id) $desc" 'FIX'
    try {
        & $Check.Fix
        Write-Log "Fix applied: $($Check.Id)" 'FIX'
        if ($Check.NeedsReboot) { [void]$RebootNeeded.Add($Check.Id) }
    } catch {
        Write-Host "  Fix failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Log "Fix failed: $($Check.Id): $($_.Exception.Message)" 'FIX'
    }
    Invoke-Check $Check
    $note = ''
    if ($Check.NeedsReboot -and $Check.Status -ne 'Pass') { $note = ' (may show as fixed only after reboot)' }
    Write-Host ("  {0} is now {1}{2}" -f $Check.Id, $Check.Status.ToUpper(), $note) -ForegroundColor $StatusColor[$Check.Status]
}

function Show-Menu {
    while ($true) {
        $open = Get-OpenIssues
        $auto = @($open | Where-Object { $_.Fix })
        $low = @($auto | Where-Object { $_.FixRisk -eq 'Low' })
        Write-Host ''
        Write-Host '================ Resolve menu ================' -ForegroundColor White
        Write-Host ("Open issues: {0} ({1} auto-fixable, {2} of them low risk)  Elevated: {3}" -f $open.Count, $auto.Count, $low.Count, $IsAdmin)
        Write-Host '  1) Auto-fix all LOW-risk issues'
        Write-Host '  2) Fix selected issues (by ID)'
        Write-Host '  3) Show remediation steps for all open issues'
        Write-Host '  4) Show results again'
        Write-Host '  5) Re-run all checks'
        Write-Host '  6) Export report'
        Write-Host '  Q) Quit'
        $choice = (Read-Host 'Choose').Trim().ToUpper()
        switch ($choice) {
            '1' { if (-not $low) { Write-Host '  Nothing low-risk to fix.' } else { foreach ($c in $low) { Invoke-Fix $c } } }
            '2' {
                $ids = (Read-Host '  IDs, comma-separated (e.g. SEC-06,PERM-04)') -split '[,\s]+' | Where-Object { $_ }
                foreach ($id in $ids) {
                    $c = $Checks | Where-Object { $_.Id -eq $id.ToUpper() } | Select-Object -First 1
                    if ($c) { Invoke-Fix $c } else { Write-Host "  Unknown ID: $id" -ForegroundColor Yellow }
                }
            }
            '3' { if ($open) { Show-Remediation $open } else { Write-Host '  No open issues.' -ForegroundColor Green } }
            '4' { Show-Results }
            '5' { Invoke-AllChecks; Show-Results }
            '6' { Export-Report }
            'Q' { return }
            default { Write-Host '  Choose 1-6 or Q.' }
        }
    }
}

Write-Host "Delinea -> CyberArk migration server readiness ($ScriptVersion)" -ForegroundColor Cyan
Write-Host "Root: $MigrationRoot   Config: $ConfigPath   Elevated: $IsAdmin"
if (-not $IsAdmin -and $OnWindows) { Write-Host 'Tip: some checks read more, and most fixes need, an elevated window (Run as Administrator).' -ForegroundColor DarkYellow }

Invoke-AllChecks
Show-Results

# -FixIds A,B arrives as one string when called with powershell.exe -File (e.g. from the UI).
if ($FixIds) { $FixIds = @($FixIds | ForEach-Object { $_ -split '[,\s]+' } | Where-Object { $_ }) }
if ($NonInteractive -and $FixIds) {
    foreach ($id in $FixIds) {
        $c = $Checks | Where-Object { $_.Id -eq $id.ToUpper() } | Select-Object -First 1
        if ($c) { Invoke-Fix $c } else { Write-Host "Unknown ID: $id" -ForegroundColor Yellow }
    }
} elseif ($Mode -eq 'Resolve' -and -not $NonInteractive) {
    Show-Menu
}

Export-Report
if ($RebootNeeded.Count) { Write-Host ("Reboot required to complete: " + ($RebootNeeded -join ', ')) -ForegroundColor Yellow }
Write-Log 'Finished'

$fails = @($Checks | Where-Object { $_.Status -eq 'Fail' }).Count
$warns = @($Checks | Where-Object { $_.Status -eq 'Warn' }).Count
if ($fails) { exit 2 } elseif ($warns) { exit 1 } else { exit 0 }
