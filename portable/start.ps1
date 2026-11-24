# Start Juice Shop, ZAP and buns from portable\runtime (after setup.ps1).
#   start-portable.cmd            start everything and open the browser
#   start-portable.cmd -NoOpen    do not open the browser

param([switch]$NoOpen)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root = Split-Path -Parent $Here
$RT   = Join-Path $Here 'runtime'
$Data = Join-Path $Here 'data'
$Logs = Join-Path $Here 'logs'
$Run  = Join-Path $Here 'run'

function Say($msg)  { Write-Host $msg -ForegroundColor White }
function Info($msg) { Write-Host "  $msg" }
function Fail($msg) { Write-Host $msg -ForegroundColor Red; exit 1 }

$V = @{}
Get-Content (Join-Path $Here 'versions.env') | ForEach-Object {
    if ($_ -match '^\s*([A-Z_]+)=(.*)$') { $V[$Matches[1]] = $Matches[2].Trim() }
}
$PortBuns  = [int]$V.PORT_BUNS
$PortJuice = [int]$V.PORT_JUICE_SHOP
$PortZap   = [int]$V.PORT_ZAP

$Py = Join-Path $RT 'python\python.exe'
if (-not (Test-Path $Py) -or -not (Test-Path (Join-Path $Root 'backend\static'))) {
    Fail 'Run setup-portable.cmd first.'
}
New-Item -ItemType Directory -Force -Path $Data, $Logs, $Run | Out-Null

# Values from .env (KEY=VALUE lines), without overriding the environment.
$envFile = Join-Path $Root '.env'
if (Test-Path $envFile) {
    Get-Content $envFile | ForEach-Object {
        if ($_ -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$') {
            $k = $Matches[1]; $v = $Matches[2].Trim().Trim('"')
            if (-not [Environment]::GetEnvironmentVariable($k)) { [Environment]::SetEnvironmentVariable($k, $v, 'Process') }
        }
    }
}
$ZapKey = $env:ZAP_API_KEY
if (-not $ZapKey -or $ZapKey.StartsWith('change-me')) {
    $keyFile = Join-Path $Data 'zap-api-key'
    if (-not (Test-Path $keyFile)) { [guid]::NewGuid().ToString('N') | Set-Content -Encoding ASCII $keyFile }
    $ZapKey = (Get-Content $keyFile -TotalCount 1).Trim()
}

function PidFile([string]$Name) { Join-Path $Run "$Name.pid" }

function Test-Alive([string]$Name) {
    $f = PidFile $Name
    if (-not (Test-Path $f)) { return $false }
    $id = [int](Get-Content $f -TotalCount 1)
    return [bool](Get-Process -Id $id -ErrorAction SilentlyContinue)
}

function Test-PortBusy([int]$Port) {
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $task = $client.ConnectAsync('127.0.0.1', $Port)
        return ($task.Wait(500) -and $client.Connected)
    } catch {
        return $false
    } finally {
        $client.Close()
    }
}

function Test-Up([string]$Url) {
    try {
        $r = Invoke-WebRequest -UseBasicParsing -TimeoutSec 3 -Uri $Url
        return ($r.StatusCode -ge 200 -and $r.StatusCode -lt 400)
    } catch {
        return $false
    }
}

function Quote([string]$s) { if ($s -match '[\s&()^]') { '"' + $s + '"' } else { $s } }

function Launch([string]$Name, [int]$Port, [string]$WorkDir, [string]$Exe, [string[]]$Arguments) {
    if (Test-Alive $Name) { Info "$Name already running"; return $true }
    if (Test-PortBusy $Port) {
        Info "$($Name): port $Port is already in use by another program. Close it or change PORT_* in portable\versions.env."
        return $false
    }
    # cmd.exe gives each service its own hidden console, so closing this
    # window does not stop the lab, and handles the log redirection.
    $log = Join-Path $Logs "$Name.log"
    $inner = ((@($Exe) + $Arguments) | ForEach-Object { Quote $_ }) -join ' '
    $cmdLine = '/d /s /c "' + $inner + ' > "' + $log + '" 2>&1"'
    $p = Start-Process -FilePath 'cmd.exe' -ArgumentList $cmdLine -WorkingDirectory $WorkDir -WindowStyle Hidden -PassThru
    Set-Content -Encoding ASCII (PidFile $Name) $p.Id
    Info "$Name started (log portable\logs\$Name.log)"
    return $true
}

function Wait-Ready([string]$Name, [string]$Url, [int]$Seconds) {
    for ($i = 0; $i -lt $Seconds; $i++) {
        if (Test-Up $Url) { Info "$Name ready"; return $true }
        if (-not (Test-Alive $Name)) {
            Info "$Name exited. Last lines of its log:"
            $path = Join-Path $Logs "$Name.log"
            if (Test-Path $path) { Get-Content $path -Tail 12 | ForEach-Object { Info "  $_" } }
            return $false
        }
        Start-Sleep -Seconds 1
    }
    Info "$Name is still starting; it will be picked up when ready"
    return $true
}

Say 'Starting the buns lab'

$JuiceDir = Join-Path $RT 'juice-shop'
if (Test-Path $JuiceDir) {
    $env:PORT = "$PortJuice"
    [void](Launch 'juice-shop' $PortJuice $JuiceDir (Join-Path $RT 'node\node.exe') @('build\app.js'))
} else {
    Info "Juice Shop not installed; expecting it on http://localhost:$PortJuice"
}

$Java   = Join-Path $RT 'jre\bin\java.exe'
$ZapJar = Get-ChildItem -Path (Join-Path $RT 'zap') -Filter 'zap-*.jar' -ErrorAction SilentlyContinue | Select-Object -First 1
if ($ZapJar -and (Test-Path $Java)) {
    [void](Launch 'zap' $PortZap (Join-Path $RT 'zap') $Java @(
        '-Xmx1024m', '-jar', $ZapJar.FullName, '-daemon', '-silent',
        '-host', '127.0.0.1', '-port', "$PortZap", '-dir', (Join-Path $Data 'zap-home'),
        '-config', "api.key=$ZapKey"))
} else {
    Info 'ZAP not installed; scans will run the cURL probes only'
}

$env:BUNS_DATABASE_URL = 'sqlite:///' + (Join-Path $Data 'buns.db').Replace('\', '/')
$env:BUNS_DATA_DIR     = $Data
if (-not $env:BUNS_SEED_TARGET) { $env:BUNS_SEED_TARGET = "http://localhost:$PortJuice" }
$env:ZAP_URL           = "http://127.0.0.1:$PortZap"
$env:ZAP_API_KEY       = $ZapKey
$env:PYTHONUNBUFFERED  = '1'
$ok = Launch 'buns' $PortBuns (Join-Path $Root 'backend') $Py @(
    '-m', 'uvicorn', 'app.main:app', '--host', '127.0.0.1', '--port', "$PortBuns")
if (-not $ok) { Fail 'buns could not start.' }

if (-not (Wait-Ready 'buns' "http://127.0.0.1:$PortBuns/api/health" 40)) { Fail 'buns did not start.' }
if (Test-Path $JuiceDir) { [void](Wait-Ready 'juice-shop' "http://127.0.0.1:$PortJuice/rest/admin/application-version" 90) }
if ($ZapJar) { [void](Wait-Ready 'zap' "http://127.0.0.1:$PortZap/JSON/core/view/version/?apikey=$ZapKey" 90) }

$Url = "http://localhost:$PortBuns"
Write-Host ''
Say "buns is running at $Url"
Info "Juice Shop: http://localhost:$PortJuice"
Info 'Stop everything with stop-portable.cmd'
if (-not $NoOpen) { Start-Process $Url }
