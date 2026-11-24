# Portable setup for Windows 10/11: downloads Python, Node.js, a Java runtime,
# OWASP ZAP and OWASP Juice Shop into portable\runtime, installs the back-end
# packages and builds the front end. Nothing is installed system-wide and no
# administrator rights are needed.
#
#   setup-portable.cmd                 everything
#   setup-portable.cmd -NoZap          skip ZAP and Java (scans use cURL probes only)
#   setup-portable.cmd -Force          re-extract everything
#
# Uses curl.exe and tar.exe, which ship with Windows 10 (1803+) and 11,
# and the .NET zip reader for .zip archives.

param(
    [switch]$NoZap,
    [switch]$NoJuiceShop,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$Here  = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root  = Split-Path -Parent $Here
$RT    = Join-Path $Here 'runtime'
$Cache = Join-Path $Here 'cache'
$Logs  = Join-Path $Here 'logs'

function Say($msg)  { Write-Host ''; Write-Host $msg -ForegroundColor White }
function Info($msg) { Write-Host "  $msg" }
function Fail($msg) {
    Write-Host ''
    Write-Host "Setup stopped: $msg" -ForegroundColor Red
    exit 1
}

# -- versions --------------------------------------------------------------
$V = @{}
Get-Content (Join-Path $Here 'versions.env') | ForEach-Object {
    if ($_ -match '^\s*([A-Z_]+)=(.*)$') { $V[$Matches[1]] = $Matches[2].Trim() }
}

foreach ($tool in 'curl.exe', 'tar.exe') {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        Fail "$tool was not found. It ships with Windows 10 version 1803 and later; please update Windows."
    }
}

# Juice Shop contains paths up to 180 characters and Windows allows 260 by
# default, so the project folder path should stay under about 45 characters.
if ($Root.Length -gt 45) {
    Write-Host "Warning: the project folder path is $($Root.Length) characters long:" -ForegroundColor Yellow
    Write-Host "  $Root" -ForegroundColor Yellow
    Write-Host "  Juice Shop may not extract. If setup fails, move the folder to C:\buns and run setup again." -ForegroundColor Yellow
}

New-Item -ItemType Directory -Force -Path $RT, $Cache, $Logs, (Join-Path $Here 'data'), (Join-Path $Here 'run') | Out-Null

# Run a command line through cmd.exe exactly as written and return its exit
# code. Used where output goes to a log file: Windows PowerShell 5.1 would
# otherwise turn harmless warnings on stderr into errors.
function Invoke-Cmd([string]$CommandLine, [string]$WorkDir = $Root) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = 'cmd.exe'
    $psi.Arguments = '/d /s /c "' + $CommandLine + '"'
    $psi.WorkingDirectory = $WorkDir
    $psi.UseShellExecute = $false
    $proc = [System.Diagnostics.Process]::Start($psi)
    $proc.WaitForExit()
    return $proc.ExitCode
}

function Fetch([string]$Url, [string]$File) {
    $out = Join-Path $Cache $File
    if ((Test-Path $out) -and ((Get-Item $out).Length -gt 0)) { Info "cached   $File"; return }
    Info "download $File"
    $part = "$out.part"
    & curl.exe -fL --retry 3 --connect-timeout 20 --progress-bar -o $part $Url
    if ($LASTEXITCODE -ne 0) { Fail "could not download $Url" }
    Move-Item -Force $part $out
}

# Extract an archive and move its single top-level folder to runtime\<Name>.
function Unpack([string]$File, [string]$Name) {
    $dest = Join-Path $RT $Name
    if ((Test-Path $dest) -and -not $Force) { Info "present  runtime\$Name"; return }
    Info "unpacking $File (can take several minutes while Windows scans the files)"
    $tmp = Join-Path $RT ".tmp-$Name"
    foreach ($p in $tmp, $dest) { if (Test-Path $p) { Remove-Item -Recurse -Force $p } }
    New-Item -ItemType Directory -Force -Path $tmp | Out-Null
    $archive = Join-Path $Cache $File
    if ($File.EndsWith('.zip')) {
        # tar.exe cannot read some file names in the Juice Shop zip; the .NET
        # zip reader handles them.
        try {
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            [System.IO.Compression.ZipFile]::ExtractToDirectory($archive, $tmp)
        } catch {
            Fail "could not extract $($File): $($_.Exception.Message) If the path is long, move the project to C:\buns and retry."
        }
    } else {
        & tar.exe -xf $archive -C $tmp
        if ($LASTEXITCODE -ne 0) { Fail "could not extract $File. If the path is long, move the project to C:\buns and retry." }
    }
    $items = @(Get-ChildItem -Force $tmp)
    if ($items.Count -eq 1 -and $items[0].PSIsContainer) {
        Move-Item $items[0].FullName $dest
        Remove-Item -Recurse -Force $tmp
    } else {
        Move-Item $tmp $dest
    }
    Info "unpacked runtime\$Name"
}

# -- Python -----------------------------------------------------------------
Say "Python $($V.PYTHON_VERSION)"
$pyFile = "cpython-$($V.PYTHON_VERSION)+$($V.PYTHON_BUILD)-x86_64-pc-windows-msvc-install_only.tar.gz"
$pyUrl  = "https://github.com/astral-sh/python-build-standalone/releases/download/$($V.PYTHON_BUILD)/" + $pyFile.Replace('+', '%2B')
Fetch $pyUrl $pyFile
Unpack $pyFile 'python'
$Py = Join-Path $RT 'python\python.exe'
# Ensure global/system pip.ini (e.g. require-virtualenv = true) does not block portable install
"[global]`r`nrequire-virtualenv = false" | Set-Content -Encoding ASCII (Join-Path $RT 'python\pip.ini')
$env:PIP_REQUIRE_VIRTUALENV = '0'
Info 'installing back-end packages (1-5 minutes, details in portable\logs\pip.log)'
$pipLog = Join-Path $Logs 'pip.log'
$req = Join-Path $Root 'backend\requirements.txt'
$code = Invoke-Cmd "`"$Py`" -m pip install --disable-pip-version-check --no-warn-script-location -r `"$req`" > `"$pipLog`" 2>&1"
if ($code -ne 0) { Fail 'installing the back-end packages failed; see portable\logs\pip.log' }
Info 'back-end packages installed'

# -- Node.js -------------------------------------------------------------------
Say "Node.js $($V.NODE_MAJOR)"
$nodeVersion = $env:NODE_VERSION
if (-not $nodeVersion) {
    $sums = & curl.exe -fsSL "https://nodejs.org/dist/latest-v$($V.NODE_MAJOR).x/SHASUMS256.txt"
    if ($LASTEXITCODE -ne 0) { Fail "could not look up the latest Node.js $($V.NODE_MAJOR) release." }
    $m = [regex]::Match(($sums -join "`n"), "node-v($($V.NODE_MAJOR)\.\d+\.\d+)-win-x64\.zip")
    if (-not $m.Success) { Fail 'could not find a Windows Node.js package in the release list.' }
    $nodeVersion = $m.Groups[1].Value
}
$nodeFile = "node-v$nodeVersion-win-x64.zip"
Fetch "https://nodejs.org/dist/v$nodeVersion/$nodeFile" $nodeFile
Unpack $nodeFile 'node'
$NodeDir = Join-Path $RT 'node'
$env:Path = "$NodeDir;$env:Path"

Say 'Front end'
$buildLog = Join-Path $Logs 'frontend-build.log'
$npm = Join-Path $NodeDir 'npm.cmd'
$web = Join-Path $Root 'frontend'
Info 'installing and building the front end (2-4 minutes)'
$code = Invoke-Cmd "`"$npm`" ci --no-audit --no-fund --loglevel=error > `"$buildLog`" 2>&1" $web
if ($code -ne 0) {
    # If npm ci failed due to a file lock in node_modules, retry with npm install
    $code = Invoke-Cmd "`"$npm`" install --no-audit --no-fund --loglevel=error >> `"$buildLog`" 2>&1" $web
}
if ($code -ne 0) { Fail "npm build/install failed; see portable\logs\frontend-build.log" }
$code = Invoke-Cmd "`"$npm`" run build >> `"$buildLog`" 2>&1" $web
if ($code -ne 0) { Fail "front-end build failed; see portable\logs\frontend-build.log" }
$static = Join-Path $Root 'backend\static'
if (Test-Path $static) { Remove-Item -Recurse -Force $static }
Copy-Item -Recurse (Join-Path $Root 'frontend\dist') $static
Info 'built and copied to backend\static'

# -- Java + ZAP --------------------------------------------------------------
if (-not $NoZap) {
    Say "Java runtime $($V.JAVA_MAJOR)"
    $javaFile = "temurin-jre-$($V.JAVA_MAJOR)-windows-x64.zip"
    Fetch "https://api.adoptium.net/v3/binary/latest/$($V.JAVA_MAJOR)/ga/windows/x64/jre/hotspot/normal/eclipse" $javaFile
    Unpack $javaFile 'jre'

    Say "OWASP ZAP $($V.ZAP_VERSION)"
    $zapFile = "ZAP_$($V.ZAP_VERSION)_Crossplatform.zip"
    Fetch "https://github.com/zaproxy/zaproxy/releases/download/v$($V.ZAP_VERSION)/$zapFile" $zapFile
    Unpack $zapFile 'zap'
} else {
    Say 'Skipping ZAP (-NoZap): scans will run the cURL probes only.'
}

# -- Juice Shop -----------------------------------------------------------------
if (-not $NoJuiceShop) {
    Say "OWASP Juice Shop $($V.JUICE_SHOP_VERSION)"
    $jsFile = "juice-shop-$($V.JUICE_SHOP_VERSION)_node$($V.NODE_MAJOR)_win32_x64.zip"
    Fetch "https://github.com/juice-shop/juice-shop/releases/download/v$($V.JUICE_SHOP_VERSION)/$jsFile" $jsFile
    Unpack $jsFile 'juice-shop'
}

@(
    'os=windows', 'arch=x64',
    "python=$($V.PYTHON_VERSION)", "node=$nodeVersion",
    "zap=$(if ($NoZap) { 'none' } else { $V.ZAP_VERSION })",
    "juice_shop=$(if ($NoJuiceShop) { 'none' } else { $V.JUICE_SHOP_VERSION })"
) | Set-Content -Encoding ASCII (Join-Path $RT 'manifest.txt')

Say 'Done. Start everything with start-portable.cmd'
