# Stop everything started by start.ps1.
$Run = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'run'

$stopped = $false
foreach ($name in 'buns', 'zap', 'juice-shop') {
    $f = Join-Path $Run "$name.pid"
    if (-not (Test-Path $f)) { continue }
    $id = [int](Get-Content $f -TotalCount 1)
    if (Get-Process -Id $id -ErrorAction SilentlyContinue) {
        & taskkill.exe /PID $id /T /F | Out-Null
        Write-Host "  stopped $name"
        $stopped = $true
    }
    Remove-Item -Force $f
}
if (-not $stopped) { Write-Host '  nothing was running' }
