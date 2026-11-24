@echo off
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0portable\start.ps1" %*
echo.
echo You can close this window. The lab keeps running until you run stop-portable.cmd.
pause
