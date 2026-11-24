@echo off
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0portable\setup.ps1" %*
echo.
pause
