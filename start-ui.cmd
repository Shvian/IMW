@echo off
setlocal
REM Starts the Idira Migration Workbench (HTTPS, self-signed certificate) in your browser. Close this window to stop it.
cd /d "%~dp0"
if not exist "%~dp0IMW.exe" (
  echo IMW.exe was not found next to this script.
  echo.
  echo Download IMW-win-x64 from the project's GitHub Actions page ^(workflow "Windows app"^),
  echo unzip IMW.exe into this folder, then double-click start-ui.cmd again.
  echo.
  pause
  exit /b 1
)
echo Starting the Workbench with: IMW.exe
"%~dp0IMW.exe" ui %*
pause
