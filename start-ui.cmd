@echo off
setlocal
REM Starts the Idira Migration Workbench (HTTPS, self-signed certificate) in your browser. Close this window to stop it.
cd /d "%~dp0"
REM Find a Python 3 that really runs: the py launcher, then python, then python3. Each is tried with
REM --version first, so a missing command (or the Microsoft Store placeholder) is skipped quietly.
set "IMW_PY="
py -3 --version >nul 2>nul && set "IMW_PY=py -3"
if not defined IMW_PY python --version >nul 2>nul && set "IMW_PY=python"
if not defined IMW_PY python3 --version >nul 2>nul && set "IMW_PY=python3"
if not defined IMW_PY (
  echo Python 3 was not found on this computer.
  echo.
  echo Install Python 3.8 or later from https://www.python.org/downloads/windows/
  echo and tick "Add python.exe to PATH" in the installer, then double-click start-ui.cmd again.
  echo If Python is installed already, open a new Command Prompt and check that "python --version" works.
  echo.
  pause
  exit /b 1
)
echo Starting the Workbench with: %IMW_PY%
%IMW_PY% -m imw ui %*
pause
