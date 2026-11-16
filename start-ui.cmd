@echo off
setlocal
REM Starts the Idira Migration Workbench (HTTPS, self-signed certificate) in your browser. Close this window to stop it.
cd /d "%~dp0"
REM The Windows app (IMW.exe) needs no Python. Use it when it sits next to this script.
if exist "%~dp0IMW.exe" (
  echo Starting the Workbench with: IMW.exe
  "%~dp0IMW.exe" ui %*
  pause
  exit /b
)
REM Otherwise run the Python version.
REM Find a Python 3 that really runs. Each candidate is tried with --version first, so a missing
REM command (or the Microsoft Store placeholder) is skipped quietly.
set "IMW_PY="
REM 1. The usual commands on PATH.
py -3 --version >nul 2>nul && set "IMW_PY=py -3"
if not defined IMW_PY python --version >nul 2>nul && set "IMW_PY=python"
if not defined IMW_PY python3 --version >nul 2>nul && set "IMW_PY=python3"
REM 2. The usual install folders, for when this window's PATH has no Python (it can differ from a terminal's).
if not defined IMW_PY for %%P in ("%LOCALAPPDATA%\Programs\Python\Launcher\py.exe" "%SystemRoot%\py.exe") do (
  if not defined IMW_PY if exist %%P %%P -3 --version >nul 2>nul && set "IMW_PY=%%P -3"
)
if not defined IMW_PY for /d %%D in ("%LOCALAPPDATA%\Programs\Python\Python3*" "%ProgramFiles%\Python3*" "%LOCALAPPDATA%\Python\pythoncore-3*") do (
  if not defined IMW_PY if exist "%%~D\python.exe" "%%~D\python.exe" --version >nul 2>nul && set "IMW_PY="%%~D\python.exe""
)
REM 3. Whatever PowerShell finds as py or python (the same lookup as typing it in PowerShell).
if not defined IMW_PY for /f "usebackq delims=" %%P in (`powershell -NoLogo -Command "$c = @(Get-Command py.exe, python.exe -CommandType Application -ErrorAction SilentlyContinue); if ($c.Count) { $c[0].Source }" 2^>nul`) do (
  if not defined IMW_PY "%%P" --version >nul 2>nul && set "IMW_PY="%%P""
)
if not defined IMW_PY (
  echo Python 3 was not found on this computer.
  echo.
  echo Install Python 3.8 or later from https://www.python.org/downloads/windows/
  echo and tick "Add python.exe to PATH" in the installer, then double-click start-ui.cmd again.
  echo If Python is installed already, open PowerShell in this folder and run:  py -m imw ui
  echo.
  pause
  exit /b 1
)
echo Starting the Workbench with: %IMW_PY%
%IMW_PY% -m imw ui %*
pause
