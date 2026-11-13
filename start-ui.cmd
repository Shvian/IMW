@echo off
REM Starts the Idira Migration Workbench (HTTPS, self-signed certificate) in your browser. Close this window to stop it.
cd /d "%~dp0"
REM Use the py launcher when it exists, else python. Only one of them runs, even if it exits with an error.
where py >nul 2>nul
if %errorlevel%==0 (py -3 -m imw ui %*) else (python -m imw ui %*)
pause
