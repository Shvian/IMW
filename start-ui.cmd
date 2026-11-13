@echo off
REM Starts the Idira Migration Workbench (HTTPS, self-signed certificate) in your browser. Close this window to stop it.
cd /d "%~dp0"
where py >nul 2>nul && (py -3 -m pam2pc ui %*) || (python -m pam2pc ui %*)
pause
