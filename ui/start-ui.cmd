@echo off
rem Starts the migration UI on this server (127.0.0.1 only) and opens the browser.
rem Keep this window open: it prints the one-time link (press Enter for a new one)
rem and Ctrl+C here stops the UI and drops the credentials held in memory.
setlocal
cd /d "%~dp0.."
where py >nul 2>nul
if %errorlevel%==0 (
  py -3 "%~dp0server\migration_ui.py" %*
) else (
  python "%~dp0server\migration_ui.py" %*
)
endlocal
