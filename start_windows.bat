@echo off
rem Start the SecReport web interface. Open the full link (with ?token=...) that appears below.
cd /d "%~dp0"
where py >nul 2>nul && (py -3 -m secreport serve --workspace workspace) || (python -m secreport serve --workspace workspace)
pause
