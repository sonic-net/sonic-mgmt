@echo off
setlocal
cd /d "%~dp0"

REM Always run inside the local virtualenv. Bootstrap on first launch.
if not exist .venv\Scripts\pythonw.exe (
    echo First-time setup: creating .venv and installing dependencies...
    python -m venv .venv || goto :fail
    .venv\Scripts\python.exe -m pip install --upgrade pip >nul || goto :fail
    .venv\Scripts\python.exe -m pip install -r requirements.txt || goto :fail
)

REM /B = no new console; pythonw is GUI so nothing further is shown.
start "" /B .venv\Scripts\pythonw.exe editor.py
exit /b 0

:fail
echo.
echo Setup failed. See messages above.
pause
exit /b 1
