@echo off
REM Run this file by double-clicking it, or from PowerShell: .\run.bat
cd /d "%~dp0"

echo Checking for virtual environment...
if not exist ".venv" (
    echo Creating virtual environment...
    python -m venv .venv
)

echo Activating virtual environment...
call .venv\Scripts\activate.bat

echo Installing dependencies...
pip install -r requirements.txt

echo.
echo Checking artifacts folder...
python check_setup.py
if errorlevel 1 (
    echo.
    echo Setup check failed. Fix the issue above before continuing.
    pause
    exit /b 1
)

echo.
echo Starting server at http://localhost:8000  (docs at http://localhost:8000/docs)
echo Press CTRL+C to stop.
uvicorn app:app --reload --host 0.0.0.0 --port 8000

pause
