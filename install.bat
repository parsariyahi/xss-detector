@echo off
REM Setup script for XSS Scanner (Windows)

echo ========================================
echo XSS Scanner Setup
echo ========================================

REM Check Python version
python --version
if %errorlevel% neq 0 (
    echo Error: Python 3 is required
    exit /b 1
)

REM Create virtual environment (optional but recommended)
set /p create_venv="Create virtual environment? (y/n): "
if /i "%create_venv%"=="y" (
    python -m venv venv
    call venv\Scripts\activate.bat
    echo Virtual environment activated
)

REM Install requirements
echo Installing Python dependencies...
pip install -r requirements.txt

REM Install Playwright browsers
echo Installing Playwright Chromium browser...
playwright install chromium

echo ========================================
echo Setup completed!
echo ========================================
echo.
echo You can now run the scanner with:
echo   python xss_scanner.py https://example.com
echo.
echo For more information, see README.md
pause
