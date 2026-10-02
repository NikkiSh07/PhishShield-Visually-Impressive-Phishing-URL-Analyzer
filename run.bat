@echo off
REM ============================================================
REM PhishShield — Flask + MySQL + Java Setup & Run Script
REM ============================================================

echo.
echo  ██████╗ ██╗  ██╗██╗███████╗██╗  ██╗    ███████╗██╗  ██╗██╗███████╗██╗     ██████╗
echo  ██╔══██╗██║  ██║██║██╔════╝██║  ██║    ██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗
echo  ██████╔╝███████║██║███████╗███████║    ███████╗███████║██║█████╗  ██║     ██║  ██║
echo  ██╔═══╝ ██╔══██║██║╚════██║██╔══██║    ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║
echo  ██║     ██║  ██║██║███████║██║  ██║    ███████║██║  ██║██║███████╗███████╗██████╔╝
echo  ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝    ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝
echo.
echo  Flask + MySQL + Java  ^|  v2.1
echo ============================================================
echo.

REM ---- Step 1: Check Python -----------------------------------------------
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Please install Python 3.10+
    pause & exit /b 1
)
echo [OK] Python found

REM ---- Step 2: Install Python deps ----------------------------------------
echo [..] Installing Python dependencies...
pip install -q flask flask-cors mysql-connector-python python-whois scikit-learn numpy
echo [OK] Python packages ready

REM ---- Step 3: Compile Java (optional) ------------------------------------
where javac >nul 2>&1
if errorlevel 1 (
    echo [WARN] javac not found. Java feature analysis will be skipped.
    echo        To enable Java: install JDK from https://adoptium.net
) else (
    echo [..] Compiling Java PhishAnalyzer...
    javac "flask_app\java\PhishAnalyzer.java" >nul 2>&1
    if errorlevel 1 (
        echo [WARN] Java compilation failed. Java features disabled.
    ) else (
        echo [OK] Java PhishAnalyzer compiled
    )
)

REM ---- Step 4: MySQL setup note -------------------------------------------
echo.
echo [INFO] MySQL Setup:
echo        1. Start MySQL server
echo        2. Run: mysql -u root -p ^< schema.sql
echo        3. Edit PHISHSHIELD_DB_* env vars if needed (default: root/password)
echo.

REM ---- Step 5: Start Flask -------------------------------------------------
echo [OK] Starting Flask server at http://localhost:5000
echo      Press Ctrl+C to stop
echo.
cd flask_app
python app.py
