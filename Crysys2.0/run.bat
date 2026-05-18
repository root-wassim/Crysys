@echo off
echo =======================================
echo   Crysys 2.0 Setup and Launcher
echo =======================================

echo.
echo Checking python dependencies...
python -c "import flask, cryptography, Crypto, sympy, matplotlib, numpy, phe, requests" 2>nul
if errorlevel 1 goto install
echo Python dependencies are already satisfied.
goto compile

:install
echo Installing missing python packages...
pip install -r requirements.txt
if errorlevel 1 (
    echo [WARNING] Dependency installation failed! Attempting to proceed anyway...
)

:compile
echo.
echo Compiling C Engine...
python build.py
if errorlevel 1 (
    echo [ERROR] Build failed!
    pause
    exit /b 1
)

echo.
echo Starting Flask App...
python app.py
pause
