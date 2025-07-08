@echo off
chcp 65001 >nul
title checklist-parameter-juniper-fabric

echo.
echo ==================================================================================
echo                      checklist-parameter-juniper-fabric
echo                  This script is used to execute checklist parameters.
echo                                Version: v2.0
echo ==================================================================================
echo.                    NOTE: No action is required while installing.
echo ==================================================================================
echo.

:: Set variables
set "REQ_FILE=requirements.txt"
set "EXE_FILE=script.exe"

:: Check if Python is installed
echo [CHECK] Checking for Python and pip...
where python >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python not found. Please install Python before continuing.
    pause
    exit /b
)

where pip >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] pip not found. Please ensure Python and pip are correctly installed.
    pause
    exit /b
)

:: Install Python requirements
echo.
echo [PROCESS] Installing Python requirements...
if exist "%REQ_FILE%" (
    pip install -r "%REQ_FILE%"
    if %errorlevel% neq 0 (
        echo [FAILED] Failed to install packages from requirements.txt
        pause
        exit /b
    )
    echo.
    echo [SUCCESS] Python packages installed.
) else (
    echo.
    echo [FAILED] No requirements.txt found. Skipping pip install.
)

:: Build EXE from script.py using PyInstaller
echo.
echo [PROCESS] Building EXE from script.py using PyInstaller...
where pyinstaller >nul 2>&1
if %errorlevel% neq 0 (
    echo [INFO] PyInstaller not found. Installing it...
    pip install pyinstaller
)

pyinstaller --onefile script.py
if exist "dist\%EXE_FILE%" (
    copy /Y "dist\%EXE_FILE%" . >nul
    echo [SUCCESS] %EXE_FILE% successfully created.
) else (
    echo [FAILED] Build failed. Check PyInstaller output above.
    pause
    exit /b
)

:: Create shortcut to Desktop
echo.
echo [PROCESS] Creating shortcut to Desktop...
powershell -Command "$s=(New-Object -COM WScript.Shell).CreateShortcut('%USERPROFILE%\Desktop\juniper-checklist-parameter.lnk');$s.TargetPath='%CD%\%EXE_FILE%';$s.WorkingDirectory='%CD%';$s.Save()"
echo [SUCCESS] Shortcut created on Desktop: juniper-checklist-parameter.lnk
echo.

:: Final notes
echo +--------------------------------------------------------------------------------------+
echo ^|                       TOOLS INSTALLATION AUTOMATION COMPLETED                     ^|
echo ^|                         ENJOY AND RUN THE SCRIPT!                                 ^|
echo +--------------------------------------------------------------------------------------+
echo.

echo NOTES:
echo 1. If installation failed, make sure Python and pip are installed and try again.
echo 2. Ensure your internet connection is stable.
echo.

echo ================================================================================ 
echo NEXT STEP:
echo 1. The script will be named: juniper-checklist-parameter.exe
echo 2. A shortcut has been created on Desktop.
echo 3. Double click the file ond Desktop: juniper-checklist-parameter.exe
echo 4. Input credentials, Juniper commands, and device IP list.
echo 5. Results will be stored in folder output-{timestamp}, report.csv, and report.xlsx
echo 6. Enjoy and stay connected. Thank you!
echo ================================================================================

:: Run script.exe automatically
if exist "%EXE_FILE%" (
    echo [INFO] Running %EXE_FILE%...
    start "" "%EXE_FILE%"
) else (
    echo [WARNING] %EXE_FILE% not found. Make sure build was successful.
)

pause
