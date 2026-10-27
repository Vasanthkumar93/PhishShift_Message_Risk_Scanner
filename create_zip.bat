@echo off
title PhishShift - Create ZIP Archive
cd /d "%~dp0"
echo ====================================================
echo   PhishShift - Packaging Project to ZIP Archive
echo ====================================================
echo.

where python >nul 2>nul
if %errorlevel% equ 0 (
    python package_to_zip.py
) else (
    echo Python not found in PATH, using PowerShell Compress-Archive...
    powershell -NoProfile -Command "Compress-Archive -Path '%~dp0*' -DestinationPath '%~dp0phishshift_project.zip' -Force"
    echo [OK] phishshift_project.zip generated successfully!
)

echo.
echo ====================================================
echo  ZIP ready at: %~dp0phishshift_project.zip
echo ====================================================
pause
