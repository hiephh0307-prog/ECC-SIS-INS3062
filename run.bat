@echo off
setlocal EnableExtensions
chcp 65001 >nul 2>&1
title ECC-SIS - INS306202 One-Click Launcher

cd /d "%~dp0"

if not exist "scripts\start-sis.ps1" (
    echo [ERROR] Missing scripts\start-sis.ps1 in folder.
    pause
    exit /b 1
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Get-ChildItem -LiteralPath '.\scripts' -Filter '*.ps1' -Force -ErrorAction SilentlyContinue | Unblock-File -ErrorAction SilentlyContinue" >nul 2>&1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\scripts\start-sis.ps1" %*
set "EXIT_CODE=%ERRORLEVEL%"

if not "%EXIT_CODE%"=="0" (
    echo.
    echo [ECC-SIS] Process exited with code %EXIT_CODE%.
    pause
)

exit /b %EXIT_CODE%
