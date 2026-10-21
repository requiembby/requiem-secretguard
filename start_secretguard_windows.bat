@echo off
cd /d "%~dp0"
title REQUIEM SecretGuard - Local Dashboard
python -m secretguard.web
if errorlevel 1 (
  echo.
  echo Could not start SecretGuard. Check Python installation and the README.
)
pause
