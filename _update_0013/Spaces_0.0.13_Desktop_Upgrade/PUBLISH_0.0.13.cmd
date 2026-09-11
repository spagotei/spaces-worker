@echo off
setlocal EnableExtensions
set "BACKEND=%USERPROFILE%\OneDrive\Documents\spaces"
set "APP=%USERPROFILE%\OneDrive\Documents\SpacesApp"

if not exist "%BACKEND%\scripts\publish-desktop-update.mjs" (
  echo [ERROR] The working R2 updater publisher is not installed.
  echo Keep the updater backend you already set up for 0.0.12.
  pause
  exit /b 1
)

if not exist "%APP%\src-tauri\target\release\bundle\nsis\Spaces_0.0.13_x64-setup.exe" (
  echo [ERROR] Signed 0.0.13 NSIS installer was not found.
  echo Build it first with npm.cmd run desktop:build and your existing updater signing key.
  pause
  exit /b 1
)

cd /d "%BACKEND%"
set "SPACES_PREVIOUS_VERSION=0.0.12"
node scripts\publish-desktop-update.mjs
if errorlevel 1 (
  pause
  exit /b 1
)

echo.
echo ============================================================
echo   Spaces 0.0.13 published to the updater.
echo ============================================================
echo Keep 0.0.12 installed to test the purple update arrow.
pause
