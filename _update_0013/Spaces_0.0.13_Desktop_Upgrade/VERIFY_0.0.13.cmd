@echo off
setlocal EnableExtensions
set "APP=%USERPROFILE%\OneDrive\Documents\SpacesApp"
cd /d "%APP%"

echo.
echo ============================================================
echo   Verify Spaces 0.0.13
 echo ============================================================
echo.

node -e "const fs=require('fs'); const p=require('./package.json'); const t=JSON.parse(fs.readFileSync('src-tauri/tauri.conf.json','utf8')); if(p.version!=='0.0.13'||t.version!=='0.0.13'){console.error('[ERROR] Version mismatch',p.version,t.version);process.exit(1)} console.log('[OK] package.json + tauri.conf.json = 0.0.13')"
if errorlevel 1 goto :fail

if not exist "src\components\ChannelPermissionsEditor.tsx" (
  echo [ERROR] ChannelPermissionsEditor.tsx is missing.
  goto :fail
)
if not exist "src\components\SpacesLogo.tsx" (
  echo [ERROR] SpacesLogo.tsx is missing.
  goto :fail
)
if not exist "src-tauri\icons\icon-transparent.png" (
  echo [ERROR] Transparent building logo asset is missing.
  goto :fail
)

echo [OK] Required 0.0.13 files are present.

echo.
echo [1/2] TypeScript...
call npm.cmd run typecheck
if errorlevel 1 goto :fail

echo.
echo [2/2] Production frontend build...
call npm.cmd run build
if errorlevel 1 goto :fail

echo.
echo ============================================================
echo   Spaces 0.0.13 verification PASSED.
echo ============================================================
pause
exit /b 0

:fail
echo.
echo [ERROR] Verification failed. Do not build/publish the installer yet.
pause
exit /b 1
