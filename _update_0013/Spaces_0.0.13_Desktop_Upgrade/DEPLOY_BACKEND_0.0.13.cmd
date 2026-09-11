@echo off
setlocal EnableExtensions
set "BACKEND=%USERPROFILE%\OneDrive\Documents\spaces"

if not exist "%BACKEND%\migrations\0013_channel_permission_overwrites.sql" (
  echo [ERROR] 0013 migration is missing. Run APPLY_0.0.13.cmd first.
  pause
  exit /b 1
)

cd /d "%BACKEND%"

echo.
echo ============================================================
echo   Spaces 0.0.13 backend deployment
 echo ============================================================
echo.

echo [1/2] Applying pending D1 migrations...
call npx.cmd wrangler d1 migrations apply scrounge-spaces --remote
if errorlevel 1 (
  echo [ERROR] D1 migration failed. Worker was not deployed.
  pause
  exit /b 1
)

echo.
echo [2/2] Deploying the Spaces Worker...
call npm.cmd run deploy
if errorlevel 1 (
  echo [ERROR] Worker deployment failed.
  pause
  exit /b 1
)

echo.
echo ============================================================
echo   Backend 0.0.13 support is live.
echo ============================================================
pause
