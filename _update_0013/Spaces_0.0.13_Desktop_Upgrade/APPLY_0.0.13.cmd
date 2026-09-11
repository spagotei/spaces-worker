@echo off
setlocal EnableExtensions

set "APP=%USERPROFILE%\OneDrive\Documents\SpacesApp"
set "BACKEND=%USERPROFILE%\OneDrive\Documents\spaces"
set "HERE=%~dp0"

if not exist "%APP%\package.json" (
  echo [ERROR] SpacesApp was not found at:
  echo %APP%
  pause
  exit /b 1
)

if not exist "%BACKEND%\src\worker.js" (
  echo [ERROR] Spaces backend was not found at:
  echo %BACKEND%
  pause
  exit /b 1
)

set "BACKUP=%APP%\_backup_before_0.0.13"
if not exist "%BACKUP%" mkdir "%BACKUP%"

if not exist "%BACKUP%\src" xcopy "%APP%\src" "%BACKUP%\src\" /E /I /Y >nul
if exist "%APP%\package.json" copy /Y "%APP%\package.json" "%BACKUP%\package.json" >nul
if exist "%APP%\src-tauri\tauri.conf.json" copy /Y "%APP%\src-tauri\tauri.conf.json" "%BACKUP%\tauri.conf.json" >nul

robocopy "%HERE%PATCH\src" "%APP%\src" /E /NFL /NDL /NJH /NJS /NP >nul
if errorlevel 8 (
  echo [ERROR] Could not copy the 0.0.13 app source.
  pause
  exit /b 1
)

robocopy "%HERE%PATCH\src-tauri\icons" "%APP%\src-tauri\icons" /E /NFL /NDL /NJH /NJS /NP >nul
if errorlevel 8 (
  echo [ERROR] Could not copy the new Spaces icon assets.
  pause
  exit /b 1
)

copy /Y "%HERE%PATCH\public\icon-128.png" "%APP%\public\icon-128.png" >nul
copy /Y "%HERE%PATCH\public\icon-256.png" "%APP%\public\icon-256.png" >nul
copy /Y "%HERE%CHANGELOG_0.0.13.txt" "%APP%\CHANGELOG_0.0.13.txt" >nul

pushd "%APP%"
node -e "const fs=require('fs'); const p=JSON.parse(fs.readFileSync('package.json','utf8')); p.version='0.0.13'; fs.writeFileSync('package.json',JSON.stringify(p,null,2)+'\n'); if(fs.existsSync('package-lock.json')){const l=JSON.parse(fs.readFileSync('package-lock.json','utf8')); l.version='0.0.13'; if(l.packages&&l.packages['']) l.packages[''].version='0.0.13'; fs.writeFileSync('package-lock.json',JSON.stringify(l,null,2)+'\n')} const t=JSON.parse(fs.readFileSync('src-tauri/tauri.conf.json','utf8')); t.version='0.0.13'; fs.writeFileSync('src-tauri/tauri.conf.json',JSON.stringify(t,null,2)+'\n');"
if errorlevel 1 (
  popd
  echo [ERROR] Could not update Spaces version metadata.
  pause
  exit /b 1
)
popd

copy /Y "%BACKEND%\src\worker.js" "%BACKEND%\src\worker.before-0.0.13.js" >nul
copy /Y "%HERE%BACKEND\src\worker.js" "%BACKEND%\src\worker.js" >nul
copy /Y "%HERE%BACKEND\migrations\0013_channel_permission_overwrites.sql" "%BACKEND%\migrations\0013_channel_permission_overwrites.sql" >nul

if not exist "%BACKEND%\release-notes" mkdir "%BACKEND%\release-notes"
copy /Y "%HERE%CHANGELOG_0.0.13.txt" "%BACKEND%\release-notes\0.0.13.txt" >nul

echo.
echo ============================================================
echo   Spaces 0.0.13 files applied.
echo ============================================================
echo.
echo Existing Tauri updater configuration was preserved.
echo Next run: DEPLOY_BACKEND_0.0.13.cmd
pause
