SPACES 0.0.13 — DESKTOP UPGRADE
================================

This package is intentionally a PATCH, not a full replacement project.
It preserves your existing Tauri updater configuration/signing setup and only
replaces the app source/assets that changed.

1) APPLY THE FRONTEND + BACKEND FILES
-------------------------------------
Run:
  APPLY_0.0.13.cmd

The script targets:
  C:\Users\ldc-c\OneDrive\Documents\SpacesApp
  C:\Users\ldc-c\OneDrive\Documents\spaces

It preserves the current src-tauri\tauri.conf.json contents and only changes
its version to 0.0.13, so the updater endpoint/public key you already proved
working are not overwritten.

2) APPLY THE NEW D1 MIGRATION + DEPLOY WORKER
---------------------------------------------
Run:
  DEPLOY_BACKEND_0.0.13.cmd

Remote migration history was already repaired through 0012, so this applies
only the new 0013_channel_permission_overwrites.sql migration and deploys the
updated Worker.

3) VERIFY THE APP
-----------------
Run:
  VERIFY_0.0.13.cmd

This runs npm typecheck + Vite production build and verifies that package.json
and tauri.conf.json both report 0.0.13.

4) BUILD THE SIGNED WINDOWS RELEASE
-----------------------------------
From PowerShell in SpacesApp, set your existing updater key environment vars
(the same real key/password you used successfully for 0.0.12), then run:

  npm.cmd run desktop:build

Do NOT regenerate your signing key.

Expected files:
  src-tauri\target\release\bundle\nsis\Spaces_0.0.13_x64-setup.exe
  src-tauri\target\release\bundle\nsis\Spaces_0.0.13_x64-setup.exe.sig

5) PUBLISH THROUGH THE WORKING R2 UPDATER
-----------------------------------------
Keep 0.0.12 installed while testing the updater, then run:
  PUBLISH_0.0.13.cmd

That reuses the publisher already installed at:
  C:\Users\ldc-c\OneDrive\Documents\spaces\scripts\publish-desktop-update.mjs

It sets the previous version to 0.0.12, uploads the signed 0.0.13 installer,
publishes desktop/latest.json last, and verifies the live Worker response.

For this release the update check is manual: a newer build should show the
purple download arrow in the custom titlebar. Clicking it opens the Spaces
update panel; the check itself does not call downloadAndInstall().
