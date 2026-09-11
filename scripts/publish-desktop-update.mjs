import {existsSync, readFileSync, writeFileSync, unlinkSync} from 'node:fs'
import { homedir, tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { spawnSync } from 'node:child_process'

const backendRoot = resolve(process.cwd())
const defaultAppRoot = resolve(backendRoot, '..', 'SpacesApp')
const appRoot = process.env.SPACES_APP_DIR || defaultAppRoot
const bucket = process.env.SPACES_RELEASE_BUCKET || 'spaces-desktop-releases'
const workerOrigin = (process.env.SPACES_WORKER_ORIGIN || 'https://spaces.spagotei.workers.dev').replace(/\/+$/u, '')

function fail(message) {
  console.error(`\n[ERROR] ${message}`)
  process.exit(1)
}

function runWrangler(args) {
  // Avoid Windows .cmd/shell quoting entirely. Running Wrangler's JS entrypoint
  // with the current Node executable preserves each argument exactly as one argv.
  const wranglerBin = join(
    backendRoot,
    'node_modules',
    'wrangler',
    'bin',
    'wrangler.js',
  )

  if (!existsSync(wranglerBin)) {
    fail(
      `Wrangler CLI was not found at ${wranglerBin}. Run npm.cmd install in ${backendRoot} first.`,
    )
  }

  const result = spawnSync(
    process.execPath,
    [wranglerBin, ...args],
    {
      cwd: backendRoot,
      stdio: 'inherit',
      shell: false,
    },
  )

  if (result.error) {
    fail(`Could not start Wrangler: ${result.error.message}`)
  }

  if (result.status !== 0) {
    fail(`Wrangler exited with code ${result.status ?? 'unknown'}.`)
  }
}

const packagePath = join(appRoot, 'package.json')
if (!existsSync(packagePath)) fail(`SpacesApp package.json not found: ${packagePath}`)
const appPackage = JSON.parse(readFileSync(packagePath, 'utf8'))
const version = String(appPackage.version ?? '').trim()
if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/u.test(version)) fail(`Invalid Spaces version: ${version}`)

const nsisDir = join(appRoot, 'src-tauri', 'target', 'release', 'bundle', 'nsis')
const fileName = `Spaces_${version}_x64-setup.exe`
const installerPath = join(nsisDir, fileName)
const signaturePath = `${installerPath}.sig`

if (!existsSync(installerPath)) fail(`Signed NSIS installer not found: ${installerPath}`)
if (!existsSync(signaturePath)) fail(`Updater signature not found: ${signaturePath}`)

const signature = readFileSync(signaturePath, 'utf8').trim()
if (!signature) fail('Updater signature file is empty.')

const noteCandidates = [
  join(backendRoot, 'release-notes', `${version}.txt`),
  join(appRoot, `CHANGELOG_${version}.txt`),
]
const notePath = noteCandidates.find(existsSync)
const notes = notePath
  ? readFileSync(notePath, 'utf8').trim()
  : `Spaces ${version}`

const artifactKey = `desktop/${version}/windows/x86_64/${fileName}`
const manifest = {
  schema: 1,
  version,
  notes,
  pub_date: new Date().toISOString(),
  platforms: {
    'windows-x86_64': {
      artifactKey,
      signature,
      fileName,
    },
  },
}

const manifestPath = join(tmpdir(), `spaces-desktop-latest-${process.pid}.json`)
writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`)

console.log(`\nPublishing Spaces ${version} desktop update...`)
console.log(`Installer: ${installerPath}`)
console.log(`Signature: ${signaturePath}`)
console.log(`Bucket: ${bucket}`)

runWrangler([
  'r2', 'object', 'put', `${bucket}/${artifactKey}`,
  '--file', installerPath,
  '--content-type', 'application/octet-stream',
  '--content-disposition', `attachment; filename=${fileName}`,
  '--cache-control', 'public, max-age=31536000, immutable',
  '--remote', '--force',
])

// Publish the manifest LAST. This makes the release atomic: clients cannot see
// the new version until its installer is already available in R2.
runWrangler([
  'r2', 'object', 'put', `${bucket}/desktop/latest.json`,
  '--file', manifestPath,
  '--content-type', 'application/json; charset=utf-8',
  '--cache-control', 'no-store, max-age=0',
  '--remote', '--force',
])

try { unlinkSync(manifestPath) } catch {}

const previousVersion = process.env.SPACES_PREVIOUS_VERSION || '0.0.11'
const checkUrl = `${workerOrigin}/v1/desktop/update/windows/x86_64/${encodeURIComponent(previousVersion)}`
console.log(`\nVerifying updater endpoint against ${previousVersion}...`)

try {
  const response = await fetch(checkUrl, { headers: { Accept: 'application/json' } })
  if (!response.ok) fail(`Updater endpoint verification failed with HTTP ${response.status}.`)
  const body = await response.json()
  if (body.version !== version) fail(`Updater endpoint returned ${body.version ?? 'no version'} instead of ${version}.`)
  if (String(body.signature ?? '').trim() !== signature) fail('Updater endpoint signature does not match the generated .sig file.')
  if (!String(body.url ?? '').includes(`/v1/desktop/releases/${version}/windows/x86_64`)) fail('Updater endpoint returned an unexpected download URL.')
  console.log(`[OK] Updater endpoint advertises Spaces ${version}.`)
  console.log(`[OK] Signed installer URL: ${body.url}`)
  console.log('[OK] Signature matches the local Tauri .sig file.')
  console.log('\nYour installed previous version can now discover this release.')
} catch (caught) {
  fail(caught instanceof Error ? caught.message : String(caught))
}
