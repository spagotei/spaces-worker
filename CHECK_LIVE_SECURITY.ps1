$ErrorActionPreference = 'Stop'
$health = Invoke-RestMethod -Uri 'https://spaces.spagotei.workers.dev/health' -Method Get -TimeoutSec 20
$health | Select-Object ok,service,apiVersion,verifiedEmail,authenticator2fa,recoveryCodes,emailService,emailSenderConfigured | Format-List
