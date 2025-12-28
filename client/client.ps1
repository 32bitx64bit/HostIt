# HostIt tunnel agent launcher (Windows / PowerShell)
# Mirrors ./client.sh behavior.

$ErrorActionPreference = 'Stop'

# Always run from this script's directory so relative CONFIG paths are stable.
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

# Optional overrides via environment variables
# WEB: bind address for the agent dashboard (default: 127.0.0.1:7003)
# CONFIG: agent config json path (default: agent.json)
# SERVER/TOKEN: if set, overrides config and can autostart

$web = if ($env:WEB -and $env:WEB.Trim()) { $env:WEB } else { '127.0.0.1:7003' }
$config = if ($env:CONFIG -and $env:CONFIG.Trim()) { $env:CONFIG } else { 'agent.json' }

if (-not [System.IO.Path]::IsPathRooted($config)) {
  $config = Join-Path $root $config
}

$argsList = @('-web', $web, '-config', $config)

$exe = Join-Path $root 'bin\tunnel-agent.exe'

if ($env:SERVER -and $env:SERVER.Trim()) {
  $argsList += @('-server', $env:SERVER)
}

if ($env:TOKEN -and $env:TOKEN.Trim()) {
  $argsList += @('-token', $env:TOKEN)
  # With an explicit token, we can autostart.
  if (Test-Path $exe) {
    & $exe @argsList
  } else {
    & go run ./cmd/agent @argsList
  }
  exit $LASTEXITCODE
}

# No token provided; run UI-only mode.
if (Test-Path $exe) {
  & $exe @argsList -autostart=false
} else {
  & go run ./cmd/agent @argsList -autostart=false
}
exit $LASTEXITCODE
