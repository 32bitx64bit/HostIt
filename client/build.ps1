# Build HostIt tunnel agent (Windows / PowerShell)
# Produces: .\bin\tunnel-agent.exe

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

New-Item -ItemType Directory -Force -Path (Join-Path $root 'bin') | Out-Null

# Optional:
#   $env:GOOS='windows'
#   $env:GOARCH='amd64'

& go build -trimpath -ldflags "-s -w" -o (Join-Path $root 'bin\tunnel-agent.exe') ./cmd/agent
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "Built: bin\tunnel-agent.exe"
