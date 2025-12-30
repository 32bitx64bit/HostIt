# Build HostIt tunnel agent (Windows / PowerShell)
# Produces: .\bin\tunnel-agent.exe

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$outDir = Join-Path $root 'bin'
$outBin = Join-Path $outDir 'tunnel-agent.exe'
$pkg = './cmd/agent'

function Log([string]$Message) {
	$ts = Get-Date -Format 'HH:mm:ss'
	Write-Host "$ts $Message"
}

if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
	throw 'go not found in PATH'
}

Push-Location $root
try {
	Log 'HostIt agent build starting'
	Log "Dir: $root"
	Log ("Go: " + (& go version))
	Log ("Env: GOOS=$env:GOOS GOARCH=$env:GOARCH CGO_ENABLED=$env:CGO_ENABLED")
	Log "Output: $outBin"
	Log "Package: $pkg"

	New-Item -ItemType Directory -Force -Path $outDir | Out-Null

# Optional:
#   $env:GOOS='windows'
#   $env:GOARCH='amd64'

	Log 'Building…'
	& go build -v -trimpath -ldflags "-s -w" -o $outBin $pkg
	if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

	Log "Built: $outBin"
	if (Test-Path $outBin) {
		Get-Item $outBin | Select-Object FullName, Length, LastWriteTime | Format-List
	}
	Log "✅ Build finished"
}
finally {
	Pop-Location
}
