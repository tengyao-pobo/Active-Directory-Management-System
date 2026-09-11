param([string]$Configuration = 'Release')
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$dotnet = Join-Path $root '.tools\dotnet\dotnet.exe'
if (-not (Test-Path -LiteralPath $dotnet)) { $dotnet = 'dotnet' }
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
Push-Location $root
try {
    & $dotnet restore ITManagement.slnx --locked-mode
    if ($LASTEXITCODE -ne 0) { throw 'Restore failed' }
    & $dotnet build ITManagement.slnx -c $Configuration --no-restore
    if ($LASTEXITCODE -ne 0) { throw 'Build failed' }
    # Database fixtures change shared role/schema catalogs; serialize projects, not concurrency tests inside them.
    & $dotnet test ITManagement.slnx -m:1 -c $Configuration --no-build --logger trx
    if ($LASTEXITCODE -ne 0) { throw 'Tests failed' }
} finally { Pop-Location }
