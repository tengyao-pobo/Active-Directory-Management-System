param([string]$Configuration = 'Release')
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$dotnet = Join-Path $root '.tools\dotnet\dotnet.exe'
if (-not (Test-Path -LiteralPath $dotnet)) { $dotnet = 'dotnet' }
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
Push-Location $root
try {
    & (Join-Path $PSScriptRoot 'update-enrollment-delivery-catalog-slices.ps1') -Check
    & (Join-Path $PSScriptRoot 'update-enrollment-delivery-internal-functions.ps1') -Check
    & (Join-Path $PSScriptRoot 'update-enrollment-delivery-catalog-functions.ps1') -Check
    & (Join-Path $PSScriptRoot 'update-enrollment-delivery-history.ps1') -Check
    & (Join-Path $PSScriptRoot 'update-enrollment-profile4-manifest.ps1') -Check
    & (Join-Path $PSScriptRoot 'update-enrollment-profile4-function-contracts.ps1') -Check
    & (Join-Path $PSScriptRoot 'update-enrollment-profile4-membership.ps1') -Check
    & (Join-Path $PSScriptRoot 'update-enrollment-profile4-publication-template.ps1') -Check
    & (Join-Path $PSScriptRoot 'update-enrollment-profile4-audit-split.ps1') -Check
    & (Join-Path $PSScriptRoot 'update-enrollment-profile4-publication.ps1') -Check
    & (Join-Path $PSScriptRoot 'update-enrollment-profile4-history-transition.ps1') -Check
    & (Join-Path $PSScriptRoot 'update-enrollment-profile4-api-functions.ps1') -Check
    & (Join-Path $PSScriptRoot 'update-enrollment-profile4-api-capabilities.ps1') -Check
    & (Join-Path $PSScriptRoot 'update-enrollment-profile4-api-relations.ps1') -Check
    & $dotnet restore ITManagement.slnx --locked-mode
    if ($LASTEXITCODE -ne 0) { throw 'Restore failed' }
    & $dotnet build ITManagement.slnx -c $Configuration --no-restore
    if ($LASTEXITCODE -ne 0) { throw 'Build failed' }
    # Database fixtures change shared role/schema catalogs; serialize projects, not concurrency tests inside them.
    & $dotnet test ITManagement.slnx -m:1 -c $Configuration --no-build --logger trx
    if ($LASTEXITCODE -ne 0) { throw 'Tests failed' }
} finally { Pop-Location }
