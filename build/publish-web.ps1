$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
Push-Location (Join-Path $root 'src\Web')
try {
    pnpm install --frozen-lockfile
    if ($LASTEXITCODE -ne 0) { throw 'Frontend restore failed' }
    pnpm build
    if ($LASTEXITCODE -ne 0) { throw 'Frontend build failed' }
    $destination = Join-Path $root 'src\Server\Api\wwwroot'
    New-Item -ItemType Directory -Force -Path $destination | Out-Null
    # Fingerprinted assets can coexist until release deployment removes obsolete files.
    Copy-Item -Path '.\dist\*' -Destination $destination -Recurse -Force
} finally { Pop-Location }
