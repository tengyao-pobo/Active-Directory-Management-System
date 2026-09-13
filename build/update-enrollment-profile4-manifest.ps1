param([switch]$Check)
$ErrorActionPreference = 'Stop'
# These independent source roots must never embed the manifest or generated ready function.
# The manifest supplements live catalog attestation; it does not replace it.
$names = @(
 'audit-enrollment-delivery-acks.sql',
 'audit-enrollment-delivery-envelopes.sql',
 'audit-enrollment-delivery-history-rows.sql',
 'audit-enrollment-delivery-permits.sql',
 'audit-enrollment-delivery-results.sql',
 'audit-enrollment-delivery-status.sql',
 'audit-enrollment-delivery-stops.sql',
 'enrollment-profile4-readiness.sql'
)
$encoding = [Text.UTF8Encoding]::new($false)
$lines = [Collections.Generic.List[string]]::new()
foreach ($name in $names) {
 $source = [IO.File]::ReadAllText((Join-Path $PSScriptRoot $name)).Replace("`r`n","`n")
 $digest = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($encoding.GetBytes($source))).ToLowerInvariant()
 $lines.Add($name + "`n" + $digest + "`n")
}
$manifest = 'enrollment-profile4-attestation-v1' + "`n" + ($lines -join '')
$hash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($encoding.GetBytes($manifest))).ToLowerInvariant()
$path = Join-Path $PSScriptRoot 'enrollment-profile4-ready.sql'
$original = [IO.File]::ReadAllText($path).Replace("`r`n","`n")
$pattern = '(?m)^    expected_manifest constant bytea := decode\(''[0-9a-f]{64}'',''hex''\);$'
if ([regex]::Matches($original,$pattern).Count -ne 1) { throw 'Expected one generated manifest constant.' }
$updated = [regex]::Replace($original,$pattern,"    expected_manifest constant bytea := decode('$hash','hex');")
if ($Check) {
 if ($updated -cne $original) { throw 'Readiness manifest is stale; regenerate and review.' }
} else { [IO.File]::WriteAllText($path,$updated,$encoding) }
