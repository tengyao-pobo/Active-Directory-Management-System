param([switch]$Check)
$ErrorActionPreference = 'Stop'
$target = Join-Path $PSScriptRoot 'audit-enrollment-delivery-catalog.sql'
$beginMarker = '-- BEGIN generated delivery function contracts'
$endMarker = '-- END generated delivery function contracts'
$types = @{ uuid = 2950; text = 25; smallint = 21; bigint = 20; timestamptz = 1184; bytea = 17; boolean = 16 }
$catalogTypes = @{ smallint = 'int2'; bigint = 'int8'; boolean = 'bool' }
$functions = @(
    @('audit_execution_privileges', 'enrollment-execution-profile.sql', 'owner', 's', ''),
    @('audit_delivery_privileges', 'enrollment-delivery-profile.sql', 'owner', 's', 'both'),
    @('delivery_worker_scope', 'enrollment-delivery-profile.sql', 'owner', 's', ''),
    @('read_grant_status_receipt', 'enrollment-delivery-profile.sql', 'definer', 'v', 'EnrollmentGrantStatusRefresh'),
    @('append_grant_status_observation', 'enrollment-delivery-profile.sql', 'definer', 'v', 'EnrollmentGrantStatusRefresh'),
    @('read_grant_delivery', 'enrollment-delivery-profile.sql', 'definer', 'v', 'EnrollmentGrantDelivery'),
    @('acknowledge_grant_delivery', 'enrollment-delivery-profile.sql', 'definer', 'v', 'EnrollmentGrantDelivery')
)
function Read-Fields([string]$value) {
    if ([string]::IsNullOrWhiteSpace($value)) { return }
    foreach ($field in $value.Split(',')) {
        $match = [regex]::Match($field.Trim(), '^(?<name>[a-z_][a-z_0-9]*)\s+(?<type>uuid|text|smallint|bigint|timestamptz|bytea|boolean)$')
        if (-not $match.Success) { throw "Unsupported function field: $field" }
        [pscustomobject]@{ Name = $match.Groups['name'].Value; Type = $match.Groups['type'].Value }
    }
}
$rows = foreach ($function in $functions) {
    $source = [IO.File]::ReadAllText((Join-Path $PSScriptRoot $function[1]))
    $pattern = 'CREATE(?: OR REPLACE)? FUNCTION enrollment_execution\.' + $function[0] +
        '\((?<args>.*?)\)\s+RETURNS\s+(?:TABLE\((?<outs>.*?)\)|(?<scalar>boolean))\s+LANGUAGE\s+' +
        '(?<header>(?:(?!\$function\$;|CREATE(?: OR REPLACE)? FUNCTION).)*?)AS \$function\$(?<body>.*?)\$function\$;'
    $sourceMatches = [regex]::Matches($source, $pattern, [Text.RegularExpressions.RegexOptions]::Singleline)
    if ($sourceMatches.Count -ne 1) { throw "Expected one source definition: $($function[0])" }
    $match = $sourceMatches[0]
    $volatility = if ($function[3] -eq 's') { 'STABLE' } else { 'VOLATILE' }
    $header = [regex]::Replace($match.Groups['header'].Value, '\s+', ' ').Trim()
    $expectedHeader = "plpgsql $volatility PARALLEL UNSAFE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on"
    if ($header -cne $expectedHeader) { throw "Unexpected function header: $($function[0])" }
    $arguments = @(Read-Fields $match.Groups['args'].Value)
    $outputs = @(Read-Fields $match.Groups['outs'].Value)
    if (($function[0] -eq 'delivery_worker_scope') -ne ($outputs.Count -eq 0)) {
        throw "Unexpected function return form: $($function[0])"
    }
    $signature = 'enrollment_execution.' + $function[0] + '(' + (($arguments | ForEach-Object {
        'pg_catalog.' + $(if ($catalogTypes.ContainsKey($_.Type)) { $catalogTypes[$_.Type] } else { $_.Type })
    }) -join ',') + ')'
    $inputTypes = ($arguments | ForEach-Object { $types[$_.Type] }) -join ' '
    $names = 'ARRAY[' + ((@($arguments) + @($outputs) | ForEach-Object { "'$($_.Name)'" }) -join ',') + ']::text[]'
    if ($outputs.Count) {
        $allTypes = 'ARRAY[' + ((@($arguments) + @($outputs) | ForEach-Object { $types[$_.Type] }) -join ',') + ']::oid[]'
        $modes = 'ARRAY[' + ((@($arguments | ForEach-Object { "'i'" }) + @($outputs | ForEach-Object { "'t'" })) -join ',') + ']::"char"[]'
        $returnType = 2249
        $returnsSet = 'true'
    } else {
        $allTypes = 'NULL::oid[]'
        $modes = 'NULL::"char"[]'
        $returnType = $types[$match.Groups['scalar'].Value]
        $returnsSet = 'false'
    }
    $body = [regex]::Replace($match.Groups['body'].Value, '\s+', ' ').Trim()
    $hash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($body))).ToLowerInvariant()
    " ('$signature','$($function[2])','$($function[3])','$($function[4])','$hash','$inputTypes',$allTypes,$names,$modes,${returnType}::oid,$returnsSet)"
}
$replacement = $beginMarker + "`n" + ($rows -join ",`n") + "`n" + $endMarker
$current = [IO.File]::ReadAllText($target).Replace("`r`n", "`n")
foreach ($marker in @($beginMarker, $endMarker)) {
    if ([regex]::Matches($current, [regex]::Escape($marker)).Count -ne 1) { throw 'Nonunique contract marker' }
}
$begin = $current.IndexOf($beginMarker, [StringComparison]::Ordinal)
$end = $current.IndexOf($endMarker, [StringComparison]::Ordinal) + $endMarker.Length
if ($end -le $begin) { throw 'Invalid contract marker order' }
$updated = $current.Substring(0, $begin) + $replacement + $current.Substring($end)
if ($Check) {
    if ($updated -cne $current) { throw 'Delivery function contracts are stale; regenerate and review the source changes.' }
} else { [IO.File]::WriteAllText($target, $updated) }
