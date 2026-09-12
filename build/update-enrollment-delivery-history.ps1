param([switch]$Check)
$ErrorActionPreference = 'Stop'
$path = Join-Path $PSScriptRoot 'audit-enrollment-delivery-history.sql'
$original = [IO.File]::ReadAllText($path).Replace("`r`n","`n")
$profile = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'enrollment-execution-profile.sql'))
$sourceMatches = [regex]::Matches($profile,'CREATE OR REPLACE FUNCTION enrollment_execution\.audit_execution_privileges\(p_environment uuid\).*?AS \$function\$(?<body>.*?)\$function\$;', [Text.RegularExpressions.RegexOptions]::Singleline)
if ($sourceMatches.Count -ne 1) { throw 'Expected one canonical base audit source.' }
$body = [regex]::Replace($sourceMatches[0].Groups['body'].Value,'\s+',' ').Trim()
$hash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($body))).ToLowerInvariant()
$rows = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'audit-enrollment-delivery-history-rows.sql'))
$start = $rows.IndexOf('WITH ',[StringComparison]::Ordinal)
if ($start -lt 0) { throw 'Missing history row query.' }
$query = $rows.Substring($start).Trim().TrimEnd(';')
$updated = $original
foreach ($part in @(
    @{ Name='history audit hash'; Indent='    '; Content="    expected_audit_hash constant text := '$hash';" },
    @{ Name='history row rules'; Indent='      '; Content="      valid := (`n$query`n      );" }
)) {
    $begin = $part.Indent + '-- BEGIN generated ' + $part.Name
    $end = $part.Indent + '-- END generated ' + $part.Name
    if ([regex]::Matches($updated,[regex]::Escape($begin)).Count -ne 1 -or [regex]::Matches($updated,[regex]::Escape($end)).Count -ne 1) { throw 'Nonunique history markers.' }
    $start = $updated.IndexOf($begin,[StringComparison]::Ordinal)
    $finish = $updated.IndexOf($end,[StringComparison]::Ordinal)
    if ($finish -le $start) { throw 'Invalid history marker order.' }
    $updated = $updated.Substring(0,$start) + $begin + "`n" + $part.Content + "`n" + $end + $updated.Substring($finish+$end.Length)
}
if ($Check) {
    if ($updated -cne $original) { throw 'History audit is stale; regenerate and review.' }
} else { [IO.File]::WriteAllText($path,$updated,[Text.UTF8Encoding]::new($false)) }
