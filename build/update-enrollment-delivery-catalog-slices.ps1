param([switch]$Check)
$ErrorActionPreference = 'Stop'
$profilePath = Join-Path $PSScriptRoot 'enrollment-execution-profile.sql'
$profile = [IO.File]::ReadAllText($profilePath)
$begin = '    -- BEGIN generated delivery catalog slices'
$end = '    -- END generated delivery catalog slices'
$replacements = [ordered]@{
    ":'expected_table_owner_role'" = 'pg_catalog.pg_get_userbyid(table_owner)'
    ":'execution_definer_role'" = 'pg_catalog.pg_get_userbyid(definer)'
    ":'delivery_definer_role'" = 'pg_catalog.pg_get_userbyid(delivery_definer)'
    ":'enrollment_plan_lock_owner_role'" = "(SELECT pg_catalog.pg_get_userbyid(plan_helper.proowner) FROM pg_catalog.pg_proc plan_helper WHERE plan_helper.oid=pg_catalog.to_regprocedure('public.lock_enrollment_grant_plan_context(uuid,uuid,uuid[])'))"
}
$parts = foreach ($file in @('audit-enrollment-delivery-bindings.sql','audit-enrollment-delivery-identity.sql')) {
    $source = [IO.File]::ReadAllText((Join-Path $PSScriptRoot $file))
    $start = $source.IndexOf('WITH ', [StringComparison]::Ordinal)
    if ($start -lt 0) { throw "Missing catalog query in $file" }
    $query = $source.Substring($start).Trim().TrimEnd(';')
    foreach ($entry in $replacements.GetEnumerator()) { $query = $query.Replace($entry.Key,$entry.Value) }
    "    -- Source: $file`n    ok := ok AND (`n$query`n    );"
}
$generated = $begin + "`n" + ($parts -join "`n") + "`n" + $end
$start = $profile.IndexOf($begin, [StringComparison]::Ordinal)
$finish = $profile.IndexOf($end, [StringComparison]::Ordinal)
if ($start -lt 0 -or $finish -le $start) { throw 'Missing generated catalog markers' }
if ($profile.IndexOf($begin,$start+$begin.Length,[StringComparison]::Ordinal) -ge 0 -or
    $profile.IndexOf($end,$finish+$end.Length,[StringComparison]::Ordinal) -ge 0) { throw 'Duplicate generated catalog markers' }
$updated = $profile.Substring(0,$start) + $generated + $profile.Substring($finish+$end.Length)
if ($Check) {
    if ($updated.Replace("`r`n","`n") -cne $profile.Replace("`r`n","`n")) { throw 'Delivery catalog slices are stale; run this script without -Check.' }
} else {
    [IO.File]::WriteAllText($profilePath,$updated,[Text.UTF8Encoding]::new($false))
}
