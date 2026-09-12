param([switch]$Check)
$ErrorActionPreference = 'Stop'
$profilePath = Join-Path $PSScriptRoot 'enrollment-execution-profile.sql'
$profile = [IO.File]::ReadAllText($profilePath)
$original = $profile
$replacements = [ordered]@{
    ":'expected_table_owner_role'" = 'pg_catalog.pg_get_userbyid(table_owner)'
    ":'execution_definer_role'" = 'pg_catalog.pg_get_userbyid(definer)'
    ":'delivery_definer_role'" = 'pg_catalog.pg_get_userbyid(delivery_definer)'
    ":'enrollment_plan_lock_owner_role'" = "(SELECT pg_catalog.pg_get_userbyid(plan_helper.proowner) FROM pg_catalog.pg_proc plan_helper WHERE plan_helper.oid=pg_catalog.to_regprocedure('public.lock_enrollment_grant_plan_context(uuid,uuid,uuid[])'))"
}
$groups = @(
    @{ Name='delivery catalog slices'; Files=@('audit-enrollment-delivery-bindings.sql','audit-enrollment-delivery-identity.sql','audit-owner-mapping-guard.sql') },
    @{ Name='delivery definer catalog'; Files=@('audit-enrollment-delivery-definer.sql') },
    @{ Name='delivery status structure catalog'; Files=@('audit-enrollment-delivery-status.sql') },
    @{ Name='delivery stop structure catalog'; Files=@('audit-enrollment-delivery-stops.sql') },
    @{ Name='delivery envelope structure catalog'; Files=@('audit-enrollment-delivery-envelopes.sql') },
    @{ Name='delivery ack structure catalog'; Files=@('audit-enrollment-delivery-acks.sql') },
    @{ Name='delivery result structure catalog'; Files=@('audit-enrollment-delivery-results.sql') },
    @{ Name='delivery permit structure catalog'; Files=@('audit-enrollment-delivery-permits.sql') }
)
foreach ($group in $groups) {
    $begin = '    -- BEGIN generated ' + $group.Name
    $end = '    -- END generated ' + $group.Name
    $parts = foreach ($file in $group.Files) {
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
    $profile = $profile.Substring(0,$start) + $generated + $profile.Substring($finish+$end.Length)
}
if ($Check) {
    if ($profile.Replace("`r`n","`n") -cne $original.Replace("`r`n","`n")) { throw 'Delivery catalog slices are stale; run this script without -Check.' }
} else {
    [IO.File]::WriteAllText($profilePath,$profile,[Text.UTF8Encoding]::new($false))
}
