param([switch]$Check)
$ErrorActionPreference='Stop'
$encoding=[Text.UTF8Encoding]::new($false)
$profile=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'enrollment-execution-profile.sql')).Replace("`r`n","`n")
$matchesSource=[regex]::Matches($profile,'CREATE OR REPLACE FUNCTION enrollment_execution\.audit_execution_privileges\(p_environment uuid\)(?<header>.*?)AS \$function\$(?<body>.*?)\$function\$;',[Text.RegularExpressions.RegexOptions]::Singleline)
if($matchesSource.Count -ne 1){throw 'Expected one source execution audit.'}
$header=$matchesSource[0].Groups['header'].Value.Replace('SECURITY DEFINER','SECURITY INVOKER')
$body=$matchesSource[0].Groups['body'].Value
$deliveryContract="('enrollment_execution.audit_delivery_privileges(pg_catalog.uuid)',table_owner,'plpgsql','s',true,true,"
if([regex]::Matches($body,[regex]::Escape($deliveryContract)).Count -ne 1){throw 'Expected one delivery audit volatility contract.'}
$body=$body.Replace($deliveryContract,$deliveryContract.Replace("'s'","'v'"))
$helperConfiguration="AND p.proconfig IS NOT DISTINCT FROM ARRAY['search_path=pg_catalog, pg_temp','row_security=off']"
if([regex]::Matches($body,[regex]::Escape($helperConfiguration)).Count -ne 1){throw 'Expected one public helper configuration contract.'}
$body=$body.Replace($helperConfiguration,"AND p.proconfig IS NOT DISTINCT FROM ARRAY['search_path=pg_catalog, pg_temp',CASE WHEN p.proname='has_environment_membership' THEN 'row_security=on' ELSE 'row_security=off' END]")
$end='    RETURN QUERY SELECT COALESCE(ok,false),CASE WHEN COALESCE(ok,false) THEN ''None'' ELSE ''ProfileDrift'' END,4::smallint;'
if([regex]::Matches($body,[regex]::Escape($end)).Count -ne 1){throw 'Expected one final structure verdict.'}
$blocks=[Collections.Generic.List[string]]::new()
foreach($file in @('audit-enrollment-profile4-readiness-structure.sql','audit-enrollment-profile4-readiness-functions.sql','audit-enrollment-profile4-runtime-metadata.sql','audit-enrollment-profile4-membership.sql','audit-enrollment-profile4-publication-metadata.sql')){
 $source=[IO.File]::ReadAllText((Join-Path $PSScriptRoot $file)).Replace("`r`n","`n")
 $start=$source.IndexOf('WITH ',[StringComparison]::Ordinal)
 if($start -lt 0){throw 'Missing readiness catalog query.'}
 $query=$source.Substring($start).Trim().TrimEnd(';')
 $placeholder=":'expected_table_owner_role'"
 if([regex]::Matches($query,[regex]::Escape($placeholder)).Count -ne 1){throw 'Expected one owner placeholder.'}
 $query=$query.Replace($placeholder,'(SELECT rolname FROM pg_catalog.pg_roles WHERE oid=table_owner)')
 $blocks.Add("    -- BEGIN generated $file`n    ok := ok AND (`n$query`n    );`n    -- END generated $file`n")
}
$body=$body.Replace($end,($blocks -join "`n")+"`n"+$end)
$structure="-- Unconsumed generated maintenance audit; owner-only INVOKER, with no readiness-state bypass in the ordinary audit.`nCREATE FUNCTION enrollment_execution.audit_execution_profile_structure(p_environment uuid)"+$header+'AS $function$'+$body+'$function$;'+"`nREVOKE ALL ON FUNCTION enrollment_execution.audit_execution_profile_structure(uuid) FROM PUBLIC;`n"
$structurePath=Join-Path $PSScriptRoot 'enrollment-profile4-structure-audit.sql'
$hash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($encoding.GetBytes($body))).ToLowerInvariant()
$runtimePath=Join-Path $PSScriptRoot 'enrollment-profile4-runtime-audit.sql'
$runtime=[IO.File]::ReadAllText($runtimePath).Replace("`r`n","`n")
$pattern='(?m)^    expected_structure_hash constant text := ''[0-9a-f]{64}'';$'
if([regex]::Matches($runtime,$pattern).Count -ne 1){throw 'Expected one structure hash constant.'}
$updatedRuntime=[regex]::Replace($runtime,$pattern,"    expected_structure_hash constant text := '$hash';")
if($Check){
 if(-not [IO.File]::Exists($structurePath) -or [IO.File]::ReadAllText($structurePath).Replace("`r`n","`n") -cne $structure -or $runtime -cne $updatedRuntime){throw 'Split audit candidate is stale; regenerate and review.'}
}else{
 [IO.File]::WriteAllText($structurePath,$structure,$encoding)
 [IO.File]::WriteAllText($runtimePath,$updatedRuntime,$encoding)
}
