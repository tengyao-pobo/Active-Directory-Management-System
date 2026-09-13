param([switch]$Check)
$ErrorActionPreference='Stop'
$rows=[Collections.Generic.List[string]]::new()
foreach($contract in @(
 @{ Name='guard_profile4_readiness'; File='enrollment-profile4-readiness.sql'; Volatility='v'; Definer='false'; Return=2279 },
 @{ Name='profile4_ready'; File='enrollment-profile4-ready.sql'; Volatility='s'; Definer='true'; Return=16 }
)) {
 $source=[IO.File]::ReadAllText((Join-Path $PSScriptRoot $contract.File))
 $pattern='CREATE FUNCTION enrollment_execution\.'+[regex]::Escape($contract.Name)+'\(\).*?AS \$function\$(?<body>.*?)\$function\$;'
 $sourceMatches=[regex]::Matches($source,$pattern,[Text.RegularExpressions.RegexOptions]::Singleline)
 if($sourceMatches.Count -ne 1){throw 'Expected one readiness function source.'}
 $body=$sourceMatches[0].Groups['body'].Value.Replace("`r`n","`n")
 $hash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($body))).ToLowerInvariant()
 $rows.Add(" ('enrollment_execution.$($contract.Name)()','$($contract.Volatility)',$($contract.Definer),$($contract.Return)::oid,'$hash')")
}
$path=Join-Path $PSScriptRoot 'audit-enrollment-profile4-readiness-functions.sql'
$original=[IO.File]::ReadAllText($path).Replace("`r`n","`n")
$begin='-- BEGIN generated readiness function contracts'
$end='-- END generated readiness function contracts'
if([regex]::Matches($original,[regex]::Escape($begin)).Count -ne 1 -or [regex]::Matches($original,[regex]::Escape($end)).Count -ne 1){throw 'Nonunique readiness contract markers.'}
$start=$original.IndexOf($begin,[StringComparison]::Ordinal)
$finish=$original.IndexOf($end,[StringComparison]::Ordinal)
if($finish -le $start){throw 'Invalid readiness marker order.'}
$updated=$original.Substring(0,$start)+$begin+"`n"+($rows -join ",`n")+"`n"+$original.Substring($finish)
if($Check){if($updated -cne $original){throw 'Readiness function contracts are stale; regenerate and review.'}}
else{[IO.File]::WriteAllText($path,$updated,[Text.UTF8Encoding]::new($false))}
