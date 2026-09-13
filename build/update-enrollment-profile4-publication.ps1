param([switch]$Check)
$ErrorActionPreference='Stop'
$encoding=[Text.UTF8Encoding]::new($false)
$newline=[string][char]10
function Read-Source([string]$name){[IO.File]::ReadAllText((Join-Path $PSScriptRoot $name)).Replace(([string][char]13+[char]10),$newline)}
function Body-Hash([string]$source){
 $matchesBody=[regex]::Matches($source,'AS \$function\$(?<body>.*?)\$function\$;',[Text.RegularExpressions.RegexOptions]::Singleline)
 if($matchesBody.Count -ne 1){throw 'Expected one function body.'}
 [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($encoding.GetBytes($matchesBody[0].Groups['body'].Value))).ToLowerInvariant()
}
$template=Read-Source 'enrollment-profile4-publication.template.sql'
$placeholder='__RUNTIME_AUDIT_SHA256__'
if([regex]::Matches($template,[regex]::Escape($placeholder)).Count -ne 1){throw 'Expected one publication runtime hash placeholder.'}
$runtimeHash=Body-Hash (Read-Source 'enrollment-profile4-runtime-audit.sql')
$rendered=$template.Replace($placeholder,$runtimeHash)
$metadata=Read-Source 'audit-enrollment-profile4-publication-metadata.sql'
$start=$metadata.IndexOf('WITH ',[StringComparison]::Ordinal)
if($start -lt 0){throw 'Missing publication metadata query.'}
$query=$metadata.Substring($start).Trim().TrimEnd(';')
$guardHash=Body-Hash $rendered
$catalog='-- Unconsumed exact rendered publication guard attestation for history and external composition.'+$newline+
 'SELECT ('+$newline+$query+$newline+') AND EXISTS(SELECT 1 FROM pg_catalog.pg_proc p'+$newline+
 " WHERE p.oid=pg_catalog.to_regprocedure('enrollment_execution.guard_profile4_publication()')"+$newline+
 " AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(pg_catalog.replace(p.prosrc,E'\r\n',E'\n'),'UTF8')),'hex')='$guardHash') AS is_valid;"+$newline
foreach($item in @(@('enrollment-profile4-publication.sql',$rendered),@('audit-enrollment-profile4-publication.sql',$catalog))){
 $path=Join-Path $PSScriptRoot $item[0]
 if($Check){if(-not [IO.File]::Exists($path) -or (Read-Source $item[0]) -cne $item[1]){throw "Stale generated publication artifact: $($item[0])"}}
 else{[IO.File]::WriteAllText($path,$item[1],$encoding)}
}
