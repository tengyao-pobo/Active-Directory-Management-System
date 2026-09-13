param([switch]$Check)
$ErrorActionPreference='Stop'
$encoding=[Text.UTF8Encoding]::new($false)
function Read-Source([string]$name){[IO.File]::ReadAllText((Join-Path $PSScriptRoot $name)).Replace("`r`n","`n")}
function One-Match([string]$source,[string]$pattern){
 $found=[regex]::Matches($source,$pattern,[Text.RegularExpressions.RegexOptions]::Singleline)
 if($found.Count -ne 1){throw 'Expected one canonical function source.'}
 $found[0]
}
$noneNames='NULL::text[]'
$noneTypes='NULL::oid[]'
$noneModes='NULL::"char"[]'
$auditNames="ARRAY['p_environment','is_valid','diagnostic_code','profile_version']::text[]"
$auditTypes='ARRAY[2950,16,25,21]::oid[]'
$auditModes='ARRAY[''i'',''t'',''t'',''t'']::"char"[]'
$contracts=@(
 @{Name='enrollment_execution.execution_store_profile'; Signature='enrollment_execution.execution_store_profile()'; File='upgrade-enrollment-execution-v3-to-v4.sql'; Kind='marker'; Language='sql'; Volatility='i'; Parallel='s'; Definer='false'; Strict='false'; Set='false'; Return=21; Types=''; Names=$noneNames; All=$noneTypes; Modes=$noneModes; Rls=''; Acl='owner'},
 @{Name='enrollment_execution.audit_execution_privileges'; Signature='enrollment_execution.audit_execution_privileges(uuid)'; File='enrollment-profile4-runtime-audit.sql'; Kind='function'; Language='plpgsql'; Volatility='v'; Parallel='u'; Definer='true'; Strict='false'; Set='true'; Return=2249; Types='2950'; Names=$auditNames; All=$auditTypes; Modes=$auditModes; Rls='on'; Acl='runtime'},
 @{Name='enrollment_execution.audit_delivery_privileges'; Signature='enrollment_execution.audit_delivery_privileges(uuid)'; File='enrollment-delivery-profile.sql'; Kind='function'; Language='plpgsql'; Volatility='v'; Parallel='u'; Definer='true'; Strict='false'; Set='true'; Return=2249; Types='2950'; Names=$auditNames; All=$auditTypes; Modes=$auditModes; Rls='on'; Acl='runtime'},
 @{Name='enrollment_execution.guard_profile4_publication'; Signature='enrollment_execution.guard_profile4_publication()'; File='enrollment-profile4-publication.sql'; Kind='function'; Language='plpgsql'; Volatility='v'; Parallel='u'; Definer='true'; Strict='false'; Set='false'; Return=2279; Types=''; Names=$noneNames; All=$noneTypes; Modes=$noneModes; Rls='on'; Acl='owner'},
 @{Name='public.api_database_session'; Signature='public.api_database_session()'; File='enrollment-delivery-identity.sql'; Kind='function'; Language='sql'; Volatility='s'; Parallel='u'; Definer='true'; Strict='false'; Set='false'; Return=16; Types=''; Names=$noneNames; All=$noneTypes; Modes=$noneModes; Rls='on'; Acl='public'},
 @{Name='public.has_environment_membership'; Signature='public.has_environment_membership(uuid,uuid)'; File='enrollment-profile4-membership.sql'; Kind='function'; Language='sql'; Volatility='s'; Parallel='u'; Definer='true'; Strict='true'; Set='false'; Return=16; Types='2950 2950'; Names="ARRAY['p_environment_id','p_principal_id']::text[]"; All=$noneTypes; Modes=$noneModes; Rls='on'; Acl='membership'},
 @{Name='public.directory_database_access'; Signature='public.directory_database_access(uuid,uuid)'; File='../src/Infrastructure/Persistence/Migrations/20260911132500_BindDirectoryDatabaseIdentity.cs'; Kind='migration'; Language='sql'; Volatility='s'; Parallel='u'; Definer='true'; Strict='false'; Set='false'; Return=16; Types='2950 2950'; Names="ARRAY['p_environment','p_principal']::text[]"; All=$noneTypes; Modes=$noneModes; Rls='off'; Acl='directory'}
)
$rows=[Collections.Generic.List[string]]::new()
foreach($contract in $contracts){
 $source=Read-Source $contract.File
 $prefix='CREATE (?:OR REPLACE )?FUNCTION '+[regex]::Escape($contract.Name)+'\(.*?\).*?'
 if($contract.Kind -eq 'migration'){
   # C# raw strings remove the closing delimiter's indentation. Verify the whole
   # literal before extracting SQL; do not use whitespace-normalized body hashes.
   $literal=One-Match $source 'migrationBuilder\.Sql\("""\n(?<literal>.*?)\n(?<indent> *)"""\);'
   $indent=$literal.Groups['indent'].Value
   $lines=$literal.Groups['literal'].Value.Split("`n")
   $dedented=foreach($line in $lines){
     if($line.Length -eq 0){''}
     elseif($line.StartsWith($indent,[StringComparison]::Ordinal)){$line.Substring($indent.Length)}
     else{throw 'Unexpected C# SQL raw-string indentation.'}
   }
   $body=(One-Match ($dedented -join "`n") ($prefix+'AS \$\$(?<body>.*?)\$\$;')).Groups['body'].Value
 }elseif($contract.Kind -eq 'marker'){
   $body=(One-Match $source ($prefix+"AS '(?<body>[^']*)';")).Groups['body'].Value
 }else{
   $body=(One-Match $source ($prefix+'AS \$function\$(?<body>.*?)\$function\$;')).Groups['body'].Value
 }
 $hash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($encoding.GetBytes($body))).ToLowerInvariant()
 $config="ARRAY['search_path=pg_catalog, pg_temp'"
 if($contract.Rls){$config+=",'row_security=$($contract.Rls)'"}
 $config+=']::text[]'
 $rows.Add(" ('$($contract.Signature)','$($contract.Language)','$($contract.Volatility)','$($contract.Parallel)',$($contract.Definer),$($contract.Strict),$($contract.Set),$($contract.Return)::oid,'$($contract.Types)',$($contract.Names),$($contract.All),$($contract.Modes),$config,'$hash','$($contract.Acl)')")
}
$name='audit-enrollment-profile4-api-functions.sql'
$source=Read-Source $name
$pattern='-- BEGIN generated API function roots\n.*?\n-- END generated API function roots'
[void](One-Match $source $pattern)
$updated=[regex]::Replace($source,$pattern,('-- BEGIN generated API function roots'+"`n"+($rows -join ",`n")+"`n"+'-- END generated API function roots'),[Text.RegularExpressions.RegexOptions]::Singleline)
if($Check){if($source -cne $updated){throw 'API function-root catalog is stale.'}}
else{[IO.File]::WriteAllText((Join-Path $PSScriptRoot $name),$updated,$encoding)}
