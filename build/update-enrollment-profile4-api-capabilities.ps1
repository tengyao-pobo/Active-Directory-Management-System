param([switch]$Check)
$ErrorActionPreference='Stop'
$encoding=[Text.UTF8Encoding]::new($false)
$types=@{ uuid=2950; 'uuid[]'=2951; text=25; smallint=21; integer=23; bigint=20; timestamptz=1184; bytea=17; boolean=16; void=2278 }
$contracts=@(
 @{Name='public.lock_enrollment_grant_plan_context'; Group='plan'; File='../src/Infrastructure/Persistence/Migrations/20260911214940_EnrollmentGrantPlans.cs'; Header='plpgsql SECURITY DEFINER VOLATILE PARALLEL UNSAFE SET search_path=pg_catalog,pg_temp'},
 @{Name='enrollment_execution.worker_scope'; Group='execution'; File='enrollment-execution-functions.sql'; Header='plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog,pg_temp'},
 @{Name='enrollment_execution.queue_worker_scope'; Group='queue'; File='enrollment-execution-queue.sql'; Header='plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog,pg_temp'}
)
foreach($name in @('read_execution_record','read_and_lock_plan_context','authorize_and_store_candidate','record_execution_result','quarantine_execution')) {
 $contracts+=@{Name="enrollment_execution.$name";Group='execution';File='enrollment-execution-functions.sql';Header='plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on'}
}
foreach($name in @('claim_next','defer_claim','complete_claim')) {
 $contracts+=@{Name="enrollment_execution.$name";Group='queue';File='enrollment-execution-queue.sql';Header='plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on'}
}
foreach($name in @('read_grant_status_receipt','append_grant_status_observation','read_grant_delivery','acknowledge_grant_delivery')) {
 $contracts+=@{Name="enrollment_execution.$name";Group='delivery';File='enrollment-delivery-profile.sql';Header='plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on'}
}
function Fields([string]$text){
 if([string]::IsNullOrWhiteSpace($text)){return}
 foreach($field in $text.Split(',')){
  $match=[regex]::Match($field.Trim(),'^(?<name>[a-z_][a-z_0-9]*)\s+(?<type>uuid\[\]|uuid|text|smallint|integer|bigint|timestamptz|bytea|boolean)$')
  if(-not $match.Success){throw "Unexpected field: $field"}
  [pscustomobject]@{Name=$match.Groups['name'].Value;Type=$match.Groups['type'].Value}
 }
}
$rows=foreach($contract in $contracts){
 $source=[IO.File]::ReadAllText((Join-Path $PSScriptRoot $contract.File)).Replace("`r`n","`n")
 if($contract.Group -eq 'plan'){
  $literals=@([regex]::Matches($source,'migrationBuilder\.Sql\("""\n(?<literal>.*?)\n(?<indent> *)"""\);','Singleline') | Where-Object {$_.Groups['literal'].Value.Contains('CREATE FUNCTION '+$contract.Name)})
  if($literals.Count -ne 1){throw 'Expected one plan-lock SQL literal.'}
  $indent=$literals[0].Groups['indent'].Value
  $source=(@(foreach($line in $literals[0].Groups['literal'].Value.Split("`n")){
   if($line.Length -eq 0){''}elseif($line.StartsWith($indent,[StringComparison]::Ordinal)){$line.Substring($indent.Length)}else{throw 'Unexpected migration indentation.'}
  }) -join "`n")
 }
 $pattern='CREATE(?: OR REPLACE)? FUNCTION '+[regex]::Escape($contract.Name)+'\((?<args>[^)]*)\)\s+RETURNS\s+(?:TABLE\s*\((?<outs>[^)]*)\)|(?<scalar>boolean|void))\s+LANGUAGE\s+(?<header>.*?)AS \$function\$(?<body>.*?)\$function\$;'
 $matches=[regex]::Matches($source,$pattern,'Singleline')
 if($matches.Count -ne 1){throw "Expected one capability source: $($contract.Name)"}
 $match=$matches[0]
 if([regex]::Replace($match.Groups['header'].Value,'\s+',' ').Trim() -cne $contract.Header){throw "Unexpected capability header: $($contract.Name)"}
 $arguments=@(Fields $match.Groups['args'].Value); $outputs=@(Fields $match.Groups['outs'].Value)
 $signature=$contract.Name+'('+(($arguments | ForEach-Object {$_.Type}) -join ',')+')'
 $inputTypes=($arguments | ForEach-Object {$types[$_.Type]}) -join ' '
 $names='ARRAY['+((@($arguments)+@($outputs) | ForEach-Object {"'$($_.Name)'"}) -join ',')+']::text[]'
 if($outputs.Count){
  $all='ARRAY['+((@($arguments)+@($outputs) | ForEach-Object {$types[$_.Type]}) -join ',')+']::oid[]'
  $modes='ARRAY['+((@($arguments | ForEach-Object {"'i'"})+@($outputs | ForEach-Object {"'t'"})) -join ',')+']::"char"[]'
  $return=2249;$set='true'
 }else{$all='NULL::oid[]';$modes='NULL::"char"[]';$return=$types[$match.Groups['scalar'].Value];$set='false'}
 $scope=$contract.Name.EndsWith('worker_scope',[StringComparison]::Ordinal)
 $volatility=if($scope){'s'}else{'v'}
 $definer=if($scope){'false'}else{'true'}
 $config="ARRAY['search_path=pg_catalog, pg_temp'"
 if($contract.Group -ne 'plan' -and -not $scope){$config+=",'row_security=on'"}
 $config+=']::text[]'
 $hash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($encoding.GetBytes($match.Groups['body'].Value))).ToLowerInvariant()
 $acl=if($scope){'owner'}elseif($contract.Group -eq 'plan'){'api'}else{'runtime'}
 " ('$signature','$($contract.Group)','$volatility',$definer,$set,${return}::oid,'$inputTypes',$names,$all,$modes,$config,'$hash','$acl')"
}
$path=Join-Path $PSScriptRoot 'audit-enrollment-profile4-api-capabilities.sql'
$source=[IO.File]::ReadAllText($path).Replace("`r`n","`n")
$pattern='-- BEGIN generated API capability functions\n.*?\n-- END generated API capability functions'
if([regex]::Matches($source,$pattern,'Singleline').Count -ne 1){throw 'Expected one capability contract block.'}
$updated=[regex]::Replace($source,$pattern,('-- BEGIN generated API capability functions'+"`n"+($rows -join ",`n")+"`n"+'-- END generated API capability functions'),'Singleline')
if($Check){if($source -cne $updated){throw 'API capability-function catalog is stale.'}}
else{[IO.File]::WriteAllText($path,$updated,$encoding)}
