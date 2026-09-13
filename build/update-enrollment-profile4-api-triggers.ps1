param([switch]$Check)
$ErrorActionPreference='Stop'
$encoding=[Text.UTF8Encoding]::new($false)
$migrations='../src/Infrastructure/Persistence/Migrations/'
$contracts=@(
 @('public.guard_operator_identity',($migrations+'20260911123256_BindIsolationToMembership.cs'),$false,$false),
 @('public.reject_enrollment_grant_reservation_mutation',($migrations+'20260911214940_EnrollmentGrantPlans.cs'),$false,$true),
 @('public.reject_enrollment_grant_operation_mutation',($migrations+'20260912003114_EnrollmentGrantOperations.cs'),$false,$true),
 @('public.guard_enrollment_grant_queued_plan',($migrations+'20260912100000_EnrollmentGrantQueuedAnchors.cs'),$false,$false),
 @('public.guard_enrollment_grant_plan_child',($migrations+'20260912100000_EnrollmentGrantQueuedAnchors.cs'),$false,$false),
 @('public.guard_enrollment_grant_operation_parent',($migrations+'20260912100000_EnrollmentGrantQueuedAnchors.cs'),$false,$false),
 @('public.guard_enrollment_grant_outbox_anchor',($migrations+'20260912100000_EnrollmentGrantQueuedAnchors.cs'),$false,$false),
 @('public.validate_enrollment_grant_queue_anchor','enrollment-execution-queue.sql',$false,$false),
 @('enrollment_execution.reject_worker_update','enrollment-execution-profile.sql',$true,$false),
 @('enrollment_execution.reject_delivery_update','enrollment-delivery-profile.sql',$true,$false),
 @('enrollment_execution.validate_work_queue',($migrations+'20260912110000_EnrollmentGrantExecutionQueue.cs'),$true,$false),
 @('enrollment_execution.guard_profile4_publication','enrollment-profile4-publication.sql',$true,$false)
)
$rows=foreach($contract in $contracts){
 $source=[IO.File]::ReadAllText((Join-Path $PSScriptRoot $contract[1])).Replace("`r`n","`n")
 if($contract[1].EndsWith('.cs')){
  $literals=@([regex]::Matches($source,'migrationBuilder\.Sql\("""\n(?<literal>.*?)\n(?<indent> *)"""\);','Singleline') | Where-Object {$_.Groups['literal'].Value.Contains('CREATE FUNCTION '+$contract[0])})
  if($literals.Count -ne 1){throw 'Expected one trigger migration literal.'}
  $indent=$literals[0].Groups['indent'].Value
  $source=(@(foreach($line in $literals[0].Groups['literal'].Value.Split("`n")){
   if($line.Length -eq 0){''}elseif($line.StartsWith($indent,[StringComparison]::Ordinal)){$line.Substring($indent.Length)}else{throw 'Unexpected trigger migration indentation.'}
  }) -join "`n")
 }
 $matches=[regex]::Matches($source,'CREATE (?:OR REPLACE )?FUNCTION '+[regex]::Escape($contract[0])+'\(\) RETURNS trigger\s+.*?AS (?<delimiter>\$function\$|\$\$)(?<body>.*?)\k<delimiter>;','Singleline')
 if($matches.Count -ne 1){throw "Expected one trigger function: $($contract[0])"}
 $hash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($encoding.GetBytes($matches[0].Groups['body'].Value))).ToLowerInvariant()
 $config=if($contract[3]){"ARRAY['search_path=pg_catalog, public, pg_temp']"}elseif($contract[2]){"ARRAY['search_path=pg_catalog, pg_temp','row_security=on']"}else{"ARRAY['search_path=pg_catalog, pg_temp']"}
 if($contract[0] -eq 'public.guard_operator_identity'){$config='NULL'}
 " ('$($contract[0])',$($contract[2].ToString().ToLowerInvariant()),$config::text[],'$hash')"
}
$path=Join-Path $PSScriptRoot 'audit-enrollment-profile4-api-triggers.sql'
$source=[IO.File]::ReadAllText($path).Replace("`r`n","`n")
$pattern='-- BEGIN generated API trigger functions\n.*?\n-- END generated API trigger functions'
if([regex]::Matches($source,$pattern,'Singleline').Count -ne 1){throw 'Expected one trigger contract block.'}
$replacement='-- BEGIN generated API trigger functions'+"`n"+($rows -join ",`n")+"`n"+'-- END generated API trigger functions'
$updated=[regex]::Replace($source,$pattern,[Text.RegularExpressions.MatchEvaluator]{param($match) $replacement},'Singleline')
if($Check){if($source -cne $updated){throw 'API trigger catalog is stale.'}}else{[IO.File]::WriteAllText($path,$updated,$encoding)}
