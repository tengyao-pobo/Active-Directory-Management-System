param([switch]$Check)
$ErrorActionPreference='Stop'
$encoding=[Text.UTF8Encoding]::new($false)
$types=@{uuid=2950;bytea=17;boolean=16;bigint=20;'timestamp with time zone'=1184;'character varying(64)'=1043}
$rows=[Collections.Generic.List[string]]::new()
foreach($contract in @(
 @{Table='EnrollmentGrantOperations';File='../src/Infrastructure/Persistence/Migrations/20260912003114_EnrollmentGrantOperations.cs'},
 @{Table='EnrollmentGrantRecipientReservations';File='../src/Infrastructure/Persistence/Migrations/20260911214940_EnrollmentGrantPlans.cs'},
 @{Table='Memberships';File='../src/Infrastructure/Persistence/Migrations/20260911122339_InitialIdentityAndAccess.cs'}
)){
 $source=[IO.File]::ReadAllText((Join-Path $PSScriptRoot $contract.File))
 $matches=[regex]::Matches($source,'migrationBuilder\.CreateTable\(\s*name: "'+$contract.Table+'",\s*columns: table => new\s*\{(?<columns>.*?)\}\s*,\s*constraints:','Singleline')
 if($matches.Count -ne 1){throw 'Expected one table source.'}
 $columns=[regex]::Matches($matches[0].Groups['columns'].Value,'(?<name>\w+) = table\.Column<[^>]+>\(type: "(?<type>[^"]+)"(?:, maxLength: 64)?, nullable: false\)')
 if($columns.Count -eq 0 -or [regex]::Matches($matches[0].Groups['columns'].Value,'table\.Column').Count -ne $columns.Count){throw 'Unexpected column source.'}
 $position=0
 foreach($column in $columns){
  $position++;$type=$column.Groups['type'].Value
  if(-not $types.ContainsKey($type)){throw 'Unknown column type.'}
  $modifier=if($type -eq 'character varying(64)'){68}else{-1}
  $collation=if($type -eq 'character varying(64)'){'pg_catalog.to_regcollation(''pg_catalog."default"'')::oid'}else{'0::oid'}
  $rows.Add(" ('$($contract.Table)',$position,'$($column.Groups['name'].Value)',$($types[$type])::oid,$modifier,$collation)")
 }
}
$legacy=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'audit-enrollment-grant-operations.sql')).Replace("`r`n","`n")
$constraints=[regex]::Matches($legacy,'expected_constraints\(definition\) AS \(VALUES\n(?<rows>.*?)\),\nactual_constraints','Singleline')
if($constraints.Count -ne 1){throw 'Expected one canonical Operations constraint block.'}
$constraintRows=$constraints[0].Groups['rows'].Value.Replace('REFERENCES "','REFERENCES public."')
$path=Join-Path $PSScriptRoot 'audit-enrollment-profile4-api-relations.sql'
$source=[IO.File]::ReadAllText($path).Replace("`r`n","`n")
$updated=$source
foreach($block in @(@{Name='API relation columns';Text=$rows -join ",`n"},@{Name='API operation constraints';Text=$constraintRows})){
 $pattern='-- BEGIN generated '+$block.Name+'\n.*?\n-- END generated '+$block.Name
 if([regex]::Matches($updated,$pattern,'Singleline').Count -ne 1){throw 'Expected one relation contract block.'}
 $replacement='-- BEGIN generated '+$block.Name+"`n"+$block.Text+"`n"+'-- END generated '+$block.Name
 $updated=[regex]::Replace($updated,$pattern,[Text.RegularExpressions.MatchEvaluator]{param($match) $replacement},'Singleline')
}
if($Check){if($source -cne $updated){throw 'API relation catalog is stale.'}}
else{[IO.File]::WriteAllText($path,$updated,$encoding)}
