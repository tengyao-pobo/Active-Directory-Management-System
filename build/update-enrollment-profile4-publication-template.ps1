param([switch]$Check)
$ErrorActionPreference='Stop'
$encoding=[Text.UTF8Encoding]::new($false)
$newline=[string][char]10
function Read-Source([string]$name){[IO.File]::ReadAllText((Join-Path $PSScriptRoot $name)).Replace(([string][char]13+[char]10),$newline)}
$template=Read-Source 'enrollment-profile4-publication.template.sql'
$placeholder='__RUNTIME_AUDIT_SHA256__'
if([regex]::Matches($template,[regex]::Escape($placeholder)).Count -ne 1){throw 'Expected one publication runtime hash placeholder.'}
$bodies=[regex]::Matches($template,'AS \$function\$(?<body>.*?)\$function\$;',[Text.RegularExpressions.RegexOptions]::Singleline)
if($bodies.Count -ne 1){throw 'Expected one publication template body.'}
if(-not $bodies[0].Groups['body'].Value.Contains("    expected_runtime_hash constant text := '$placeholder';")){throw 'Missing canonical hash assignment.'}
$hash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($encoding.GetBytes($bodies[0].Groups['body'].Value))).ToLowerInvariant()
$path=Join-Path $PSScriptRoot 'audit-enrollment-profile4-publication-metadata.sql'
$source=Read-Source 'audit-enrollment-profile4-publication-metadata.sql'
$pattern="'[0-9a-f]{64}' -- generated publication template SHA-256"
if([regex]::Matches($source,$pattern).Count -ne 1){throw 'Expected one template metadata hash.'}
$updated=[regex]::Replace($source,$pattern,"'$hash' -- generated publication template SHA-256")
if($Check){if($updated -cne $source){throw 'Publication template metadata is stale.'}}
else{[IO.File]::WriteAllText($path,$updated,$encoding)}
