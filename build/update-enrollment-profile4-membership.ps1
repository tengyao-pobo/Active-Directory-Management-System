param([switch]$Check)
$ErrorActionPreference='Stop'
$encoding=[Text.UTF8Encoding]::new($false)
$newline=[string][char]10
function Read-Source([string]$name){[IO.File]::ReadAllText((Join-Path $PSScriptRoot $name)).Replace(([string][char]13+[char]10),$newline)}
$source=Read-Source 'enrollment-profile4-membership.sql'
$bodies=[regex]::Matches($source,'AS \$function\$(?<body>.*?)\$function\$;',[Text.RegularExpressions.RegexOptions]::Singleline)
if($bodies.Count -ne 1){throw 'Expected one membership helper body.'}
$hash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($encoding.GetBytes($bodies[0].Groups['body'].Value))).ToLowerInvariant()
$metadata=Read-Source 'audit-enrollment-profile4-membership.sql'
$pattern="'[0-9a-f]{64}' -- generated membership helper SHA-256"
if([regex]::Matches($metadata,$pattern).Count -ne 1){throw 'Expected one membership body pin.'}
$updated=[regex]::Replace($metadata,$pattern,"'$hash' -- generated membership helper SHA-256")
if($Check){if($updated -cne $metadata){throw 'Membership helper metadata is stale.'}}
else{[IO.File]::WriteAllText((Join-Path $PSScriptRoot 'audit-enrollment-profile4-membership.sql'),$updated,$encoding)}
