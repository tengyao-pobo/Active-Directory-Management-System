param([switch]$Check)
$ErrorActionPreference = 'Stop'
$target = Join-Path $PSScriptRoot 'enrollment-execution-profile.sql'
$beginMarker = '      -- BEGIN generated delivery internal functions'
$endMarker = '      -- END generated delivery internal functions'
$migrations = '../src/Infrastructure/Persistence/Migrations/'
$status = $migrations + '20260912120000_EnrollmentGrantStatusObservations.cs'
$helpers = $migrations + '20260912130000_EnrollmentGrantDeliveryHelpers.cs'
$authority = $migrations + '20260912103200_EnrollmentGrantExecutionAuthority.cs'
$journal = $migrations + '20260912090000_EnrollmentGrantExecutionJournal.cs'
$stops = $migrations + '20260912090100_EnrollmentGrantExecutionStops.cs'
$delivery = 'enrollment-delivery-profile.sql'
$invoker = 'plpgsql VOLATILE PARALLEL UNSAFE SECURITY INVOKER SET search_path=pg_catalog,pg_temp'
$definer = 'plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on'
$stable = $definer.Replace('VOLATILE','STABLE')
$functions = @(
    @('guard_status_observation',$status,'table_owner',$invoker,'plpgsql','v',$false,$false),
    @('record_status_observation',$status,'table_owner',$invoker,'plpgsql','v',$false,$false),
    @('read_status_refresh_receipt',$helpers,'table_owner',$invoker,'plpgsql','v',$false,$false),
    @('lock_delivery_context',$helpers,'table_owner',$invoker,'plpgsql','v',$false,$false),
    @('get_sealed_delivery',$helpers,'table_owner',$invoker,'plpgsql','v',$false,$false),
    @('ack_sealed_delivery',$helpers,'table_owner',$invoker,'plpgsql','v',$false,$false),
    @('delivery_worker_scope',$delivery,'table_owner',$stable,'plpgsql','s',$true,$true),
    @('read_grant_status_receipt',$delivery,'delivery_definer',$definer,'plpgsql','v',$true,$true),
    @('append_grant_status_observation',$delivery,'delivery_definer',$definer,'plpgsql','v',$true,$true),
    @('read_grant_delivery',$delivery,'delivery_definer',$definer,'plpgsql','v',$true,$true),
    @('acknowledge_grant_delivery',$delivery,'delivery_definer',$definer,'plpgsql','v',$true,$true),
    @('reject_delivery_update',$delivery,'table_owner',$definer,'plpgsql','v',$true,$true),
    @('audit_delivery_privileges',$delivery,'table_owner',$stable,'plpgsql','s',$true,$true),
    @('scope_uuid',$authority,'table_owner','plpgsql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog,pg_temp','plpgsql','i',$false,$false),
    @('has_computer_permission',$authority,'table_owner','sql STABLE SECURITY INVOKER SET search_path=pg_catalog,pg_temp','sql','s',$false,$false),
    @('reject_history_mutation',$journal,'table_owner','plpgsql SET search_path=pg_catalog,pg_temp','plpgsql','v',$false,$false),
    @('validate_journal',$journal,'table_owner','plpgsql SET search_path=pg_catalog,pg_temp','plpgsql','v',$false,$false),
    @('validate_execution_stop',$stops,'table_owner','plpgsql SET search_path=pg_catalog,pg_temp','plpgsql','v',$false,$false),
    @('lock_execution_stop_boundary',$stops,'table_owner','plpgsql SET search_path=pg_catalog,pg_temp','plpgsql','v',$false,$false)
)
$types = @{ uuid=2950; text=25; smallint=21; bigint=20; timestamptz=1184; bytea=17; boolean=16; trigger=2279 }
$catalogTypes = @{ smallint='int2'; bigint='int8'; boolean='bool' }
function Read-Fields([string]$value) {
    if ([string]::IsNullOrWhiteSpace($value)) { return }
    foreach ($field in $value.Split(',')) {
        $match = [regex]::Match($field.Trim(),'^(?<name>[a-z_][a-z_0-9]*)\s+(?<type>uuid|text|smallint|bigint|timestamptz|bytea|boolean)$')
        if (-not $match.Success) { throw "Unsupported function field: $field" }
        [pscustomobject]@{ Name=$match.Groups['name'].Value; Type=$match.Groups['type'].Value }
    }
}
$rows = foreach ($function in $functions) {
    $source = [IO.File]::ReadAllText((Join-Path $PSScriptRoot $function[1]))
    $pattern = 'CREATE(?: OR REPLACE)? FUNCTION enrollment_execution\.' + $function[0] +
        '\((?<args>[^)]*)\)\s+RETURNS\s+(?:TABLE\((?<outs>[^)]*)\)|(?<scalar>boolean|uuid|trigger))\s+LANGUAGE\s+' +
        '(?<header>(?:(?!\$function\$;|CREATE(?: OR REPLACE)? FUNCTION).)*?)AS \$function\$(?<body>.*?)\$function\$;'
    $sourceMatches = [regex]::Matches($source,$pattern,[Text.RegularExpressions.RegexOptions]::Singleline)
    if ($sourceMatches.Count -ne 1) { throw "Expected one source definition: $($function[0])" }
    $match = $sourceMatches[0]
    if ([regex]::Replace($match.Groups['header'].Value,'\s+',' ').Trim() -cne $function[3]) {
        throw "Unexpected function header: $($function[0])"
    }
    $arguments = @(Read-Fields $match.Groups['args'].Value)
    $outputs = @(Read-Fields $match.Groups['outs'].Value)
    $signature = 'enrollment_execution.' + $function[0] + '(' + (($arguments | ForEach-Object {
        'pg_catalog.' + $(if ($catalogTypes.ContainsKey($_.Type)) { $catalogTypes[$_.Type] } else { $_.Type })
    }) -join ',') + ')'
    $inputTypes = ($arguments | ForEach-Object { $types[$_.Type] }) -join ' '
    $names = if ($arguments.Count + $outputs.Count) {
        'ARRAY[' + ((@($arguments) + @($outputs) | ForEach-Object { "'$($_.Name)'" }) -join ',') + ']::text[]'
    } else { 'NULL::text[]' }
    if ($outputs.Count) {
        $allTypes = 'ARRAY[' + ((@($arguments) + @($outputs) | ForEach-Object { $types[$_.Type] }) -join ',') + ']::oid[]'
        $modes = 'ARRAY[' + ((@($arguments | ForEach-Object { "'i'" }) + @($outputs | ForEach-Object { "'t'" })) -join ',') + ']::"char"[]'
        $returnType=2249; $returnsSet='true'
    } else {
        $allTypes='NULL::oid[]'; $modes='NULL::"char"[]'
        $returnType=$types[$match.Groups['scalar'].Value]; $returnsSet='false'
    }
    $body = [regex]::Replace($match.Groups['body'].Value,'\s+',' ').Trim()
    $hash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($body))).ToLowerInvariant()
    $securityDefiner=$function[6].ToString().ToLowerInvariant(); $withRls=$function[7].ToString().ToLowerInvariant()
    "          ('$signature',$($function[2]),'$($function[4])','$($function[5])',$securityDefiner,$withRls,'$hash',$($arguments.Count),'$inputTypes',$allTypes,$names,$modes,${returnType}::oid,$returnsSet)"
}
$generated = $beginMarker + @'

      AND NOT EXISTS(
        WITH expected(signature,owner_oid,language,volatility,security_definer,with_rls,body_hash,input_count,input_types,all_types,arg_names,arg_modes,return_type,returns_set) AS (VALUES
'@ + "`n" + ($rows -join ",`n") + @'
),
        actual AS (SELECT expected.*,function_row.*,language_row.lanname
          FROM expected LEFT JOIN pg_catalog.pg_proc function_row ON function_row.oid=pg_catalog.to_regprocedure(expected.signature)
          LEFT JOIN pg_catalog.pg_language language_row ON language_row.oid=function_row.prolang)
        SELECT 1 FROM actual WHERE oid IS NULL OR proowner<>owner_oid OR lanname<>language
          OR prokind<>'f' OR prosecdef<>security_definer OR proisstrict OR proleakproof OR prosupport<>0
          OR provolatile::text<>volatility OR proparallel<>'u' OR proretset<>returns_set OR prorettype<>return_type
          OR pronargs<>input_count OR proargtypes::text<>input_types
          OR proallargtypes IS DISTINCT FROM all_types OR proargnames IS DISTINCT FROM arg_names OR proargmodes IS DISTINCT FROM arg_modes
          OR pronargdefaults<>0 OR proargdefaults IS NOT NULL OR provariadic<>0 OR probin IS NOT NULL OR prosqlbody IS NOT NULL
          OR proconfig IS DISTINCT FROM CASE WHEN with_rls THEN ARRAY['search_path=pg_catalog, pg_temp','row_security=on']
                                            ELSE ARRAY['search_path=pg_catalog, pg_temp'] END
          OR pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(pg_catalog.btrim(
               pg_catalog.regexp_replace(prosrc,'[[:space:]]+',' ','g')),'UTF8')),'hex')<>body_hash
        UNION ALL
        SELECT 1 FROM pg_catalog.pg_proc extra JOIN pg_catalog.pg_namespace ns ON ns.oid=extra.pronamespace
        WHERE ns.nspname='enrollment_execution'
          AND extra.proname IN(SELECT pg_catalog.split_part(pg_catalog.split_part(signature,'.',2),'(',1) FROM expected)
          AND NOT EXISTS(SELECT 1 FROM expected WHERE pg_catalog.to_regprocedure(signature)=extra.oid))
'@ + "`n" + $endMarker
$current = [IO.File]::ReadAllText($target).Replace("`r`n","`n")
foreach ($marker in @($beginMarker,$endMarker)) {
    if ([regex]::Matches($current,[regex]::Escape($marker)).Count -ne 1) { throw 'Nonunique internal contract marker' }
}
$begin = $current.IndexOf($beginMarker,[StringComparison]::Ordinal)
$end = $current.IndexOf($endMarker,[StringComparison]::Ordinal) + $endMarker.Length
if ($end -le $begin) { throw 'Invalid internal contract marker order' }
$updated = $current.Substring(0,$begin) + $generated + $current.Substring($end)
if ($Check) {
    if ($updated -cne $current) { throw 'Delivery internal function contracts are stale; regenerate before the outer contracts.' }
} else { [IO.File]::WriteAllText($target,$updated,[Text.UTF8Encoding]::new($false)) }
