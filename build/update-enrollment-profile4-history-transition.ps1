param([switch]$Check)
$ErrorActionPreference='Stop'
$encoding=[Text.UTF8Encoding]::new($false)
$nl=[string][char]10
function Read-Source([string]$name){[IO.File]::ReadAllText((Join-Path $PSScriptRoot $name)).Replace(([string][char]13+[char]10),[string][char]10)}
function Get-BodyHash([string]$name){
 $source=Read-Source $name
 $bodyMatches=[regex]::Matches($source,'AS \$function\$(?<body>.*?)\$function\$;',[Text.RegularExpressions.RegexOptions]::Singleline)
 if($bodyMatches.Count -ne 1){throw 'Expected one audit body.'}
 [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($encoding.GetBytes($bodyMatches[0].Groups['body'].Value))).ToLowerInvariant()
}
$source=Read-Source 'audit-enrollment-delivery-history.sql'
$ownerContext='AND role.rolname=CURRENT_USER AND role.rolname=SESSION_USER AND role.rolcanlogin AND NOT role.rolsuper AND NOT role.rolbypassrls;'
if([regex]::Matches($source,[regex]::Escape($ownerContext)).Count -ne 1){throw 'Expected one owner context.'}
$source=$source.Replace($ownerContext,@'
AND role.rolname=CURRENT_USER AND role.rolname=SESSION_USER AND role.rolcanlogin
      AND NOT(role.rolsuper OR role.rolbypassrls OR role.rolcreatedb OR role.rolcreaterole OR role.rolinherit OR role.rolreplication)
      AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members membership WHERE membership.member=role.oid OR membership.roleid=role.oid);
'@)
$maintenanceHash=Get-BodyHash 'enrollment-profile4-structure-audit.sql'
$runtimeHash=Get-BodyHash 'enrollment-profile4-runtime-audit.sql'
$manifestMatches=[regex]::Matches((Read-Source 'enrollment-profile4-ready.sql'),"expected_manifest constant bytea := decode\('(?<hash>[0-9a-f]{64})','hex'\);")
if($manifestMatches.Count -ne 1){throw 'Expected one manifest.'}
$manifest=$manifestMatches[0].Groups['hash'].Value
$pinMatches=[regex]::Matches($source,'    IF NOT EXISTS\(SELECT 1 FROM pg_catalog\.pg_proc function_row JOIN pg_catalog\.pg_language language_row.*?\n    END IF;',[Text.RegularExpressions.RegexOptions]::Singleline)
if($pinMatches.Count -ne 1){throw 'Expected one original audit pin.'}
$pin=$pinMatches[0].Value
$rawPin=$pin.Replace("pg_catalog.btrim(pg_catalog.regexp_replace(function_row.prosrc,'[[:space:]]+',' ','g'))","pg_catalog.replace(function_row.prosrc,E'\r\n',E'\n')")
$maintenancePin=$rawPin.Replace('audit_execution_privileges','audit_execution_profile_structure').Replace("AND function_row.prokind='f' AND function_row.prosecdef","AND function_row.prokind='f' AND NOT function_row.prosecdef")
$maintenancePin=$maintenancePin.Replace('=expected_audit_hash)',@'
=expected_audit_hash
        AND (SELECT count(*)=1 AND bool_and(acl.grantor=owner_oid AND acl.grantee=owner_oid
          AND acl.privilege_type='EXECUTE' AND NOT acl.is_grantable)
          FROM pg_catalog.aclexplode(COALESCE(function_row.proacl,pg_catalog.acldefault('f',function_row.proowner))) acl))
'@)
$runtimePin=$rawPin.Replace('expected_audit_hash','expected_runtime_audit_hash').Replace('History audit function contract is invalid.','History ordinary audit function contract is invalid.')
$source=$source.Replace($pin,$maintenancePin+$nl+'    -- Ordinary ACL is attested transitively by maintenance before any ordinary call.'+$nl+$runtimePin)
$source=$source.Replace('FROM enrollment_execution.audit_execution_privileges(binding.environment_id) result','FROM enrollment_execution.audit_execution_profile_structure(binding.environment_id) result')
$source=[regex]::Replace($source,"expected_audit_hash constant text := '[0-9a-f]{64}';","expected_audit_hash constant text := '$maintenanceHash';")
$source=$source.Replace('    owner_oid oid;',("    expected_runtime_audit_hash constant text := '$runtimeHash';"+$nl+"    expected_manifest constant bytea := decode('$manifest','hex');"+$nl+'    expected_input record;'+$nl+'    installed_state record;'+$nl+'    owner_oid oid;'))
$afterMaintenance=@'
      IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class relation
        WHERE relation.oid=pg_catalog.to_regclass('pg_temp.profile4_history_expected')
          AND relation.relnamespace=pg_catalog.pg_my_temp_schema() AND relation.relowner=owner_oid
          AND relation.relkind='r' AND relation.relpersistence='t' AND NOT relation.relispartition
          AND NOT relation.relrowsecurity AND NOT relation.relforcerowsecurity
          AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_inherits inheritance WHERE inheritance.inhrelid=relation.oid OR inheritance.inhparent=relation.oid)
          AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_rewrite rewrite WHERE rewrite.ev_class=relation.oid)) THEN
        RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='History expected input carrier is invalid.';
      END IF;
      SELECT * INTO STRICT expected_input FROM pg_temp.profile4_history_expected;
      SELECT * INTO STRICT installed_state FROM enrollment_execution.profile4_readiness FOR UPDATE;
      IF (expected_input.singleton IS TRUE AND expected_input.generation>0
          AND expected_input.installation_nonce<>'00000000-0000-0000-0000-000000000000'::uuid
          AND expected_input.attestation_manifest_sha256=expected_manifest
          AND installed_state.singleton IS TRUE AND installed_state.profile_version=4
          AND installed_state.state='PendingHistoryAudit' AND installed_state.generation=expected_input.generation
          AND installed_state.installation_nonce=expected_input.installation_nonce
          AND installed_state.attestation_manifest_sha256=expected_manifest
          AND isfinite(installed_state.pending_at) AND installed_state.ready_at IS NULL AND installed_state.ready_by IS NULL) IS NOT TRUE THEN
        RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='History pending installation tuple does not match.';
      END IF;
      FOR binding IN SELECT "EnvironmentId" environment_id FROM public."DirectoryDatabaseBindings" WHERE "Purpose"='EnrollmentGrantExecution'
      LOOP
        SELECT count(*),bool_and(result.is_valid IS FALSE AND result.diagnostic_code='ProfileDrift' AND result.profile_version=4)
          INTO row_count,valid FROM enrollment_execution.audit_execution_privileges(binding.environment_id) result;
        IF row_count<>1 OR valid IS DISTINCT FROM true THEN
          RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='History pending runtime gate is not closed.';
        END IF;
      END LOOP;
'@
$marker='      IF pass=2 THEN EXIT; END IF;'
if([regex]::Matches($source,[regex]::Escape($marker)).Count -ne 1){throw 'Expected one maintenance stage marker.'}
$source=$source.Replace($marker,$marker+$nl+$afterMaintenance)
$transition=@'
    UPDATE enrollment_execution.profile4_readiness SET state='Ready',ready_at=statement_timestamp(),ready_by=SESSION_USER
      WHERE singleton AND profile_version=4 AND state='PendingHistoryAudit'
        AND generation=expected_input.generation AND installation_nonce=expected_input.installation_nonce
        AND attestation_manifest_sha256=expected_manifest AND pending_at=installed_state.pending_at
        AND ready_at IS NULL AND ready_by IS NULL;
    GET DIAGNOSTICS row_count=ROW_COUNT;
    IF row_count<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='History ready transition did not match one installation.'; END IF;
    -- Separate statement: STABLE audit must see this transaction's preceding Ready update.
    FOR binding IN SELECT "EnvironmentId" environment_id FROM public."DirectoryDatabaseBindings" WHERE "Purpose"='EnrollmentGrantExecution'
    LOOP
      SELECT count(*),bool_and(result.is_valid IS TRUE AND result.diagnostic_code='None' AND result.profile_version=4)
        INTO row_count,valid FROM enrollment_execution.audit_execution_privileges(binding.environment_id) result;
      IF row_count<>1 OR valid IS DISTINCT FROM true THEN
        RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='History final runtime audit failed.';
      END IF;
    END LOOP;
'@
$footer='END'+$nl+'$delivery_history_audit$;'
if([regex]::Matches($source,[regex]::Escape($footer)).Count -ne 1){throw 'Expected one history footer.'}
$source=$source.Replace($footer,$transition+$nl+$footer)
$source='-- Generated UNCONSUMED transition candidate. Only activate-enrollment-profile4-candidate.sql is a supported entrypoint; direct DO execution is unsupported.'+$nl+$source
$path=Join-Path $PSScriptRoot 'audit-enrollment-profile4-history-transition.sql'
if($Check){if(-not [IO.File]::Exists($path) -or (Read-Source 'audit-enrollment-profile4-history-transition.sql') -cne $source){throw 'History transition candidate is stale; regenerate and review.'}}
else{[IO.File]::WriteAllText($path,$source,$encoding)}
