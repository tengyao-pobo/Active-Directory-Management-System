-- Generated UNCONSUMED transition candidate. Only activate-enrollment-profile4-candidate.sql is a supported entrypoint; direct DO execution is unsupported.
-- Unconsumed activation-time audit. Requires reviewed maintenance downtime/lock timeout.
-- One DO statement owns temporary policy creation, history validation and cleanup.
-- Never call from per-request audits or turn off FORCE RLS.
DO $delivery_history_audit$
DECLARE
    -- BEGIN generated history audit hash
    expected_audit_hash constant text := '6b623e8e062c5278d4705a0407de5da972066db2477010e7c997d838992c8814';
    -- END generated history audit hash
    canonical_operation_policy constant text := $policy$((("EnvironmentId")::text = current_setting('app.environment_id'::text, true)) AND ("RequesterId" = (NULLIF(current_setting('app.principal_id'::text, true), ''::text))::uuid) AND public.has_environment_membership("EnvironmentId", (NULLIF(current_setting('app.principal_id'::text, true), ''::text))::uuid))$policy$;
    expected_runtime_audit_hash constant text := '6bfa71bb3eb83232a9838e07238c057ac2062d62620ca4229110847fb1933853';
    expected_manifest constant bytea := decode('2f5386a0255f2b859393ceccc8edc8e36097d6a86ba401f4977eaf98d3e82579','hex');
    expected_input record;
    installed_state record;
    owner_oid oid;
    owner_name name;
    history_tables oid[];
    binding record;
    target record;
    audited integer;
    row_count bigint;
    valid boolean;
    pass integer;
BEGIN
    PERFORM pg_catalog.pg_advisory_xact_lock(1162235478,1);
    LOCK TABLE enrollment_execution.delivery_acks,enrollment_execution.execution_stops,
      enrollment_execution.issue_results,enrollment_execution.mint_permits,enrollment_execution.sealed_envelopes,
      enrollment_execution.status_observations,public."DirectoryDatabaseBindings",public."EnrollmentGrantOperations",
      public."Environments" IN ACCESS EXCLUSIVE MODE;
    SELECT relation.relowner INTO owner_oid FROM pg_catalog.pg_class relation
      WHERE relation.oid=pg_catalog.to_regclass('public."Environments"') AND relation.relkind='r' AND relation.relpersistence='p';
    SELECT role.rolname INTO owner_name FROM pg_catalog.pg_roles role WHERE role.oid=owner_oid
      AND role.rolname=CURRENT_USER AND role.rolname=SESSION_USER AND role.rolcanlogin
      AND NOT(role.rolsuper OR role.rolbypassrls OR role.rolcreatedb OR role.rolcreaterole OR role.rolinherit OR role.rolreplication)
      AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members membership WHERE membership.member=role.oid OR membership.roleid=role.oid);
    IF owner_name IS NULL OR pg_catalog.current_setting('row_security')<>'on'
      OR pg_catalog.current_setting('session_replication_role')<>'origin'
      OR pg_catalog.current_setting('search_path') NOT IN('pg_catalog,pg_temp','pg_catalog, pg_temp') THEN
      RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='History audit owner context is invalid.';
    END IF;
    history_tables:=ARRAY[pg_catalog.to_regclass('enrollment_execution.delivery_acks')::oid,
      pg_catalog.to_regclass('enrollment_execution.execution_stops')::oid,pg_catalog.to_regclass('enrollment_execution.issue_results')::oid,
      pg_catalog.to_regclass('enrollment_execution.mint_permits')::oid,pg_catalog.to_regclass('enrollment_execution.sealed_envelopes')::oid,
      pg_catalog.to_regclass('enrollment_execution.status_observations')::oid,pg_catalog.to_regclass('public."EnrollmentGrantOperations"')::oid];
    IF (SELECT count(*)=7 AND count(DISTINCT relation.oid)=7 AND bool_and(relation.relowner=owner_oid
        AND relation.relkind='r' AND relation.relpersistence='p' AND NOT relation.relispartition
        AND relation.relrowsecurity AND relation.relforcerowsecurity)
      FROM pg_catalog.pg_class relation WHERE relation.oid=ANY(history_tables)) IS NOT TRUE
      OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class relation
        WHERE relation.oid=pg_catalog.to_regclass('public."DirectoryDatabaseBindings"') AND relation.relowner=owner_oid
          AND relation.relkind='r' AND relation.relpersistence='p' AND NOT relation.relispartition
          AND NOT relation.relrowsecurity AND NOT relation.relforcerowsecurity) THEN
      RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='History audit relation context is invalid.';
    END IF;
    IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc function_row JOIN pg_catalog.pg_language language_row ON language_row.oid=function_row.prolang
      WHERE function_row.oid=pg_catalog.to_regprocedure('enrollment_execution.audit_execution_profile_structure(pg_catalog.uuid)')
        AND function_row.proowner=owner_oid AND language_row.lanname='plpgsql' AND function_row.prokind='f' AND NOT function_row.prosecdef
        AND function_row.provolatile='s' AND function_row.proparallel='u' AND NOT function_row.proisstrict AND NOT function_row.proleakproof
        AND function_row.prosupport=0 AND function_row.proretset AND function_row.prorettype=2249 AND function_row.pronargs=1
        AND function_row.proargtypes::text='2950' AND function_row.proallargtypes IS NOT DISTINCT FROM ARRAY[2950,16,25,21]::oid[]
        AND function_row.proargnames IS NOT DISTINCT FROM ARRAY['p_environment','is_valid','diagnostic_code','profile_version']::text[]
        AND function_row.proargmodes IS NOT DISTINCT FROM ARRAY['i','t','t','t']::"char"[]
        AND function_row.pronargdefaults=0 AND function_row.proargdefaults IS NULL AND function_row.provariadic=0
        AND function_row.protrftypes IS NULL AND function_row.probin IS NULL AND function_row.prosqlbody IS NULL
        AND function_row.proconfig IS NOT DISTINCT FROM ARRAY['search_path=pg_catalog, pg_temp','row_security=on']
        AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
          pg_catalog.replace(function_row.prosrc,E'\r\n',E'\n'),'UTF8')),'hex')=expected_audit_hash
        AND (SELECT count(*)=1 AND bool_and(acl.grantor=owner_oid AND acl.grantee=owner_oid
          AND acl.privilege_type='EXECUTE' AND NOT acl.is_grantable)
          FROM pg_catalog.aclexplode(COALESCE(function_row.proacl,pg_catalog.acldefault('f',function_row.proowner))) acl))
      OR (SELECT count(*) FROM pg_catalog.pg_proc function_row
        WHERE function_row.pronamespace=pg_catalog.to_regnamespace('enrollment_execution') AND function_row.proname='audit_execution_profile_structure')<>1 THEN
      RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='History audit function contract is invalid.';
    END IF;
    -- Ordinary ACL is attested transitively by maintenance before any ordinary call.
    IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc function_row JOIN pg_catalog.pg_language language_row ON language_row.oid=function_row.prolang
      WHERE function_row.oid=pg_catalog.to_regprocedure('enrollment_execution.audit_execution_privileges(pg_catalog.uuid)')
        AND function_row.proowner=owner_oid AND language_row.lanname='plpgsql' AND function_row.prokind='f' AND function_row.prosecdef
        AND function_row.provolatile='v' AND function_row.proparallel='u' AND NOT function_row.proisstrict AND NOT function_row.proleakproof
        AND function_row.prosupport=0 AND function_row.proretset AND function_row.prorettype=2249 AND function_row.pronargs=1
        AND function_row.proargtypes::text='2950' AND function_row.proallargtypes IS NOT DISTINCT FROM ARRAY[2950,16,25,21]::oid[]
        AND function_row.proargnames IS NOT DISTINCT FROM ARRAY['p_environment','is_valid','diagnostic_code','profile_version']::text[]
        AND function_row.proargmodes IS NOT DISTINCT FROM ARRAY['i','t','t','t']::"char"[]
        AND function_row.pronargdefaults=0 AND function_row.proargdefaults IS NULL AND function_row.provariadic=0
        AND function_row.protrftypes IS NULL AND function_row.probin IS NULL AND function_row.prosqlbody IS NULL
        AND function_row.proconfig IS NOT DISTINCT FROM ARRAY['search_path=pg_catalog, pg_temp','row_security=on']
        AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
          pg_catalog.replace(function_row.prosrc,E'\r\n',E'\n'),'UTF8')),'hex')=expected_runtime_audit_hash)
      OR (SELECT count(*) FROM pg_catalog.pg_proc function_row
        WHERE function_row.pronamespace=pg_catalog.to_regnamespace('enrollment_execution') AND function_row.proname='audit_execution_privileges')<>1 THEN
      RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='History ordinary audit function contract is invalid.';
    END IF;
    FOR pass IN 1..2 LOOP
      audited:=0;
      FOR binding IN SELECT "EnvironmentId" environment_id FROM public."DirectoryDatabaseBindings" WHERE "Purpose"='EnrollmentGrantExecution'
      LOOP
        SELECT count(*),bool_and(result.is_valid IS TRUE AND result.diagnostic_code='None' AND result.profile_version=4)
          INTO row_count,valid FROM enrollment_execution.audit_execution_profile_structure(binding.environment_id) result;
        IF row_count<>1 OR valid IS DISTINCT FROM true THEN
          RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='History audit profile is invalid.';
        END IF;
        audited:=audited+1;
      END LOOP;
      IF audited=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='History audit execution bindings are empty.'; END IF;
      IF pass=2 THEN EXIT; END IF;
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
      IF EXISTS(SELECT 1 FROM pg_catalog.pg_policy policy WHERE policy.polname IN(
        'enrollment_history_check_delivery_acks','enrollment_history_check_execution_stops','enrollment_history_check_issue_results',
        'enrollment_history_check_mint_permits','enrollment_history_check_sealed_envelopes','enrollment_history_check_status_observations',
        'enrollment_history_check_EnrollmentGrantOperations')) THEN
        RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='History audit temporary policy name is occupied.';
      END IF;
      -- Close the full applicable set: permissive expressions can have side effects too.
      IF (SELECT count(*)=1 AND bool_and((policy.polrelid=pg_catalog.to_regclass('public."EnrollmentGrantOperations"')
          AND policy.polname='environment_enrollment_grant_operations' AND policy.polcmd='*' AND policy.polpermissive
          AND policy.polroles=ARRAY[0]::oid[] AND pg_catalog.pg_get_expr(policy.polqual,policy.polrelid)=canonical_operation_policy
          AND pg_catalog.pg_get_expr(policy.polwithcheck,policy.polrelid)=canonical_operation_policy) IS TRUE)
        FROM pg_catalog.pg_policy policy WHERE policy.polrelid=ANY(history_tables) AND policy.polcmd IN('r','*') AND EXISTS(
          SELECT 1 FROM unnest(policy.polroles) policy_role WHERE CASE WHEN policy_role=0 THEN true
            ELSE pg_catalog.pg_has_role(owner_oid,policy_role,'USAGE') END)) IS NOT TRUE THEN
        RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='History audit applicable policies are invalid.';
      END IF;
      FOR target IN SELECT relation.oid,namespace.nspname,relation.relname FROM pg_catalog.pg_class relation
        JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace WHERE relation.oid=ANY(history_tables) ORDER BY relation.oid
      LOOP
        EXECUTE pg_catalog.format('CREATE POLICY %I ON %I.%I AS PERMISSIVE FOR SELECT TO %I USING (true)',
          'enrollment_history_check_'||target.relname,target.nspname,target.relname,owner_name);
      END LOOP;
      IF (SELECT count(*)=8 AND bool_and((
          (policy.polrelid=pg_catalog.to_regclass('public."EnrollmentGrantOperations"') AND policy.polname='environment_enrollment_grant_operations'
            AND policy.polcmd='*' AND policy.polpermissive AND policy.polroles=ARRAY[0]::oid[]
            AND pg_catalog.pg_get_expr(policy.polqual,policy.polrelid)=canonical_operation_policy
            AND pg_catalog.pg_get_expr(policy.polwithcheck,policy.polrelid)=canonical_operation_policy)
          OR (policy.polname='enrollment_history_check_'||relation.relname AND policy.polcmd='r' AND policy.polpermissive
            AND policy.polroles=ARRAY[owner_oid] AND pg_catalog.pg_get_expr(policy.polqual,policy.polrelid)='true' AND policy.polwithcheck IS NULL)) IS TRUE)
        FROM pg_catalog.pg_policy policy JOIN pg_catalog.pg_class relation ON relation.oid=policy.polrelid
        WHERE policy.polrelid=ANY(history_tables) AND policy.polcmd IN('r','*') AND EXISTS(
          SELECT 1 FROM unnest(policy.polroles) policy_role WHERE CASE WHEN policy_role=0 THEN true
            ELSE pg_catalog.pg_has_role(owner_oid,policy_role,'USAGE') END)) IS NOT TRUE THEN
        RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='History audit temporary policies are invalid.';
      END IF;
      -- BEGIN generated history row rules
      valid := (
WITH status_ordered AS (
 SELECT observation.*,
   max(recorded_at) FILTER(WHERE state='Unknown') OVER (
     PARTITION BY operation_id ORDER BY sequence ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING) prior_unknown_barrier
 FROM enrollment_execution.status_observations observation
), status_sequences AS (
 SELECT operation_id,min(sequence) first_sequence,max(sequence) last_sequence,count(*) sequence_count,
   count(DISTINCT sequence) distinct_sequences,count(*) FILTER(WHERE state IN('Consumed','Revoked','Expired')) terminal_count,
   max(sequence) FILTER(WHERE state IN('Consumed','Revoked','Expired')) terminal_sequence
 FROM enrollment_execution.status_observations GROUP BY operation_id
)
SELECT
 NOT EXISTS(
   SELECT 1 FROM enrollment_execution.mint_permits permit
   LEFT JOIN public."EnrollmentGrantOperations" operation ON operation."Id"=permit.operation_id
   LEFT JOIN enrollment_execution.issue_results result ON result.operation_id=permit.operation_id
   LEFT JOIN enrollment_execution.delivery_acks ack ON ack.operation_id=permit.operation_id
   LEFT JOIN enrollment_execution.sealed_envelopes envelope ON envelope.operation_id=permit.operation_id
   WHERE operation."Id" IS NULL
     OR (permit.issued_at>=operation."QueuedAt" AND permit.not_after<=operation."AuthorizationNotAfter"
       AND permit.recipient_fingerprint=operation."RecipientKeyFingerprint") IS NOT TRUE
     OR (envelope.operation_id IS NOT NULL AND pg_catalog.sha256(envelope.ciphertext) IS DISTINCT FROM permit.ciphertext_sha256)
     OR (result.operation_id IS NOT NULL AND (result.recorded_at>=permit.issued_at
       AND (result.diagnostic<>'MintPermitExpired' OR result.recorded_at>=permit.not_after)) IS NOT TRUE)
     OR (result.outcome='Issued' AND (result.environment_id=operation."EnvironmentId"
       AND result.directory_object_id=operation."DirectoryObjectId" AND result.device_id=operation."ServerDeviceId"
       AND result.mapping_created_at=operation."MappingCreatedAt" AND result.mint_permit_not_after=permit.not_after
       AND result.grant_created_at>=permit.issued_at AND result.token_sha256=permit.token_sha256
       AND result.authorization_digest=permit.authorization_digest) IS NOT TRUE)
     OR (ack.operation_id IS NOT NULL AND (result.outcome='Issued' AND ack.requester_id=operation."RequesterId"
       AND ack.ciphertext_sha256=permit.ciphertext_sha256 AND ack.token_sha256=permit.token_sha256
       AND ack.acknowledged_at>=result.recorded_at) IS NOT TRUE)
     OR CASE WHEN ack.operation_id IS NOT NULL OR result.outcome='Rejected'
       THEN envelope.operation_id IS NOT NULL ELSE envelope.operation_id IS NULL END
 )
 AND NOT EXISTS(SELECT 1 FROM enrollment_execution.sealed_envelopes envelope
   LEFT JOIN enrollment_execution.mint_permits permit ON permit.operation_id=envelope.operation_id WHERE permit.operation_id IS NULL)
 AND NOT EXISTS(SELECT 1 FROM enrollment_execution.issue_results result
   LEFT JOIN enrollment_execution.mint_permits permit ON permit.operation_id=result.operation_id WHERE permit.operation_id IS NULL)
 AND NOT EXISTS(SELECT 1 FROM enrollment_execution.delivery_acks ack
   LEFT JOIN enrollment_execution.issue_results result ON result.operation_id=ack.operation_id WHERE result.operation_id IS NULL)
 AND NOT EXISTS(
   SELECT 1 FROM enrollment_execution.execution_stops stop
   LEFT JOIN public."EnrollmentGrantOperations" operation ON operation."Id"=stop.operation_id
   LEFT JOIN enrollment_execution.mint_permits permit ON permit.operation_id=stop.operation_id
   LEFT JOIN enrollment_execution.issue_results result ON result.operation_id=stop.operation_id
   LEFT JOIN enrollment_execution.delivery_acks ack ON ack.operation_id=stop.operation_id
   WHERE operation."Id" IS NULL OR (stop.recorded_at>=operation."QueuedAt"
     AND (stop.reason<>'AuthorizationExpired' OR stop.recorded_at>=operation."AuthorizationNotAfter")) IS NOT TRUE
     OR (permit.operation_id IS NOT NULL AND permit.issued_at>stop.recorded_at)
     OR (stop.reason IN('OperationConflict','ReceiptMismatch') AND permit.operation_id IS NULL)
     OR (stop.reason IN('AuthorizationChanged','AuthorizationExpired') AND permit.operation_id IS NOT NULL)
     OR result.operation_id IS NOT NULL OR ack.operation_id IS NOT NULL
 )
 AND NOT EXISTS(SELECT 1 FROM status_sequences WHERE first_sequence<>1 OR last_sequence<>sequence_count
   OR distinct_sequences<>sequence_count OR terminal_count>1 OR (terminal_count=1 AND terminal_sequence<>last_sequence))
 AND NOT EXISTS(
   SELECT 1 FROM status_ordered observation
   LEFT JOIN enrollment_execution.issue_results result ON result.operation_id=observation.operation_id
   LEFT JOIN public."EnrollmentGrantOperations" operation ON operation."Id"=observation.operation_id
   WHERE (result.outcome='Issued' AND result.environment_id=observation.environment_id
       AND operation."EnvironmentId"=observation.environment_id) IS NOT TRUE
     OR (observation.state<>'Unknown' AND (observation.private_observed_at>=result.grant_created_at) IS NOT TRUE)
     OR (observation.state='Available' AND (observation.private_observed_at<result.grant_expires_at
       AND observation.private_observed_at>observation.recorded_at-interval '15 seconds'
       AND (observation.prior_unknown_barrier IS NULL OR observation.private_observed_at>=observation.prior_unknown_barrier)
       AND observation.available_until=least(observation.private_observed_at+interval '15 seconds',
         observation.recorded_at+interval '15 seconds',result.grant_expires_at)) IS NOT TRUE)
     OR (observation.state='Expired' AND (observation.private_observed_at>=result.grant_expires_at) IS NOT TRUE)
     OR (observation.state IN('Consumed','Revoked') AND (observation.private_state_changed_at>=result.grant_created_at
       AND (observation.state<>'Consumed' OR observation.private_state_changed_at<result.grant_expires_at)) IS NOT TRUE)
 ) AS is_valid
      );
      -- END generated history row rules
      IF valid IS DISTINCT FROM true THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='Enrollment delivery history is inconsistent.';
      END IF;
      FOR target IN SELECT relation.oid,namespace.nspname,relation.relname FROM pg_catalog.pg_class relation
        JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace WHERE relation.oid=ANY(history_tables) ORDER BY relation.oid
      LOOP
        EXECUTE pg_catalog.format('DROP POLICY %I ON %I.%I','enrollment_history_check_'||target.relname,target.nspname,target.relname);
      END LOOP;
      IF EXISTS(SELECT 1 FROM pg_catalog.pg_policy policy WHERE policy.polname IN(
        'enrollment_history_check_delivery_acks','enrollment_history_check_execution_stops','enrollment_history_check_issue_results',
        'enrollment_history_check_mint_permits','enrollment_history_check_sealed_envelopes','enrollment_history_check_status_observations',
        'enrollment_history_check_EnrollmentGrantOperations')) THEN
        RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='History audit temporary policies were not removed.';
      END IF;
    END LOOP;
    UPDATE enrollment_execution.profile4_readiness SET state='Ready',ready_at=statement_timestamp(),ready_by=SESSION_USER
      WHERE singleton AND profile_version=4 AND state='PendingHistoryAudit'
        AND generation=expected_input.generation AND installation_nonce=expected_input.installation_nonce
        AND attestation_manifest_sha256=expected_manifest AND pending_at=installed_state.pending_at
        AND ready_at IS NULL AND ready_by IS NULL;
    GET DIAGNOSTICS row_count=ROW_COUNT;
    IF row_count<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='History ready transition did not match one installation.'; END IF;
    -- Separate statement: the locking audit must see this transaction's preceding Ready update.
    FOR binding IN SELECT "EnvironmentId" environment_id FROM public."DirectoryDatabaseBindings" WHERE "Purpose"='EnrollmentGrantExecution'
    LOOP
      SELECT count(*),bool_and(result.is_valid IS TRUE AND result.diagnostic_code='None' AND result.profile_version=4)
        INTO row_count,valid FROM enrollment_execution.audit_execution_privileges(binding.environment_id) result;
      IF row_count<>1 OR valid IS DISTINCT FROM true THEN
        RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='History final runtime audit failed.';
      END IF;
    END LOOP;
END
$delivery_history_audit$;
