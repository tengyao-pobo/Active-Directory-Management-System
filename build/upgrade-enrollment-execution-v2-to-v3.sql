\set ON_ERROR_STOP on
BEGIN;
SELECT pg_catalog.pg_advisory_xact_lock(1162235478,1);
SELECT pg_catalog.set_config('app.execution_upgrade_definer',:'execution_definer_role',true),
 pg_catalog.set_config('app.execution_upgrade_queue_definer',:'execution_queue_definer_role',true),
 pg_catalog.set_config('app.execution_upgrade_owner',:'expected_table_owner_role',true);

DO $preflight$
DECLARE owner_oid oid; definer_oid oid; queue_oid oid; audit_oid oid; marker_oid oid; invalid_audit boolean;
BEGIN
 SELECT oid INTO owner_oid FROM pg_catalog.pg_roles WHERE rolname=current_setting('app.execution_upgrade_owner');
 SELECT oid INTO definer_oid FROM pg_catalog.pg_roles WHERE rolname=current_setting('app.execution_upgrade_definer');
 SELECT oid INTO queue_oid FROM pg_catalog.pg_roles WHERE rolname=current_setting('app.execution_upgrade_queue_definer');
 SELECT p.oid INTO audit_oid FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_language l ON l.oid=p.prolang
  WHERE p.oid=pg_catalog.to_regprocedure('enrollment_execution.audit_execution_privileges(uuid)')
    AND p.proowner=owner_oid AND l.lanname='plpgsql' AND p.prosecdef AND p.provolatile='s' AND p.proparallel='u'
    AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp','row_security=on']
    AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
      pg_catalog.btrim(pg_catalog.regexp_replace(p.prosrc,'[[:space:]]+',' ','g')),'UTF8')),'hex')
      ='8ed83a1a4736e9caab7c0a9c32ef8b2e53b48dbdcf184824a8436d3fc33d3da3';
 SELECT p.oid INTO marker_oid FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_language l ON l.oid=p.prolang
  WHERE p.oid=pg_catalog.to_regprocedure('enrollment_execution.execution_store_profile()')
    AND p.proowner=owner_oid AND l.lanname='sql' AND NOT p.prosecdef AND p.provolatile='i' AND p.proparallel='s'
    AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp'] AND pg_catalog.btrim(p.prosrc,E' \t\r\n')='SELECT 2::smallint';
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_language l ON l.oid=p.prolang
      WHERE p.oid=pg_catalog.to_regprocedure('public.validate_enrollment_grant_queue_anchor()')
        AND p.proowner=owner_oid AND l.lanname='plpgsql' AND NOT p.prosecdef AND p.provolatile='v' AND p.proparallel='u'
        AND p.prokind='f' AND NOT p.proretset AND p.prorettype='trigger'::regtype AND p.pronargs=0
        AND NOT p.proisstrict AND NOT p.proleakproof AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']
        AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
            pg_catalog.btrim(pg_catalog.regexp_replace(p.prosrc,'[[:space:]]+',' ','g')),'UTF8')),'hex')
            ='7c6f273e7eb359289dc69e4e7a0d7d95efd951f93cccc464c3da56e553e61d7c'
        AND NOT EXISTS(SELECT 1 FROM pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) acl
            WHERE acl.grantee<>owner_oid OR acl.privilege_type<>'EXECUTE' OR acl.is_grantable))
  OR owner_oid IS NULL OR owner_oid<>CURRENT_USER::regrole::oid OR definer_oid IS NULL OR queue_oid IS NULL
  OR queue_oid IN(owner_oid,definer_oid) OR audit_oid IS NULL OR marker_oid IS NULL
  OR EXISTS(SELECT 1 FROM pg_catalog.pg_roles r WHERE r.oid=queue_oid AND
     (r.rolcanlogin OR r.rolsuper OR r.rolbypassrls OR r.rolcreatedb OR r.rolcreaterole OR r.rolinherit OR r.rolreplication))
  OR EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members m WHERE m.member=queue_oid OR m.roleid=queue_oid)
  OR EXISTS(SELECT 1 FROM pg_catalog.pg_database d WHERE d.datdba=queue_oid)
  OR EXISTS(SELECT 1 FROM pg_catalog.pg_namespace n WHERE n.nspowner=queue_oid)
  OR EXISTS(SELECT 1 FROM pg_catalog.pg_class c WHERE c.relowner=queue_oid)
  OR EXISTS(SELECT 1 FROM pg_catalog.pg_proc p WHERE p.proowner=queue_oid)
  OR EXISTS(SELECT 1 FROM enrollment_execution.role_reservations r WHERE r.role_name=current_setting('app.execution_upgrade_queue_definer')::name OR r.role_oid=queue_oid)
  OR pg_catalog.to_regprocedure('enrollment_execution.claim_next(uuid,uuid)') IS NOT NULL
  OR pg_catalog.to_regprocedure('enrollment_execution.defer_claim(uuid,uuid,uuid,text)') IS NOT NULL
  OR pg_catalog.to_regprocedure('enrollment_execution.complete_claim(uuid,uuid,uuid)') IS NOT NULL
  OR pg_catalog.to_regprocedure('enrollment_execution.queue_worker_scope(uuid)') IS NOT NULL
 OR pg_catalog.to_regclass('enrollment_execution.work_queue') IS NULL
  OR pg_catalog.to_regclass('enrollment_execution.claim_leases') IS NULL
  OR EXISTS(SELECT 1 FROM public."Outbox" outbox
      LEFT JOIN public."EnrollmentGrantOperations" operation
        ON operation."EnvironmentId"=outbox."EnvironmentId" AND operation."Id"=outbox."Id"
      WHERE outbox."EventType"='EnrollmentGrantExecutionRequested'
        AND (operation."Id" IS NULL OR outbox."Version"<>1 OR outbox."DeliveredAt" IS NOT NULL
          OR outbox."CreatedAt"<>operation."QueuedAt"
          OR outbox."Payload"<>jsonb_build_object('version',1,'environmentId',outbox."EnvironmentId",'operationId',outbox."Id"))) THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='Enrollment execution v2 upgrade preflight failed.';
 END IF;
 SELECT EXISTS(SELECT 1 FROM public."DirectoryDatabaseBindings" b
   CROSS JOIN LATERAL enrollment_execution.audit_execution_privileges(b."EnvironmentId") a
   WHERE b."Purpose"='EnrollmentGrantExecution'
     AND (NOT a.is_valid OR a.diagnostic_code<>'None' OR a.profile_version<>2)) INTO invalid_audit;
 IF invalid_audit OR NOT EXISTS(SELECT 1 FROM public."DirectoryDatabaseBindings" WHERE "Purpose"='EnrollmentGrantExecution') THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='Enrollment execution v2 source profile is invalid.';
 END IF;
END
$preflight$;

ALTER TABLE enrollment_execution.role_reservations DROP CONSTRAINT role_reservations_role_kind_check;
ALTER TABLE enrollment_execution.role_reservations ADD CONSTRAINT role_reservations_role_kind_check
 CHECK(role_kind IN('Runtime','Definer','QueueDefiner'));
INSERT INTO enrollment_execution.role_reservations(role_name,role_oid,capability,role_kind,reservation_schema_version)
 SELECT :'execution_queue_definer_role'::name,oid,'EnrollmentGrantExecution','QueueDefiner',1
 FROM pg_catalog.pg_roles WHERE rolname=:'execution_queue_definer_role';

\ir enrollment-execution-queue.sql
\ir enrollment-execution-functions.sql
ALTER FUNCTION enrollment_execution.worker_scope(uuid) OWNER TO :"execution_definer_role";
ALTER FUNCTION enrollment_execution.read_execution_record(uuid,uuid) OWNER TO :"execution_definer_role";
ALTER FUNCTION enrollment_execution.read_and_lock_plan_context(uuid,uuid) OWNER TO :"execution_definer_role";
ALTER FUNCTION enrollment_execution.authorize_and_store_candidate(uuid,uuid,text,bytea,bytea,bytea) OWNER TO :"execution_definer_role";
ALTER FUNCTION enrollment_execution.record_execution_result(uuid,uuid,bytea,text,text,uuid,uuid,uuid,uuid,timestamptz,timestamptz,timestamptz,smallint,timestamptz,bytea,bytea) OWNER TO :"execution_definer_role";
ALTER FUNCTION enrollment_execution.quarantine_execution(uuid,uuid,bytea,text) OWNER TO :"execution_definer_role";
ALTER FUNCTION enrollment_execution.queue_worker_scope(uuid) OWNER TO :"execution_queue_definer_role";
ALTER FUNCTION enrollment_execution.claim_next(uuid,uuid) OWNER TO :"execution_queue_definer_role";
ALTER FUNCTION enrollment_execution.defer_claim(uuid,uuid,uuid,text) OWNER TO :"execution_queue_definer_role";
ALTER FUNCTION enrollment_execution.complete_claim(uuid,uuid,uuid) OWNER TO :"execution_queue_definer_role";
ALTER FUNCTION enrollment_execution.guard_work_queue() OWNER TO :"expected_table_owner_role";
ALTER FUNCTION enrollment_execution.validate_work_queue() OWNER TO :"expected_table_owner_role";
ALTER FUNCTION enrollment_execution.claim_next_work(uuid,uuid) OWNER TO :"expected_table_owner_role";
ALTER FUNCTION enrollment_execution.defer_work_claim(uuid,uuid,uuid,text) OWNER TO :"expected_table_owner_role";
ALTER FUNCTION enrollment_execution.complete_work_claim(uuid,uuid,uuid) OWNER TO :"expected_table_owner_role";

DROP FUNCTION enrollment_execution.audit_execution_privileges(uuid);
DROP FUNCTION enrollment_execution.reject_worker_update() CASCADE;
DO $drop_policies$ DECLARE row record; BEGIN
 FOR row IN SELECT n.nspname,c.relname,p.polname FROM pg_catalog.pg_policy p
   JOIN pg_catalog.pg_class c ON c.oid=p.polrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
   WHERE p.polname LIKE 'enrollment_execution_worker_%' OR p.polname LIKE 'enrollment_execution_queue_%'
 LOOP EXECUTE pg_catalog.format('DROP POLICY %I ON %I.%I',row.polname,row.nspname,row.relname); END LOOP;
END $drop_policies$;
DROP FUNCTION enrollment_execution.execution_store_profile();
\ir enrollment-execution-profile.sql

GRANT SELECT("LoginRole","Purpose","ContractVersion","EnvironmentId","PrincipalId") ON public."DirectoryDatabaseBindings" TO :"execution_queue_definer_role";
GRANT USAGE ON SCHEMA enrollment_execution TO :"execution_queue_definer_role";
GRANT EXECUTE ON FUNCTION public.has_environment_membership(uuid,uuid) TO :"execution_queue_definer_role";
GRANT SELECT("EnvironmentId","Id","QueuedAt") ON public."EnrollmentGrantOperations" TO :"execution_queue_definer_role";
GRANT SELECT("EnvironmentId","Id","EventType","Version","Payload","CreatedAt","DeliveredAt","Attempts"),UPDATE("Attempts","DeliveredAt") ON public."Outbox" TO :"execution_queue_definer_role";
GRANT SELECT,INSERT,UPDATE ON enrollment_execution.work_queue TO :"execution_queue_definer_role";
GRANT SELECT,INSERT ON enrollment_execution.claim_leases TO :"execution_queue_definer_role";
GRANT SELECT ON enrollment_execution.issue_results,enrollment_execution.execution_stops TO :"execution_queue_definer_role";
GRANT EXECUTE ON FUNCTION enrollment_execution.claim_next_work(uuid,uuid),
 enrollment_execution.defer_work_claim(uuid,uuid,uuid,text),enrollment_execution.complete_work_claim(uuid,uuid,uuid),
 enrollment_execution.audit_execution_privileges(uuid) TO :"execution_queue_definer_role";
GRANT EXECUTE ON FUNCTION enrollment_execution.audit_execution_privileges(uuid) TO :"execution_definer_role";

DO $runtime_grants$ DECLARE row record; BEGIN
 FOR row IN SELECT role_name FROM enrollment_execution.role_reservations WHERE role_kind='Runtime'
 LOOP EXECUTE pg_catalog.format('GRANT EXECUTE ON FUNCTION enrollment_execution.claim_next(uuid,uuid), enrollment_execution.defer_claim(uuid,uuid,uuid,text), enrollment_execution.complete_claim(uuid,uuid,uuid), enrollment_execution.audit_execution_privileges(uuid) TO %I',row.role_name); END LOOP;
END $runtime_grants$;
REVOKE CREATE ON SCHEMA public,enrollment_execution FROM :"execution_queue_definer_role";

CREATE FUNCTION enrollment_execution.execution_store_profile() RETURNS smallint
 LANGUAGE sql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path=pg_catalog,pg_temp
 AS 'SELECT 3::smallint';
REVOKE ALL ON FUNCTION enrollment_execution.execution_store_profile() FROM PUBLIC;
ALTER FUNCTION enrollment_execution.execution_store_profile() OWNER TO :"expected_table_owner_role";

DO $postflight$ DECLARE row record; BEGIN
 FOR row IN SELECT b."EnvironmentId" environment_id FROM public."DirectoryDatabaseBindings" b
   WHERE b."Purpose"='EnrollmentGrantExecution'
 LOOP
  IF NOT EXISTS(SELECT 1 FROM enrollment_execution.audit_execution_privileges(row.environment_id) a
      WHERE a.is_valid AND a.diagnostic_code='None' AND a.profile_version=3) THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='Enrollment execution v3 postflight failed.',DETAIL=(SELECT pg_catalog.jsonb_build_object(
 'function_sha256',(SELECT pg_catalog.jsonb_object_agg(p.proname,
   pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(pg_catalog.btrim(
     pg_catalog.regexp_replace(p.prosrc,'[[:space:]]+',' ','g')),'UTF8')),'hex'))
   FROM pg_catalog.pg_proc p WHERE p.pronamespace='enrollment_execution'::regnamespace
     AND p.proname IN('guard_work_queue','validate_work_queue','claim_next_work','defer_work_claim',
       'complete_work_claim','queue_worker_scope','claim_next','defer_claim','complete_claim')),
 'constraints',(SELECT pg_catalog.jsonb_object_agg(c.relname,x.definitions)
   FROM pg_catalog.pg_class c CROSS JOIN LATERAL (
     SELECT pg_catalog.jsonb_agg(pg_catalog.pg_get_constraintdef(k.oid,true)
       ORDER BY pg_catalog.pg_get_constraintdef(k.oid,true) COLLATE "C") definitions
     FROM pg_catalog.pg_constraint k WHERE k.conrelid=c.oid AND k.contype IN('p','u','f','c') AND k.convalidated) x
   WHERE c.oid IN('enrollment_execution.work_queue'::regclass,'enrollment_execution.claim_leases'::regclass)),
 'policy_md5',(SELECT pg_catalog.jsonb_object_agg(p.polname,pg_catalog.md5(
     COALESCE(pg_catalog.pg_get_expr(p.polqual,p.polrelid),'')||'|'||
     COALESCE(pg_catalog.pg_get_expr(p.polwithcheck,p.polrelid),'')))
   FROM pg_catalog.pg_policy p WHERE p.polname LIKE 'enrollment_execution_queue_%'))::text);
  END IF;
 END LOOP;
END $postflight$;
COMMIT;
