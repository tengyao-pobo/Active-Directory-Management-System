\set ON_ERROR_STOP on
BEGIN;
SELECT pg_catalog.pg_advisory_xact_lock(1162235478,1);
SELECT pg_catalog.set_config('app.execution_install_runtime',:'execution_runtime_role',true),
 pg_catalog.set_config('app.execution_install_definer',:'execution_definer_role',true),
 pg_catalog.set_config('app.execution_install_owner',:'expected_table_owner_role',true),
 pg_catalog.set_config('app.execution_install_environment',:'expected_environment_id',true),
 pg_catalog.set_config('app.execution_install_database',:'DBNAME',true);
DO $preflight$
DECLARE runtime_role pg_catalog.pg_roles%ROWTYPE; definer_role pg_catalog.pg_roles%ROWTYPE; owner_role pg_catalog.pg_roles%ROWTYPE;
 api_oid oid; private_registry oid; private_marker oid;
BEGIN
 IF current_setting('app.execution_install_environment')::uuid='00000000-0000-0000-0000-000000000000' OR current_setting('app.execution_install_database')<>current_database() THEN
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='Invalid enrollment execution deployment target.'; END IF;
 SELECT c.oid INTO private_registry FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
  WHERE n.nspname='agent_private' AND c.relname='agent_capability_roles';
 SELECT p.oid INTO private_marker FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
  WHERE n.nspname='agent_private' AND p.proname='agent_capability_isolation_profile' LIMIT 1;
 IF private_registry IS NOT NULL OR private_marker IS NOT NULL THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='Enrollment execution requires a database without the private capability registry.';
 END IF;
 SELECT * INTO runtime_role FROM pg_catalog.pg_roles WHERE rolname=current_setting('app.execution_install_runtime');
 SELECT * INTO definer_role FROM pg_catalog.pg_roles WHERE rolname=current_setting('app.execution_install_definer');
 SELECT * INTO owner_role FROM pg_catalog.pg_roles WHERE rolname=current_setting('app.execution_install_owner');
 SELECT r.oid INTO api_oid FROM public."DirectoryDatabaseBindings" b JOIN pg_catalog.pg_roles r ON r.rolname=b."LoginRole" WHERE b."Purpose"='Api';
 IF runtime_role.oid IS NULL OR NOT runtime_role.rolcanlogin OR runtime_role.rolsuper OR runtime_role.rolbypassrls
  OR runtime_role.rolcreatedb OR runtime_role.rolcreaterole OR runtime_role.rolinherit OR runtime_role.rolreplication
  OR definer_role.oid IS NULL OR definer_role.rolcanlogin OR definer_role.rolsuper OR definer_role.rolbypassrls
  OR definer_role.rolcreatedb OR definer_role.rolcreaterole OR definer_role.rolinherit OR definer_role.rolreplication
  OR owner_role.oid IS NULL OR owner_role.oid<>CURRENT_USER::regrole::oid OR api_oid IS NULL
  OR runtime_role.oid IN(definer_role.oid,owner_role.oid,api_oid) OR definer_role.oid IN(owner_role.oid,api_oid)
  OR EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members m WHERE m.member IN(runtime_role.oid,definer_role.oid) OR m.roleid IN(runtime_role.oid,definer_role.oid))
  OR EXISTS(SELECT 1 FROM pg_catalog.pg_database d WHERE d.datdba IN(runtime_role.oid,definer_role.oid))
  OR EXISTS(SELECT 1 FROM pg_catalog.pg_namespace n WHERE n.nspowner IN(runtime_role.oid,definer_role.oid))
  OR EXISTS(SELECT 1 FROM pg_catalog.pg_class c WHERE c.relowner IN(runtime_role.oid,definer_role.oid))
  OR EXISTS(SELECT 1 FROM pg_catalog.pg_proc p WHERE p.proowner=runtime_role.oid)
  OR EXISTS(SELECT 1 FROM pg_catalog.pg_proc p WHERE p.proowner=definer_role.oid AND p.oid NOT IN(
    pg_catalog.to_regprocedure('enrollment_execution.worker_scope(uuid)'),
    pg_catalog.to_regprocedure('enrollment_execution.read_execution_record(uuid,uuid)'),
    pg_catalog.to_regprocedure('enrollment_execution.read_and_lock_plan_context(uuid,uuid)'),
    pg_catalog.to_regprocedure('enrollment_execution.authorize_and_store_candidate(uuid,uuid,text,bytea,bytea,bytea)'),
    pg_catalog.to_regprocedure('enrollment_execution.record_execution_result(uuid,uuid,bytea,text,text,uuid,uuid,uuid,uuid,timestamptz,timestamptz,timestamptz,smallint,timestamptz,bytea,bytea)'),
    pg_catalog.to_regprocedure('enrollment_execution.quarantine_execution(uuid,uuid,bytea,text)')))
  OR has_database_privilege(runtime_role.oid,current_database(),'CREATE') OR has_database_privilege(definer_role.oid,current_database(),'CREATE')
  OR has_schema_privilege(runtime_role.oid,'public','CREATE') OR has_schema_privilege(definer_role.oid,'public','CREATE')
  OR has_schema_privilege(runtime_role.oid,'enrollment_execution','CREATE') OR has_schema_privilege(definer_role.oid,'enrollment_execution','CREATE') THEN
  RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='Unsafe enrollment execution role profile.'; END IF;
 IF EXISTS(SELECT 1 FROM enrollment_execution.role_reservations r WHERE (r.role_name=current_setting('app.execution_install_runtime')::name OR r.role_oid=runtime_role.oid)
   AND NOT(r.role_name=current_setting('app.execution_install_runtime')::name AND r.role_oid=runtime_role.oid AND r.capability='EnrollmentGrantExecution' AND r.role_kind='Runtime' AND r.reservation_schema_version=1))
  OR EXISTS(SELECT 1 FROM public."DirectoryDatabaseBindings" b WHERE b."LoginRole"=current_setting('app.execution_install_runtime')
   AND NOT(b."Purpose"='EnrollmentGrantExecution' AND b."ContractVersion"=2 AND b."EnvironmentId"=current_setting('app.execution_install_environment')::uuid AND b."PrincipalId" IS NULL)) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='Enrollment execution runtime identity is already used.'; END IF;
END
$preflight$;

SELECT (pg_catalog.to_regprocedure('enrollment_execution.execution_store_profile()') IS NULL)::int AS profile_absent \gset

-- Never invoke the installed SECURITY DEFINER audit until its catalog identity and body
-- have been independently pinned.  The internal audit supplies the remaining exact profile.
DO $catalog_preflight$
DECLARE owner_oid oid; definer_oid oid; audit_oid oid;
BEGIN
 IF pg_catalog.to_regprocedure('enrollment_execution.execution_store_profile()') IS NOT NULL THEN
  SELECT oid INTO owner_oid FROM pg_catalog.pg_roles WHERE rolname=current_setting('app.execution_install_owner');
  SELECT oid INTO definer_oid FROM pg_catalog.pg_roles WHERE rolname=current_setting('app.execution_install_definer');
  SELECT p.oid INTO audit_oid FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_language l ON l.oid=p.prolang
   WHERE p.oid=pg_catalog.to_regprocedure('enrollment_execution.audit_execution_privileges(uuid)')
     AND p.proowner=owner_oid AND l.lanname='plpgsql' AND p.prosecdef AND p.provolatile='s' AND p.proparallel='u'
     AND p.prokind='f' AND p.proretset AND p.prorettype='record'::regtype AND p.pronargs=1
     AND p.proargtypes='2950'::oidvector
     AND p.proargnames=ARRAY['p_environment','is_valid','diagnostic_code','profile_version']
     AND p.proallargtypes=ARRAY['uuid'::regtype::oid,'boolean'::regtype::oid,'text'::regtype::oid,'smallint'::regtype::oid]
     AND p.proargmodes=ARRAY['i','t','t','t']::"char"[]
     AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp','row_security=on']
     AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
       pg_catalog.btrim(pg_catalog.regexp_replace(p.prosrc,'[[:space:]]+',' ','g')),'UTF8')),'hex')
       ='8ed83a1a4736e9caab7c0a9c32ef8b2e53b48dbdcf184824a8436d3fc33d3da3';
  IF audit_oid IS NULL OR EXISTS(SELECT 1 FROM pg_catalog.aclexplode(
       COALESCE((SELECT proacl FROM pg_catalog.pg_proc WHERE oid=audit_oid),pg_catalog.acldefault('f',owner_oid))) acl
       WHERE acl.privilege_type<>'EXECUTE' OR acl.is_grantable OR acl.grantee=0
          OR acl.grantee NOT IN(owner_oid,definer_oid)
             AND acl.grantee NOT IN(SELECT role_oid FROM enrollment_execution.role_reservations WHERE role_kind='Runtime')) THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='Enrollment execution catalog attestation failed.';
  END IF;
 END IF;
END
$catalog_preflight$;

\if :profile_absent
DO $fresh$
BEGIN
 IF EXISTS(SELECT 1 FROM enrollment_execution.role_reservations)
  OR EXISTS(SELECT 1 FROM public."DirectoryDatabaseBindings" WHERE "Purpose"='EnrollmentGrantExecution')
  OR EXISTS(SELECT 1 FROM pg_catalog.pg_proc WHERE pronamespace='enrollment_execution'::regnamespace
   AND proname IN('worker_scope','read_execution_record','read_and_lock_plan_context','authorize_and_store_candidate','record_execution_result','quarantine_execution','audit_execution_privileges','reject_worker_update'))
  OR EXISTS(SELECT 1 FROM pg_catalog.pg_policy WHERE polname LIKE 'enrollment_execution_worker_%')
  OR EXISTS(SELECT 1 FROM pg_catalog.pg_trigger WHERE NOT tgisinternal AND tgname LIKE 'enrollment_execution_worker_%') THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='Enrollment execution profile is partially installed.'; END IF;
END
$fresh$;
-- Establish the exact API-only source profile before the first execution-profile mutation.
SELECT "LoginRole" AS runtime_role FROM public."DirectoryDatabaseBindings" WHERE "Purpose"='Api' \gset
\ir audit-enrollment-grant-operations.sql
INSERT INTO enrollment_execution.role_reservations SELECT :'execution_definer_role'::name,oid,'EnrollmentGrantExecution','Definer',1 FROM pg_roles WHERE rolname=:'execution_definer_role';
INSERT INTO enrollment_execution.role_reservations SELECT :'execution_runtime_role'::name,oid,'EnrollmentGrantExecution','Runtime',1 FROM pg_roles WHERE rolname=:'execution_runtime_role';
INSERT INTO public."DirectoryDatabaseBindings"("LoginRole","Purpose","ContractVersion","EnvironmentId","PrincipalId")
 VALUES(:'execution_runtime_role','EnrollmentGrantExecution',2,:'expected_environment_id'::uuid,NULL);
\ir enrollment-execution-functions.sql
ALTER FUNCTION enrollment_execution.worker_scope(uuid) OWNER TO :"execution_definer_role";
ALTER FUNCTION enrollment_execution.read_execution_record(uuid,uuid) OWNER TO :"execution_definer_role";
ALTER FUNCTION enrollment_execution.read_and_lock_plan_context(uuid,uuid) OWNER TO :"execution_definer_role";
ALTER FUNCTION enrollment_execution.authorize_and_store_candidate(uuid,uuid,text,bytea,bytea,bytea) OWNER TO :"execution_definer_role";
ALTER FUNCTION enrollment_execution.record_execution_result(uuid,uuid,bytea,text,text,uuid,uuid,uuid,uuid,timestamptz,timestamptz,timestamptz,smallint,timestamptz,bytea,bytea) OWNER TO :"execution_definer_role";
ALTER FUNCTION enrollment_execution.quarantine_execution(uuid,uuid,bytea,text) OWNER TO :"execution_definer_role";
\ir enrollment-execution-profile.sql
GRANT USAGE ON SCHEMA enrollment_execution TO :"execution_definer_role";
GRANT EXECUTE ON FUNCTION enrollment_execution.read_record(uuid,uuid),enrollment_execution.authorization_digest(public."EnrollmentGrantOperations",smallint,timestamptz,timestamptz,bytea,bytea,bytea),
 enrollment_execution.lock_plan_context(uuid,uuid),enrollment_execution.scope_uuid(text),enrollment_execution.has_computer_permission(uuid,uuid,uuid,uuid,text),
 enrollment_execution.current_authority_matches(public."EnrollmentGrantOperations",timestamptz),enrollment_execution.store_candidate(uuid,uuid,text,bytea,bytea,bytea),
 enrollment_execution.store_result(uuid,uuid,bytea,text,text,uuid,uuid,uuid,uuid,timestamptz,timestamptz,timestamptz,smallint,timestamptz,bytea,bytea),
 enrollment_execution.store_quarantine(uuid,uuid,bytea,text) TO :"execution_definer_role";
GRANT EXECUTE ON FUNCTION public.has_environment_membership(uuid,uuid),public.directory_database_access(uuid,uuid) TO :"execution_definer_role";
GRANT SELECT("LoginRole","Purpose","ContractVersion","EnvironmentId","PrincipalId") ON public."DirectoryDatabaseBindings" TO :"execution_definer_role";
GRANT SELECT("Id","Version"),UPDATE("Name") ON public."Environments" TO :"execution_definer_role";
GRANT SELECT("EnvironmentId","Status","Generation","CompletedAt"),UPDATE("ErrorCode") ON public."DirectorySync" TO :"execution_definer_role";
GRANT SELECT("EnvironmentId","Id","Generation","Kind","Department","ParentOuId","OuAncestry"),UPDATE("Name") ON public."DirectoryObjects" TO :"execution_definer_role";
GRANT SELECT("Id","OperatorId","Enabled"),UPDATE("DisplayName") ON public."Principals" TO :"execution_definer_role";
GRANT SELECT("EnvironmentId","PrincipalId","Active"),UPDATE("Active") ON public."Memberships" TO :"execution_definer_role";
GRANT SELECT("EnvironmentId","Id","RequesterId","Action","ImmutablePlanJson","PlanHash","PolicyVersion","ExpiresAt","State","Reason"),UPDATE("Reason") ON public."Plans" TO :"execution_definer_role";
GRANT SELECT("EnvironmentId","PlanId","Id","TargetId","ExpectedVersion") ON public."PlanItems" TO :"execution_definer_role";
GRANT SELECT("EnvironmentId","Id","PlanId","PlanHash","ApproverId","ApprovedAt","ExpiresAt") ON public."Approvals" TO :"execution_definer_role";
GRANT SELECT("Fingerprint","EnvironmentId","PlanId","RequesterId","RequestId","RequestDigest","CreatedAt") ON public."EnrollmentGrantRecipientReservations" TO :"execution_definer_role";
GRANT SELECT("EnvironmentId","Id","PlanId","RequestId","ApprovalId","RequesterId","ApproverId","RequesterOperatorId","ApproverOperatorId","PlanHash","DirectoryObjectId","ServerDeviceId","MappingCreatedAt","DirectoryGeneration","EnvironmentVersion","RecipientSpki","RecipientKeyFingerprint","QueuedAt","AuthorizationNotAfter"),UPDATE("PlanHash") ON public."EnrollmentGrantOperations" TO :"execution_definer_role";
GRANT SELECT("EnvironmentId","Id","EventType","Version","Payload","CreatedAt","DeliveredAt","Attempts"),UPDATE("Attempts","DeliveredAt") ON public."Outbox" TO :"execution_definer_role";
GRANT SELECT("EnvironmentId","Id","BuiltInKind") ON public."Roles" TO :"execution_definer_role";
GRANT SELECT("EnvironmentId","RoleId","Permission") ON public."RolePermissions" TO :"execution_definer_role";
GRANT SELECT("EnvironmentId","PrincipalId","RoleId","ScopeId") ON public."Assignments" TO :"execution_definer_role";
GRANT SELECT("EnvironmentId","Id","Kind","Value","IncludeDescendants") ON public."Scopes" TO :"execution_definer_role";
GRANT SELECT("EnvironmentId","TagId","ObjectId") ON public."DeviceTagAssignments" TO :"execution_definer_role";
GRANT SELECT ON enrollment_execution.mint_permits,enrollment_execution.sealed_envelopes,enrollment_execution.issue_results,enrollment_execution.delivery_acks,enrollment_execution.execution_stops TO :"execution_definer_role";
GRANT INSERT ON enrollment_execution.mint_permits,enrollment_execution.sealed_envelopes,enrollment_execution.issue_results,enrollment_execution.execution_stops TO :"execution_definer_role";
GRANT DELETE ON enrollment_execution.sealed_envelopes TO :"execution_definer_role";
\else
DO $existing$
DECLARE bad boolean;
BEGIN
 IF enrollment_execution.execution_store_profile()<>2
  OR (SELECT role_oid FROM enrollment_execution.role_reservations WHERE role_name=current_setting('app.execution_install_definer')::name AND role_kind='Definer')
     IS DISTINCT FROM (SELECT oid FROM pg_roles WHERE rolname=current_setting('app.execution_install_definer'))
  OR EXISTS(SELECT 1 FROM public."DirectoryDatabaseBindings" b CROSS JOIN LATERAL enrollment_execution.audit_execution_privileges(b."EnvironmentId") a
     WHERE b."Purpose"='EnrollmentGrantExecution' AND (NOT a.is_valid OR a.diagnostic_code<>'None' OR a.profile_version<>2)) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='Existing enrollment execution profile is invalid.'; END IF;
END
$existing$;
INSERT INTO enrollment_execution.role_reservations SELECT :'execution_runtime_role'::name,oid,'EnrollmentGrantExecution','Runtime',1 FROM pg_roles WHERE rolname=:'execution_runtime_role' ON CONFLICT(role_name) DO NOTHING;
INSERT INTO public."DirectoryDatabaseBindings"("LoginRole","Purpose","ContractVersion","EnvironmentId","PrincipalId") VALUES(:'execution_runtime_role','EnrollmentGrantExecution',2,:'expected_environment_id'::uuid,NULL) ON CONFLICT("LoginRole") DO NOTHING;
\endif

GRANT CONNECT ON DATABASE :"DBNAME" TO :"execution_runtime_role";
GRANT USAGE ON SCHEMA enrollment_execution TO :"execution_runtime_role";
REVOKE CREATE ON SCHEMA enrollment_execution FROM :"execution_runtime_role";
REVOKE CREATE ON SCHEMA public FROM :"execution_runtime_role",:"execution_definer_role";
GRANT EXECUTE ON FUNCTION enrollment_execution.read_execution_record(uuid,uuid),enrollment_execution.read_and_lock_plan_context(uuid,uuid),
 enrollment_execution.authorize_and_store_candidate(uuid,uuid,text,bytea,bytea,bytea),
 enrollment_execution.record_execution_result(uuid,uuid,bytea,text,text,uuid,uuid,uuid,uuid,timestamptz,timestamptz,timestamptz,smallint,timestamptz,bytea,bytea),
 enrollment_execution.quarantine_execution(uuid,uuid,bytea,text),enrollment_execution.audit_execution_privileges(uuid) TO :"execution_runtime_role";
GRANT EXECUTE ON FUNCTION enrollment_execution.audit_execution_privileges(uuid) TO :"execution_definer_role";
\if :profile_absent
-- Marker is the final mutation of the one-time profile installation.
CREATE FUNCTION enrollment_execution.execution_store_profile() RETURNS smallint LANGUAGE sql IMMUTABLE PARALLEL SAFE SECURITY INVOKER
 SET search_path=pg_catalog,pg_temp AS 'SELECT 2::smallint';
REVOKE ALL ON FUNCTION enrollment_execution.execution_store_profile() FROM PUBLIC;
ALTER FUNCTION enrollment_execution.execution_store_profile() OWNER TO :"expected_table_owner_role";
\endif
DO $catalog_postflight$
DECLARE owner_oid oid; definer_oid oid; audit_oid oid;
BEGIN
 SELECT oid INTO owner_oid FROM pg_catalog.pg_roles WHERE rolname=current_setting('app.execution_install_owner');
 SELECT oid INTO definer_oid FROM pg_catalog.pg_roles WHERE rolname=current_setting('app.execution_install_definer');
 SELECT p.oid INTO audit_oid FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_language l ON l.oid=p.prolang
  WHERE p.oid=pg_catalog.to_regprocedure('enrollment_execution.audit_execution_privileges(uuid)')
    AND p.proowner=owner_oid AND l.lanname='plpgsql' AND p.prosecdef AND p.provolatile='s' AND p.proparallel='u'
    AND p.prokind='f' AND p.proretset AND p.prorettype='record'::regtype AND p.pronargs=1
    AND p.proargtypes='2950'::oidvector
    AND p.proargnames=ARRAY['p_environment','is_valid','diagnostic_code','profile_version']
    AND p.proallargtypes=ARRAY['uuid'::regtype::oid,'boolean'::regtype::oid,'text'::regtype::oid,'smallint'::regtype::oid]
    AND p.proargmodes=ARRAY['i','t','t','t']::"char"[]
    AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp','row_security=on']
    AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
      pg_catalog.btrim(pg_catalog.regexp_replace(p.prosrc,'[[:space:]]+',' ','g')),'UTF8')),'hex')
      ='8ed83a1a4736e9caab7c0a9c32ef8b2e53b48dbdcf184824a8436d3fc33d3da3';
 IF audit_oid IS NULL OR EXISTS(SELECT 1 FROM pg_catalog.aclexplode(
      COALESCE((SELECT proacl FROM pg_catalog.pg_proc WHERE oid=audit_oid),pg_catalog.acldefault('f',owner_oid))) acl
      WHERE acl.privilege_type<>'EXECUTE' OR acl.is_grantable OR acl.grantee=0
         OR acl.grantee NOT IN(owner_oid,definer_oid)
            AND acl.grantee NOT IN(SELECT role_oid FROM enrollment_execution.role_reservations WHERE role_kind='Runtime')) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='Enrollment execution catalog postflight failed.';
 END IF;
END
$catalog_postflight$;
DO $postflight$ DECLARE a record; BEGIN SELECT * INTO STRICT a FROM enrollment_execution.audit_execution_privileges(current_setting('app.execution_install_environment')::uuid);
 IF a.is_valid IS DISTINCT FROM TRUE OR a.diagnostic_code<>'None' OR a.profile_version<>2 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='Enrollment execution profile postflight failed.'; END IF; END $postflight$;
COMMIT;
