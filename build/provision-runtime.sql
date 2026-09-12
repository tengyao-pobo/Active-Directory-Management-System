\set ON_ERROR_STOP on
BEGIN;
-- Run by a DBA against the intended database after migrations.
-- Create the LOGIN role separately through your secret-management procedure.
-- Create the dedicated restricted NOLOGIN lock-owner role separately.
-- This script never embeds a password. psql: -v runtime_role=your_role -v enrollment_plan_lock_owner_role=your_lock_owner -f this-file
SELECT CASE WHEN btrim(:'runtime_role')<>'' AND btrim(:'enrollment_plan_lock_owner_role')<>''
    AND :'runtime_role'<>:'enrollment_plan_lock_owner_role' AND EXISTS (
    SELECT 1 FROM pg_roles r WHERE r.rolname=:'enrollment_plan_lock_owner_role' AND NOT r.rolcanlogin AND NOT r.rolsuper
        AND NOT r.rolbypassrls AND NOT r.rolcreatedb AND NOT r.rolcreaterole AND NOT r.rolinherit AND NOT r.rolreplication
        AND NOT EXISTS (SELECT 1 FROM pg_auth_members m WHERE m.roleid=r.oid OR m.member=r.oid)
        AND NOT EXISTS (SELECT 1 FROM pg_database d WHERE d.datdba=r.oid)
        AND NOT EXISTS (SELECT 1 FROM pg_namespace n WHERE n.nspowner=r.oid)
        AND NOT EXISTS (SELECT 1 FROM pg_class c WHERE c.relowner=r.oid)
        AND NOT EXISTS (SELECT 1 FROM pg_proc p WHERE p.proowner=r.oid AND p.oid<>'public.lock_enrollment_grant_plan_context(uuid,uuid,uuid[])'::regprocedure)
        AND NOT has_schema_privilege(r.rolname,'public','CREATE')
    ) AND EXISTS (
        SELECT 1 FROM pg_roles r WHERE r.rolname=:'runtime_role' AND r.rolcanlogin AND NOT r.rolsuper
        AND NOT r.rolbypassrls AND NOT r.rolcreatedb AND NOT r.rolcreaterole AND NOT r.rolinherit AND NOT r.rolreplication
        AND NOT EXISTS (SELECT 1 FROM pg_auth_members m WHERE m.roleid=r.oid OR m.member=r.oid)
        AND NOT EXISTS (SELECT 1 FROM pg_database d WHERE d.datdba=r.oid)
        AND NOT EXISTS (SELECT 1 FROM pg_namespace n WHERE n.nspowner=r.oid)
        AND NOT EXISTS (SELECT 1 FROM pg_class c WHERE c.relowner=r.oid)
        AND NOT EXISTS (SELECT 1 FROM pg_proc p WHERE p.proowner=r.oid)
    ) THEN 1 ELSE 1/(pg_catalog.pg_backend_pid()-pg_catalog.pg_backend_pid()) END AS enrollment_plan_lock_owner_preflight;
SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM enrollment_execution.role_reservations
    WHERE role_name IN (:'runtime_role'::name,:'enrollment_plan_lock_owner_role'::name)
       OR role_oid IN (:'runtime_role'::regrole::oid,:'enrollment_plan_lock_owner_role'::regrole::oid))
 THEN 1 ELSE 1/(pg_catalog.pg_backend_pid()-pg_catalog.pg_backend_pid()) END AS enrollment_execution_role_isolation_preflight;
-- Existing identities and grants may be absent or within this exact capability; never repurpose another login.
-- Anchor drift must fail before broad provisioning can remove the evidence.
SELECT CASE WHEN NOT EXISTS(
    SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_roles r ON r.rolname=:'runtime_role'
    WHERE c.relnamespace='public'::regnamespace AND c.relname IN ('Plans','PlanItems','Approvals','Outbox')
    AND (pg_catalog.has_table_privilege(r.oid,c.oid,'TRUNCATE') OR pg_catalog.has_table_privilege(r.oid,c.oid,'TRIGGER'))
) THEN 1 ELSE 1/(pg_catalog.pg_backend_pid()-pg_catalog.pg_backend_pid()) END AS enrollment_anchor_privilege_preflight;
WITH locker AS (SELECT oid FROM pg_roles WHERE rolname=:'enrollment_plan_lock_owner_role'),
runtime AS (SELECT oid FROM pg_roles WHERE rolname=:'runtime_role'),
allowed_tables(table_name,privilege_type) AS (VALUES
    ('DirectoryDatabaseBindings','SELECT'),('Environments','SELECT'),('Environments','UPDATE'),
    ('DirectorySync','SELECT'),('DirectorySync','UPDATE'),('DirectoryObjects','SELECT'),('DirectoryObjects','UPDATE'),
    ('Principals','SELECT'),('Principals','UPDATE'),('Memberships','SELECT'),('Memberships','UPDATE')),
reservation_acl AS (
    SELECT a.privilege_type,a.is_grantable FROM pg_class c
    CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
    WHERE c.oid='public."EnrollmentGrantRecipientReservations"'::regclass AND a.grantee=(SELECT oid FROM runtime)
), operation_acl AS (
    SELECT a.privilege_type,a.is_grantable FROM pg_class c
    CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
    WHERE c.oid='public."EnrollmentGrantOperations"'::regclass AND a.grantee=(SELECT oid FROM runtime)
)
SELECT CASE WHEN
    NOT EXISTS(SELECT 1 FROM operation_acl WHERE privilege_type NOT IN ('SELECT','INSERT') OR is_grantable) AND
    NOT EXISTS(SELECT 1 FROM pg_attribute a CROSS JOIN LATERAL aclexplode(a.attacl) acl
        WHERE a.attrelid='public."EnrollmentGrantOperations"'::regclass AND acl.grantee=(SELECT oid FROM runtime)) AND
    NOT EXISTS (SELECT 1 FROM public."DirectoryDatabaseBindings"
        WHERE "LoginRole"=:'runtime_role' AND ("Purpose" IS DISTINCT FROM 'Api' OR "EnvironmentId" IS NOT NULL OR "PrincipalId" IS NOT NULL)) AND
    NOT EXISTS (SELECT 1 FROM public."DirectoryDatabaseBindings" WHERE "LoginRole"=:'enrollment_plan_lock_owner_role') AND
    NOT EXISTS (
        SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
        WHERE a.grantee=(SELECT oid FROM locker) AND
            (a.is_grantable OR n.nspname<>'public' OR c.relkind<>'r' OR NOT EXISTS (
                SELECT 1 FROM allowed_tables t WHERE t.table_name=c.relname AND t.privilege_type=a.privilege_type))) AND
    NOT EXISTS (
        SELECT 1 FROM pg_proc p CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
        WHERE a.grantee=(SELECT oid FROM locker) AND (a.is_grantable OR a.privilege_type<>'EXECUTE' OR p.oid NOT IN (
            'public.has_environment_membership(uuid,uuid)'::regprocedure,'public.directory_database_access(uuid,uuid)'::regprocedure))) AND
    NOT EXISTS (
        SELECT 1 FROM pg_namespace n CROSS JOIN LATERAL aclexplode(coalesce(n.nspacl,acldefault('n',n.nspowner))) a
        WHERE a.grantee=(SELECT oid FROM locker) AND (n.nspname<>'public' OR a.privilege_type<>'USAGE' OR a.is_grantable)) AND
    NOT EXISTS (SELECT 1 FROM pg_attribute a CROSS JOIN LATERAL aclexplode(a.attacl) acl WHERE acl.grantee=(SELECT oid FROM locker)) AND
    NOT EXISTS (SELECT 1 FROM pg_class c WHERE CASE WHEN c.relkind='S' THEN has_sequence_privilege(:'enrollment_plan_lock_owner_role',c.oid,'USAGE,SELECT,UPDATE') ELSE false END) AND
    NOT EXISTS (
        SELECT 1 FROM pg_proc p CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
        WHERE p.oid='public.lock_enrollment_grant_plan_context(uuid,uuid,uuid[])'::regprocedure
            AND a.grantee=(SELECT oid FROM runtime) AND (a.is_grantable OR a.privilege_type<>'EXECUTE')) AND
    (NOT EXISTS (SELECT 1 FROM reservation_acl) OR (
        (SELECT count(*) FROM reservation_acl WHERE privilege_type='SELECT')=1 AND
        (SELECT count(*) FROM reservation_acl WHERE privilege_type='INSERT')=1 AND
        NOT EXISTS (SELECT 1 FROM reservation_acl WHERE is_grantable OR privilege_type NOT IN ('SELECT','INSERT')))) AND
    NOT EXISTS (SELECT 1 FROM pg_attribute a CROSS JOIN LATERAL aclexplode(a.attacl) acl
        WHERE a.attrelid='public."EnrollmentGrantRecipientReservations"'::regclass AND acl.grantee=(SELECT oid FROM runtime))
 AND
    NOT has_database_privilege(:'runtime_role',current_database(),'CREATE') AND
    NOT has_database_privilege(:'enrollment_plan_lock_owner_role',current_database(),'CREATE') AND
    NOT has_schema_privilege(:'runtime_role','public','CREATE') AND
    NOT has_table_privilege(:'runtime_role','public."DirectorySync"','INSERT,UPDATE,DELETE,TRUNCATE') AND
    NOT has_table_privilege(:'runtime_role','public."DirectoryObjects"','INSERT,UPDATE,DELETE,TRUNCATE') AND
    NOT has_any_column_privilege(:'runtime_role','public."DirectorySync"','INSERT,UPDATE') AND
    NOT has_any_column_privilege(:'runtime_role','public."DirectoryObjects"','INSERT,UPDATE') AND
    NOT EXISTS (SELECT 1 FROM runtime r JOIN pg_namespace n ON n.nspname<>'public'
        CROSS JOIN LATERAL aclexplode(n.nspacl) acl WHERE acl.grantee=r.oid) AND
    NOT EXISTS (SELECT 1 FROM runtime r JOIN pg_class c ON true JOIN pg_namespace n ON n.oid=c.relnamespace AND n.nspname<>'public'
        CROSS JOIN LATERAL aclexplode(c.relacl) acl WHERE acl.grantee=r.oid) AND
    NOT EXISTS (SELECT 1 FROM runtime r JOIN pg_attribute a ON a.attrelid<>0 JOIN pg_class c ON c.oid=a.attrelid
        JOIN pg_namespace n ON n.oid=c.relnamespace AND n.nspname<>'public' CROSS JOIN LATERAL aclexplode(a.attacl) acl WHERE acl.grantee=r.oid) AND
    NOT EXISTS (SELECT 1 FROM runtime r JOIN pg_proc p ON true JOIN pg_namespace n ON n.oid=p.pronamespace AND n.nspname<>'public'
        CROSS JOIN LATERAL aclexplode(p.proacl) acl WHERE acl.grantee=r.oid)
    THEN 1 ELSE 1/(pg_catalog.pg_backend_pid()-pg_catalog.pg_backend_pid()) END AS enrollment_plan_capability_preflight;
GRANT CONNECT ON DATABASE :DBNAME TO :"runtime_role";
GRANT USAGE ON SCHEMA public TO :"runtime_role";
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM :"runtime_role";
GRANT EXECUTE ON FUNCTION public.has_environment_membership(uuid, uuid) TO :"runtime_role";
REVOKE ALL ON FUNCTION public.lock_enrollment_grant_plan_context(uuid,uuid,uuid[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.lock_enrollment_grant_plan_context(uuid,uuid,uuid[]) FROM :"enrollment_plan_lock_owner_role";
REVOKE ALL ON FUNCTION public.lock_enrollment_grant_plan_context(uuid,uuid,uuid[]) FROM CURRENT_USER;
ALTER FUNCTION public.lock_enrollment_grant_plan_context(uuid,uuid,uuid[]) OWNER TO :"enrollment_plan_lock_owner_role";
GRANT USAGE ON SCHEMA public TO :"enrollment_plan_lock_owner_role";
GRANT EXECUTE ON FUNCTION public.has_environment_membership(uuid,uuid), public.directory_database_access(uuid,uuid) TO :"enrollment_plan_lock_owner_role";
GRANT SELECT ON "DirectoryDatabaseBindings" TO :"enrollment_plan_lock_owner_role";
GRANT SELECT, UPDATE ON "Environments", "DirectorySync", "DirectoryObjects", "Principals", "Memberships" TO :"enrollment_plan_lock_owner_role";
GRANT EXECUTE ON FUNCTION public.lock_enrollment_grant_plan_context(uuid,uuid,uuid[]) TO :"runtime_role";
INSERT INTO "DirectoryDatabaseBindings" ("LoginRole","Purpose") VALUES (:'runtime_role','Api')
    ON CONFLICT ("LoginRole") DO UPDATE SET "Purpose"='Api',"EnvironmentId"=NULL,"PrincipalId"=NULL;
GRANT EXECUTE ON FUNCTION public.directory_database_access(uuid,uuid), public.directory_connector_scope(uuid,uuid) TO :"runtime_role";
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO :"runtime_role";
REVOKE ALL ON "__EFMigrationsHistory" FROM :"runtime_role";
REVOKE ALL ON "DirectoryDatabaseBindings" FROM :"runtime_role";
REVOKE UPDATE, DELETE, TRUNCATE ON "Audit", "SecurityEvents" FROM :"runtime_role";
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON "Principals" FROM :"runtime_role";
REVOKE INSERT, DELETE, TRUNCATE ON "LocalCredentials" FROM :"runtime_role";
REVOKE INSERT, DELETE, TRUNCATE ON "EnrollmentGrants" FROM :"runtime_role";
REVOKE TRUNCATE ON ALL TABLES IN SCHEMA public FROM :"runtime_role";
REVOKE INSERT, UPDATE, DELETE ON "DirectoryObjects", "DirectorySync" FROM :"runtime_role";
REVOKE DELETE ON "DeviceTags" FROM :"runtime_role";
REVOKE UPDATE ON "SavedFilters" FROM :"runtime_role";
GRANT UPDATE ("Name","Kind","Search","TagId","Version","UpdatedAt") ON "SavedFilters" TO :"runtime_role";
REVOKE UPDATE, DELETE, TRUNCATE ON "EnrollmentGrantRecipientReservations" FROM :"runtime_role";
REVOKE SELECT ("Fingerprint","EnvironmentId","PlanId","RequesterId","RequestId","RequestDigest","CreatedAt"),
    INSERT ("Fingerprint","EnvironmentId","PlanId","RequesterId","RequestId","RequestDigest","CreatedAt"),
    UPDATE ("Fingerprint","EnvironmentId","PlanId","RequesterId","RequestId","RequestDigest","CreatedAt"),
    REFERENCES ("Fingerprint","EnvironmentId","PlanId","RequesterId","RequestId","RequestDigest","CreatedAt")
    ON "EnrollmentGrantRecipientReservations" FROM :"runtime_role";
GRANT SELECT, INSERT ON "EnrollmentGrantRecipientReservations" TO :"runtime_role";
REVOKE UPDATE, DELETE, TRUNCATE ON "EnrollmentGrantOperations" FROM :"runtime_role";
GRANT SELECT, INSERT ON "EnrollmentGrantOperations" TO :"runtime_role";
REVOKE UPDATE ON "DeviceTags", "DeviceTagAssignments" FROM :"runtime_role";
GRANT UPDATE ("Version", "ArchivedAt", "UpdatedAt", "UpdatedBy") ON "DeviceTags" TO :"runtime_role";
-- Keep this catalog query aligned with EnrollmentGrantPlanApi.LockHelperIsValidAsync.
WITH verified_profile AS (
WITH target AS (
    SELECT p.*,r.oid AS owner_oid,r.rolname AS owner_name,r.rolcanlogin,r.rolsuper,r.rolbypassrls,
        r.rolcreatedb,r.rolcreaterole,r.rolinherit,r.rolreplication,l.lanname
    FROM pg_proc p JOIN pg_roles r ON r.oid=p.proowner JOIN pg_language l ON l.oid=p.prolang
    WHERE p.oid='public.lock_enrollment_grant_plan_context(uuid,uuid,uuid[])'::regprocedure
), expected_tables(schema_name,table_name,privilege_type,is_grantable) AS (VALUES
    ('public','DirectoryDatabaseBindings','SELECT',false),('public','Environments','SELECT',false),('public','Environments','UPDATE',false),
    ('public','DirectorySync','SELECT',false),('public','DirectorySync','UPDATE',false),('public','DirectoryObjects','SELECT',false),('public','DirectoryObjects','UPDATE',false),
    ('public','Principals','SELECT',false),('public','Principals','UPDATE',false),('public','Memberships','SELECT',false),('public','Memberships','UPDATE',false)
), actual_tables AS (
    SELECT n.nspname::text AS schema_name,c.relname::text AS table_name,a.privilege_type::text,a.is_grantable
    FROM target t JOIN pg_class c ON true JOIN pg_namespace n ON n.oid=c.relnamespace
    CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
    WHERE c.relkind IN ('r','p','v','m','f') AND a.grantee=t.owner_oid
), expected_functions(function_oid,is_grantable) AS (VALUES
    ('public.has_environment_membership(uuid,uuid)'::regprocedure::oid,false),('public.directory_database_access(uuid,uuid)'::regprocedure::oid,false)
), actual_functions AS (
    SELECT p.oid AS function_oid,a.is_grantable
    FROM target t JOIN pg_proc p ON true CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
    WHERE a.grantee=t.owner_oid AND a.privilege_type='EXECUTE'
), actual_lock_acl AS (
    SELECT a.grantee,a.is_grantable FROM target t
    CROSS JOIN LATERAL aclexplode(coalesce(t.proacl,acldefault('f',t.proowner))) a
    WHERE a.privilege_type='EXECUTE'
), expected_lock_acl AS (
    SELECT r.oid AS grantee,false AS is_grantable FROM pg_roles r WHERE r.rolname=:'runtime_role'
), reservation AS (
    SELECT c.oid,c.relowner,c.relrowsecurity,c.relforcerowsecurity
    FROM pg_class c WHERE c.oid='public."EnrollmentGrantRecipientReservations"'::regclass AND c.relkind='r'
), expected_columns(column_name,type_name,is_not_null) AS (VALUES
    ('Fingerprint','bytea',true),('EnvironmentId','uuid',true),('PlanId','uuid',true),('RequesterId','uuid',true),
    ('RequestId','uuid',true),('RequestDigest','bytea',true),('CreatedAt','timestamp with time zone',true)
), actual_columns AS (
    SELECT a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull
    FROM reservation r JOIN pg_attribute a ON a.attrelid=r.oid
    WHERE a.attnum>0 AND NOT a.attisdropped
), expected_reservation_acl(privilege_type,is_grantable) AS (VALUES ('SELECT',false),('INSERT',false)),
actual_reservation_acl AS (
    SELECT a.privilege_type::text,a.is_grantable
    FROM reservation r CROSS JOIN LATERAL aclexplode(coalesce((SELECT relacl FROM pg_class WHERE oid=r.oid),acldefault('r',r.relowner))) a
    JOIN pg_roles role ON role.oid=a.grantee
    WHERE a.grantee<>r.relowner AND role.rolname=:'runtime_role'
), unexpected_reservation_acl AS (
    SELECT 1 FROM reservation r CROSS JOIN LATERAL aclexplode(coalesce((SELECT relacl FROM pg_class WHERE oid=r.oid),acldefault('r',r.relowner))) a
    LEFT JOIN pg_roles role ON role.oid=a.grantee
    WHERE a.grantee<>r.relowner AND (a.grantee=0 OR role.rolname IS DISTINCT FROM :'runtime_role')
), execution_marker AS (
    SELECT p.*,l.lanname FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='enrollment_execution' AND p.proname='execution_store_profile' AND p.pronargs=0
), execution_audit AS (
    SELECT p.*,l.lanname FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='enrollment_execution' AND p.proname='audit_execution_privileges' AND p.proargtypes='2950'::oidvector
), execution_definer AS (
    SELECT r.* FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles r ON r.oid=p.proowner
    WHERE n.nspname='enrollment_execution' AND p.proname='read_execution_record' AND p.proargtypes='2950 2950'::oidvector
), execution_profile AS (
    SELECT COALESCE(
      (SELECT count(*)=1 AND bool_and(lanname='sql' AND NOT prosecdef AND provolatile='i' AND proparallel='s'
        AND proowner=(SELECT relowner FROM reservation) AND proconfig=ARRAY['search_path=pg_catalog, pg_temp']
        AND btrim(prosrc,E' \t\r\n') IN('SELECT 2::smallint','SELECT 3::smallint')) FROM execution_marker)
      AND (SELECT count(*)=1 AND bool_and(lanname='plpgsql' AND prosecdef AND provolatile='s' AND proparallel='u'
        AND proowner=(SELECT relowner FROM reservation) AND proconfig=ARRAY['search_path=pg_catalog, pg_temp','row_security=on']
        AND encode(sha256(convert_to(btrim(regexp_replace(prosrc,'[[:space:]]+',' ','g')),'UTF8')),'hex')
          =CASE (SELECT btrim(prosrc,E' \t\r\n') FROM execution_marker)
             WHEN 'SELECT 2::smallint' THEN '8ed83a1a4736e9caab7c0a9c32ef8b2e53b48dbdcf184824a8436d3fc33d3da3'
             WHEN 'SELECT 3::smallint' THEN 'ec0ae2639db2b390471dd63fba05c7851a34112068e425d2d60066770fa16650'
             ELSE '' END) FROM execution_audit)
      AND (SELECT count(*)=1 AND bool_and(NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcreatedb
        AND NOT rolcreaterole AND NOT rolinherit AND NOT rolreplication) FROM execution_definer),false) installed
), reject_function AS (
    SELECT p.*,l.lanname FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang
    WHERE p.oid='public.reject_enrollment_grant_reservation_mutation()'::regprocedure
), runtime AS (
    SELECT * FROM pg_roles WHERE rolname=:'runtime_role'
), expected_schema_acl(schema_name,privilege_type,is_grantable) AS (VALUES ('public','USAGE',false)),
actual_schema_acl AS (
    SELECT n.nspname::text,acl.privilege_type::text,acl.is_grantable
    FROM target t JOIN pg_namespace n ON true CROSS JOIN LATERAL aclexplode(n.nspacl) acl
    WHERE acl.grantee=t.owner_oid
)
SELECT valid AS "IsValid", CASE WHEN valid THEN 'None' ELSE 'PrivilegeAuditFailed' END AS "DiagnosticCode",
    1::smallint AS "ProfileVersion" FROM (SELECT ((SELECT count(*) FROM target)=1 AND
    (SELECT lanname='plpgsql' AND prosecdef AND provolatile='v' AND proparallel='u' AND prorettype='void'::regtype AND
        proargtypes='2950 2950 2951'::oidvector AND
        proargnames=ARRAY['p_environment_id','p_directory_object_id','p_principal_ids'] AND proallargtypes IS NULL AND proargmodes IS NULL AND
        proconfig=ARRAY['search_path=pg_catalog, pg_temp'] AND NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls AND
        NOT rolcreatedb AND NOT rolcreaterole AND NOT rolinherit AND NOT rolreplication FROM target) AND
    NOT EXISTS (SELECT 1 FROM target t JOIN pg_auth_members m ON m.roleid=t.owner_oid OR m.member=t.owner_oid) AND
    NOT EXISTS (SELECT 1 FROM target t JOIN pg_database d ON d.datdba=t.owner_oid) AND
    NOT EXISTS (SELECT 1 FROM target t JOIN pg_namespace n ON n.nspowner=t.owner_oid) AND
    NOT EXISTS (SELECT 1 FROM target t JOIN pg_class c ON c.relowner=t.owner_oid) AND
    NOT EXISTS (SELECT 1 FROM target t JOIN pg_proc p ON p.proowner=t.owner_oid WHERE p.oid<>t.oid) AND
    NOT EXISTS (SELECT * FROM expected_tables EXCEPT SELECT * FROM actual_tables) AND
    NOT EXISTS (SELECT * FROM actual_tables EXCEPT SELECT * FROM expected_tables) AND
    NOT EXISTS (SELECT * FROM expected_functions EXCEPT SELECT * FROM actual_functions) AND
    NOT EXISTS (SELECT * FROM actual_functions EXCEPT SELECT * FROM expected_functions) AND
    NOT EXISTS (SELECT * FROM expected_schema_acl EXCEPT SELECT * FROM actual_schema_acl) AND
    NOT EXISTS (SELECT * FROM actual_schema_acl EXCEPT SELECT * FROM expected_schema_acl) AND
    NOT EXISTS (SELECT 1 FROM target t JOIN pg_attribute a ON a.attrelid<>0 CROSS JOIN LATERAL aclexplode(a.attacl) acl WHERE acl.grantee=t.owner_oid) AND
    NOT EXISTS (SELECT 1 FROM target t JOIN pg_class c ON true WHERE CASE WHEN c.relkind='S' THEN has_sequence_privilege(t.owner_name,c.oid,'USAGE,SELECT,UPDATE') ELSE false END) AND
    NOT EXISTS (SELECT * FROM expected_lock_acl EXCEPT SELECT * FROM actual_lock_acl) AND
    NOT EXISTS (SELECT * FROM actual_lock_acl EXCEPT SELECT * FROM expected_lock_acl) AND
    NOT has_table_privilege(:'runtime_role','public."DirectorySync"','INSERT,UPDATE,DELETE,TRUNCATE') AND
    NOT has_table_privilege(:'runtime_role','public."DirectoryObjects"','INSERT,UPDATE,DELETE,TRUNCATE') AND
    NOT has_any_column_privilege(:'runtime_role','public."DirectorySync"','INSERT,UPDATE') AND
    NOT has_any_column_privilege(:'runtime_role','public."DirectoryObjects"','INSERT,UPDATE') AND
    (SELECT count(*)=1 AND bool_and(relrowsecurity AND relforcerowsecurity) FROM reservation) AND
    NOT EXISTS (SELECT * FROM expected_columns EXCEPT SELECT * FROM actual_columns) AND
    NOT EXISTS (SELECT * FROM actual_columns EXCEPT SELECT * FROM expected_columns) AND
    NOT EXISTS (SELECT * FROM expected_reservation_acl EXCEPT SELECT * FROM actual_reservation_acl) AND
    NOT EXISTS (SELECT * FROM actual_reservation_acl EXCEPT SELECT * FROM expected_reservation_acl) AND
    NOT EXISTS (SELECT 1 FROM unexpected_reservation_acl) AND
    (SELECT CASE WHEN profile.installed THEN
      (SELECT count(*)=7 AND bool_and(acl.grantee=(SELECT oid FROM execution_definer)
          AND acl.privilege_type='SELECT' AND NOT acl.is_grantable
          AND a.attname IN('Fingerprint','EnvironmentId','PlanId','RequesterId','RequestId','RequestDigest','CreatedAt'))
       FROM reservation r JOIN pg_attribute a ON a.attrelid=r.oid CROSS JOIN LATERAL aclexplode(a.attacl) acl)
      ELSE NOT EXISTS(SELECT 1 FROM reservation r JOIN pg_attribute a ON a.attrelid=r.oid
          CROSS JOIN LATERAL aclexplode(a.attacl) acl) END FROM execution_profile profile) AND
    (SELECT count(*)=1 FROM pg_constraint c JOIN reservation r ON r.oid=c.conrelid
        WHERE c.contype='p' AND c.conkey=ARRAY[(SELECT attnum FROM pg_attribute WHERE attrelid=r.oid AND attname='Fingerprint')]::smallint[]) AND
    (SELECT count(*)=1 FROM pg_index i JOIN reservation r ON r.oid=i.indrelid
        WHERE i.indisunique AND i.indisvalid AND i.indisready AND NOT i.indisprimary AND i.indpred IS NULL AND
        ARRAY(SELECT a.attname::text FROM unnest(i.indkey) WITH ORDINALITY k(attnum,ord) JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=k.attnum ORDER BY k.ord)
        =ARRAY['EnvironmentId','PlanId']) AND
    (SELECT count(*)=1 FROM pg_index i JOIN reservation r ON r.oid=i.indrelid
        WHERE i.indisunique AND i.indisvalid AND i.indisready AND NOT i.indisprimary AND i.indpred IS NULL AND
        ARRAY(SELECT a.attname::text FROM unnest(i.indkey) WITH ORDINALITY k(attnum,ord) JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=k.attnum ORDER BY k.ord)
        =ARRAY['EnvironmentId','RequesterId','RequestId']) AND
    (SELECT count(*)=3 FROM pg_index i JOIN reservation r ON r.oid=i.indrelid WHERE i.indisunique AND NOT i.indisprimary) AND
                (SELECT count(*)=1 FROM pg_index i JOIN reservation r ON r.oid=i.indrelid
                    WHERE i.indisunique AND i.indisvalid AND i.indisready AND NOT i.indisprimary AND i.indpred IS NULL AND i.indexprs IS NULL AND i.indnatts=5 AND
                    ARRAY(SELECT a.attname::text FROM unnest(i.indkey) WITH ORDINALITY k(attnum,ord) JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=k.attnum ORDER BY k.ord)
                    =ARRAY['Fingerprint','EnvironmentId','PlanId','RequesterId','RequestId']) AND
    (SELECT count(*)=1 FROM pg_constraint c JOIN reservation r ON r.oid=c.conrelid WHERE c.contype='f' AND c.confrelid='public."Plans"'::regclass AND c.confdeltype='r' AND
        pg_get_constraintdef(c.oid,true)='FOREIGN KEY ("EnvironmentId", "PlanId") REFERENCES "Plans"("EnvironmentId", "Id") ON DELETE RESTRICT') AND
    (SELECT count(*)=3 FROM pg_constraint c JOIN reservation r ON r.oid=c.conrelid WHERE c.contype='c' AND c.convalidated AND
        (c.conname,pg_get_constraintdef(c.oid,true)) IN (
            ('enrollment_grant_recipient_fingerprint_length','CHECK (octet_length("Fingerprint") = 32)'),
            ('enrollment_grant_request_digest_length','CHECK (octet_length("RequestDigest") = 32)'),
            ('enrollment_grant_reservation_ids_nonempty','CHECK ("EnvironmentId" <> ''00000000-0000-0000-0000-000000000000''::uuid AND "PlanId" <> ''00000000-0000-0000-0000-000000000000''::uuid AND "RequesterId" <> ''00000000-0000-0000-0000-000000000000''::uuid AND "RequestId" <> ''00000000-0000-0000-0000-000000000000''::uuid)'))) AND
    EXISTS (SELECT 1 FROM pg_constraint c WHERE c.conrelid='public."Plans"'::regclass AND c.conname='enrollment_grant_plan_never_executed' AND c.contype='c' AND c.convalidated AND
        pg_get_constraintdef(c.oid,true)='CHECK ("Action" <> ''agent-enrollment.initial-grant.v1''::text OR "State" <> 2)') AND
    (SELECT count(*)=CASE WHEN (SELECT installed FROM execution_profile) THEN 3 ELSE 1 END
       FROM pg_policy p JOIN reservation r ON r.oid=p.polrelid) AND
    (SELECT count(*)=1 FROM pg_policy p JOIN reservation r ON r.oid=p.polrelid WHERE p.polname='environment_enrollment_grant_recipient_reservations' AND p.polcmd='*' AND p.polpermissive AND p.polroles=ARRAY[0::oid] AND
        pg_get_expr(p.polqual,p.polrelid)=pg_get_expr(p.polwithcheck,p.polrelid) AND
        pg_get_expr(p.polqual,p.polrelid)='((("EnvironmentId")::text = current_setting(''app.environment_id''::text, true)) AND has_environment_membership("EnvironmentId", (NULLIF(current_setting(''app.principal_id''::text, true), ''''::text))::uuid))') AND
    (SELECT NOT profile.installed OR (SELECT count(*)=2 AND bool_and(p.polcmd='r' AND p.polroles=ARRAY[(SELECT oid FROM execution_definer)]
        AND ((p.polname='enrollment_execution_worker_reservations_allow' AND p.polpermissive)
          OR (p.polname='enrollment_execution_worker_reservations_limit' AND NOT p.polpermissive))
        AND p.polwithcheck IS NULL
        AND md5(COALESCE(pg_get_expr(p.polqual,p.polrelid),'')||'|'||COALESCE(pg_get_expr(p.polwithcheck,p.polrelid),''))
          ='158b72978f11ad4651c98e8dbe14e0c0')
      FROM pg_policy p JOIN reservation r ON r.oid=p.polrelid
      WHERE p.polname IN('enrollment_execution_worker_reservations_allow','enrollment_execution_worker_reservations_limit'))
     FROM execution_profile profile) AND
    (SELECT count(*)=1 FROM pg_trigger tg JOIN reservation r ON r.oid=tg.tgrelid WHERE NOT tg.tgisinternal) AND
    (SELECT count(*)=1 FROM pg_trigger tg JOIN reservation r ON r.oid=tg.tgrelid WHERE NOT tg.tgisinternal AND tg.tgenabled='O' AND tg.tgname='enrollment_grant_recipient_reservations_immutable' AND
        tg.tgfoid='public.reject_enrollment_grant_reservation_mutation()'::regprocedure AND (tg.tgtype & 1)=1 AND (tg.tgtype & 2)=2 AND (tg.tgtype & 8)=8 AND (tg.tgtype & 16)=16 AND (tg.tgtype & 4)=0) AND
    (SELECT count(*)=1 AND bool_and(lanname='plpgsql' AND NOT prosecdef AND provolatile='v' AND proparallel='u' AND prorettype='trigger'::regtype AND
        proargtypes=''::oidvector AND proargnames IS NULL AND proallargtypes IS NULL AND proargmodes IS NULL AND
        proconfig=ARRAY['search_path=pg_catalog, public, pg_temp'] AND proowner=(SELECT relowner FROM reservation)) FROM reject_function) AND
    (SELECT count(*)=1 FROM reject_function rf CROSS JOIN LATERAL aclexplode(coalesce(rf.proacl,acldefault('f',rf.proowner))) acl
        WHERE acl.grantee=rf.proowner AND acl.privilege_type='EXECUTE' AND NOT acl.is_grantable) AND
    (SELECT count(*)=1 FROM reject_function rf CROSS JOIN LATERAL aclexplode(coalesce(rf.proacl,acldefault('f',rf.proowner))) acl WHERE acl.privilege_type='EXECUTE') AND
    has_schema_privilege((SELECT owner_name FROM target),'public','USAGE') AND NOT has_schema_privilege((SELECT owner_name FROM target),'public','CREATE') AND
    NOT has_database_privilege((SELECT owner_name FROM target),current_database(),'CREATE') AND
    NOT has_database_privilege(:'runtime_role',current_database(),'CREATE') AND NOT has_schema_privilege(:'runtime_role','public','CREATE') AND
    (SELECT count(*)=1 AND bool_and(rolcanlogin AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolinherit AND NOT rolreplication) FROM runtime) AND
    NOT EXISTS (SELECT 1 FROM runtime r JOIN pg_auth_members m ON m.roleid=r.oid OR m.member=r.oid) AND
    NOT EXISTS (SELECT 1 FROM runtime r JOIN pg_database d ON d.datdba=r.oid) AND
    NOT EXISTS (SELECT 1 FROM runtime r JOIN pg_namespace n ON n.nspowner=r.oid) AND
    NOT EXISTS (SELECT 1 FROM runtime r JOIN pg_class c ON c.relowner=r.oid) AND
    NOT EXISTS (SELECT 1 FROM runtime r JOIN pg_proc p ON p.proowner=r.oid) AND
    NOT EXISTS (SELECT 1 FROM runtime r JOIN pg_namespace n ON n.nspname<>'public' CROSS JOIN LATERAL aclexplode(n.nspacl) acl WHERE acl.grantee=r.oid) AND
    NOT EXISTS (SELECT 1 FROM runtime r JOIN pg_class c ON true JOIN pg_namespace n ON n.oid=c.relnamespace AND n.nspname<>'public'
        CROSS JOIN LATERAL aclexplode(c.relacl) acl WHERE acl.grantee=r.oid) AND
    NOT EXISTS (SELECT 1 FROM runtime r JOIN pg_attribute a ON a.attrelid<>0 JOIN pg_class c ON c.oid=a.attrelid
        JOIN pg_namespace n ON n.oid=c.relnamespace AND n.nspname<>'public' CROSS JOIN LATERAL aclexplode(a.attacl) acl WHERE acl.grantee=r.oid) AND
    NOT EXISTS (SELECT 1 FROM runtime r JOIN pg_proc p ON true JOIN pg_namespace n ON n.oid=p.pronamespace AND n.nspname<>'public'
        CROSS JOIN LATERAL aclexplode(p.proacl) acl WHERE acl.grantee=r.oid)) AS valid) audit
)
SELECT CASE WHEN
    (SELECT "IsValid" AND "DiagnosticCode"='None' AND "ProfileVersion"=1 FROM verified_profile) IS TRUE AND
    EXISTS (SELECT 1 FROM pg_proc p JOIN pg_roles r ON r.oid=p.proowner
        WHERE p.oid='public.lock_enrollment_grant_plan_context(uuid,uuid,uuid[])'::regprocedure
            AND r.rolname=:'enrollment_plan_lock_owner_role'
            AND encode(sha256(convert_to(btrim(replace(p.prosrc,E'\r\n',E'\n'),E' \t\r\n'),'UTF8')),'hex')='b9a6befb836015684839e3c4483ec2944c74320e3ab4bc5bc2d3c971fa3dd2bd') AND
    EXISTS (SELECT 1 FROM pg_proc p
        WHERE p.oid='public.reject_enrollment_grant_reservation_mutation()'::regprocedure
            AND encode(sha256(convert_to(btrim(replace(p.prosrc,E'\r\n',E'\n'),E' \t\r\n'),'UTF8')),'hex')='1e63149eed78eefadac5046c5acc6d507fe94bc7f43cc640fc5f6437fc7172d7') AND
    EXISTS (SELECT 1 FROM public."DirectoryDatabaseBindings" WHERE "LoginRole"=:'runtime_role'
        AND "Purpose"='Api' AND "EnvironmentId" IS NULL AND "PrincipalId" IS NULL)
    THEN 1 ELSE 1/(pg_catalog.pg_backend_pid()-pg_catalog.pg_backend_pid()) END AS enrollment_plan_profile_postflight;
WITH locker AS (SELECT oid FROM pg_roles WHERE rolname=:'enrollment_plan_lock_owner_role'),
runtime AS (SELECT oid FROM pg_roles WHERE rolname=:'runtime_role'),
allowed_tables(table_name,privilege_type) AS (VALUES
    ('DirectoryDatabaseBindings','SELECT'),('Environments','SELECT'),('Environments','UPDATE'),
    ('DirectorySync','SELECT'),('DirectorySync','UPDATE'),('DirectoryObjects','SELECT'),('DirectoryObjects','UPDATE'),
    ('Principals','SELECT'),('Principals','UPDATE'),('Memberships','SELECT'),('Memberships','UPDATE')),
reservation_acl AS (
    SELECT a.privilege_type,a.is_grantable FROM pg_class c
    CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
    WHERE c.oid='public."EnrollmentGrantRecipientReservations"'::regclass AND a.grantee=(SELECT oid FROM runtime)
)
SELECT CASE WHEN
    NOT EXISTS (SELECT 1 FROM public."DirectoryDatabaseBindings"
        WHERE "LoginRole"=:'runtime_role' AND ("Purpose" IS DISTINCT FROM 'Api' OR "EnvironmentId" IS NOT NULL OR "PrincipalId" IS NOT NULL)) AND
    NOT EXISTS (SELECT 1 FROM public."DirectoryDatabaseBindings" WHERE "LoginRole"=:'enrollment_plan_lock_owner_role') AND
    NOT EXISTS (
        SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
        WHERE a.grantee=(SELECT oid FROM locker) AND
            (a.is_grantable OR n.nspname<>'public' OR c.relkind<>'r' OR NOT EXISTS (
                SELECT 1 FROM allowed_tables t WHERE t.table_name=c.relname AND t.privilege_type=a.privilege_type))) AND
    NOT EXISTS (
        SELECT 1 FROM pg_proc p CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
        WHERE a.grantee=(SELECT oid FROM locker) AND (a.is_grantable OR a.privilege_type<>'EXECUTE' OR p.oid NOT IN (
            'public.has_environment_membership(uuid,uuid)'::regprocedure,'public.directory_database_access(uuid,uuid)'::regprocedure))) AND
    NOT EXISTS (
        SELECT 1 FROM pg_namespace n CROSS JOIN LATERAL aclexplode(coalesce(n.nspacl,acldefault('n',n.nspowner))) a
        WHERE a.grantee=(SELECT oid FROM locker) AND (n.nspname<>'public' OR a.privilege_type<>'USAGE' OR a.is_grantable)) AND
    NOT EXISTS (SELECT 1 FROM pg_attribute a CROSS JOIN LATERAL aclexplode(a.attacl) acl WHERE acl.grantee=(SELECT oid FROM locker)) AND
    NOT EXISTS (SELECT 1 FROM pg_class c WHERE CASE WHEN c.relkind='S' THEN has_sequence_privilege(:'enrollment_plan_lock_owner_role',c.oid,'USAGE,SELECT,UPDATE') ELSE false END) AND
    NOT EXISTS (
        SELECT 1 FROM pg_proc p CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
        WHERE p.oid='public.lock_enrollment_grant_plan_context(uuid,uuid,uuid[])'::regprocedure
            AND a.grantee=(SELECT oid FROM runtime) AND (a.is_grantable OR a.privilege_type<>'EXECUTE')) AND
    (NOT EXISTS (SELECT 1 FROM reservation_acl) OR (
        (SELECT count(*) FROM reservation_acl WHERE privilege_type='SELECT')=1 AND
        (SELECT count(*) FROM reservation_acl WHERE privilege_type='INSERT')=1 AND
        NOT EXISTS (SELECT 1 FROM reservation_acl WHERE is_grantable OR privilege_type NOT IN ('SELECT','INSERT')))) AND
    NOT EXISTS (SELECT 1 FROM pg_attribute a CROSS JOIN LATERAL aclexplode(a.attacl) acl
        WHERE a.attrelid='public."EnrollmentGrantRecipientReservations"'::regclass AND acl.grantee=(SELECT oid FROM runtime))
 AND
    NOT has_database_privilege(:'runtime_role',current_database(),'CREATE') AND
    NOT has_database_privilege(:'enrollment_plan_lock_owner_role',current_database(),'CREATE') AND
    NOT has_schema_privilege(:'runtime_role','public','CREATE') AND
    NOT has_table_privilege(:'runtime_role','public."DirectorySync"','INSERT,UPDATE,DELETE,TRUNCATE') AND
    NOT has_table_privilege(:'runtime_role','public."DirectoryObjects"','INSERT,UPDATE,DELETE,TRUNCATE') AND
    NOT has_any_column_privilege(:'runtime_role','public."DirectorySync"','INSERT,UPDATE') AND
    NOT has_any_column_privilege(:'runtime_role','public."DirectoryObjects"','INSERT,UPDATE') AND
    NOT EXISTS (SELECT 1 FROM runtime r JOIN pg_namespace n ON n.nspname<>'public'
        CROSS JOIN LATERAL aclexplode(n.nspacl) acl WHERE acl.grantee=r.oid) AND
    NOT EXISTS (SELECT 1 FROM runtime r JOIN pg_class c ON true JOIN pg_namespace n ON n.oid=c.relnamespace AND n.nspname<>'public'
        CROSS JOIN LATERAL aclexplode(c.relacl) acl WHERE acl.grantee=r.oid) AND
    NOT EXISTS (SELECT 1 FROM runtime r JOIN pg_attribute a ON a.attrelid<>0 JOIN pg_class c ON c.oid=a.attrelid
        JOIN pg_namespace n ON n.oid=c.relnamespace AND n.nspname<>'public' CROSS JOIN LATERAL aclexplode(a.attacl) acl WHERE acl.grantee=r.oid) AND
    NOT EXISTS (SELECT 1 FROM runtime r JOIN pg_proc p ON true JOIN pg_namespace n ON n.oid=p.pronamespace AND n.nspname<>'public'
        CROSS JOIN LATERAL aclexplode(p.proacl) acl WHERE acl.grantee=r.oid)
    THEN 1 ELSE 1/(pg_catalog.pg_backend_pid()-pg_catalog.pg_backend_pid()) END AS enrollment_plan_capability_postflight;
\ir audit-enrollment-grant-operations.sql
COMMIT;
