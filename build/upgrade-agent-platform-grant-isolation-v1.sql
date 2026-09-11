\set ON_ERROR_STOP on
BEGIN;
-- Apply to an existing projection v2 store before installing platform grants.
SELECT 1/pg_catalog.count(*) AS expected_roles_are_safe FROM (SELECT 1 WHERE
 :'agent_table_owner_role'<>:'agent_enrollment_definer_role' AND
 :'agent_table_owner_role'<>:'agent_projection_definer_role' AND
 :'agent_enrollment_definer_role'<>:'agent_projection_definer_role' AND
 (SELECT pg_catalog.count(*)=3 AND pg_catalog.bool_and(NOT role.rolcanlogin AND NOT role.rolsuper AND NOT role.rolbypassrls AND
    NOT role.rolcreatedb AND NOT role.rolcreaterole AND NOT role.rolinherit AND NOT role.rolreplication)
  FROM pg_catalog.pg_roles role WHERE role.rolname IN(:'agent_table_owner_role',:'agent_enrollment_definer_role',:'agent_projection_definer_role')) AND
 NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members member JOIN pg_catalog.pg_roles role ON member.member=role.oid OR member.roleid=role.oid
   WHERE role.rolname IN(:'agent_table_owner_role',:'agent_enrollment_definer_role',:'agent_projection_definer_role')) AND
 (SELECT pg_catalog.count(*)=1 FROM pg_catalog.pg_namespace namespace JOIN pg_catalog.pg_roles owner ON owner.oid=namespace.nspowner
   WHERE namespace.nspname='agent_private' AND owner.rolname=:'agent_table_owner_role') AND
 (SELECT pg_catalog.count(*)=3 AND pg_catalog.bool_and(function.prosecdef AND function.proconfig=ARRAY['search_path=pg_catalog, agent_private, pg_temp']::text[] AND
   owner.rolname=CASE function.proname WHEN 'audit_ingest_privileges' THEN :'agent_table_owner_role'
      WHEN 'audit_enrollment_privileges' THEN :'agent_enrollment_definer_role' ELSE :'agent_projection_definer_role' END)
  FROM pg_catalog.pg_proc function JOIN pg_catalog.pg_roles owner ON owner.oid=function.proowner
  WHERE function.oid IN(pg_catalog.to_regprocedure('agent_private.audit_ingest_privileges(name)'),
    pg_catalog.to_regprocedure('agent_private.audit_enrollment_privileges(name,name,text)'),
    pg_catalog.to_regprocedure('agent_private.audit_projection_privileges(uuid,name,name)'))) AND
 pg_catalog.pg_get_function_result(pg_catalog.to_regprocedure('agent_private.audit_projection_privileges(uuid,name,name)'))=
   'TABLE(is_valid boolean, diagnostic_code text, profile_version smallint)') checked;
CREATE OR REPLACE FUNCTION agent_private.platform_grant_role_is_unbound(p_role name)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, agent_private, pg_temp
AS $function$
DECLARE v_unbound boolean;
BEGIN
    IF p_role IS NULL OR NOT (COALESCE((SELECT
    helper.proowner=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=CURRENT_USER::name) AND
    helper.proowner=namespace.nspowner AND helper.prosecdef AND helper.prokind='f' AND
    NOT helper.proretset AND helper.prorettype='boolean'::pg_catalog.regtype AND
    helper.proargnames=ARRAY['p_role']::text[] AND
    helper.proconfig=ARRAY['search_path=pg_catalog, agent_private, pg_temp']::text[] AND
    NOT EXISTS(
      SELECT 1 FROM pg_catalog.aclexplode(COALESCE(helper.proacl,pg_catalog.acldefault('f',helper.proowner))) acl
      LEFT JOIN pg_catalog.pg_roles grantee ON grantee.oid=acl.grantee
      WHERE acl.privilege_type<>'EXECUTE' OR grantee.oid IS NULL OR
        (acl.grantee<>helper.proowner AND acl.is_grantable) OR
        grantee.rolcanlogin OR grantee.rolsuper OR grantee.rolbypassrls OR grantee.rolcreatedb OR
        grantee.rolcreaterole OR grantee.rolinherit OR grantee.rolreplication OR
        EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members member WHERE member.member=grantee.oid OR member.roleid=grantee.oid) OR
        acl.grantee NOT IN(
          SELECT helper.proowner UNION SELECT audit.proowner FROM pg_catalog.pg_proc audit
          WHERE audit.oid IN(pg_catalog.to_regprocedure('agent_private.audit_enrollment_privileges(name,name,text)'),
                            pg_catalog.to_regprocedure('agent_private.audit_projection_privileges(uuid,name,name)')))) AND
    NOT EXISTS(
      SELECT 1 FROM(
        SELECT helper.proowner AS oid UNION SELECT audit.proowner FROM pg_catalog.pg_proc audit
        WHERE audit.oid IN(pg_catalog.to_regprocedure('agent_private.audit_enrollment_privileges(name,name,text)'),
                          pg_catalog.to_regprocedure('agent_private.audit_projection_privileges(uuid,name,name)'))) expected
      WHERE NOT EXISTS(SELECT 1 FROM pg_catalog.aclexplode(COALESCE(helper.proacl,pg_catalog.acldefault('f',helper.proowner))) acl
                       WHERE acl.grantee=expected.oid AND acl.privilege_type='EXECUTE'))
    FROM pg_catalog.pg_proc helper JOIN pg_catalog.pg_namespace namespace ON namespace.oid=helper.pronamespace
    WHERE helper.oid=pg_catalog.to_regprocedure('agent_private.platform_grant_role_is_unbound(name)')),false)) THEN
        RETURN false;
    END IF;
    IF EXISTS(SELECT 1 FROM pg_catalog.pg_proc function
        JOIN pg_catalog.pg_roles owner ON owner.oid=function.proowner
        WHERE owner.rolname=p_role AND function.oid IN(
            pg_catalog.to_regprocedure('agent_private.issue_initial_enrollment_grant(uuid,uuid,uuid,uuid,timestamp with time zone,bytea,bytea)'),
            pg_catalog.to_regprocedure('agent_private.audit_platform_grant_privileges(uuid,name,name)'))) THEN
        RETURN false;
    END IF;
    IF pg_catalog.to_regclass('agent_private.platform_grant_database_bindings') IS NULL THEN
        RETURN true;
    END IF;
    EXECUTE 'SELECT NOT EXISTS (SELECT 1 FROM agent_private.platform_grant_database_bindings WHERE login_role = $1)'
        INTO v_unbound USING p_role;
    RETURN v_unbound;
END;
$function$;
ALTER FUNCTION agent_private.platform_grant_role_is_unbound(name) OWNER TO :"agent_table_owner_role";
REVOKE ALL ON FUNCTION agent_private.platform_grant_role_is_unbound(name) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION agent_private.platform_grant_role_is_unbound(name)
    TO :"agent_enrollment_definer_role", :"agent_projection_definer_role";
CREATE OR REPLACE FUNCTION agent_private.audit_ingest_privileges(expected_definer name)
RETURNS TABLE (
    login_exists boolean,
    attributes_too_broad boolean,
    has_role_membership boolean,
    binding_valid boolean,
    has_direct_object_privilege boolean,
    function_execute_granted boolean,
    function_owner_matches boolean,
    definer_attributes_too_broad boolean,
    definer_has_membership boolean,
    function_security_definer boolean,
    function_search_path_valid boolean,
    schema_create_granted boolean,
    login_owns_database_or_schema boolean,
    unexpected_function_execute boolean,
    table_security_valid boolean)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, agent_private, pg_temp
AS $function$
    SELECT
        role.oid IS NOT NULL,
        COALESCE(role.rolsuper OR role.rolbypassrls OR role.rolcreatedb OR role.rolcreaterole OR
                 role.rolinherit OR role.rolreplication, true),
        EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members membership
                WHERE membership.member = role.oid OR membership.roleid = role.oid),
        EXISTS (
            SELECT 1 FROM agent_private.agent_database_bindings binding
            WHERE binding.login_role = SESSION_USER::name
              AND binding.purpose = 'Ingest')
          AND agent_private.platform_grant_role_is_unbound(SESSION_USER::name)
          AND agent_private.platform_grant_role_is_unbound(expected_definer)
          AND (COALESCE((SELECT
    helper.proowner=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=expected_definer) AND
    helper.proowner=namespace.nspowner AND helper.prosecdef AND helper.prokind='f' AND
    NOT helper.proretset AND helper.prorettype='boolean'::pg_catalog.regtype AND
    helper.proargnames=ARRAY['p_role']::text[] AND
    helper.proconfig=ARRAY['search_path=pg_catalog, agent_private, pg_temp']::text[] AND
    NOT EXISTS(
      SELECT 1 FROM pg_catalog.aclexplode(COALESCE(helper.proacl,pg_catalog.acldefault('f',helper.proowner))) acl
      LEFT JOIN pg_catalog.pg_roles grantee ON grantee.oid=acl.grantee
      WHERE acl.privilege_type<>'EXECUTE' OR grantee.oid IS NULL OR
        (acl.grantee<>helper.proowner AND acl.is_grantable) OR
        grantee.rolcanlogin OR grantee.rolsuper OR grantee.rolbypassrls OR grantee.rolcreatedb OR
        grantee.rolcreaterole OR grantee.rolinherit OR grantee.rolreplication OR
        EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members member WHERE member.member=grantee.oid OR member.roleid=grantee.oid) OR
        acl.grantee NOT IN(
          SELECT helper.proowner UNION SELECT audit.proowner FROM pg_catalog.pg_proc audit
          WHERE audit.oid IN(pg_catalog.to_regprocedure('agent_private.audit_enrollment_privileges(name,name,text)'),
                            pg_catalog.to_regprocedure('agent_private.audit_projection_privileges(uuid,name,name)')))) AND
    NOT EXISTS(
      SELECT 1 FROM(
        SELECT helper.proowner AS oid UNION SELECT audit.proowner FROM pg_catalog.pg_proc audit
        WHERE audit.oid IN(pg_catalog.to_regprocedure('agent_private.audit_enrollment_privileges(name,name,text)'),
                          pg_catalog.to_regprocedure('agent_private.audit_projection_privileges(uuid,name,name)'))) expected
      WHERE NOT EXISTS(SELECT 1 FROM pg_catalog.aclexplode(COALESCE(helper.proacl,pg_catalog.acldefault('f',helper.proowner))) acl
                       WHERE acl.grantee=expected.oid AND acl.privilege_type='EXECUTE'))
    FROM pg_catalog.pg_proc helper JOIN pg_catalog.pg_namespace namespace ON namespace.oid=helper.pronamespace
    WHERE helper.oid=pg_catalog.to_regprocedure('agent_private.platform_grant_role_is_unbound(name)')),false)),
        EXISTS (
            SELECT 1
            FROM pg_catalog.pg_class object
            JOIN pg_catalog.pg_namespace namespace ON namespace.oid = object.relnamespace
            WHERE namespace.nspname = 'agent_private'
              AND object.relkind IN ('r','p','S','v','m')
              AND (pg_catalog.has_table_privilege(SESSION_USER, object.oid, 'SELECT')
                OR pg_catalog.has_table_privilege(SESSION_USER, object.oid, 'INSERT')
                OR pg_catalog.has_table_privilege(SESSION_USER, object.oid, 'UPDATE')
                OR pg_catalog.has_table_privilege(SESSION_USER, object.oid, 'DELETE')
                OR pg_catalog.has_table_privilege(SESSION_USER, object.oid, 'TRUNCATE')
                OR pg_catalog.has_table_privilege(SESSION_USER, object.oid, 'REFERENCES')
                OR pg_catalog.has_table_privilege(SESSION_USER, object.oid, 'TRIGGER'))),
        pg_catalog.has_function_privilege(
            SESSION_USER,
            'agent_private.ingest_attested_envelope(bytea,integer,uuid,bigint,bigint,uuid,bigint,bytea,text,text)'::pg_catalog.regprocedure,
            'EXECUTE'),
        function_owner.rolname = expected_definer,
        COALESCE(definer.rolcanlogin OR definer.rolsuper OR definer.rolbypassrls OR definer.rolcreatedb OR
                 definer.rolcreaterole OR definer.rolinherit OR definer.rolreplication, true),
        EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members membership
                WHERE membership.member = definer.oid OR membership.roleid = definer.oid),
        function_owner.prosecdef,
        function_owner.proconfig = ARRAY['search_path=pg_catalog, agent_private, pg_temp']::text[],
        pg_catalog.has_schema_privilege(SESSION_USER, 'agent_private', 'CREATE'),
        schema_owner.rolname = role.rolname OR database_owner.rolname = role.rolname,
        EXISTS (
            SELECT 1 FROM pg_catalog.pg_proc callable
            WHERE callable.pronamespace = function_owner.pronamespace
              AND callable.oid NOT IN (
                  'agent_private.ingest_attested_envelope(bytea,integer,uuid,bigint,bigint,uuid,bigint,bytea,text,text)'::pg_catalog.regprocedure,
                  'agent_private.audit_ingest_privileges(name)'::pg_catalog.regprocedure)
              AND pg_catalog.has_function_privilege(SESSION_USER, callable.oid, 'EXECUTE')),
        (SELECT pg_catalog.count(*) = 8 AND pg_catalog.bool_and(
                    object.relowner = definer.oid AND object.relrowsecurity AND object.relforcerowsecurity AND
                    EXISTS (SELECT 1 FROM pg_catalog.pg_policy policy
                            WHERE policy.polrelid = object.oid AND policy.polname = 'definer_all' AND
                                  policy.polcmd = '*' AND policy.polpermissive AND
                                  policy.polroles = ARRAY[definer.oid]::oid[] AND
                                  pg_catalog.pg_get_expr(policy.polqual, policy.polrelid) = 'true' AND
                                  pg_catalog.pg_get_expr(policy.polwithcheck, policy.polrelid) = 'true'))
         FROM pg_catalog.pg_class object
         WHERE object.relnamespace = function_owner.pronamespace AND object.relkind = 'r' AND
               object.relname = ANY (ARRAY['agent_database_bindings','devices','registrations','certificate_bindings',
                                           'replay_state','receipts','snapshot_history','inventory_projection']))
    FROM (SELECT SESSION_USER::name AS login_role) session
    LEFT JOIN pg_catalog.pg_roles role ON role.rolname = session.login_role
    LEFT JOIN pg_catalog.pg_roles definer ON definer.rolname = expected_definer
    CROSS JOIN LATERAL (
        SELECT owner.rolname
        FROM pg_catalog.pg_namespace namespace
        JOIN pg_catalog.pg_roles owner ON owner.oid = namespace.nspowner
        WHERE namespace.nspname = 'agent_private'
    ) schema_owner
    CROSS JOIN LATERAL (
        SELECT owner.rolname
        FROM pg_catalog.pg_database database
        JOIN pg_catalog.pg_roles owner ON owner.oid = database.datdba
        WHERE database.datname = pg_catalog.current_database()
    ) database_owner
    CROSS JOIN LATERAL (
        SELECT owner.rolname, function.prosecdef, function.proconfig, function.pronamespace
        FROM pg_catalog.pg_proc function
        JOIN pg_catalog.pg_namespace namespace ON namespace.oid = function.pronamespace
        JOIN pg_catalog.pg_roles owner ON owner.oid = function.proowner
        WHERE namespace.nspname = 'agent_private'
          AND function.oid =
              'agent_private.ingest_attested_envelope(bytea,integer,uuid,bigint,bigint,uuid,bigint,bytea,text,text)'::pg_catalog.regprocedure
    ) function_owner;
$function$;
CREATE OR REPLACE FUNCTION agent_private.audit_enrollment_privileges(
    p_expected_table_owner name,p_expected_function_owner name,p_expected_purpose text)
RETURNS TABLE(is_valid boolean,diagnostic_code text)
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, agent_private, pg_temp AS $function$
WITH login AS (SELECT role.* FROM pg_catalog.pg_roles role WHERE role.rolname=SESSION_USER),
function_owner AS (SELECT role.* FROM pg_catalog.pg_roles role WHERE role.rolname=p_expected_function_owner),
table_owner AS (SELECT role.* FROM pg_catalog.pg_roles role WHERE role.rolname=p_expected_table_owner),
schema_info AS (SELECT namespace.oid,namespace.nspowner FROM pg_catalog.pg_namespace namespace WHERE namespace.nspname='agent_private'),
expected_table_acl(relname,privilege_type,is_grantable) AS (VALUES
 ('enrollment_database_bindings','SELECT',false),('enrollment_grants','SELECT',false),('enrollment_grants','UPDATE',false),
 ('enrollment_requests','SELECT',false),('enrollment_requests','INSERT',false),('enrollment_requests','UPDATE',false),
 ('enrollment_results','SELECT',false),('enrollment_results','INSERT',false),('devices','SELECT',false),
 ('registrations','SELECT',false),('registrations','INSERT',false),('certificate_bindings','SELECT',false),('certificate_bindings','INSERT',false)),
actual_table_acl AS (
 SELECT object.relname,acl.privilege_type,acl.is_grantable FROM pg_catalog.pg_class object,schema_info,function_owner,
 LATERAL pg_catalog.aclexplode(COALESCE(object.relacl,pg_catalog.acldefault('r',object.relowner))) acl
 WHERE object.relnamespace=schema_info.oid AND acl.grantee=function_owner.oid),
expected_column_acl(relname,attname,privilege_type,is_grantable) AS (VALUES ('devices','next_registration_epoch','UPDATE',false)),
actual_column_acl AS (
 SELECT object.relname,attribute.attname,acl.privilege_type,acl.is_grantable FROM pg_catalog.pg_class object
 JOIN pg_catalog.pg_attribute attribute ON attribute.attrelid=object.oid,
 schema_info,function_owner,LATERAL pg_catalog.aclexplode(attribute.attacl) acl
 WHERE object.relnamespace=schema_info.oid AND acl.grantee=function_owner.oid),
expected_execute(proname) AS (
 SELECT entry.proname FROM (VALUES
  ('Enroll','submit_or_recover_enrollment'),('Enroll','audit_enrollment_privileges'),
  ('Issue','claim_enrollment_issuance'),('Issue','complete_enrollment_issuance'),('Issue','defer_enrollment_issuance'),
  ('Issue','mark_enrollment_issuance_unknown'),('Issue','fail_enrollment_issuance_definitively'),
  ('Issue','audit_enrollment_privileges')) entry(purpose,proname) WHERE entry.purpose=p_expected_purpose),
actual_execute AS (
 SELECT function.proname FROM pg_catalog.pg_proc function,schema_info
 WHERE function.pronamespace=schema_info.oid AND pg_catalog.has_function_privilege(SESSION_USER,function.oid,'EXECUTE')),
checks AS (
 SELECT
   (SELECT pg_catalog.count(*)=1 FROM login) AND
   NOT EXISTS(SELECT 1 FROM login WHERE rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole OR rolinherit OR rolreplication) AND
   NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members membership,login WHERE membership.member=login.oid OR membership.roleid=login.oid) AND
   (SELECT pg_catalog.count(*)=1 FROM agent_private.enrollment_database_bindings binding
     WHERE binding.login_role=SESSION_USER::name AND binding.purpose=p_expected_purpose) AND
   p_expected_purpose IN ('Enroll','Issue') AND
   agent_private.platform_grant_role_is_unbound(SESSION_USER::name) AND
   agent_private.platform_grant_role_is_unbound(p_expected_function_owner) AND
   agent_private.platform_grant_role_is_unbound(p_expected_table_owner) AND
   (COALESCE((SELECT
    helper.proowner=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=p_expected_table_owner) AND
    helper.proowner=namespace.nspowner AND helper.prosecdef AND helper.prokind='f' AND
    NOT helper.proretset AND helper.prorettype='boolean'::pg_catalog.regtype AND
    helper.proargnames=ARRAY['p_role']::text[] AND
    helper.proconfig=ARRAY['search_path=pg_catalog, agent_private, pg_temp']::text[] AND
    NOT EXISTS(
      SELECT 1 FROM pg_catalog.aclexplode(COALESCE(helper.proacl,pg_catalog.acldefault('f',helper.proowner))) acl
      LEFT JOIN pg_catalog.pg_roles grantee ON grantee.oid=acl.grantee
      WHERE acl.privilege_type<>'EXECUTE' OR grantee.oid IS NULL OR
        (acl.grantee<>helper.proowner AND acl.is_grantable) OR
        grantee.rolcanlogin OR grantee.rolsuper OR grantee.rolbypassrls OR grantee.rolcreatedb OR
        grantee.rolcreaterole OR grantee.rolinherit OR grantee.rolreplication OR
        EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members member WHERE member.member=grantee.oid OR member.roleid=grantee.oid) OR
        acl.grantee NOT IN(
          SELECT helper.proowner UNION SELECT audit.proowner FROM pg_catalog.pg_proc audit
          WHERE audit.oid IN(pg_catalog.to_regprocedure('agent_private.audit_enrollment_privileges(name,name,text)'),
                            pg_catalog.to_regprocedure('agent_private.audit_projection_privileges(uuid,name,name)')))) AND
    NOT EXISTS(
      SELECT 1 FROM(
        SELECT helper.proowner AS oid UNION SELECT audit.proowner FROM pg_catalog.pg_proc audit
        WHERE audit.oid IN(pg_catalog.to_regprocedure('agent_private.audit_enrollment_privileges(name,name,text)'),
                          pg_catalog.to_regprocedure('agent_private.audit_projection_privileges(uuid,name,name)'))) expected
      WHERE NOT EXISTS(SELECT 1 FROM pg_catalog.aclexplode(COALESCE(helper.proacl,pg_catalog.acldefault('f',helper.proowner))) acl
                       WHERE acl.grantee=expected.oid AND acl.privilege_type='EXECUTE'))
    FROM pg_catalog.pg_proc helper JOIN pg_catalog.pg_namespace namespace ON namespace.oid=helper.pronamespace
    WHERE helper.oid=pg_catalog.to_regprocedure('agent_private.platform_grant_role_is_unbound(name)')),false)) AND
   NOT pg_catalog.has_schema_privilege(SESSION_USER,'agent_private','CREATE') AND
   NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object,schema_info WHERE object.relnamespace=schema_info.oid AND
     object.relkind IN ('r','p','v','m') AND (pg_catalog.has_table_privilege(SESSION_USER,object.oid,'SELECT') OR
     pg_catalog.has_table_privilege(SESSION_USER,object.oid,'INSERT') OR pg_catalog.has_table_privilege(SESSION_USER,object.oid,'UPDATE') OR
     pg_catalog.has_table_privilege(SESSION_USER,object.oid,'DELETE') OR pg_catalog.has_table_privilege(SESSION_USER,object.oid,'TRUNCATE') OR
     pg_catalog.has_table_privilege(SESSION_USER,object.oid,'REFERENCES') OR pg_catalog.has_table_privilege(SESSION_USER,object.oid,'TRIGGER'))) AND
   NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object,schema_info WHERE object.relnamespace=schema_info.oid AND object.relkind='S' AND
     (pg_catalog.has_sequence_privilege(SESSION_USER,object.oid,'USAGE') OR pg_catalog.has_sequence_privilege(SESSION_USER,object.oid,'SELECT') OR
      pg_catalog.has_sequence_privilege(SESSION_USER,object.oid,'UPDATE'))) AND
   NOT EXISTS(SELECT 1 FROM pg_catalog.pg_database database,login WHERE database.datdba=login.oid) AND
   NOT EXISTS(SELECT 1 FROM schema_info,login WHERE schema_info.nspowner=login.oid) AND
   NOT EXISTS(SELECT 1 FROM function_owner WHERE rolcanlogin OR rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole OR rolinherit OR rolreplication) AND
   NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members membership,function_owner WHERE membership.member=function_owner.oid OR membership.roleid=function_owner.oid) AND
   NOT EXISTS(SELECT 1 FROM pg_catalog.pg_database database,function_owner WHERE database.datdba=function_owner.oid) AND
   NOT EXISTS(SELECT 1 FROM schema_info,function_owner WHERE schema_info.nspowner=function_owner.oid) AND
   NOT pg_catalog.has_schema_privilege(p_expected_function_owner,'agent_private','CREATE') AND
   NOT EXISTS(SELECT 1 FROM table_owner WHERE rolcanlogin OR rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole OR rolinherit OR rolreplication) AND
   NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members membership,table_owner WHERE membership.member=table_owner.oid OR membership.roleid=table_owner.oid) AND
   NOT EXISTS(SELECT 1 FROM pg_catalog.pg_database database,table_owner WHERE database.datdba=table_owner.oid) AND
   (SELECT pg_catalog.count(*)=1 FROM schema_info,table_owner WHERE schema_info.nspowner=table_owner.oid) AND
   NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc function,schema_info,login,
      LATERAL pg_catalog.aclexplode(function.proacl) acl WHERE function.pronamespace=schema_info.oid AND
      acl.grantee=login.oid AND acl.privilege_type='EXECUTE' AND acl.is_grantable) AND
   NOT EXISTS((SELECT * FROM expected_table_acl EXCEPT SELECT * FROM actual_table_acl) UNION ALL
              (SELECT * FROM actual_table_acl EXCEPT SELECT * FROM expected_table_acl)) AND
   NOT EXISTS((SELECT * FROM expected_column_acl EXCEPT SELECT * FROM actual_column_acl) UNION ALL
              (SELECT * FROM actual_column_acl EXCEPT SELECT * FROM expected_column_acl)) AND
   NOT EXISTS((SELECT * FROM expected_execute EXCEPT SELECT * FROM actual_execute) UNION ALL
              (SELECT * FROM actual_execute EXCEPT SELECT * FROM expected_execute)) AND
   NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc function,schema_info,
      LATERAL pg_catalog.aclexplode(COALESCE(function.proacl,pg_catalog.acldefault('f',function.proowner))) acl
      WHERE function.pronamespace=schema_info.oid AND acl.grantee=0 AND acl.privilege_type='EXECUTE') AND
   (SELECT pg_catalog.count(*)=7 AND pg_catalog.bool_and(function.proowner=function_owner.oid AND function.prosecdef AND
      function.proconfig=ARRAY['search_path=pg_catalog, agent_private, pg_temp']::text[])
    FROM pg_catalog.pg_proc function,schema_info,function_owner WHERE function.pronamespace=schema_info.oid AND function.proname=ANY(ARRAY[
      'submit_or_recover_enrollment','claim_enrollment_issuance','complete_enrollment_issuance','defer_enrollment_issuance',
      'mark_enrollment_issuance_unknown','fail_enrollment_issuance_definitively','audit_enrollment_privileges'])) AND
   (SELECT pg_catalog.count(*)=7 AND pg_catalog.bool_and(object.relowner=table_owner.oid AND object.relrowsecurity AND object.relforcerowsecurity)
    FROM pg_catalog.pg_class object,schema_info,pg_catalog.pg_roles table_owner WHERE table_owner.rolname=p_expected_table_owner AND
      object.relnamespace=schema_info.oid AND object.relkind='r' AND object.relname=ANY(ARRAY[
      'devices','registrations','certificate_bindings','enrollment_database_bindings','enrollment_grants','enrollment_requests','enrollment_results'])) AND
   NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object,schema_info,function_owner,table_owner WHERE object.relnamespace=schema_info.oid AND
      object.relname=ANY(ARRAY['devices','registrations','certificate_bindings','enrollment_database_bindings','enrollment_grants','enrollment_requests','enrollment_results']) AND
      (NOT EXISTS(SELECT 1 FROM pg_catalog.pg_policy policy WHERE policy.polrelid=object.oid AND policy.polname='enrollment_definer_access' AND
        policy.polroles=ARRAY[function_owner.oid]::oid[] AND policy.polcmd='*' AND pg_catalog.pg_get_expr(policy.polqual,policy.polrelid)='true' AND
        pg_catalog.pg_get_expr(policy.polwithcheck,policy.polrelid)='true') OR
       NOT EXISTS(SELECT 1 FROM pg_catalog.pg_policy policy WHERE policy.polrelid=object.oid AND policy.polname='definer_all' AND
        policy.polroles=ARRAY[table_owner.oid]::oid[] AND policy.polcmd='*' AND pg_catalog.pg_get_expr(policy.polqual,policy.polrelid)='true' AND
        pg_catalog.pg_get_expr(policy.polwithcheck,policy.polrelid)='true'))) AS valid
)
SELECT checks.valid,CASE WHEN checks.valid THEN 'None' ELSE 'PrivilegeAuditFailed' END FROM checks;
$function$;
CREATE OR REPLACE FUNCTION agent_private.audit_projection_privileges(p_expected_environment_id uuid,p_expected_table_owner name,p_expected_function_owner name)
RETURNS TABLE(is_valid boolean,diagnostic_code text,profile_version smallint)
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,agent_private,pg_temp AS $function$
WITH login AS(SELECT role.* FROM pg_catalog.pg_roles role WHERE role.rolname=SESSION_USER),
 function_owner AS(SELECT role.* FROM pg_catalog.pg_roles role WHERE role.rolname=p_expected_function_owner),
 table_owner AS(SELECT role.* FROM pg_catalog.pg_roles role WHERE role.rolname=p_expected_table_owner),
 schema_info AS(SELECT namespace.oid,namespace.nspowner FROM pg_catalog.pg_namespace namespace WHERE namespace.nspname='agent_private'),
expected_columns(relname,attname,privilege_type,is_grantable) AS(VALUES
  ('agent_database_bindings','login_role','SELECT',false),('enrollment_database_bindings','login_role','SELECT',false),
  ('agent_projection_database_bindings','login_role','SELECT',false),('agent_projection_database_bindings','environment_id','SELECT',false),('agent_projection_database_bindings','purpose','SELECT',false),
  ('agent_device_directory_bindings','environment_id','SELECT',false),('agent_device_directory_bindings','directory_object_id','SELECT',false),('agent_device_directory_bindings','device_id','SELECT',false),
  ('devices','environment_id','SELECT',false),('devices','device_id','SELECT',false),('devices','state','SELECT',false),('devices','last_seen_at','SELECT',false),
  ('registrations','environment_id','SELECT',false),('registrations','registration_id','SELECT',false),('registrations','device_id','SELECT',false),('registrations','registration_epoch','SELECT',false),('registrations','state','SELECT',false),
  ('inventory_projection','environment_id','SELECT',false),('inventory_projection','device_id','SELECT',false),('inventory_projection','registration_id','SELECT',false),('inventory_projection','registration_epoch','SELECT',false),('inventory_projection','sequence','SELECT',false),('inventory_projection','receipt_id','SELECT',false),('inventory_projection','normalized_payload','SELECT',false),
  ('receipts','environment_id','SELECT',false),('receipts','registration_id','SELECT',false),('receipts','registration_epoch','SELECT',false),('receipts','sequence','SELECT',false),('receipts','receipt_id','SELECT',false),('receipts','device_id','SELECT',false),('receipts','received_at','SELECT',false)),
 actual_columns AS(SELECT object.relname,attribute.attname,acl.privilege_type,acl.is_grantable FROM pg_catalog.pg_class object
  JOIN pg_catalog.pg_attribute attribute ON attribute.attrelid=object.oid,schema_info,function_owner,
  LATERAL pg_catalog.aclexplode(attribute.attacl) acl WHERE object.relnamespace=schema_info.oid AND acl.grantee=function_owner.oid),
 expected_execute(proname) AS(VALUES('read_current_bitlocker_projection'),('read_current_inventory_projection'),('audit_projection_privileges')),
 actual_execute AS(SELECT function.proname FROM pg_catalog.pg_proc function,schema_info WHERE function.pronamespace=schema_info.oid AND
  pg_catalog.has_function_privilege(SESSION_USER,function.oid,'EXECUTE')),
 checks AS(SELECT
  (SELECT pg_catalog.count(*)=1 FROM login) AND (SELECT pg_catalog.count(*)=1 FROM function_owner) AND (SELECT pg_catalog.count(*)=1 FROM table_owner) AND
  NOT EXISTS(SELECT 1 FROM login WHERE rolcanlogin=false OR rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole OR rolinherit OR rolreplication) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members membership,login WHERE membership.member=login.oid OR membership.roleid=login.oid) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_database database,login WHERE database.datdba=login.oid) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc function,schema_info,login WHERE function.pronamespace=schema_info.oid AND function.proowner=login.oid) AND
  agent_private.platform_grant_role_is_unbound(SESSION_USER::name) AND
  agent_private.platform_grant_role_is_unbound(p_expected_function_owner) AND
  agent_private.platform_grant_role_is_unbound(p_expected_table_owner) AND
   (COALESCE((SELECT
    helper.proowner=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=p_expected_table_owner) AND
    helper.proowner=namespace.nspowner AND helper.prosecdef AND helper.prokind='f' AND
    NOT helper.proretset AND helper.prorettype='boolean'::pg_catalog.regtype AND
    helper.proargnames=ARRAY['p_role']::text[] AND
    helper.proconfig=ARRAY['search_path=pg_catalog, agent_private, pg_temp']::text[] AND
    NOT EXISTS(
      SELECT 1 FROM pg_catalog.aclexplode(COALESCE(helper.proacl,pg_catalog.acldefault('f',helper.proowner))) acl
      LEFT JOIN pg_catalog.pg_roles grantee ON grantee.oid=acl.grantee
      WHERE acl.privilege_type<>'EXECUTE' OR grantee.oid IS NULL OR
        (acl.grantee<>helper.proowner AND acl.is_grantable) OR
        grantee.rolcanlogin OR grantee.rolsuper OR grantee.rolbypassrls OR grantee.rolcreatedb OR
        grantee.rolcreaterole OR grantee.rolinherit OR grantee.rolreplication OR
        EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members member WHERE member.member=grantee.oid OR member.roleid=grantee.oid) OR
        acl.grantee NOT IN(
          SELECT helper.proowner UNION SELECT audit.proowner FROM pg_catalog.pg_proc audit
          WHERE audit.oid IN(pg_catalog.to_regprocedure('agent_private.audit_enrollment_privileges(name,name,text)'),
                            pg_catalog.to_regprocedure('agent_private.audit_projection_privileges(uuid,name,name)')))) AND
    NOT EXISTS(
      SELECT 1 FROM(
        SELECT helper.proowner AS oid UNION SELECT audit.proowner FROM pg_catalog.pg_proc audit
        WHERE audit.oid IN(pg_catalog.to_regprocedure('agent_private.audit_enrollment_privileges(name,name,text)'),
                          pg_catalog.to_regprocedure('agent_private.audit_projection_privileges(uuid,name,name)'))) expected
      WHERE NOT EXISTS(SELECT 1 FROM pg_catalog.aclexplode(COALESCE(helper.proacl,pg_catalog.acldefault('f',helper.proowner))) acl
                       WHERE acl.grantee=expected.oid AND acl.privilege_type='EXECUTE'))
    FROM pg_catalog.pg_proc helper JOIN pg_catalog.pg_namespace namespace ON namespace.oid=helper.pronamespace
    WHERE helper.oid=pg_catalog.to_regprocedure('agent_private.platform_grant_role_is_unbound(name)')),false)) AND
  NOT EXISTS(SELECT 1 FROM agent_private.agent_database_bindings binding WHERE binding.login_role=SESSION_USER::name) AND
  NOT EXISTS(SELECT 1 FROM agent_private.enrollment_database_bindings binding WHERE binding.login_role=SESSION_USER::name) AND
  (SELECT pg_catalog.count(*)=1 FROM agent_private.agent_projection_database_bindings binding WHERE binding.login_role=SESSION_USER::name AND binding.environment_id=p_expected_environment_id AND binding.purpose='ReadDeviceProjection') AND
  NOT pg_catalog.has_schema_privilege(SESSION_USER,'agent_private','CREATE') AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object,schema_info WHERE object.relnamespace=schema_info.oid AND object.relkind IN('r','p','v','m') AND
   (pg_catalog.has_table_privilege(SESSION_USER,object.oid,'SELECT') OR pg_catalog.has_table_privilege(SESSION_USER,object.oid,'INSERT') OR pg_catalog.has_table_privilege(SESSION_USER,object.oid,'UPDATE') OR
    pg_catalog.has_table_privilege(SESSION_USER,object.oid,'DELETE') OR pg_catalog.has_table_privilege(SESSION_USER,object.oid,'TRUNCATE') OR pg_catalog.has_table_privilege(SESSION_USER,object.oid,'REFERENCES') OR pg_catalog.has_table_privilege(SESSION_USER,object.oid,'TRIGGER'))) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object JOIN pg_catalog.pg_attribute attribute ON attribute.attrelid=object.oid,
   schema_info,login,LATERAL pg_catalog.aclexplode(attribute.attacl) acl WHERE object.relnamespace=schema_info.oid AND acl.grantee=login.oid) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object JOIN pg_catalog.pg_attribute attribute ON attribute.attrelid=object.oid,
   schema_info,LATERAL pg_catalog.aclexplode(attribute.attacl) acl WHERE object.relnamespace=schema_info.oid AND acl.grantee=0) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object,schema_info WHERE object.relnamespace=schema_info.oid AND object.relkind='S' AND
   (pg_catalog.has_sequence_privilege(SESSION_USER,object.oid,'USAGE') OR pg_catalog.has_sequence_privilege(SESSION_USER,object.oid,'SELECT') OR pg_catalog.has_sequence_privilege(SESSION_USER,object.oid,'UPDATE'))) AND
  NOT EXISTS((SELECT * FROM expected_execute EXCEPT SELECT * FROM actual_execute) UNION ALL(SELECT * FROM actual_execute EXCEPT SELECT * FROM expected_execute)) AND
  NOT EXISTS(SELECT 1 FROM function_owner WHERE rolcanlogin OR rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole OR rolinherit OR rolreplication) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members membership,function_owner WHERE membership.member=function_owner.oid OR membership.roleid=function_owner.oid) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_database database,function_owner WHERE database.datdba=function_owner.oid) AND
  NOT EXISTS(SELECT 1 FROM schema_info,function_owner WHERE schema_info.nspowner=function_owner.oid) AND
  NOT pg_catalog.has_schema_privilege(p_expected_function_owner,'agent_private','CREATE') AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object,schema_info,function_owner WHERE object.relnamespace=schema_info.oid AND object.relowner=function_owner.oid) AND
  (SELECT pg_catalog.count(*)=3 FROM pg_catalog.pg_proc function,schema_info,function_owner WHERE function.pronamespace=schema_info.oid AND function.proowner=function_owner.oid) AND
  NOT EXISTS(SELECT 1 FROM agent_private.agent_database_bindings binding,function_owner WHERE binding.login_role=function_owner.rolname::name) AND
  NOT EXISTS(SELECT 1 FROM agent_private.enrollment_database_bindings binding,function_owner WHERE binding.login_role=function_owner.rolname::name) AND
  NOT EXISTS(SELECT 1 FROM agent_private.agent_projection_database_bindings binding,function_owner WHERE binding.login_role=function_owner.rolname::name) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object,schema_info,function_owner WHERE object.relnamespace=schema_info.oid AND object.relkind IN('r','p','v','m') AND
   (pg_catalog.has_table_privilege(function_owner.rolname,object.oid,'SELECT') OR pg_catalog.has_table_privilege(function_owner.rolname,object.oid,'INSERT') OR pg_catalog.has_table_privilege(function_owner.rolname,object.oid,'UPDATE') OR
    pg_catalog.has_table_privilege(function_owner.rolname,object.oid,'DELETE') OR pg_catalog.has_table_privilege(function_owner.rolname,object.oid,'TRUNCATE') OR pg_catalog.has_table_privilege(function_owner.rolname,object.oid,'REFERENCES') OR pg_catalog.has_table_privilege(function_owner.rolname,object.oid,'TRIGGER'))) AND
  NOT EXISTS((SELECT * FROM expected_columns EXCEPT SELECT * FROM actual_columns) UNION ALL(SELECT * FROM actual_columns EXCEPT SELECT * FROM expected_columns)) AND
  NOT EXISTS(SELECT 1 FROM table_owner WHERE rolcanlogin OR rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole OR rolinherit OR rolreplication) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members membership,table_owner WHERE membership.member=table_owner.oid OR membership.roleid=table_owner.oid) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_database database,table_owner WHERE database.datdba=table_owner.oid) AND
  (SELECT pg_catalog.count(*)=1 FROM schema_info,table_owner WHERE schema_info.nspowner=table_owner.oid) AND
  (SELECT pg_catalog.count(*)=3 AND pg_catalog.bool_and(function.proowner=function_owner.oid AND function.prosecdef AND function.proconfig=ARRAY['search_path=pg_catalog, agent_private, pg_temp']::text[] AND
    pg_catalog.pg_get_function_identity_arguments(function.oid)=CASE function.proname WHEN 'read_current_bitlocker_projection' THEN 'p_environment_id uuid, p_directory_object_id uuid' WHEN 'read_current_inventory_projection' THEN 'p_environment_id uuid, p_directory_object_id uuid' ELSE 'p_expected_environment_id uuid, p_expected_table_owner name, p_expected_function_owner name' END AND
    pg_catalog.pg_get_function_result(function.oid)=CASE function.proname WHEN 'read_current_bitlocker_projection' THEN 'TABLE(outcome text, diagnostic_code text, environment_id uuid, directory_object_id uuid, device_id uuid, registration_id uuid, registration_epoch bigint, sequence bigint, receipt_id uuid, collected_at timestamp with time zone, source_observed_at timestamp with time zone, received_at timestamp with time zone, last_seen_at timestamp with time zone, source text, is_truncated boolean, volumes_json text)' WHEN 'read_current_inventory_projection' THEN 'TABLE(outcome text, diagnostic_code text, environment_id uuid, directory_object_id uuid, device_id uuid, registration_id uuid, registration_epoch bigint, sequence bigint, receipt_id uuid, collected_at timestamp with time zone, received_at timestamp with time zone, last_seen_at timestamp with time zone, basic_json text, software_json text, hardware_json text)' ELSE 'TABLE(is_valid boolean, diagnostic_code text, profile_version smallint)' END)
   FROM pg_catalog.pg_proc function,schema_info,function_owner WHERE function.pronamespace=schema_info.oid AND function.proname IN('read_current_bitlocker_projection','read_current_inventory_projection','audit_projection_privileges')) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc function,schema_info,LATERAL pg_catalog.aclexplode(COALESCE(function.proacl,pg_catalog.acldefault('f',function.proowner))) acl
   WHERE function.pronamespace=schema_info.oid AND function.proname IN('read_current_bitlocker_projection','read_current_inventory_projection','audit_projection_privileges') AND acl.grantee=0 AND acl.privilege_type='EXECUTE') AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc function,schema_info,function_owner,login,
   LATERAL pg_catalog.aclexplode(COALESCE(function.proacl,pg_catalog.acldefault('f',function.proowner))) acl
   WHERE function.pronamespace=schema_info.oid AND function.proname IN('read_current_bitlocker_projection','read_current_inventory_projection','audit_projection_privileges') AND
    acl.privilege_type='EXECUTE' AND (acl.grantee NOT IN(function_owner.oid,login.oid) OR (acl.grantee=login.oid AND acl.is_grantable))) AND
  (SELECT pg_catalog.count(*)=8 AND pg_catalog.bool_and(object.relowner=table_owner.oid AND object.relrowsecurity AND object.relforcerowsecurity)
   FROM pg_catalog.pg_class object,schema_info,table_owner WHERE object.relnamespace=schema_info.oid AND object.relkind='r' AND object.relname IN('agent_database_bindings','enrollment_database_bindings','agent_projection_database_bindings','agent_device_directory_bindings','devices','registrations','inventory_projection','receipts')) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object,schema_info,function_owner WHERE object.relnamespace=schema_info.oid AND
   object.relname IN('agent_database_bindings','enrollment_database_bindings','agent_projection_database_bindings','agent_device_directory_bindings','devices','registrations','inventory_projection','receipts') AND NOT EXISTS(
    SELECT 1 FROM pg_catalog.pg_policy policy WHERE policy.polrelid=object.oid AND policy.polname='projection_definer_select' AND policy.polroles=ARRAY[function_owner.oid]::oid[] AND policy.polcmd='r' AND
     pg_catalog.pg_get_expr(policy.polqual,policy.polrelid)='true' AND policy.polwithcheck IS NULL)) AS valid)
SELECT checks.valid,CASE WHEN checks.valid THEN 'None' ELSE 'PrivilegeAuditFailed' END,2::smallint FROM checks;
$function$;
ALTER FUNCTION agent_private.audit_ingest_privileges(name) OWNER TO :"agent_table_owner_role";
ALTER FUNCTION agent_private.audit_enrollment_privileges(name,name,text) OWNER TO :"agent_enrollment_definer_role";
ALTER FUNCTION agent_private.audit_projection_privileges(uuid,name,name) OWNER TO :"agent_projection_definer_role";
REVOKE ALL ON FUNCTION agent_private.audit_ingest_privileges(name),
    agent_private.audit_enrollment_privileges(name,name,text),
    agent_private.audit_projection_privileges(uuid,name,name) FROM PUBLIC;
SELECT 1/pg_catalog.count(*) AS isolation_guard_postflight FROM (SELECT 1 WHERE
    agent_private.platform_grant_role_is_unbound(:'agent_table_owner_role'::name) AND
    agent_private.platform_grant_role_is_unbound(:'agent_enrollment_definer_role'::name) AND
    agent_private.platform_grant_role_is_unbound(:'agent_projection_definer_role'::name)) checked;
-- Completion capability: emitted only after all three audit replacements and postflight.
CREATE OR REPLACE FUNCTION agent_private.platform_grant_isolation_profile()
RETURNS smallint LANGUAGE sql SECURITY INVOKER
SET search_path=pg_catalog,agent_private,pg_temp
AS 'SELECT 1::smallint';
ALTER FUNCTION agent_private.platform_grant_isolation_profile() OWNER TO :"agent_table_owner_role";
REVOKE ALL ON FUNCTION agent_private.platform_grant_isolation_profile() FROM PUBLIC;
COMMIT;