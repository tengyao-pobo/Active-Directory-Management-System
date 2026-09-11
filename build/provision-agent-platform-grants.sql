\set ON_ERROR_STOP on
BEGIN;
-- Optional legacy mode remains available while the v2 marker and registry are both absent.
-- Once v2 exists, role identity is reserved transactionally before any ALTER or GRANT.
DO $capability_registry_reservation$
DECLARE v_marker regprocedure:=pg_catalog.to_regprocedure('agent_private.agent_capability_isolation_profile()');v_registry regclass:=pg_catalog.to_regclass('agent_private.agent_capability_roles');v_valid boolean;
BEGIN
 IF (v_marker IS NULL)<>(v_registry IS NULL) THEN RAISE EXCEPTION USING ERRCODE='22012';END IF;
 IF v_marker IS NULL THEN RETURN;END IF;
 SELECT marker.proowner=namespace.nspowner AND marker.prolang=(SELECT oid FROM pg_catalog.pg_language WHERE lanname='sql') AND NOT marker.prosecdef AND marker.prokind='f' AND NOT marker.proretset AND marker.prorettype='smallint'::pg_catalog.regtype AND marker.pronargs=0 AND marker.proargnames IS NULL AND marker.proconfig=ARRAY['search_path=pg_catalog, agent_private, pg_temp']::text[] AND pg_catalog.btrim(marker.prosrc)=pg_catalog.btrim('SELECT 2::smallint') INTO v_valid FROM pg_catalog.pg_proc marker JOIN pg_catalog.pg_namespace namespace ON namespace.oid=marker.pronamespace WHERE marker.oid=v_marker;
 IF NOT COALESCE(v_valid,false) THEN RAISE EXCEPTION USING ERRCODE='22012';END IF;
 EXECUTE 'SELECT NOT EXISTS(SELECT 1 FROM agent_private.agent_capability_roles WHERE role_name=$1 AND (capability<>$2 OR role_kind<>$3))' INTO v_valid USING :'agent_platform_grant_role'::name,'PlatformGrant','Runtime';
 IF NOT v_valid THEN RAISE EXCEPTION USING ERRCODE='22012';END IF;
 EXECUTE 'SELECT count(*)=1 FROM agent_private.agent_capability_roles WHERE role_name=$1 AND capability=$2 AND role_kind=''Definer''' INTO v_valid USING :'agent_platform_grant_definer_role'::name,'PlatformGrant';
 IF NOT v_valid THEN RAISE EXCEPTION USING ERRCODE='22012';END IF;
 EXECUTE 'INSERT INTO agent_private.agent_capability_roles(role_name,capability,role_kind) VALUES($1,$2,$3) ON CONFLICT(role_name) DO NOTHING' USING :'agent_platform_grant_role'::name,'PlatformGrant','Runtime';
 EXECUTE 'SELECT count(*)=1 FROM agent_private.agent_capability_roles WHERE role_name=$1 AND capability=$2 AND role_kind=$3' INTO v_valid USING :'agent_platform_grant_role'::name,'PlatformGrant','Runtime';
 IF NOT v_valid THEN RAISE EXCEPTION USING ERRCODE='22012';END IF;
END
$capability_registry_reservation$;

SELECT 1/pg_catalog.count(*) AS roles_are_distinct FROM (SELECT 1 WHERE
 :'agent_table_owner_role'<>:'agent_platform_grant_definer_role' AND :'agent_table_owner_role'<>:'agent_platform_grant_role' AND :'agent_platform_grant_definer_role'<>:'agent_platform_grant_role') checked;
SELECT 1/pg_catalog.count(*) AS roles_are_unbound FROM (SELECT 1 WHERE
 NOT EXISTS(SELECT 1 FROM agent_private.agent_database_bindings WHERE login_role IN(:'agent_platform_grant_role'::name,:'agent_platform_grant_definer_role'::name)) AND
 NOT EXISTS(SELECT 1 FROM agent_private.enrollment_database_bindings WHERE login_role IN(:'agent_platform_grant_role'::name,:'agent_platform_grant_definer_role'::name)) AND
 NOT EXISTS(SELECT 1 FROM agent_private.agent_projection_database_bindings WHERE login_role IN(:'agent_platform_grant_role'::name,:'agent_platform_grant_definer_role'::name)) AND
 NOT EXISTS(SELECT 1 FROM agent_private.platform_grant_database_bindings WHERE login_role=:'agent_platform_grant_definer_role'::name) AND
 NOT EXISTS(SELECT 1 FROM agent_private.platform_grant_database_bindings WHERE login_role=:'agent_platform_grant_role'::name AND (environment_id<>:'environment_id'::uuid OR purpose<>'IssueInitialGrant')) AND
 NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles old_role WHERE old_role.rolname IN(
   SELECT login_role::text FROM agent_private.agent_database_bindings UNION SELECT login_role::text FROM agent_private.enrollment_database_bindings UNION SELECT login_role::text FROM agent_private.agent_projection_database_bindings)
   AND old_role.rolname IN(:'agent_platform_grant_role',:'agent_platform_grant_definer_role'))) checked;
SELECT 1/pg_catalog.count(*) AS role_shapes_are_safe FROM (SELECT 1 WHERE
 (SELECT pg_catalog.count(*)=1 FROM pg_catalog.pg_roles role WHERE role.rolname=:'agent_table_owner_role' AND NOT role.rolcanlogin AND NOT role.rolsuper AND NOT role.rolbypassrls AND NOT role.rolcreatedb AND NOT role.rolcreaterole AND NOT role.rolinherit AND NOT role.rolreplication) AND
 (SELECT pg_catalog.count(*)=1 FROM pg_catalog.pg_roles role WHERE role.rolname=:'agent_platform_grant_definer_role' AND NOT role.rolcanlogin AND NOT role.rolsuper AND NOT role.rolbypassrls AND NOT role.rolcreatedb AND NOT role.rolcreaterole AND NOT role.rolinherit AND NOT role.rolreplication) AND
 (SELECT pg_catalog.count(*)=1 FROM pg_catalog.pg_roles role WHERE role.rolname=:'agent_platform_grant_role' AND role.rolcanlogin AND NOT role.rolsuper AND NOT role.rolbypassrls AND NOT role.rolcreatedb AND NOT role.rolcreaterole AND NOT role.rolinherit AND NOT role.rolreplication) AND
 NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members member JOIN pg_catalog.pg_roles role ON member.member=role.oid OR member.roleid=role.oid WHERE role.rolname IN(:'agent_table_owner_role',:'agent_platform_grant_definer_role',:'agent_platform_grant_role')) AND
 NOT EXISTS(SELECT 1 FROM pg_catalog.pg_database database JOIN pg_catalog.pg_roles role ON role.oid=database.datdba WHERE role.rolname IN(:'agent_table_owner_role',:'agent_platform_grant_definer_role',:'agent_platform_grant_role')) AND
 NOT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace namespace JOIN pg_catalog.pg_roles role ON role.oid=namespace.nspowner WHERE role.rolname IN(:'agent_platform_grant_definer_role',:'agent_platform_grant_role')) AND
 NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object JOIN pg_catalog.pg_roles role ON role.oid=object.relowner WHERE role.rolname IN(:'agent_platform_grant_definer_role',:'agent_platform_grant_role')) AND
 NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc function JOIN pg_catalog.pg_roles role ON role.oid=function.proowner WHERE role.rolname=:'agent_platform_grant_role') AND
 NOT pg_catalog.has_schema_privilege(:'agent_platform_grant_role','agent_private','CREATE') AND NOT pg_catalog.has_schema_privilege(:'agent_platform_grant_definer_role','agent_private','CREATE') AND
 NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object JOIN pg_catalog.pg_namespace namespace ON namespace.oid=object.relnamespace WHERE namespace.nspname='agent_private' AND object.relkind IN('r','p','v','m') AND (pg_catalog.has_table_privilege(:'agent_platform_grant_role',object.oid,'SELECT') OR pg_catalog.has_table_privilege(:'agent_platform_grant_role',object.oid,'INSERT') OR pg_catalog.has_table_privilege(:'agent_platform_grant_role',object.oid,'UPDATE') OR pg_catalog.has_table_privilege(:'agent_platform_grant_role',object.oid,'DELETE') OR pg_catalog.has_table_privilege(:'agent_platform_grant_role',object.oid,'TRUNCATE') OR pg_catalog.has_table_privilege(:'agent_platform_grant_role',object.oid,'REFERENCES') OR pg_catalog.has_table_privilege(:'agent_platform_grant_role',object.oid,'TRIGGER'))) AND
 NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object JOIN pg_catalog.pg_attribute attribute ON attribute.attrelid=object.oid JOIN pg_catalog.pg_namespace namespace ON namespace.oid=object.relnamespace,LATERAL pg_catalog.aclexplode(attribute.attacl) acl JOIN pg_catalog.pg_roles role ON role.oid=acl.grantee WHERE namespace.nspname='agent_private' AND role.rolname=:'agent_platform_grant_role') AND
 NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object JOIN pg_catalog.pg_namespace namespace ON namespace.oid=object.relnamespace WHERE namespace.nspname='agent_private' AND object.relkind='S' AND (pg_catalog.has_sequence_privilege(:'agent_platform_grant_role',object.oid,'USAGE') OR pg_catalog.has_sequence_privilege(:'agent_platform_grant_role',object.oid,'SELECT') OR pg_catalog.has_sequence_privilege(:'agent_platform_grant_role',object.oid,'UPDATE'))) AND
 NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object JOIN pg_catalog.pg_namespace namespace ON namespace.oid=object.relnamespace WHERE namespace.nspname='agent_private' AND object.relkind IN('r','p','v','m') AND (pg_catalog.has_table_privilege(:'agent_platform_grant_definer_role',object.oid,'SELECT') OR pg_catalog.has_table_privilege(:'agent_platform_grant_definer_role',object.oid,'INSERT') OR pg_catalog.has_table_privilege(:'agent_platform_grant_definer_role',object.oid,'UPDATE') OR pg_catalog.has_table_privilege(:'agent_platform_grant_definer_role',object.oid,'DELETE') OR pg_catalog.has_table_privilege(:'agent_platform_grant_definer_role',object.oid,'TRUNCATE') OR pg_catalog.has_table_privilege(:'agent_platform_grant_definer_role',object.oid,'REFERENCES') OR pg_catalog.has_table_privilege(:'agent_platform_grant_definer_role',object.oid,'TRIGGER'))) AND
 NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object JOIN pg_catalog.pg_namespace namespace ON namespace.oid=object.relnamespace WHERE namespace.nspname='agent_private' AND object.relkind='S' AND (pg_catalog.has_sequence_privilege(:'agent_platform_grant_definer_role',object.oid,'USAGE') OR pg_catalog.has_sequence_privilege(:'agent_platform_grant_definer_role',object.oid,'SELECT') OR pg_catalog.has_sequence_privilege(:'agent_platform_grant_definer_role',object.oid,'UPDATE')))) checked;

ALTER ROLE :"agent_platform_grant_definer_role" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION;
ALTER ROLE :"agent_platform_grant_role" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION;
GRANT CONNECT ON DATABASE :DBNAME TO :"agent_platform_grant_role";
GRANT USAGE ON SCHEMA agent_private TO :"agent_platform_grant_role";
REVOKE ALL ON ALL TABLES IN SCHEMA agent_private FROM :"agent_platform_grant_role";
REVOKE ALL ON ALL SEQUENCES IN SCHEMA agent_private FROM :"agent_platform_grant_role";
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA agent_private FROM :"agent_platform_grant_role";
GRANT EXECUTE ON FUNCTION agent_private.issue_initial_enrollment_grant(uuid,uuid,uuid,uuid,timestamptz,bytea,bytea),agent_private.audit_platform_grant_privileges(uuid,name,name) TO :"agent_platform_grant_role";
INSERT INTO agent_private.platform_grant_database_bindings(login_role,environment_id,purpose)
VALUES(:'agent_platform_grant_role'::name,:'environment_id'::uuid,'IssueInitialGrant') ON CONFLICT DO NOTHING;
SELECT 1/pg_catalog.count(*) AS exact_binding FROM agent_private.platform_grant_database_bindings binding WHERE binding.login_role=:'agent_platform_grant_role'::name AND binding.environment_id=:'environment_id'::uuid AND binding.purpose='IssueInitialGrant';
SELECT 1/pg_catalog.count(*) AS unique_environment_binding FROM agent_private.platform_grant_database_bindings binding WHERE binding.environment_id=:'environment_id'::uuid AND binding.purpose='IssueInitialGrant';

-- Generated from the runtime audit predicates; provisioning evaluates the same invariants for the named login.
WITH login AS(SELECT role.* FROM pg_catalog.pg_roles role WHERE role.rolname=:'agent_platform_grant_role'),
 function_owner AS(SELECT role.* FROM pg_catalog.pg_roles role WHERE role.rolname=:'agent_platform_grant_definer_role'::name),
 table_owner AS(SELECT role.* FROM pg_catalog.pg_roles role WHERE role.rolname=:'agent_table_owner_role'::name),
 schema_info AS(SELECT namespace.oid,namespace.nspowner FROM pg_catalog.pg_namespace namespace WHERE namespace.nspname='agent_private'),
 eligible_logins AS(SELECT role.* FROM agent_private.platform_grant_database_bindings binding JOIN pg_catalog.pg_roles role ON role.rolname=binding.login_role WHERE binding.purpose='IssueInitialGrant'),
 expected_columns(relname,attname,privilege_type,is_grantable) AS(VALUES
  ('platform_grant_database_bindings','login_role','SELECT',false),('platform_grant_database_bindings','environment_id','SELECT',false),('platform_grant_database_bindings','purpose','SELECT',false),
  ('agent_database_bindings','login_role','SELECT',false),('enrollment_database_bindings','login_role','SELECT',false),('agent_projection_database_bindings','login_role','SELECT',false),
  ('platform_grant_receipts','environment_id','SELECT',false),('platform_grant_receipts','operation_id','SELECT',false),('platform_grant_receipts','grant_id','SELECT',false),('platform_grant_receipts','directory_object_id','SELECT',false),('platform_grant_receipts','device_id','SELECT',false),('platform_grant_receipts','mapping_created_at','SELECT',false),('platform_grant_receipts','token_sha256','SELECT',false),('platform_grant_receipts','authorization_digest','SELECT',false),('platform_grant_receipts','created_at','SELECT',false),('platform_grant_receipts','expires_at','SELECT',false),
  ('platform_grant_receipts','environment_id','INSERT',false),('platform_grant_receipts','operation_id','INSERT',false),('platform_grant_receipts','grant_id','INSERT',false),('platform_grant_receipts','directory_object_id','INSERT',false),('platform_grant_receipts','device_id','INSERT',false),('platform_grant_receipts','mapping_created_at','INSERT',false),('platform_grant_receipts','token_sha256','INSERT',false),('platform_grant_receipts','authorization_digest','INSERT',false),('platform_grant_receipts','created_at','INSERT',false),('platform_grant_receipts','expires_at','INSERT',false),
  ('agent_device_directory_bindings','environment_id','SELECT',false),('agent_device_directory_bindings','directory_object_id','SELECT',false),('agent_device_directory_bindings','device_id','SELECT',false),('agent_device_directory_bindings','created_at','SELECT',false),
  ('devices','environment_id','SELECT',false),('devices','device_id','SELECT',false),('devices','state','SELECT',false),
  ('registrations','environment_id','SELECT',false),('registrations','device_id','SELECT',false),('registrations','state','SELECT',false),
  ('enrollment_requests','environment_id','SELECT',false),('enrollment_requests','device_id','SELECT',false),('enrollment_requests','state','SELECT',false),
  ('enrollment_grants','environment_id','SELECT',false),('enrollment_grants','grant_id','SELECT',false),('enrollment_grants','device_id','SELECT',false),('enrollment_grants','token_sha256','SELECT',false),('enrollment_grants','state','SELECT',false),
  ('enrollment_grants','environment_id','INSERT',false),('enrollment_grants','grant_id','INSERT',false),('enrollment_grants','device_id','INSERT',false),('enrollment_grants','token_sha256','INSERT',false),('enrollment_grants','state','INSERT',false),('enrollment_grants','created_at','INSERT',false),('enrollment_grants','expires_at','INSERT',false)),
 actual_columns AS(SELECT object.relname,attribute.attname,acl.privilege_type,acl.is_grantable FROM pg_catalog.pg_class object JOIN pg_catalog.pg_attribute attribute ON attribute.attrelid=object.oid,schema_info,function_owner,LATERAL pg_catalog.aclexplode(attribute.attacl) acl WHERE object.relnamespace=schema_info.oid AND acl.grantee=function_owner.oid),
 expected_execute(signature) AS(VALUES('agent_private.issue_initial_enrollment_grant(uuid,uuid,uuid,uuid,timestamptz,bytea,bytea)'::pg_catalog.regprocedure),('agent_private.audit_platform_grant_privileges(uuid,name,name)'::pg_catalog.regprocedure)),
 actual_execute AS(SELECT function.oid::pg_catalog.regprocedure AS signature FROM pg_catalog.pg_proc function,schema_info WHERE function.pronamespace=schema_info.oid AND pg_catalog.has_function_privilege(:'agent_platform_grant_role',function.oid,'EXECUTE')),
 expected_function_acl(signature,grantee,is_grantable) AS(
  SELECT expected.signature,function_owner.oid,false FROM expected_execute expected,function_owner
  UNION ALL SELECT expected.signature,eligible.oid,false FROM expected_execute expected,eligible_logins eligible),
 actual_function_acl AS(SELECT function.oid::pg_catalog.regprocedure AS signature,acl.grantee,acl.is_grantable FROM pg_catalog.pg_proc function,schema_info,LATERAL pg_catalog.aclexplode(coalesce(function.proacl,pg_catalog.acldefault('f',function.proowner))) acl WHERE function.pronamespace=schema_info.oid AND function.oid=ANY(ARRAY['agent_private.issue_initial_enrollment_grant(uuid,uuid,uuid,uuid,timestamptz,bytea,bytea)'::pg_catalog.regprocedure,'agent_private.audit_platform_grant_privileges(uuid,name,name)'::pg_catalog.regprocedure]::oid[]) AND acl.privilege_type='EXECUTE'),
 expected_policies(relname,polname,polcmd,qual,withcheck) AS(VALUES
  ('platform_grant_database_bindings','platform_grant_definer_select','r','true',NULL::text),
  ('platform_grant_receipts','platform_grant_definer_select','r','true',NULL::text),('platform_grant_receipts','platform_grant_definer_insert','a',NULL::text,'true'),
  ('agent_database_bindings','platform_grant_definer_select','r','true',NULL::text),('enrollment_database_bindings','platform_grant_definer_select','r','true',NULL::text),('agent_projection_database_bindings','platform_grant_definer_select','r','true',NULL::text),
  ('agent_device_directory_bindings','platform_grant_definer_select','r','true',NULL::text),('devices','platform_grant_definer_select','r','true',NULL::text),
  ('registrations','platform_grant_definer_select','r','true',NULL::text),('enrollment_requests','platform_grant_definer_select','r','true',NULL::text),
  ('enrollment_grants','platform_grant_definer_select','r','true',NULL::text),('enrollment_grants','platform_grant_definer_insert','a',NULL::text,'true')),
 expected_owner_policies(relname) AS(VALUES('platform_grant_database_bindings'),('platform_grant_receipts')),
 checks AS(SELECT
  (SELECT pg_catalog.count(*)=1 FROM login) AND (SELECT pg_catalog.count(*)=1 FROM function_owner) AND (SELECT pg_catalog.count(*)=1 FROM table_owner) AND
  NOT EXISTS(SELECT 1 FROM login WHERE NOT rolcanlogin OR rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole OR rolinherit OR rolreplication) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members member,login WHERE member.member=login.oid OR member.roleid=login.oid) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_database database,login WHERE database.datdba=login.oid) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace namespace,login WHERE namespace.nspowner=login.oid) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object,login WHERE object.relowner=login.oid) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc function,login WHERE function.proowner=login.oid) AND
  NOT EXISTS(SELECT 1 FROM agent_private.agent_database_bindings binding WHERE binding.login_role=:'agent_platform_grant_role'::name) AND
  NOT EXISTS(SELECT 1 FROM agent_private.enrollment_database_bindings binding WHERE binding.login_role=:'agent_platform_grant_role'::name) AND
  NOT EXISTS(SELECT 1 FROM agent_private.agent_projection_database_bindings binding WHERE binding.login_role=:'agent_platform_grant_role'::name) AND
  (SELECT pg_catalog.count(*)=1 FROM agent_private.platform_grant_database_bindings binding WHERE binding.login_role=:'agent_platform_grant_role'::name AND binding.environment_id=:'environment_id'::uuid AND binding.purpose='IssueInitialGrant') AND
  NOT pg_catalog.has_schema_privilege(:'agent_platform_grant_role','agent_private','CREATE') AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object,schema_info WHERE object.relnamespace=schema_info.oid AND object.relkind IN('r','p','v','m') AND (pg_catalog.has_table_privilege(:'agent_platform_grant_role',object.oid,'SELECT') OR pg_catalog.has_table_privilege(:'agent_platform_grant_role',object.oid,'INSERT') OR pg_catalog.has_table_privilege(:'agent_platform_grant_role',object.oid,'UPDATE') OR pg_catalog.has_table_privilege(:'agent_platform_grant_role',object.oid,'DELETE') OR pg_catalog.has_table_privilege(:'agent_platform_grant_role',object.oid,'TRUNCATE') OR pg_catalog.has_table_privilege(:'agent_platform_grant_role',object.oid,'REFERENCES') OR pg_catalog.has_table_privilege(:'agent_platform_grant_role',object.oid,'TRIGGER'))) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object JOIN pg_catalog.pg_attribute attribute ON attribute.attrelid=object.oid,schema_info,login,LATERAL pg_catalog.aclexplode(attribute.attacl) acl WHERE object.relnamespace=schema_info.oid AND acl.grantee IN(0,login.oid)) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object,schema_info WHERE object.relnamespace=schema_info.oid AND object.relkind='S' AND (pg_catalog.has_sequence_privilege(:'agent_platform_grant_role',object.oid,'USAGE') OR pg_catalog.has_sequence_privilege(:'agent_platform_grant_role',object.oid,'SELECT') OR pg_catalog.has_sequence_privilege(:'agent_platform_grant_role',object.oid,'UPDATE'))) AND
  NOT EXISTS((SELECT * FROM expected_execute EXCEPT SELECT * FROM actual_execute) UNION ALL(SELECT * FROM actual_execute EXCEPT SELECT * FROM expected_execute)) AND
  (SELECT pg_catalog.count(*) FROM eligible_logins)=(SELECT pg_catalog.count(*) FROM agent_private.platform_grant_database_bindings WHERE purpose='IssueInitialGrant') AND
  NOT EXISTS(SELECT 1 FROM eligible_logins WHERE NOT rolcanlogin OR rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole OR rolinherit OR rolreplication) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members member,eligible_logins eligible WHERE member.member=eligible.oid OR member.roleid=eligible.oid) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_database database,eligible_logins eligible WHERE database.datdba=eligible.oid) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace namespace,eligible_logins eligible WHERE namespace.nspowner=eligible.oid) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object,eligible_logins eligible WHERE object.relowner=eligible.oid) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc function,eligible_logins eligible WHERE function.proowner=eligible.oid) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object,schema_info,eligible_logins eligible WHERE object.relnamespace=schema_info.oid AND object.relkind IN('r','p','v','m') AND (pg_catalog.has_table_privilege(eligible.rolname,object.oid,'SELECT') OR pg_catalog.has_table_privilege(eligible.rolname,object.oid,'INSERT') OR pg_catalog.has_table_privilege(eligible.rolname,object.oid,'UPDATE') OR pg_catalog.has_table_privilege(eligible.rolname,object.oid,'DELETE') OR pg_catalog.has_table_privilege(eligible.rolname,object.oid,'TRUNCATE') OR pg_catalog.has_table_privilege(eligible.rolname,object.oid,'REFERENCES') OR pg_catalog.has_table_privilege(eligible.rolname,object.oid,'TRIGGER'))) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object JOIN pg_catalog.pg_attribute attribute ON attribute.attrelid=object.oid,schema_info,eligible_logins eligible,LATERAL pg_catalog.aclexplode(attribute.attacl) acl WHERE object.relnamespace=schema_info.oid AND acl.grantee=eligible.oid) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object,schema_info,eligible_logins eligible WHERE object.relnamespace=schema_info.oid AND object.relkind='S' AND (pg_catalog.has_sequence_privilege(eligible.rolname,object.oid,'USAGE') OR pg_catalog.has_sequence_privilege(eligible.rolname,object.oid,'SELECT') OR pg_catalog.has_sequence_privilege(eligible.rolname,object.oid,'UPDATE'))) AND
  NOT EXISTS(SELECT 1 FROM agent_private.agent_database_bindings binding,eligible_logins eligible WHERE binding.login_role=eligible.rolname::name) AND
  NOT EXISTS(SELECT 1 FROM agent_private.enrollment_database_bindings binding,eligible_logins eligible WHERE binding.login_role=eligible.rolname::name) AND
  NOT EXISTS(SELECT 1 FROM agent_private.agent_projection_database_bindings binding,eligible_logins eligible WHERE binding.login_role=eligible.rolname::name) AND
  (COALESCE((SELECT
    helper.proowner=(SELECT oid FROM table_owner) AND helper.proowner=namespace.nspowner AND helper.prosecdef AND helper.prokind='f' AND
    NOT helper.proretset AND helper.prorettype='boolean'::pg_catalog.regtype AND helper.proargnames=ARRAY['p_role']::text[] AND
    helper.proconfig=ARRAY['search_path=pg_catalog, agent_private, pg_temp']::text[] AND
    NOT EXISTS(SELECT 1 FROM pg_catalog.aclexplode(COALESCE(helper.proacl,pg_catalog.acldefault('f',helper.proowner))) acl
      LEFT JOIN pg_catalog.pg_roles grantee ON grantee.oid=acl.grantee
      WHERE acl.privilege_type<>'EXECUTE' OR grantee.oid IS NULL OR (acl.grantee<>helper.proowner AND acl.is_grantable) OR
       grantee.rolcanlogin OR grantee.rolsuper OR grantee.rolbypassrls OR grantee.rolcreatedb OR grantee.rolcreaterole OR
       grantee.rolinherit OR grantee.rolreplication OR
       EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members member WHERE member.member=grantee.oid OR member.roleid=grantee.oid) OR
       acl.grantee NOT IN(SELECT helper.proowner UNION SELECT audit.proowner FROM pg_catalog.pg_proc audit WHERE audit.oid IN(
        pg_catalog.to_regprocedure('agent_private.audit_enrollment_privileges(name,name,text)'),
        pg_catalog.to_regprocedure('agent_private.audit_projection_privileges(uuid,name,name)')))) AND
    NOT EXISTS(SELECT 1 FROM(SELECT helper.proowner AS oid UNION SELECT audit.proowner FROM pg_catalog.pg_proc audit WHERE audit.oid IN(
        pg_catalog.to_regprocedure('agent_private.audit_enrollment_privileges(name,name,text)'),
        pg_catalog.to_regprocedure('agent_private.audit_projection_privileges(uuid,name,name)'))) expected
      WHERE NOT EXISTS(SELECT 1 FROM pg_catalog.aclexplode(COALESCE(helper.proacl,pg_catalog.acldefault('f',helper.proowner))) acl
       WHERE acl.grantee=expected.oid AND acl.privilege_type='EXECUTE'))
   FROM pg_catalog.pg_proc helper JOIN pg_catalog.pg_namespace namespace ON namespace.oid=helper.pronamespace
   WHERE helper.oid=pg_catalog.to_regprocedure('agent_private.platform_grant_role_is_unbound(name)')),false)) AND
  NOT EXISTS((SELECT * FROM expected_function_acl EXCEPT SELECT * FROM actual_function_acl) UNION ALL(SELECT * FROM actual_function_acl EXCEPT SELECT * FROM expected_function_acl)) AND
  NOT EXISTS(SELECT 1 FROM function_owner WHERE rolcanlogin OR rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole OR rolinherit OR rolreplication) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members member,function_owner WHERE member.member=function_owner.oid OR member.roleid=function_owner.oid) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_database database,function_owner WHERE database.datdba=function_owner.oid) AND
  NOT EXISTS(SELECT 1 FROM schema_info,function_owner WHERE schema_info.nspowner=function_owner.oid) AND
  NOT pg_catalog.has_schema_privilege(:'agent_platform_grant_definer_role'::name,'agent_private','CREATE') AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object,schema_info,function_owner WHERE object.relnamespace=schema_info.oid AND object.relowner=function_owner.oid) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object,schema_info,function_owner WHERE object.relnamespace=schema_info.oid AND object.relkind IN('r','p','v','m') AND (pg_catalog.has_table_privilege(function_owner.rolname,object.oid,'SELECT') OR pg_catalog.has_table_privilege(function_owner.rolname,object.oid,'INSERT') OR pg_catalog.has_table_privilege(function_owner.rolname,object.oid,'UPDATE') OR pg_catalog.has_table_privilege(function_owner.rolname,object.oid,'DELETE') OR pg_catalog.has_table_privilege(function_owner.rolname,object.oid,'TRUNCATE') OR pg_catalog.has_table_privilege(function_owner.rolname,object.oid,'REFERENCES') OR pg_catalog.has_table_privilege(function_owner.rolname,object.oid,'TRIGGER'))) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object,schema_info,function_owner WHERE object.relnamespace=schema_info.oid AND object.relkind='S' AND (pg_catalog.has_sequence_privilege(function_owner.rolname,object.oid,'USAGE') OR pg_catalog.has_sequence_privilege(function_owner.rolname,object.oid,'SELECT') OR pg_catalog.has_sequence_privilege(function_owner.rolname,object.oid,'UPDATE'))) AND
  (SELECT pg_catalog.count(*)=2 FROM pg_catalog.pg_proc function,schema_info,function_owner WHERE function.pronamespace=schema_info.oid AND function.proowner=function_owner.oid) AND
  NOT EXISTS(SELECT 1 FROM agent_private.agent_database_bindings binding,function_owner WHERE binding.login_role=function_owner.rolname::name) AND
  NOT EXISTS(SELECT 1 FROM agent_private.enrollment_database_bindings binding,function_owner WHERE binding.login_role=function_owner.rolname::name) AND
  NOT EXISTS(SELECT 1 FROM agent_private.agent_projection_database_bindings binding,function_owner WHERE binding.login_role=function_owner.rolname::name) AND
  NOT EXISTS(SELECT 1 FROM agent_private.platform_grant_database_bindings binding,function_owner WHERE binding.login_role=function_owner.rolname::name) AND
  NOT EXISTS((SELECT * FROM expected_columns EXCEPT SELECT * FROM actual_columns) UNION ALL(SELECT * FROM actual_columns EXCEPT SELECT * FROM expected_columns)) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object,schema_info,table_owner,LATERAL pg_catalog.aclexplode(object.relacl) acl WHERE object.relnamespace=schema_info.oid AND object.relname IN('platform_grant_database_bindings','platform_grant_receipts') AND acl.grantee<>table_owner.oid) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object JOIN pg_catalog.pg_attribute attribute ON attribute.attrelid=object.oid,schema_info,function_owner,LATERAL pg_catalog.aclexplode(attribute.attacl) acl WHERE object.relnamespace=schema_info.oid AND object.relname IN('platform_grant_database_bindings','platform_grant_receipts') AND acl.grantee<>function_owner.oid) AND
  NOT EXISTS(SELECT 1 FROM table_owner WHERE rolcanlogin OR rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole OR rolinherit OR rolreplication) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members member,table_owner WHERE member.member=table_owner.oid OR member.roleid=table_owner.oid) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_database database,table_owner WHERE database.datdba=table_owner.oid) AND
  (SELECT pg_catalog.count(*)=1 FROM schema_info,table_owner WHERE schema_info.nspowner=table_owner.oid) AND
  (SELECT pg_catalog.count(*)=8 AND pg_catalog.bool_and(owner.rolname=:'agent_table_owner_role'::name) FROM pg_catalog.pg_class object JOIN pg_catalog.pg_roles owner ON owner.oid=object.relowner,schema_info WHERE object.relnamespace=schema_info.oid AND object.relkind='r' AND object.relname=ANY(ARRAY['devices','registrations','enrollment_grants','enrollment_requests','agent_device_directory_bindings','agent_projection_database_bindings','platform_grant_database_bindings','platform_grant_receipts'])) AND
  (SELECT pg_catalog.count(*)=2 AND pg_catalog.bool_and(function.prosecdef AND function.proowner=function_owner.oid AND function.proconfig=ARRAY['search_path=pg_catalog, agent_private, pg_temp']) FROM pg_catalog.pg_proc function,schema_info,function_owner WHERE function.pronamespace=schema_info.oid AND function.proname=ANY(ARRAY['issue_initial_enrollment_grant','audit_platform_grant_privileges'])) AND
  (SELECT pg_catalog.count(*)=2 AND pg_catalog.bool_and(function.prosecdef AND function.proowner=table_owner.oid AND function.proconfig=ARRAY['search_path=pg_catalog, agent_private, pg_temp']) FROM pg_catalog.pg_proc function,schema_info,table_owner WHERE function.pronamespace=schema_info.oid AND function.proname=ANY(ARRAY['lock_agent_device_directory_binding','lock_agent_device'])) AND
  pg_catalog.has_function_privilege(:'agent_platform_grant_definer_role'::name,'agent_private.lock_agent_device_directory_binding(uuid,uuid)'::pg_catalog.regprocedure,'EXECUTE') AND
  pg_catalog.has_function_privilege(:'agent_platform_grant_definer_role'::name,'agent_private.lock_agent_device(uuid,uuid)'::pg_catalog.regprocedure,'EXECUTE') AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc function,schema_info,function_owner,LATERAL pg_catalog.aclexplode(coalesce(function.proacl,pg_catalog.acldefault('f',function.proowner))) acl WHERE function.pronamespace=schema_info.oid AND function.proname=ANY(ARRAY['lock_agent_device_directory_binding','lock_agent_device']) AND (acl.grantee NOT IN(function.proowner,function_owner.oid) OR acl.privilege_type<>'EXECUTE' OR (acl.grantee<>function.proowner AND acl.is_grantable))) AND
  NOT EXISTS(SELECT 1 FROM expected_policies expected,function_owner WHERE NOT EXISTS(SELECT 1 FROM pg_catalog.pg_policy policy JOIN pg_catalog.pg_class object ON object.oid=policy.polrelid JOIN pg_catalog.pg_namespace namespace ON namespace.oid=object.relnamespace WHERE namespace.nspname='agent_private' AND object.relname=expected.relname AND policy.polname=expected.polname AND policy.polcmd=expected.polcmd AND policy.polpermissive AND policy.polroles=ARRAY[function_owner.oid]::oid[] AND pg_catalog.pg_get_expr(policy.polqual,policy.polrelid) IS NOT DISTINCT FROM expected.qual AND pg_catalog.pg_get_expr(policy.polwithcheck,policy.polrelid) IS NOT DISTINCT FROM expected.withcheck)) AND
  NOT EXISTS(SELECT 1 FROM expected_owner_policies expected,table_owner WHERE NOT EXISTS(SELECT 1 FROM pg_catalog.pg_policy policy JOIN pg_catalog.pg_class object ON object.oid=policy.polrelid JOIN pg_catalog.pg_namespace namespace ON namespace.oid=object.relnamespace WHERE namespace.nspname='agent_private' AND object.relname=expected.relname AND policy.polname='definer_all' AND policy.polcmd='*' AND policy.polpermissive AND policy.polroles=ARRAY[table_owner.oid]::oid[] AND pg_catalog.pg_get_expr(policy.polqual,policy.polrelid)='true' AND pg_catalog.pg_get_expr(policy.polwithcheck,policy.polrelid)='true')) AND
  (SELECT pg_catalog.count(*)=5 FROM pg_catalog.pg_policy policy JOIN pg_catalog.pg_class object ON object.oid=policy.polrelid,schema_info WHERE object.relnamespace=schema_info.oid AND object.relname IN('platform_grant_database_bindings','platform_grant_receipts')) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_policy policy JOIN pg_catalog.pg_class object ON object.oid=policy.polrelid JOIN pg_catalog.pg_namespace namespace ON namespace.oid=object.relnamespace,function_owner WHERE namespace.nspname='agent_private' AND function_owner.oid=ANY(policy.polroles) AND policy.polname LIKE 'platform_grant_definer_%' AND NOT EXISTS(SELECT 1 FROM expected_policies expected WHERE expected.relname=object.relname AND expected.polname=policy.polname AND expected.polcmd=policy.polcmd)) AND
  (SELECT pg_catalog.count(*)=8 AND pg_catalog.bool_and(object.relrowsecurity AND object.relforcerowsecurity) FROM pg_catalog.pg_class object,schema_info WHERE object.relnamespace=schema_info.oid AND object.relkind='r' AND object.relname=ANY(ARRAY['devices','registrations','enrollment_grants','enrollment_requests','agent_device_directory_bindings','agent_projection_database_bindings','platform_grant_database_bindings','platform_grant_receipts'])) AS valid)
SELECT 1/pg_catalog.count(*) AS exact_target_privilege_postflight FROM checks WHERE valid;

COMMIT;
