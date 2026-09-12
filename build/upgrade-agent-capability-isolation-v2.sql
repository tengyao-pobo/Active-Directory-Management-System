\set ON_ERROR_STOP on
BEGIN;

-- Upgrade is accepted only from the reviewed platform-isolation profile, or from this exact completed v2 profile.
SELECT 1/pg_catalog.count(*) AS source_profile_is_known FROM (SELECT 1 WHERE
 (COALESCE((SELECT marker.proowner=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=:'agent_table_owner_role') AND marker.proowner=namespace.nspowner AND marker.prolang=(SELECT oid FROM pg_catalog.pg_language WHERE lanname='sql') AND NOT marker.prosecdef AND marker.prokind='f' AND NOT marker.proretset AND marker.prorettype='smallint'::pg_catalog.regtype AND marker.pronargs=0 AND marker.proargnames IS NULL AND marker.proconfig=ARRAY['search_path=pg_catalog, agent_private, pg_temp']::text[] AND pg_catalog.btrim(marker.prosrc,E' \t\r\n')='SELECT 1::smallint' AND NOT EXISTS(SELECT 1 FROM pg_catalog.aclexplode(COALESCE(marker.proacl,pg_catalog.acldefault('f',marker.proowner))) acl WHERE acl.privilege_type<>'EXECUTE' OR acl.grantee<>marker.proowner OR acl.is_grantable) FROM pg_catalog.pg_proc marker JOIN pg_catalog.pg_namespace namespace ON namespace.oid=marker.pronamespace WHERE marker.oid=pg_catalog.to_regprocedure('agent_private.platform_grant_isolation_profile()')),false) AND
  pg_catalog.to_regprocedure('agent_private.agent_capability_isolation_profile()') IS NULL AND
  pg_catalog.to_regclass('agent_private.agent_capability_roles') IS NULL AND
  pg_catalog.to_regprocedure('agent_private.agent_role_has_capability(name,text,text)') IS NULL)
 OR COALESCE((SELECT marker.proowner=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=:'agent_table_owner_role') AND marker.proowner=namespace.nspowner AND marker.prolang=(SELECT oid FROM pg_catalog.pg_language WHERE lanname='sql') AND NOT marker.prosecdef AND marker.prokind='f' AND
   NOT marker.proretset AND marker.prorettype='smallint'::pg_catalog.regtype AND marker.pronargs=0 AND marker.proargnames IS NULL AND
   marker.proconfig=ARRAY['search_path=pg_catalog, agent_private, pg_temp']::text[] AND
   pg_catalog.btrim(marker.prosrc,E' \t\r\n')='SELECT 2::smallint' AND NOT EXISTS(SELECT 1 FROM pg_catalog.aclexplode(COALESCE(marker.proacl,pg_catalog.acldefault('f',marker.proowner))) acl WHERE acl.privilege_type<>'EXECUTE' OR acl.grantee<>marker.proowner OR acl.is_grantable)
  FROM pg_catalog.pg_proc marker JOIN pg_catalog.pg_namespace namespace ON namespace.oid=marker.pronamespace
  WHERE marker.oid=pg_catalog.to_regprocedure('agent_private.agent_capability_isolation_profile()')),false)) checked;

-- Preserve a completed lifecycle-v2 platform audit on idempotent capability upgrades.
-- A partial lifecycle shape is rejected before any registry or audit mutation.
CREATE TEMP TABLE pg_temp.platform_grant_lifecycle_source(
 profile_version smallint PRIMARY KEY,
 audit_definition text NOT NULL
) ON COMMIT DROP;
WITH audit AS(
 SELECT function.*,owner.rolname AS owner_name,pg_catalog.md5(pg_catalog.btrim(function.prosrc,E' \t\r\n')) AS body_hash
 FROM pg_catalog.pg_proc function JOIN pg_catalog.pg_roles owner ON owner.oid=function.proowner
 WHERE function.oid=pg_catalog.to_regprocedure('agent_private.audit_platform_grant_privileges(uuid,name,name)')),
 lifecycle AS(
 SELECT CASE
  WHEN audit.body_hash='64a11bee2af9f76b2d5e33c1b168934d' AND
    pg_catalog.to_regclass('agent_private.platform_grant_revocation_receipts') IS NOT NULL AND
    (SELECT pg_catalog.count(*)=2 AND pg_catalog.bool_and(attribute.attnotnull IS NOT DISTINCT FROM expected.not_null AND attribute.atttypid=expected.type_oid) FROM (VALUES
      (pg_catalog.to_regclass('agent_private.platform_grant_receipts'),'issue_contract_version','smallint'::pg_catalog.regtype::oid,true),
      (pg_catalog.to_regclass('agent_private.platform_grant_revocation_receipts'),'issue_contract_version','smallint'::pg_catalog.regtype::oid,true)) expected(relid,attname,type_oid,not_null)
     JOIN pg_catalog.pg_attribute attribute ON attribute.attrelid=expected.relid AND attribute.attname=expected.attname AND NOT attribute.attisdropped) AND
    (SELECT pg_catalog.count(*)=2 FROM (VALUES
      (pg_catalog.to_regclass('agent_private.platform_grant_receipts'),'mint_permit_not_after'),
      (pg_catalog.to_regclass('agent_private.platform_grant_revocation_receipts'),'issue_mint_permit_not_after')) expected(relid,attname)
     JOIN pg_catalog.pg_attribute attribute ON attribute.attrelid=expected.relid AND attribute.attname=expected.attname AND NOT attribute.attisdropped AND NOT attribute.attnotnull AND attribute.atttypid='timestamptz'::pg_catalog.regtype) AND
    (SELECT pg_catalog.count(*)=1 FROM pg_catalog.pg_constraint WHERE conrelid=pg_catalog.to_regclass('agent_private.platform_grant_receipts') AND conname='platform_grant_receipts_issue_contract' AND pg_catalog.md5(pg_catalog.pg_get_constraintdef(oid))='8d85f8a1bd060af5beef075b75bda13b') AND
    (SELECT pg_catalog.count(*)=1 FROM pg_catalog.pg_constraint WHERE conrelid=pg_catalog.to_regclass('agent_private.platform_grant_revocation_receipts') AND conname='platform_grant_revocation_receipts_issue_contract' AND pg_catalog.md5(pg_catalog.pg_get_constraintdef(oid))='76cb108da4b527ec5db5eac500168e68') AND
   pg_catalog.to_regprocedure('agent_private.issue_initial_enrollment_grant(uuid,uuid,uuid,uuid,timestamptz,timestamptz,bytea,bytea)') IS NOT NULL AND
   pg_catalog.to_regprocedure('agent_private.read_initial_enrollment_grant(uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz,smallint,timestamptz)') IS NOT NULL AND
   pg_catalog.to_regprocedure('agent_private.revoke_initial_enrollment_grant(uuid,uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz,smallint,timestamptz,bytea)') IS NOT NULL
  THEN 3::smallint
  WHEN audit.body_hash='d2a58ca2b13cfb5c813a21219de07aec' AND
    pg_catalog.to_regclass('agent_private.platform_grant_revocation_receipts') IS NOT NULL AND
    NOT EXISTS(SELECT 1 FROM pg_catalog.pg_attribute WHERE attrelid IN(pg_catalog.to_regclass('agent_private.platform_grant_receipts'),pg_catalog.to_regclass('agent_private.platform_grant_revocation_receipts')) AND attname IN('issue_contract_version','mint_permit_not_after','issue_mint_permit_not_after') AND NOT attisdropped) AND
    pg_catalog.to_regprocedure('agent_private.issue_initial_enrollment_grant(uuid,uuid,uuid,uuid,timestamptz,timestamptz,bytea,bytea)') IS NULL AND
    pg_catalog.to_regprocedure('agent_private.read_initial_enrollment_grant(uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz,smallint,timestamptz)') IS NULL AND
    pg_catalog.to_regprocedure('agent_private.revoke_initial_enrollment_grant(uuid,uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz,smallint,timestamptz,bytea)') IS NULL AND
   pg_catalog.to_regprocedure('agent_private.read_initial_enrollment_grant(uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz)') IS NOT NULL AND
   pg_catalog.to_regprocedure('agent_private.revoke_initial_enrollment_grant(uuid,uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz,bytea)') IS NOT NULL
  THEN 2::smallint
  WHEN audit.body_hash IN('e8ebc587facbd65f76db469b007a7935','e98e01a5978b092ed5f6599a97a0f243') AND
   pg_catalog.to_regclass('agent_private.platform_grant_revocation_receipts') IS NULL AND
   pg_catalog.to_regprocedure('agent_private.read_initial_enrollment_grant(uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz)') IS NULL AND
   pg_catalog.to_regprocedure('agent_private.revoke_initial_enrollment_grant(uuid,uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz,bytea)') IS NULL
  THEN 1::smallint END AS profile_version,
  pg_catalog.pg_get_functiondef(audit.oid) AS audit_definition,audit.*
 FROM audit)
INSERT INTO pg_temp.platform_grant_lifecycle_source(profile_version,audit_definition)
SELECT lifecycle.profile_version,lifecycle.audit_definition FROM lifecycle
WHERE lifecycle.profile_version IS NOT NULL AND lifecycle.owner_name=:'agent_platform_grant_definer_role' AND
 lifecycle.prosecdef AND lifecycle.prokind='f' AND lifecycle.proretset AND lifecycle.provolatile='v' AND lifecycle.proparallel='u' AND
 lifecycle.prolang=(SELECT oid FROM pg_catalog.pg_language WHERE lanname='sql') AND lifecycle.proargnames=ARRAY['p_expected_environment_id','p_expected_table_owner','p_expected_function_owner','is_valid','diagnostic_code','profile_version']::text[] AND
 lifecycle.proconfig=ARRAY['search_path=pg_catalog, agent_private, pg_temp']::text[] AND
 pg_catalog.pg_get_function_result(lifecycle.oid)='TABLE(is_valid boolean, diagnostic_code text, profile_version smallint)' AND
 (lifecycle.profile_version=1 OR (
  (SELECT object.relowner=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=:'agent_table_owner_role') AND object.relrowsecurity AND object.relforcerowsecurity FROM pg_catalog.pg_class object WHERE object.oid=pg_catalog.to_regclass('agent_private.platform_grant_revocation_receipts')) AND
  (SELECT pg_catalog.count(*)=CASE lifecycle.profile_version WHEN 2 THEN 4 ELSE 7 END AND pg_catalog.bool_and(function.proowner=lifecycle.proowner AND function.prosecdef AND function.provolatile='v' AND function.proparallel='u' AND function.proconfig=ARRAY['search_path=pg_catalog, agent_private, pg_temp']::text[]) FROM pg_catalog.pg_proc function WHERE function.oid=ANY(ARRAY[
   'agent_private.issue_initial_enrollment_grant(uuid,uuid,uuid,uuid,timestamptz,bytea,bytea)'::pg_catalog.regprocedure,
   pg_catalog.to_regprocedure('agent_private.issue_initial_enrollment_grant(uuid,uuid,uuid,uuid,timestamptz,timestamptz,bytea,bytea)'),
   pg_catalog.to_regprocedure('agent_private.read_initial_enrollment_grant(uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz)'),
   pg_catalog.to_regprocedure('agent_private.read_initial_enrollment_grant(uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz,smallint,timestamptz)'),
   pg_catalog.to_regprocedure('agent_private.revoke_initial_enrollment_grant(uuid,uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz,bytea)'),
   pg_catalog.to_regprocedure('agent_private.revoke_initial_enrollment_grant(uuid,uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz,smallint,timestamptz,bytea)'),
   'agent_private.audit_platform_grant_privileges(uuid,name,name)'::pg_catalog.regprocedure]::oid[])) AND
  (SELECT pg_catalog.count(*)=8 FROM pg_catalog.pg_policy policy JOIN pg_catalog.pg_class object ON object.oid=policy.polrelid JOIN pg_catalog.pg_namespace namespace ON namespace.oid=object.relnamespace WHERE namespace.nspname='agent_private' AND object.relname IN('platform_grant_database_bindings','platform_grant_receipts','platform_grant_revocation_receipts')) AND
  (SELECT pg_catalog.count(*)=1 FROM pg_catalog.pg_constraint constraint_info WHERE constraint_info.conrelid='agent_private.platform_grant_database_bindings'::pg_catalog.regclass AND constraint_info.contype='c' AND pg_catalog.pg_get_constraintdef(constraint_info.oid) LIKE '%IssueInitialGrant%' AND pg_catalog.pg_get_constraintdef(constraint_info.oid) LIKE '%RevokeInitialGrant%') AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc function,LATERAL pg_catalog.aclexplode(COALESCE(function.proacl,pg_catalog.acldefault('f',function.proowner))) acl LEFT JOIN agent_private.platform_grant_database_bindings binding ON binding.login_role=(SELECT rolname FROM pg_catalog.pg_roles WHERE oid=acl.grantee) WHERE function.oid=ANY(ARRAY[
   'agent_private.issue_initial_enrollment_grant(uuid,uuid,uuid,uuid,timestamptz,bytea,bytea)'::pg_catalog.regprocedure,
   pg_catalog.to_regprocedure('agent_private.issue_initial_enrollment_grant(uuid,uuid,uuid,uuid,timestamptz,timestamptz,bytea,bytea)'),
   pg_catalog.to_regprocedure('agent_private.read_initial_enrollment_grant(uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz)'),
   pg_catalog.to_regprocedure('agent_private.read_initial_enrollment_grant(uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz,smallint,timestamptz)'),
   pg_catalog.to_regprocedure('agent_private.revoke_initial_enrollment_grant(uuid,uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz,bytea)'),
   pg_catalog.to_regprocedure('agent_private.revoke_initial_enrollment_grant(uuid,uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz,smallint,timestamptz,bytea)'),
   'agent_private.audit_platform_grant_privileges(uuid,name,name)'::pg_catalog.regprocedure]::oid[]) AND
   (acl.privilege_type<>'EXECUTE' OR (acl.grantee=function.proowner AND acl.is_grantable) OR (acl.grantee<>function.proowner AND (acl.is_grantable OR binding.login_role IS NULL OR NOT (function.oid='agent_private.audit_platform_grant_privileges(uuid,name,name)'::pg_catalog.regprocedure OR (binding.purpose='IssueInitialGrant' AND function.oid IN('agent_private.issue_initial_enrollment_grant(uuid,uuid,uuid,uuid,timestamptz,bytea,bytea)'::pg_catalog.regprocedure,pg_catalog.to_regprocedure('agent_private.issue_initial_enrollment_grant(uuid,uuid,uuid,uuid,timestamptz,timestamptz,bytea,bytea)'))) OR (binding.purpose='RevokeInitialGrant' AND function.oid IN(pg_catalog.to_regprocedure('agent_private.read_initial_enrollment_grant(uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz)'),pg_catalog.to_regprocedure('agent_private.read_initial_enrollment_grant(uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz,smallint,timestamptz)'),pg_catalog.to_regprocedure('agent_private.revoke_initial_enrollment_grant(uuid,uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz,bytea)'),pg_catalog.to_regprocedure('agent_private.revoke_initial_enrollment_grant(uuid,uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz,smallint,timestamptz,bytea)'))))))) AND
  (SELECT pg_catalog.count(*) FROM pg_catalog.pg_proc function,LATERAL pg_catalog.aclexplode(COALESCE(function.proacl,pg_catalog.acldefault('f',function.proowner))) acl WHERE function.oid=ANY(ARRAY[
   'agent_private.issue_initial_enrollment_grant(uuid,uuid,uuid,uuid,timestamptz,bytea,bytea)'::pg_catalog.regprocedure,
   pg_catalog.to_regprocedure('agent_private.issue_initial_enrollment_grant(uuid,uuid,uuid,uuid,timestamptz,timestamptz,bytea,bytea)'),
   pg_catalog.to_regprocedure('agent_private.read_initial_enrollment_grant(uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz)'),
   pg_catalog.to_regprocedure('agent_private.read_initial_enrollment_grant(uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz,smallint,timestamptz)'),
   pg_catalog.to_regprocedure('agent_private.revoke_initial_enrollment_grant(uuid,uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz,bytea)'),
   pg_catalog.to_regprocedure('agent_private.revoke_initial_enrollment_grant(uuid,uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz,smallint,timestamptz,bytea)'),
   'agent_private.audit_platform_grant_privileges(uuid,name,name)'::pg_catalog.regprocedure]::oid[]) AND acl.privilege_type='EXECUTE')=
   CASE lifecycle.profile_version WHEN 2 THEN 4 ELSE 7 END+(SELECT COALESCE(pg_catalog.sum(CASE purpose WHEN 'IssueInitialGrant' THEN CASE lifecycle.profile_version WHEN 2 THEN 2 ELSE 3 END WHEN 'RevokeInitialGrant' THEN CASE lifecycle.profile_version WHEN 2 THEN 3 ELSE 5 END ELSE 1000 END),0) FROM agent_private.platform_grant_database_bindings)
  )));
SELECT 1/pg_catalog.count(*) AS exact_platform_grant_lifecycle_source FROM pg_temp.platform_grant_lifecycle_source;

-- Derive every existing capability identity from authoritative bindings and exact function owners.
WITH candidates(role_name,capability,role_kind) AS(
 SELECT login_role,'Ingest','Runtime' FROM agent_private.agent_database_bindings
 UNION ALL SELECT login_role,'Enrollment','Runtime' FROM agent_private.enrollment_database_bindings
 UNION ALL SELECT login_role,'Projection','Runtime' FROM agent_private.agent_projection_database_bindings
 UNION ALL SELECT login_role,'PlatformGrant','Runtime' FROM agent_private.platform_grant_database_bindings
 UNION ALL SELECT owner.rolname::name,'Enrollment','Definer' FROM pg_catalog.pg_proc function JOIN pg_catalog.pg_roles owner ON owner.oid=function.proowner WHERE function.oid=pg_catalog.to_regprocedure('agent_private.audit_enrollment_privileges(name,name,text)')
 UNION ALL SELECT owner.rolname::name,'Projection','Definer' FROM pg_catalog.pg_proc function JOIN pg_catalog.pg_roles owner ON owner.oid=function.proowner WHERE function.oid=pg_catalog.to_regprocedure('agent_private.audit_projection_privileges(uuid,name,name)')
 UNION ALL SELECT owner.rolname::name,'PlatformGrant','Definer' FROM pg_catalog.pg_proc function JOIN pg_catalog.pg_roles owner ON owner.oid=function.proowner WHERE function.oid=pg_catalog.to_regprocedure('agent_private.audit_platform_grant_privileges(uuid,name,name)'))
SELECT 1/pg_catalog.count(*) AS no_role_aliases FROM (SELECT 1 WHERE
 NOT EXISTS(SELECT role_name FROM candidates GROUP BY role_name HAVING count(DISTINCT (capability,role_kind))<>1) AND
 NOT EXISTS(SELECT 1 FROM candidates candidate LEFT JOIN pg_catalog.pg_roles role ON role.rolname=candidate.role_name WHERE role.oid IS NULL OR candidate.role_name=:'agent_table_owner_role'::name OR
  (candidate.role_kind='Runtime' AND (NOT role.rolcanlogin OR role.rolsuper OR role.rolbypassrls OR role.rolcreatedb OR role.rolcreaterole OR role.rolinherit OR role.rolreplication)) OR
  (candidate.role_kind='Definer' AND (role.rolcanlogin OR role.rolsuper OR role.rolbypassrls OR role.rolcreatedb OR role.rolcreaterole OR role.rolinherit OR role.rolreplication)) OR
  EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members member WHERE member.member=role.oid OR member.roleid=role.oid))) checked;

CREATE TABLE IF NOT EXISTS agent_private.agent_capability_roles(
 role_name name PRIMARY KEY,
 capability text NOT NULL CHECK(capability IN('Ingest','Enrollment','Projection','PlatformGrant','EnrollmentTargetRead')),
 role_kind text NOT NULL CHECK(role_kind IN('Runtime','Definer'))
);
ALTER TABLE agent_private.agent_capability_roles OWNER TO :"agent_table_owner_role";
ALTER TABLE agent_private.agent_capability_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_private.agent_capability_roles FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS definer_all ON agent_private.agent_capability_roles;
CREATE POLICY definer_all ON agent_private.agent_capability_roles TO :"agent_table_owner_role" USING(true) WITH CHECK(true);
REVOKE ALL ON agent_private.agent_capability_roles FROM PUBLIC;

WITH candidates(role_name,capability,role_kind) AS(
 SELECT login_role,'Ingest','Runtime' FROM agent_private.agent_database_bindings
 UNION ALL SELECT login_role,'Enrollment','Runtime' FROM agent_private.enrollment_database_bindings
 UNION ALL SELECT login_role,'Projection','Runtime' FROM agent_private.agent_projection_database_bindings
 UNION ALL SELECT login_role,'PlatformGrant','Runtime' FROM agent_private.platform_grant_database_bindings
 UNION ALL SELECT owner.rolname::name,'Enrollment','Definer' FROM pg_catalog.pg_proc function JOIN pg_catalog.pg_roles owner ON owner.oid=function.proowner WHERE function.oid=pg_catalog.to_regprocedure('agent_private.audit_enrollment_privileges(name,name,text)')
 UNION ALL SELECT owner.rolname::name,'Projection','Definer' FROM pg_catalog.pg_proc function JOIN pg_catalog.pg_roles owner ON owner.oid=function.proowner WHERE function.oid=pg_catalog.to_regprocedure('agent_private.audit_projection_privileges(uuid,name,name)')
 UNION ALL SELECT owner.rolname::name,'PlatformGrant','Definer' FROM pg_catalog.pg_proc function JOIN pg_catalog.pg_roles owner ON owner.oid=function.proowner WHERE function.oid=pg_catalog.to_regprocedure('agent_private.audit_platform_grant_privileges(uuid,name,name)'))
INSERT INTO agent_private.agent_capability_roles(role_name,capability,role_kind)
SELECT DISTINCT role_name,capability,role_kind FROM candidates ON CONFLICT(role_name) DO NOTHING;

CREATE OR REPLACE FUNCTION agent_private.agent_role_has_capability(p_role name,p_capability text,p_role_kind text)
RETURNS boolean LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,agent_private,pg_temp AS $function$
 SELECT p_capability IS NOT NULL AND p_role_kind IN('Runtime','Definer') AND EXISTS(SELECT 1 FROM agent_private.agent_capability_roles reservation
        WHERE reservation.role_name=p_role AND reservation.capability=p_capability AND reservation.role_kind=p_role_kind) AND
        COALESCE((SELECT registry.relowner=namespace.nspowner AND registry.relrowsecurity AND registry.relforcerowsecurity AND
          NOT EXISTS(SELECT 1 FROM pg_catalog.aclexplode(COALESCE(registry.relacl,pg_catalog.acldefault('r',registry.relowner))) acl WHERE acl.grantee<>registry.relowner) AND
          NOT EXISTS(SELECT 1 FROM pg_catalog.pg_attribute attribute,LATERAL pg_catalog.aclexplode(attribute.attacl) acl WHERE attribute.attrelid=registry.oid AND acl.grantee<>registry.relowner) AND
          (SELECT pg_catalog.count(*)=1 AND pg_catalog.bool_and(policy.polname='definer_all' AND policy.polcmd='*' AND policy.polpermissive AND policy.polroles=ARRAY[registry.relowner]::oid[] AND pg_catalog.pg_get_expr(policy.polqual,policy.polrelid)='true' AND pg_catalog.pg_get_expr(policy.polwithcheck,policy.polrelid)='true') FROM pg_catalog.pg_policy policy WHERE policy.polrelid=registry.oid) AND
          (SELECT pg_catalog.count(*)=1 AND pg_catalog.bool_and(constraint_info.conkey=ARRAY[1]::smallint[]) FROM pg_catalog.pg_constraint constraint_info WHERE constraint_info.conrelid=registry.oid AND constraint_info.contype='p') AND
          NOT EXISTS(SELECT role_name FROM agent_private.agent_capability_roles GROUP BY role_name HAVING pg_catalog.count(*)<>1) AND
          NOT EXISTS(SELECT 1 FROM agent_private.agent_capability_roles registered LEFT JOIN pg_catalog.pg_roles role ON role.rolname=registered.role_name WHERE role.oid IS NULL OR role.oid=registry.relowner OR registered.role_kind NOT IN('Runtime','Definer') OR
           (registered.role_kind='Runtime' AND (NOT role.rolcanlogin OR role.rolsuper OR role.rolbypassrls OR role.rolcreatedb OR role.rolcreaterole OR role.rolinherit OR role.rolreplication)) OR
           (registered.role_kind='Definer' AND (role.rolcanlogin OR role.rolsuper OR role.rolbypassrls OR role.rolcreatedb OR role.rolcreaterole OR role.rolinherit OR role.rolreplication)) OR
           EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members member WHERE member.member=role.oid OR member.roleid=role.oid))
         FROM pg_catalog.pg_class registry JOIN pg_catalog.pg_namespace namespace ON namespace.oid=registry.relnamespace
         WHERE registry.oid=pg_catalog.to_regclass('agent_private.agent_capability_roles')),false) AND
        NOT EXISTS(
         (SELECT acl.grantee,acl.is_grantable,acl.privilege_type FROM pg_catalog.pg_proc helper,
           LATERAL pg_catalog.aclexplode(COALESCE(helper.proacl,pg_catalog.acldefault('f',helper.proowner))) acl
          WHERE helper.oid=pg_catalog.to_regprocedure('agent_private.agent_role_has_capability(name,text,text)')
          EXCEPT
          SELECT role.oid,false,'EXECUTE'::text FROM pg_catalog.pg_roles role
          WHERE role.oid=(SELECT helper.proowner FROM pg_catalog.pg_proc helper WHERE helper.oid=pg_catalog.to_regprocedure('agent_private.agent_role_has_capability(name,text,text)'))
             OR EXISTS(SELECT 1 FROM agent_private.agent_capability_roles reservation WHERE reservation.role_name=role.rolname::name AND reservation.role_kind='Definer'))
         UNION ALL
         (SELECT role.oid,false,'EXECUTE'::text FROM pg_catalog.pg_roles role
          WHERE role.oid=(SELECT helper.proowner FROM pg_catalog.pg_proc helper WHERE helper.oid=pg_catalog.to_regprocedure('agent_private.agent_role_has_capability(name,text,text)'))
             OR EXISTS(SELECT 1 FROM agent_private.agent_capability_roles reservation WHERE reservation.role_name=role.rolname::name AND reservation.role_kind='Definer')
          EXCEPT
          SELECT acl.grantee,acl.is_grantable,acl.privilege_type FROM pg_catalog.pg_proc helper,
           LATERAL pg_catalog.aclexplode(COALESCE(helper.proacl,pg_catalog.acldefault('f',helper.proowner))) acl
          WHERE helper.oid=pg_catalog.to_regprocedure('agent_private.agent_role_has_capability(name,text,text)')));
$function$;
ALTER FUNCTION agent_private.agent_role_has_capability(name,text,text) OWNER TO :"agent_table_owner_role";
REVOKE ALL ON FUNCTION agent_private.agent_role_has_capability(name,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION agent_private.agent_role_has_capability(name,text,text) TO :"agent_enrollment_definer_role",:"agent_projection_definer_role",:"agent_platform_grant_definer_role";

-- Existing audit definitions are replaced below without changing their signatures or result profiles.

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
          AND agent_private.agent_role_has_capability(SESSION_USER::name,'Ingest','Runtime')
          AND COALESCE((SELECT helper.proowner=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=expected_definer) AND helper.prosecdef AND helper.prolang=(SELECT oid FROM pg_catalog.pg_language WHERE lanname='sql') AND helper.prokind='f' AND NOT helper.proretset AND helper.prorettype='boolean'::pg_catalog.regtype AND helper.proargnames=ARRAY['p_role','p_capability','p_role_kind']::text[] AND helper.proconfig=ARRAY['search_path=pg_catalog, agent_private, pg_temp']::text[] AND pg_catalog.btrim(helper.prosrc,E' \t\r\n')=pg_catalog.btrim(' SELECT p_capability IS NOT NULL AND p_role_kind IN(''Runtime'',''Definer'') AND EXISTS(SELECT 1 FROM agent_private.agent_capability_roles reservation
        WHERE reservation.role_name=p_role AND reservation.capability=p_capability AND reservation.role_kind=p_role_kind) AND
        COALESCE((SELECT registry.relowner=namespace.nspowner AND registry.relrowsecurity AND registry.relforcerowsecurity AND
          NOT EXISTS(SELECT 1 FROM pg_catalog.aclexplode(COALESCE(registry.relacl,pg_catalog.acldefault(''r'',registry.relowner))) acl WHERE acl.grantee<>registry.relowner) AND
          NOT EXISTS(SELECT 1 FROM pg_catalog.pg_attribute attribute,LATERAL pg_catalog.aclexplode(attribute.attacl) acl WHERE attribute.attrelid=registry.oid AND acl.grantee<>registry.relowner) AND
          (SELECT pg_catalog.count(*)=1 AND pg_catalog.bool_and(policy.polname=''definer_all'' AND policy.polcmd=''*'' AND policy.polpermissive AND policy.polroles=ARRAY[registry.relowner]::oid[] AND pg_catalog.pg_get_expr(policy.polqual,policy.polrelid)=''true'' AND pg_catalog.pg_get_expr(policy.polwithcheck,policy.polrelid)=''true'') FROM pg_catalog.pg_policy policy WHERE policy.polrelid=registry.oid) AND
          (SELECT pg_catalog.count(*)=1 AND pg_catalog.bool_and(constraint_info.conkey=ARRAY[1]::smallint[]) FROM pg_catalog.pg_constraint constraint_info WHERE constraint_info.conrelid=registry.oid AND constraint_info.contype=''p'') AND
          NOT EXISTS(SELECT role_name FROM agent_private.agent_capability_roles GROUP BY role_name HAVING pg_catalog.count(*)<>1) AND
          NOT EXISTS(SELECT 1 FROM agent_private.agent_capability_roles registered LEFT JOIN pg_catalog.pg_roles role ON role.rolname=registered.role_name WHERE role.oid IS NULL OR role.oid=registry.relowner OR registered.role_kind NOT IN(''Runtime'',''Definer'') OR
           (registered.role_kind=''Runtime'' AND (NOT role.rolcanlogin OR role.rolsuper OR role.rolbypassrls OR role.rolcreatedb OR role.rolcreaterole OR role.rolinherit OR role.rolreplication)) OR
           (registered.role_kind=''Definer'' AND (role.rolcanlogin OR role.rolsuper OR role.rolbypassrls OR role.rolcreatedb OR role.rolcreaterole OR role.rolinherit OR role.rolreplication)) OR
           EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members member WHERE member.member=role.oid OR member.roleid=role.oid))
         FROM pg_catalog.pg_class registry JOIN pg_catalog.pg_namespace namespace ON namespace.oid=registry.relnamespace
         WHERE registry.oid=pg_catalog.to_regclass(''agent_private.agent_capability_roles'')),false) AND
        NOT EXISTS(
         (SELECT acl.grantee,acl.is_grantable,acl.privilege_type FROM pg_catalog.pg_proc helper,
           LATERAL pg_catalog.aclexplode(COALESCE(helper.proacl,pg_catalog.acldefault(''f'',helper.proowner))) acl
          WHERE helper.oid=pg_catalog.to_regprocedure(''agent_private.agent_role_has_capability(name,text,text)'')
          EXCEPT
          SELECT role.oid,false,''EXECUTE''::text FROM pg_catalog.pg_roles role
          WHERE role.oid=(SELECT helper.proowner FROM pg_catalog.pg_proc helper WHERE helper.oid=pg_catalog.to_regprocedure(''agent_private.agent_role_has_capability(name,text,text)''))
             OR EXISTS(SELECT 1 FROM agent_private.agent_capability_roles reservation WHERE reservation.role_name=role.rolname::name AND reservation.role_kind=''Definer''))
         UNION ALL
         (SELECT role.oid,false,''EXECUTE''::text FROM pg_catalog.pg_roles role
          WHERE role.oid=(SELECT helper.proowner FROM pg_catalog.pg_proc helper WHERE helper.oid=pg_catalog.to_regprocedure(''agent_private.agent_role_has_capability(name,text,text)''))
             OR EXISTS(SELECT 1 FROM agent_private.agent_capability_roles reservation WHERE reservation.role_name=role.rolname::name AND reservation.role_kind=''Definer'')
          EXCEPT
          SELECT acl.grantee,acl.is_grantable,acl.privilege_type FROM pg_catalog.pg_proc helper,
           LATERAL pg_catalog.aclexplode(COALESCE(helper.proacl,pg_catalog.acldefault(''f'',helper.proowner))) acl
          WHERE helper.oid=pg_catalog.to_regprocedure(''agent_private.agent_role_has_capability(name,text,text)'')));',E' \t\r\n') FROM pg_catalog.pg_proc helper WHERE helper.oid=pg_catalog.to_regprocedure('agent_private.agent_role_has_capability(name,text,text)')),false)
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

ALTER FUNCTION agent_private.audit_ingest_privileges(name) OWNER TO :"agent_definer_role";
REVOKE ALL ON FUNCTION agent_private.audit_ingest_privileges(name) FROM PUBLIC;

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
   agent_private.agent_role_has_capability(SESSION_USER::name,'Enrollment','Runtime') AND
   agent_private.agent_role_has_capability(p_expected_function_owner,'Enrollment','Definer') AND
   COALESCE((SELECT helper.proowner=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=p_expected_table_owner) AND helper.prosecdef AND helper.prolang=(SELECT oid FROM pg_catalog.pg_language WHERE lanname='sql') AND helper.prokind='f' AND NOT helper.proretset AND helper.prorettype='boolean'::pg_catalog.regtype AND helper.proargnames=ARRAY['p_role','p_capability','p_role_kind']::text[] AND helper.proconfig=ARRAY['search_path=pg_catalog, agent_private, pg_temp']::text[] AND pg_catalog.btrim(helper.prosrc,E' \t\r\n')=pg_catalog.btrim(' SELECT p_capability IS NOT NULL AND p_role_kind IN(''Runtime'',''Definer'') AND EXISTS(SELECT 1 FROM agent_private.agent_capability_roles reservation
        WHERE reservation.role_name=p_role AND reservation.capability=p_capability AND reservation.role_kind=p_role_kind) AND
        COALESCE((SELECT registry.relowner=namespace.nspowner AND registry.relrowsecurity AND registry.relforcerowsecurity AND
          NOT EXISTS(SELECT 1 FROM pg_catalog.aclexplode(COALESCE(registry.relacl,pg_catalog.acldefault(''r'',registry.relowner))) acl WHERE acl.grantee<>registry.relowner) AND
          NOT EXISTS(SELECT 1 FROM pg_catalog.pg_attribute attribute,LATERAL pg_catalog.aclexplode(attribute.attacl) acl WHERE attribute.attrelid=registry.oid AND acl.grantee<>registry.relowner) AND
          (SELECT pg_catalog.count(*)=1 AND pg_catalog.bool_and(policy.polname=''definer_all'' AND policy.polcmd=''*'' AND policy.polpermissive AND policy.polroles=ARRAY[registry.relowner]::oid[] AND pg_catalog.pg_get_expr(policy.polqual,policy.polrelid)=''true'' AND pg_catalog.pg_get_expr(policy.polwithcheck,policy.polrelid)=''true'') FROM pg_catalog.pg_policy policy WHERE policy.polrelid=registry.oid) AND
          (SELECT pg_catalog.count(*)=1 AND pg_catalog.bool_and(constraint_info.conkey=ARRAY[1]::smallint[]) FROM pg_catalog.pg_constraint constraint_info WHERE constraint_info.conrelid=registry.oid AND constraint_info.contype=''p'') AND
          NOT EXISTS(SELECT role_name FROM agent_private.agent_capability_roles GROUP BY role_name HAVING pg_catalog.count(*)<>1) AND
          NOT EXISTS(SELECT 1 FROM agent_private.agent_capability_roles registered LEFT JOIN pg_catalog.pg_roles role ON role.rolname=registered.role_name WHERE role.oid IS NULL OR role.oid=registry.relowner OR registered.role_kind NOT IN(''Runtime'',''Definer'') OR
           (registered.role_kind=''Runtime'' AND (NOT role.rolcanlogin OR role.rolsuper OR role.rolbypassrls OR role.rolcreatedb OR role.rolcreaterole OR role.rolinherit OR role.rolreplication)) OR
           (registered.role_kind=''Definer'' AND (role.rolcanlogin OR role.rolsuper OR role.rolbypassrls OR role.rolcreatedb OR role.rolcreaterole OR role.rolinherit OR role.rolreplication)) OR
           EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members member WHERE member.member=role.oid OR member.roleid=role.oid))
         FROM pg_catalog.pg_class registry JOIN pg_catalog.pg_namespace namespace ON namespace.oid=registry.relnamespace
         WHERE registry.oid=pg_catalog.to_regclass(''agent_private.agent_capability_roles'')),false) AND
        NOT EXISTS(
         (SELECT acl.grantee,acl.is_grantable,acl.privilege_type FROM pg_catalog.pg_proc helper,
           LATERAL pg_catalog.aclexplode(COALESCE(helper.proacl,pg_catalog.acldefault(''f'',helper.proowner))) acl
          WHERE helper.oid=pg_catalog.to_regprocedure(''agent_private.agent_role_has_capability(name,text,text)'')
          EXCEPT
          SELECT role.oid,false,''EXECUTE''::text FROM pg_catalog.pg_roles role
          WHERE role.oid=(SELECT helper.proowner FROM pg_catalog.pg_proc helper WHERE helper.oid=pg_catalog.to_regprocedure(''agent_private.agent_role_has_capability(name,text,text)''))
             OR EXISTS(SELECT 1 FROM agent_private.agent_capability_roles reservation WHERE reservation.role_name=role.rolname::name AND reservation.role_kind=''Definer''))
         UNION ALL
         (SELECT role.oid,false,''EXECUTE''::text FROM pg_catalog.pg_roles role
          WHERE role.oid=(SELECT helper.proowner FROM pg_catalog.pg_proc helper WHERE helper.oid=pg_catalog.to_regprocedure(''agent_private.agent_role_has_capability(name,text,text)''))
             OR EXISTS(SELECT 1 FROM agent_private.agent_capability_roles reservation WHERE reservation.role_name=role.rolname::name AND reservation.role_kind=''Definer'')
          EXCEPT
          SELECT acl.grantee,acl.is_grantable,acl.privilege_type FROM pg_catalog.pg_proc helper,
           LATERAL pg_catalog.aclexplode(COALESCE(helper.proacl,pg_catalog.acldefault(''f'',helper.proowner))) acl
          WHERE helper.oid=pg_catalog.to_regprocedure(''agent_private.agent_role_has_capability(name,text,text)'')));',E' \t\r\n') FROM pg_catalog.pg_proc helper WHERE helper.oid=pg_catalog.to_regprocedure('agent_private.agent_role_has_capability(name,text,text)')),false) AND
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

ALTER FUNCTION agent_private.submit_or_recover_enrollment(bytea,uuid,uuid,bytea,bytea,bytea,integer) OWNER TO :"agent_enrollment_definer_role";
ALTER FUNCTION agent_private.claim_enrollment_issuance(uuid,uuid) OWNER TO :"agent_enrollment_definer_role";
ALTER FUNCTION agent_private.complete_enrollment_issuance(uuid,uuid,uuid,uuid,uuid,uuid,bigint,integer,bytea,bytea[],bytea,bytea,bytea,timestamptz,timestamptz) OWNER TO :"agent_enrollment_definer_role";
ALTER FUNCTION agent_private.defer_enrollment_issuance(uuid,uuid,integer) OWNER TO :"agent_enrollment_definer_role";
ALTER FUNCTION agent_private.mark_enrollment_issuance_unknown(uuid,uuid) OWNER TO :"agent_enrollment_definer_role";
ALTER FUNCTION agent_private.fail_enrollment_issuance_definitively(uuid,uuid) OWNER TO :"agent_enrollment_definer_role";
ALTER FUNCTION agent_private.audit_enrollment_privileges(name,name,text) OWNER TO :"agent_enrollment_definer_role";
REVOKE ALL ON FUNCTION agent_private.submit_or_recover_enrollment(bytea,uuid,uuid,bytea,bytea,bytea,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION agent_private.claim_enrollment_issuance(uuid,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION agent_private.complete_enrollment_issuance(uuid,uuid,uuid,uuid,uuid,uuid,bigint,integer,bytea,bytea[],bytea,bytea,bytea,timestamptz,timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION agent_private.defer_enrollment_issuance(uuid,uuid,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION agent_private.mark_enrollment_issuance_unknown(uuid,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION agent_private.fail_enrollment_issuance_definitively(uuid,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION agent_private.audit_enrollment_privileges(name,name,text) FROM PUBLIC;

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
  agent_private.agent_role_has_capability(SESSION_USER::name,'Projection','Runtime') AND
  agent_private.agent_role_has_capability(p_expected_function_owner,'Projection','Definer') AND
  COALESCE((SELECT helper.proowner=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=p_expected_table_owner) AND helper.prosecdef AND helper.prolang=(SELECT oid FROM pg_catalog.pg_language WHERE lanname='sql') AND helper.prokind='f' AND NOT helper.proretset AND helper.prorettype='boolean'::pg_catalog.regtype AND helper.proargnames=ARRAY['p_role','p_capability','p_role_kind']::text[] AND helper.proconfig=ARRAY['search_path=pg_catalog, agent_private, pg_temp']::text[] AND pg_catalog.btrim(helper.prosrc,E' \t\r\n')=pg_catalog.btrim(' SELECT p_capability IS NOT NULL AND p_role_kind IN(''Runtime'',''Definer'') AND EXISTS(SELECT 1 FROM agent_private.agent_capability_roles reservation
        WHERE reservation.role_name=p_role AND reservation.capability=p_capability AND reservation.role_kind=p_role_kind) AND
        COALESCE((SELECT registry.relowner=namespace.nspowner AND registry.relrowsecurity AND registry.relforcerowsecurity AND
          NOT EXISTS(SELECT 1 FROM pg_catalog.aclexplode(COALESCE(registry.relacl,pg_catalog.acldefault(''r'',registry.relowner))) acl WHERE acl.grantee<>registry.relowner) AND
          NOT EXISTS(SELECT 1 FROM pg_catalog.pg_attribute attribute,LATERAL pg_catalog.aclexplode(attribute.attacl) acl WHERE attribute.attrelid=registry.oid AND acl.grantee<>registry.relowner) AND
          (SELECT pg_catalog.count(*)=1 AND pg_catalog.bool_and(policy.polname=''definer_all'' AND policy.polcmd=''*'' AND policy.polpermissive AND policy.polroles=ARRAY[registry.relowner]::oid[] AND pg_catalog.pg_get_expr(policy.polqual,policy.polrelid)=''true'' AND pg_catalog.pg_get_expr(policy.polwithcheck,policy.polrelid)=''true'') FROM pg_catalog.pg_policy policy WHERE policy.polrelid=registry.oid) AND
          (SELECT pg_catalog.count(*)=1 AND pg_catalog.bool_and(constraint_info.conkey=ARRAY[1]::smallint[]) FROM pg_catalog.pg_constraint constraint_info WHERE constraint_info.conrelid=registry.oid AND constraint_info.contype=''p'') AND
          NOT EXISTS(SELECT role_name FROM agent_private.agent_capability_roles GROUP BY role_name HAVING pg_catalog.count(*)<>1) AND
          NOT EXISTS(SELECT 1 FROM agent_private.agent_capability_roles registered LEFT JOIN pg_catalog.pg_roles role ON role.rolname=registered.role_name WHERE role.oid IS NULL OR role.oid=registry.relowner OR registered.role_kind NOT IN(''Runtime'',''Definer'') OR
           (registered.role_kind=''Runtime'' AND (NOT role.rolcanlogin OR role.rolsuper OR role.rolbypassrls OR role.rolcreatedb OR role.rolcreaterole OR role.rolinherit OR role.rolreplication)) OR
           (registered.role_kind=''Definer'' AND (role.rolcanlogin OR role.rolsuper OR role.rolbypassrls OR role.rolcreatedb OR role.rolcreaterole OR role.rolinherit OR role.rolreplication)) OR
           EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members member WHERE member.member=role.oid OR member.roleid=role.oid))
         FROM pg_catalog.pg_class registry JOIN pg_catalog.pg_namespace namespace ON namespace.oid=registry.relnamespace
         WHERE registry.oid=pg_catalog.to_regclass(''agent_private.agent_capability_roles'')),false) AND
        NOT EXISTS(
         (SELECT acl.grantee,acl.is_grantable,acl.privilege_type FROM pg_catalog.pg_proc helper,
           LATERAL pg_catalog.aclexplode(COALESCE(helper.proacl,pg_catalog.acldefault(''f'',helper.proowner))) acl
          WHERE helper.oid=pg_catalog.to_regprocedure(''agent_private.agent_role_has_capability(name,text,text)'')
          EXCEPT
          SELECT role.oid,false,''EXECUTE''::text FROM pg_catalog.pg_roles role
          WHERE role.oid=(SELECT helper.proowner FROM pg_catalog.pg_proc helper WHERE helper.oid=pg_catalog.to_regprocedure(''agent_private.agent_role_has_capability(name,text,text)''))
             OR EXISTS(SELECT 1 FROM agent_private.agent_capability_roles reservation WHERE reservation.role_name=role.rolname::name AND reservation.role_kind=''Definer''))
         UNION ALL
         (SELECT role.oid,false,''EXECUTE''::text FROM pg_catalog.pg_roles role
          WHERE role.oid=(SELECT helper.proowner FROM pg_catalog.pg_proc helper WHERE helper.oid=pg_catalog.to_regprocedure(''agent_private.agent_role_has_capability(name,text,text)''))
             OR EXISTS(SELECT 1 FROM agent_private.agent_capability_roles reservation WHERE reservation.role_name=role.rolname::name AND reservation.role_kind=''Definer'')
          EXCEPT
          SELECT acl.grantee,acl.is_grantable,acl.privilege_type FROM pg_catalog.pg_proc helper,
           LATERAL pg_catalog.aclexplode(COALESCE(helper.proacl,pg_catalog.acldefault(''f'',helper.proowner))) acl
          WHERE helper.oid=pg_catalog.to_regprocedure(''agent_private.agent_role_has_capability(name,text,text)'')));',E' \t\r\n') FROM pg_catalog.pg_proc helper WHERE helper.oid=pg_catalog.to_regprocedure('agent_private.agent_role_has_capability(name,text,text)')),false) AND
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

ALTER FUNCTION agent_private.read_current_bitlocker_projection(uuid,uuid) OWNER TO :"agent_projection_definer_role";
ALTER FUNCTION agent_private.read_current_inventory_projection(uuid,uuid) OWNER TO :"agent_projection_definer_role";
ALTER FUNCTION agent_private.audit_projection_privileges(uuid,name,name) OWNER TO :"agent_projection_definer_role";
REVOKE ALL ON FUNCTION agent_private.read_current_bitlocker_projection(uuid,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION agent_private.read_current_inventory_projection(uuid,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION agent_private.audit_projection_privileges(uuid,name,name) FROM PUBLIC;

CREATE OR REPLACE FUNCTION agent_private.audit_platform_grant_privileges(p_expected_environment_id uuid,p_expected_table_owner name,p_expected_function_owner name)
RETURNS TABLE(is_valid boolean,diagnostic_code text,profile_version smallint)
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,agent_private,pg_temp AS $function$
WITH login AS(SELECT role.* FROM pg_catalog.pg_roles role WHERE role.rolname=SESSION_USER),
 function_owner AS(SELECT role.* FROM pg_catalog.pg_roles role WHERE role.rolname=p_expected_function_owner),
 table_owner AS(SELECT role.* FROM pg_catalog.pg_roles role WHERE role.rolname=p_expected_table_owner),
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
 actual_execute AS(SELECT function.oid::pg_catalog.regprocedure AS signature FROM pg_catalog.pg_proc function,schema_info WHERE function.pronamespace=schema_info.oid AND pg_catalog.has_function_privilege(SESSION_USER,function.oid,'EXECUTE')),
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
  agent_private.agent_role_has_capability(SESSION_USER::name,'PlatformGrant','Runtime') AND
  agent_private.agent_role_has_capability(p_expected_function_owner,'PlatformGrant','Definer') AND
  COALESCE((SELECT helper.proowner=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=p_expected_table_owner) AND helper.prosecdef AND helper.prolang=(SELECT oid FROM pg_catalog.pg_language WHERE lanname='sql') AND helper.prokind='f' AND NOT helper.proretset AND helper.prorettype='boolean'::pg_catalog.regtype AND helper.proargnames=ARRAY['p_role','p_capability','p_role_kind']::text[] AND helper.proconfig=ARRAY['search_path=pg_catalog, agent_private, pg_temp']::text[] AND pg_catalog.btrim(helper.prosrc,E' \t\r\n')=pg_catalog.btrim(' SELECT p_capability IS NOT NULL AND p_role_kind IN(''Runtime'',''Definer'') AND EXISTS(SELECT 1 FROM agent_private.agent_capability_roles reservation
        WHERE reservation.role_name=p_role AND reservation.capability=p_capability AND reservation.role_kind=p_role_kind) AND
        COALESCE((SELECT registry.relowner=namespace.nspowner AND registry.relrowsecurity AND registry.relforcerowsecurity AND
          NOT EXISTS(SELECT 1 FROM pg_catalog.aclexplode(COALESCE(registry.relacl,pg_catalog.acldefault(''r'',registry.relowner))) acl WHERE acl.grantee<>registry.relowner) AND
          NOT EXISTS(SELECT 1 FROM pg_catalog.pg_attribute attribute,LATERAL pg_catalog.aclexplode(attribute.attacl) acl WHERE attribute.attrelid=registry.oid AND acl.grantee<>registry.relowner) AND
          (SELECT pg_catalog.count(*)=1 AND pg_catalog.bool_and(policy.polname=''definer_all'' AND policy.polcmd=''*'' AND policy.polpermissive AND policy.polroles=ARRAY[registry.relowner]::oid[] AND pg_catalog.pg_get_expr(policy.polqual,policy.polrelid)=''true'' AND pg_catalog.pg_get_expr(policy.polwithcheck,policy.polrelid)=''true'') FROM pg_catalog.pg_policy policy WHERE policy.polrelid=registry.oid) AND
          (SELECT pg_catalog.count(*)=1 AND pg_catalog.bool_and(constraint_info.conkey=ARRAY[1]::smallint[]) FROM pg_catalog.pg_constraint constraint_info WHERE constraint_info.conrelid=registry.oid AND constraint_info.contype=''p'') AND
          NOT EXISTS(SELECT role_name FROM agent_private.agent_capability_roles GROUP BY role_name HAVING pg_catalog.count(*)<>1) AND
          NOT EXISTS(SELECT 1 FROM agent_private.agent_capability_roles registered LEFT JOIN pg_catalog.pg_roles role ON role.rolname=registered.role_name WHERE role.oid IS NULL OR role.oid=registry.relowner OR registered.role_kind NOT IN(''Runtime'',''Definer'') OR
           (registered.role_kind=''Runtime'' AND (NOT role.rolcanlogin OR role.rolsuper OR role.rolbypassrls OR role.rolcreatedb OR role.rolcreaterole OR role.rolinherit OR role.rolreplication)) OR
           (registered.role_kind=''Definer'' AND (role.rolcanlogin OR role.rolsuper OR role.rolbypassrls OR role.rolcreatedb OR role.rolcreaterole OR role.rolinherit OR role.rolreplication)) OR
           EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members member WHERE member.member=role.oid OR member.roleid=role.oid))
         FROM pg_catalog.pg_class registry JOIN pg_catalog.pg_namespace namespace ON namespace.oid=registry.relnamespace
         WHERE registry.oid=pg_catalog.to_regclass(''agent_private.agent_capability_roles'')),false) AND
        NOT EXISTS(
         (SELECT acl.grantee,acl.is_grantable,acl.privilege_type FROM pg_catalog.pg_proc helper,
           LATERAL pg_catalog.aclexplode(COALESCE(helper.proacl,pg_catalog.acldefault(''f'',helper.proowner))) acl
          WHERE helper.oid=pg_catalog.to_regprocedure(''agent_private.agent_role_has_capability(name,text,text)'')
          EXCEPT
          SELECT role.oid,false,''EXECUTE''::text FROM pg_catalog.pg_roles role
          WHERE role.oid=(SELECT helper.proowner FROM pg_catalog.pg_proc helper WHERE helper.oid=pg_catalog.to_regprocedure(''agent_private.agent_role_has_capability(name,text,text)''))
             OR EXISTS(SELECT 1 FROM agent_private.agent_capability_roles reservation WHERE reservation.role_name=role.rolname::name AND reservation.role_kind=''Definer''))
         UNION ALL
         (SELECT role.oid,false,''EXECUTE''::text FROM pg_catalog.pg_roles role
          WHERE role.oid=(SELECT helper.proowner FROM pg_catalog.pg_proc helper WHERE helper.oid=pg_catalog.to_regprocedure(''agent_private.agent_role_has_capability(name,text,text)''))
             OR EXISTS(SELECT 1 FROM agent_private.agent_capability_roles reservation WHERE reservation.role_name=role.rolname::name AND reservation.role_kind=''Definer'')
          EXCEPT
          SELECT acl.grantee,acl.is_grantable,acl.privilege_type FROM pg_catalog.pg_proc helper,
           LATERAL pg_catalog.aclexplode(COALESCE(helper.proacl,pg_catalog.acldefault(''f'',helper.proowner))) acl
          WHERE helper.oid=pg_catalog.to_regprocedure(''agent_private.agent_role_has_capability(name,text,text)'')));',E' \t\r\n') FROM pg_catalog.pg_proc helper WHERE helper.oid=pg_catalog.to_regprocedure('agent_private.agent_role_has_capability(name,text,text)')),false) AND
  NOT EXISTS(SELECT 1 FROM login WHERE NOT rolcanlogin OR rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole OR rolinherit OR rolreplication) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members member,login WHERE member.member=login.oid OR member.roleid=login.oid) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_database database,login WHERE database.datdba=login.oid) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace namespace,login WHERE namespace.nspowner=login.oid) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object,login WHERE object.relowner=login.oid) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc function,login WHERE function.proowner=login.oid) AND
  NOT EXISTS(SELECT 1 FROM agent_private.agent_database_bindings binding WHERE binding.login_role=SESSION_USER::name) AND
  NOT EXISTS(SELECT 1 FROM agent_private.enrollment_database_bindings binding WHERE binding.login_role=SESSION_USER::name) AND
  NOT EXISTS(SELECT 1 FROM agent_private.agent_projection_database_bindings binding WHERE binding.login_role=SESSION_USER::name) AND
  (SELECT pg_catalog.count(*)=1 FROM agent_private.platform_grant_database_bindings binding WHERE binding.login_role=SESSION_USER::name AND binding.environment_id=p_expected_environment_id AND binding.purpose='IssueInitialGrant') AND
  NOT pg_catalog.has_schema_privilege(SESSION_USER,'agent_private','CREATE') AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object,schema_info WHERE object.relnamespace=schema_info.oid AND object.relkind IN('r','p','v','m') AND (pg_catalog.has_table_privilege(SESSION_USER,object.oid,'SELECT') OR pg_catalog.has_table_privilege(SESSION_USER,object.oid,'INSERT') OR pg_catalog.has_table_privilege(SESSION_USER,object.oid,'UPDATE') OR pg_catalog.has_table_privilege(SESSION_USER,object.oid,'DELETE') OR pg_catalog.has_table_privilege(SESSION_USER,object.oid,'TRUNCATE') OR pg_catalog.has_table_privilege(SESSION_USER,object.oid,'REFERENCES') OR pg_catalog.has_table_privilege(SESSION_USER,object.oid,'TRIGGER'))) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object JOIN pg_catalog.pg_attribute attribute ON attribute.attrelid=object.oid,schema_info,login,LATERAL pg_catalog.aclexplode(attribute.attacl) acl WHERE object.relnamespace=schema_info.oid AND acl.grantee IN(0,login.oid)) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object,schema_info WHERE object.relnamespace=schema_info.oid AND object.relkind='S' AND (pg_catalog.has_sequence_privilege(SESSION_USER,object.oid,'USAGE') OR pg_catalog.has_sequence_privilege(SESSION_USER,object.oid,'SELECT') OR pg_catalog.has_sequence_privilege(SESSION_USER,object.oid,'UPDATE'))) AND
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
  NOT pg_catalog.has_schema_privilege(p_expected_function_owner,'agent_private','CREATE') AND
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
  (SELECT pg_catalog.count(*)=8 AND pg_catalog.bool_and(owner.rolname=p_expected_table_owner) FROM pg_catalog.pg_class object JOIN pg_catalog.pg_roles owner ON owner.oid=object.relowner,schema_info WHERE object.relnamespace=schema_info.oid AND object.relkind='r' AND object.relname=ANY(ARRAY['devices','registrations','enrollment_grants','enrollment_requests','agent_device_directory_bindings','agent_projection_database_bindings','platform_grant_database_bindings','platform_grant_receipts'])) AND
  (SELECT pg_catalog.count(*)=2 AND pg_catalog.bool_and(function.prosecdef AND function.proowner=function_owner.oid AND function.proconfig=ARRAY['search_path=pg_catalog, agent_private, pg_temp']) FROM pg_catalog.pg_proc function,schema_info,function_owner WHERE function.pronamespace=schema_info.oid AND function.proname=ANY(ARRAY['issue_initial_enrollment_grant','audit_platform_grant_privileges'])) AND
  (SELECT pg_catalog.count(*)=2 AND pg_catalog.bool_and(function.prosecdef AND function.proowner=table_owner.oid AND function.proconfig=ARRAY['search_path=pg_catalog, agent_private, pg_temp']) FROM pg_catalog.pg_proc function,schema_info,table_owner WHERE function.pronamespace=schema_info.oid AND function.proname=ANY(ARRAY['lock_agent_device_directory_binding','lock_agent_device'])) AND
  pg_catalog.has_function_privilege(p_expected_function_owner,'agent_private.lock_agent_device_directory_binding(uuid,uuid)'::pg_catalog.regprocedure,'EXECUTE') AND
  pg_catalog.has_function_privilege(p_expected_function_owner,'agent_private.lock_agent_device(uuid,uuid)'::pg_catalog.regprocedure,'EXECUTE') AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc function,schema_info,function_owner,LATERAL pg_catalog.aclexplode(coalesce(function.proacl,pg_catalog.acldefault('f',function.proowner))) acl WHERE function.pronamespace=schema_info.oid AND function.proname=ANY(ARRAY['lock_agent_device_directory_binding','lock_agent_device']) AND (acl.grantee NOT IN(function.proowner,function_owner.oid) OR acl.privilege_type<>'EXECUTE' OR (acl.grantee<>function.proowner AND acl.is_grantable))) AND
  NOT EXISTS(SELECT 1 FROM expected_policies expected,function_owner WHERE NOT EXISTS(SELECT 1 FROM pg_catalog.pg_policy policy JOIN pg_catalog.pg_class object ON object.oid=policy.polrelid JOIN pg_catalog.pg_namespace namespace ON namespace.oid=object.relnamespace WHERE namespace.nspname='agent_private' AND object.relname=expected.relname AND policy.polname=expected.polname AND policy.polcmd=expected.polcmd AND policy.polpermissive AND policy.polroles=ARRAY[function_owner.oid]::oid[] AND pg_catalog.pg_get_expr(policy.polqual,policy.polrelid) IS NOT DISTINCT FROM expected.qual AND pg_catalog.pg_get_expr(policy.polwithcheck,policy.polrelid) IS NOT DISTINCT FROM expected.withcheck)) AND
  NOT EXISTS(SELECT 1 FROM expected_owner_policies expected,table_owner WHERE NOT EXISTS(SELECT 1 FROM pg_catalog.pg_policy policy JOIN pg_catalog.pg_class object ON object.oid=policy.polrelid JOIN pg_catalog.pg_namespace namespace ON namespace.oid=object.relnamespace WHERE namespace.nspname='agent_private' AND object.relname=expected.relname AND policy.polname='definer_all' AND policy.polcmd='*' AND policy.polpermissive AND policy.polroles=ARRAY[table_owner.oid]::oid[] AND pg_catalog.pg_get_expr(policy.polqual,policy.polrelid)='true' AND pg_catalog.pg_get_expr(policy.polwithcheck,policy.polrelid)='true')) AND
  (SELECT pg_catalog.count(*)=5 FROM pg_catalog.pg_policy policy JOIN pg_catalog.pg_class object ON object.oid=policy.polrelid,schema_info WHERE object.relnamespace=schema_info.oid AND object.relname IN('platform_grant_database_bindings','platform_grant_receipts')) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_policy policy JOIN pg_catalog.pg_class object ON object.oid=policy.polrelid JOIN pg_catalog.pg_namespace namespace ON namespace.oid=object.relnamespace,function_owner WHERE namespace.nspname='agent_private' AND object.relname IN(SELECT expected.relname FROM expected_policies expected) AND (function_owner.oid=ANY(policy.polroles) OR 0=ANY(policy.polroles)) AND NOT EXISTS(SELECT 1 FROM expected_policies expected WHERE expected.relname=object.relname AND expected.polname=policy.polname AND expected.polcmd=policy.polcmd AND policy.polpermissive AND policy.polroles=ARRAY[function_owner.oid]::oid[] AND pg_catalog.pg_get_expr(policy.polqual,policy.polrelid) IS NOT DISTINCT FROM expected.qual AND pg_catalog.pg_get_expr(policy.polwithcheck,policy.polrelid) IS NOT DISTINCT FROM expected.withcheck)) AND
  (SELECT pg_catalog.count(*)=8 AND pg_catalog.bool_and(object.relrowsecurity AND object.relforcerowsecurity) FROM pg_catalog.pg_class object,schema_info WHERE object.relnamespace=schema_info.oid AND object.relkind='r' AND object.relname=ANY(ARRAY['devices','registrations','enrollment_grants','enrollment_requests','agent_device_directory_bindings','agent_projection_database_bindings','platform_grant_database_bindings','platform_grant_receipts'])) AS valid)
SELECT valid,'None'::text,1::smallint FROM checks WHERE valid
UNION ALL SELECT false,'PrivilegeAuditFailed',1::smallint FROM checks WHERE NOT valid;$function$;
ALTER FUNCTION agent_private.audit_platform_grant_privileges(uuid,name,name) OWNER TO :"agent_platform_grant_definer_role";
REVOKE ALL ON FUNCTION agent_private.audit_platform_grant_privileges(uuid,name,name) FROM PUBLIC;
DO $restore_platform_grant_lifecycle_v2$
DECLARE v_definition text;
BEGIN
 SELECT source.audit_definition INTO v_definition FROM pg_temp.platform_grant_lifecycle_source source WHERE source.profile_version IN(2,3);
 IF FOUND THEN EXECUTE v_definition;END IF;
END
$restore_platform_grant_lifecycle_v2$;

SELECT 1/pg_catalog.count(*) AS capability_registry_postflight FROM (
WITH candidates(role_name,capability,role_kind) AS(
 SELECT login_role,'Ingest','Runtime' FROM agent_private.agent_database_bindings
 UNION ALL SELECT login_role,'Enrollment','Runtime' FROM agent_private.enrollment_database_bindings
 UNION ALL SELECT login_role,'Projection','Runtime' FROM agent_private.agent_projection_database_bindings
 UNION ALL SELECT login_role,'PlatformGrant','Runtime' FROM agent_private.platform_grant_database_bindings
 UNION ALL SELECT owner.rolname::name,'Enrollment','Definer' FROM pg_catalog.pg_proc function JOIN pg_catalog.pg_roles owner ON owner.oid=function.proowner WHERE function.oid=pg_catalog.to_regprocedure('agent_private.audit_enrollment_privileges(name,name,text)')
 UNION ALL SELECT owner.rolname::name,'Projection','Definer' FROM pg_catalog.pg_proc function JOIN pg_catalog.pg_roles owner ON owner.oid=function.proowner WHERE function.oid=pg_catalog.to_regprocedure('agent_private.audit_projection_privileges(uuid,name,name)')
 UNION ALL SELECT owner.rolname::name,'PlatformGrant','Definer' FROM pg_catalog.pg_proc function JOIN pg_catalog.pg_roles owner ON owner.oid=function.proowner WHERE function.oid=pg_catalog.to_regprocedure('agent_private.audit_platform_grant_privileges(uuid,name,name)')),
 expected_columns(attnum,attname,atttypid,attnotnull) AS(VALUES(1::smallint,'role_name','name'::pg_catalog.regtype::oid,true),(2::smallint,'capability','text'::pg_catalog.regtype::oid,true),(3::smallint,'role_kind','text'::pg_catalog.regtype::oid,true)),
 actual_columns AS(SELECT attribute.attnum,attribute.attname,attribute.atttypid,attribute.attnotnull FROM pg_catalog.pg_attribute attribute WHERE attribute.attrelid='agent_private.agent_capability_roles'::pg_catalog.regclass AND attribute.attnum>0 AND NOT attribute.attisdropped)
SELECT 1 WHERE
 NOT EXISTS(SELECT DISTINCT * FROM candidates EXCEPT SELECT * FROM agent_private.agent_capability_roles) AND
 NOT EXISTS((SELECT * FROM expected_columns EXCEPT SELECT * FROM actual_columns) UNION ALL (SELECT * FROM actual_columns EXCEPT SELECT * FROM expected_columns)) AND
 (SELECT pg_catalog.count(*)=3 FROM pg_catalog.pg_constraint constraint_info WHERE constraint_info.conrelid='agent_private.agent_capability_roles'::pg_catalog.regclass AND constraint_info.contype IN('p','c')) AND
 (SELECT object.relowner=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=:'agent_table_owner_role') AND object.relrowsecurity AND object.relforcerowsecurity FROM pg_catalog.pg_class object WHERE object.oid='agent_private.agent_capability_roles'::pg_catalog.regclass) AND
 NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object,LATERAL pg_catalog.aclexplode(COALESCE(object.relacl,pg_catalog.acldefault('r',object.relowner))) acl WHERE object.oid='agent_private.agent_capability_roles'::pg_catalog.regclass AND acl.grantee<>object.relowner) AND
 NOT EXISTS(SELECT 1 FROM pg_catalog.pg_attribute attribute,LATERAL pg_catalog.aclexplode(attribute.attacl) acl WHERE attribute.attrelid='agent_private.agent_capability_roles'::pg_catalog.regclass AND acl.grantee<>(SELECT relowner FROM pg_catalog.pg_class WHERE oid=attribute.attrelid)) AND
 (SELECT pg_catalog.count(*)=1 FROM pg_catalog.pg_policy policy WHERE policy.polrelid='agent_private.agent_capability_roles'::pg_catalog.regclass AND policy.polname='definer_all' AND policy.polcmd='*' AND policy.polpermissive AND policy.polroles=ARRAY[(SELECT relowner FROM pg_catalog.pg_class WHERE oid=policy.polrelid)]::oid[] AND pg_catalog.pg_get_expr(policy.polqual,policy.polrelid)='true' AND pg_catalog.pg_get_expr(policy.polwithcheck,policy.polrelid)='true') AND
 NOT EXISTS(SELECT 1 FROM agent_private.agent_capability_roles reservation LEFT JOIN pg_catalog.pg_roles role ON role.rolname=reservation.role_name WHERE role.oid IS NULL OR (reservation.role_kind='Runtime' AND (NOT role.rolcanlogin OR role.rolsuper OR role.rolbypassrls OR role.rolcreatedb OR role.rolcreaterole OR role.rolinherit OR role.rolreplication)) OR (reservation.role_kind='Definer' AND (role.rolcanlogin OR role.rolsuper OR role.rolbypassrls OR role.rolcreatedb OR role.rolcreaterole OR role.rolinherit OR role.rolreplication)) OR EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members member WHERE member.member=role.oid OR member.roleid=role.oid)) AND
 NOT EXISTS(SELECT 1 FROM agent_private.agent_capability_roles reservation WHERE NOT agent_private.agent_role_has_capability(reservation.role_name,reservation.capability,reservation.role_kind)) AND
 (SELECT pg_catalog.count(*)=4 AND pg_catalog.bool_and(function.prosecdef AND pg_catalog.strpos(function.prosrc,'agent_role_has_capability')>0) FROM pg_catalog.pg_proc function WHERE function.oid=ANY(ARRAY[pg_catalog.to_regprocedure('agent_private.audit_ingest_privileges(name)'),pg_catalog.to_regprocedure('agent_private.audit_enrollment_privileges(name,name,text)'),pg_catalog.to_regprocedure('agent_private.audit_projection_privileges(uuid,name,name)'),pg_catalog.to_regprocedure('agent_private.audit_platform_grant_privileges(uuid,name,name)')]::oid[])) AND
 (SELECT pg_catalog.md5(pg_catalog.btrim(function.prosrc,E' \t\r\n'))=CASE source.profile_version WHEN 1 THEN 'e98e01a5978b092ed5f6599a97a0f243' WHEN 2 THEN 'd2a58ca2b13cfb5c813a21219de07aec' WHEN 3 THEN '64a11bee2af9f76b2d5e33c1b168934d' END FROM pg_catalog.pg_proc function CROSS JOIN pg_temp.platform_grant_lifecycle_source source WHERE function.oid=pg_catalog.to_regprocedure('agent_private.audit_platform_grant_privileges(uuid,name,name)')) AND
 (SELECT CASE source.profile_version
   WHEN 1 THEN pg_catalog.to_regclass('agent_private.platform_grant_revocation_receipts') IS NULL AND pg_catalog.to_regprocedure('agent_private.read_initial_enrollment_grant(uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz)') IS NULL AND pg_catalog.to_regprocedure('agent_private.revoke_initial_enrollment_grant(uuid,uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz,bytea)') IS NULL
   WHEN 2 THEN pg_catalog.to_regclass('agent_private.platform_grant_revocation_receipts') IS NOT NULL AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_attribute WHERE attrelid IN(pg_catalog.to_regclass('agent_private.platform_grant_receipts'),pg_catalog.to_regclass('agent_private.platform_grant_revocation_receipts')) AND attname IN('issue_contract_version','mint_permit_not_after','issue_mint_permit_not_after') AND NOT attisdropped) AND pg_catalog.to_regprocedure('agent_private.read_initial_enrollment_grant(uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz)') IS NOT NULL AND pg_catalog.to_regprocedure('agent_private.revoke_initial_enrollment_grant(uuid,uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz,bytea)') IS NOT NULL
   WHEN 3 THEN pg_catalog.to_regclass('agent_private.platform_grant_revocation_receipts') IS NOT NULL AND pg_catalog.to_regprocedure('agent_private.issue_initial_enrollment_grant(uuid,uuid,uuid,uuid,timestamptz,timestamptz,bytea,bytea)') IS NOT NULL AND pg_catalog.to_regprocedure('agent_private.read_initial_enrollment_grant(uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz,smallint,timestamptz)') IS NOT NULL AND pg_catalog.to_regprocedure('agent_private.revoke_initial_enrollment_grant(uuid,uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz,smallint,timestamptz,bytea)') IS NOT NULL AND
    (SELECT pg_catalog.count(*)=4 FROM (VALUES
      (pg_catalog.to_regclass('agent_private.platform_grant_receipts'),'issue_contract_version','smallint'::pg_catalog.regtype::oid,true),
      (pg_catalog.to_regclass('agent_private.platform_grant_receipts'),'mint_permit_not_after','timestamptz'::pg_catalog.regtype::oid,false),
      (pg_catalog.to_regclass('agent_private.platform_grant_revocation_receipts'),'issue_contract_version','smallint'::pg_catalog.regtype::oid,true),
      (pg_catalog.to_regclass('agent_private.platform_grant_revocation_receipts'),'issue_mint_permit_not_after','timestamptz'::pg_catalog.regtype::oid,false)) expected(relid,attname,type_oid,not_null)
     JOIN pg_catalog.pg_attribute attribute ON attribute.attrelid=expected.relid AND attribute.attname=expected.attname AND NOT attribute.attisdropped AND attribute.atttypid=expected.type_oid AND attribute.attnotnull=expected.not_null) AND
    (SELECT pg_catalog.count(*)=1 FROM pg_catalog.pg_constraint WHERE conrelid=pg_catalog.to_regclass('agent_private.platform_grant_receipts') AND conname='platform_grant_receipts_issue_contract' AND pg_catalog.md5(pg_catalog.pg_get_constraintdef(oid))='8d85f8a1bd060af5beef075b75bda13b') AND
    (SELECT pg_catalog.count(*)=1 FROM pg_catalog.pg_constraint WHERE conrelid=pg_catalog.to_regclass('agent_private.platform_grant_revocation_receipts') AND conname='platform_grant_revocation_receipts_issue_contract' AND pg_catalog.md5(pg_catalog.pg_get_constraintdef(oid))='76cb108da4b527ec5db5eac500168e68')
  END FROM pg_temp.platform_grant_lifecycle_source source)) checked;
CREATE OR REPLACE FUNCTION agent_private.agent_capability_isolation_profile()
RETURNS smallint LANGUAGE sql SECURITY INVOKER SET search_path=pg_catalog,agent_private,pg_temp AS 'SELECT 2::smallint';
ALTER FUNCTION agent_private.agent_capability_isolation_profile() OWNER TO :"agent_table_owner_role";
REVOKE ALL ON FUNCTION agent_private.agent_capability_isolation_profile() FROM PUBLIC;

COMMIT;
