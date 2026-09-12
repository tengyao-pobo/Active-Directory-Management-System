-- Catalog-only external attestation. The caller invokes the pinned internal audit only after this succeeds.
WITH identities AS (
 SELECT runtime.oid runtime_oid,definer.oid definer_oid,owner_role.oid owner_oid
 FROM pg_catalog.pg_roles runtime,pg_catalog.pg_roles definer,pg_catalog.pg_roles owner_role
 WHERE runtime.rolname=:'execution_runtime_role' AND definer.rolname=:'execution_definer_role'
   AND owner_role.rolname=:'expected_table_owner_role'
), audit_function AS (
 SELECT p.*,l.lanname FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_language l ON l.oid=p.prolang
 WHERE p.oid=pg_catalog.to_regprocedure('enrollment_execution.audit_execution_privileges(uuid)')
), marker AS (
 SELECT p.*,l.lanname FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_language l ON l.oid=p.prolang
 WHERE p.oid=pg_catalog.to_regprocedure('enrollment_execution.execution_store_profile()')
), wrappers AS (
 SELECT p.oid,p.proowner FROM pg_catalog.pg_proc p WHERE p.oid IN(
  pg_catalog.to_regprocedure('enrollment_execution.read_execution_record(uuid,uuid)'),
  pg_catalog.to_regprocedure('enrollment_execution.read_and_lock_plan_context(uuid,uuid)'),
  pg_catalog.to_regprocedure('enrollment_execution.authorize_and_store_candidate(uuid,uuid,text,bytea,bytea,bytea)'),
  pg_catalog.to_regprocedure('enrollment_execution.record_execution_result(uuid,uuid,bytea,text,text,uuid,uuid,uuid,uuid,timestamptz,timestamptz,timestamptz,smallint,timestamptz,bytea,bytea)'),
  pg_catalog.to_regprocedure('enrollment_execution.quarantine_execution(uuid,uuid,bytea,text)'))
), verified AS (
 SELECT COALESCE(
  :'execution_runtime_role'=SESSION_USER AND :'expected_environment_id'::uuid<>'00000000-0000-0000-0000-000000000000'::uuid
  AND i.runtime_oid IS NOT NULL AND i.definer_oid IS NOT NULL AND i.owner_oid IS NOT NULL
  AND (SELECT count(*)=1 AND bool_and(r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolbypassrls
      AND NOT r.rolcreatedb AND NOT r.rolcreaterole AND NOT r.rolinherit AND NOT r.rolreplication)
      FROM pg_catalog.pg_roles r WHERE r.oid=i.runtime_oid)
  AND (SELECT count(*)=1 AND bool_and(NOT r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolbypassrls
      AND NOT r.rolcreatedb AND NOT r.rolcreaterole AND NOT r.rolinherit AND NOT r.rolreplication)
      FROM pg_catalog.pg_roles r WHERE r.oid=i.definer_oid)
  AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members m
      WHERE m.member IN(i.runtime_oid,i.definer_oid) OR m.roleid IN(i.runtime_oid,i.definer_oid))
  AND (SELECT count(*)=1 AND bool_and(f.proowner=i.owner_oid AND f.lanname='plpgsql' AND f.prosecdef
      AND f.provolatile='s' AND f.proparallel='u' AND f.prokind='f' AND f.proretset
      AND f.prorettype='record'::regtype AND f.pronargs=1 AND f.proargtypes='2950'::oidvector
      AND f.proargnames=ARRAY['p_environment','is_valid','diagnostic_code','profile_version']
      AND f.proallargtypes=ARRAY['uuid'::regtype::oid,'boolean'::regtype::oid,'text'::regtype::oid,'smallint'::regtype::oid]
      AND f.proargmodes=ARRAY['i','t','t','t']::"char"[]
      AND f.proconfig=ARRAY['search_path=pg_catalog, pg_temp','row_security=on']
      AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
          pg_catalog.btrim(pg_catalog.regexp_replace(f.prosrc,'[[:space:]]+',' ','g')),'UTF8')),'hex')
          ='8ed83a1a4736e9caab7c0a9c32ef8b2e53b48dbdcf184824a8436d3fc33d3da3') FROM audit_function f)
  AND (SELECT count(*)=1 AND bool_and(m.proowner=i.owner_oid AND m.lanname='sql' AND NOT m.prosecdef
      AND m.provolatile='i' AND m.proparallel='s' AND NOT m.proretset AND m.prorettype='smallint'::regtype
      AND m.pronargs=0 AND m.proconfig=ARRAY['search_path=pg_catalog, pg_temp']
      AND pg_catalog.btrim(m.prosrc,E' \t\r\n')='SELECT 2::smallint') FROM marker m)
  AND (SELECT count(*)=5 AND bool_and(w.proowner=i.definer_oid) FROM wrappers w)
  AND NOT EXISTS(SELECT 1 FROM audit_function f
      CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(f.proacl,pg_catalog.acldefault('f',f.proowner))) acl
      WHERE acl.privilege_type<>'EXECUTE' OR acl.is_grantable OR acl.grantee=0
         OR acl.grantee NOT IN(i.owner_oid,i.definer_oid,i.runtime_oid)
            AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles role WHERE role.oid=acl.grantee
                AND role.rolcanlogin AND NOT role.rolsuper AND NOT role.rolbypassrls
                AND NOT role.rolcreatedb AND NOT role.rolcreaterole AND NOT role.rolinherit AND NOT role.rolreplication))
  AND EXISTS(SELECT 1 FROM audit_function f CROSS JOIN LATERAL pg_catalog.aclexplode(f.proacl) acl
      WHERE acl.grantee=i.runtime_oid AND acl.privilege_type='EXECUTE' AND NOT acl.is_grantable),false) AS is_valid
 FROM identities i
)
SELECT is_valid FROM verified;
