-- Unconsumed catalog-only template/linkage attestation. Never invokes the guard or runtime audit.
WITH owner_role AS (
 SELECT oid FROM pg_catalog.pg_roles WHERE rolname=:'expected_table_owner_role'
), guard AS (
 SELECT p.*,l.lanname FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_language l ON l.oid=p.prolang
 WHERE p.oid=pg_catalog.to_regprocedure('enrollment_execution.guard_profile4_publication()')
), runtime AS (
 SELECT p.prosrc FROM pg_catalog.pg_proc p
 WHERE p.oid=pg_catalog.to_regprocedure('enrollment_execution.audit_execution_privileges(uuid)')
), api_roles AS (
 SELECT r.* FROM public."DirectoryDatabaseBindings" b JOIN pg_catalog.pg_roles r ON r.rolname=b."LoginRole"
 WHERE b."Purpose"='Api' AND b."ContractVersion"=1 AND b."EnvironmentId" IS NULL AND b."PrincipalId" IS NULL
), body AS (
 SELECT pg_catalog.replace(prosrc,E'\r\n',E'\n') raw_body FROM guard
), pins AS (
 SELECT count(*) pin_count,max(parts[1]) runtime_hash FROM body
 CROSS JOIN LATERAL pg_catalog.string_to_table(raw_body,E'\n') line
 CROSS JOIN LATERAL pg_catalog.regexp_matches(line,'^    expected_runtime_hash constant text := ''([0-9a-f]{64})'';$') parts
), attachments AS (
 SELECT t.* FROM pg_catalog.pg_trigger t
 WHERE t.tgname='enrollment_grant_operation_00_publication' OR t.tgfoid=(SELECT oid FROM guard)
)
SELECT COALESCE((SELECT
 g.proowner=o.oid AND g.lanname='plpgsql' AND g.prokind='f' AND g.prosecdef
 AND g.provolatile='v' AND g.proparallel='u' AND NOT g.proretset AND g.prorettype=2279
 AND NOT g.proisstrict AND NOT g.proleakproof AND g.prosupport=0
 AND g.pronargs=0 AND g.proargtypes::text='' AND g.proallargtypes IS NULL AND g.proargnames IS NULL AND g.proargmodes IS NULL
 AND g.pronargdefaults=0 AND g.proargdefaults IS NULL AND g.provariadic=0 AND g.protrftypes IS NULL
 AND g.probin IS NULL AND g.prosqlbody IS NULL
 AND g.proconfig IS NOT DISTINCT FROM ARRAY['search_path=pg_catalog, pg_temp','row_security=on']
 AND (SELECT count(*)=1 FROM pg_catalog.pg_proc p
   WHERE p.pronamespace=pg_catalog.to_regnamespace('enrollment_execution') AND p.proname='guard_profile4_publication')
 AND (SELECT count(*)=1 AND bool_and(acl.grantor=o.oid AND acl.grantee=o.oid
      AND acl.privilege_type='EXECUTE' AND NOT acl.is_grantable)
   FROM pg_catalog.aclexplode(COALESCE(g.proacl,pg_catalog.acldefault('f',g.proowner))) acl)
 AND pins.pin_count=1
 AND (SELECT count(*)=1 AND bool_and(a.oid<>o.oid AND a.rolcanlogin
     AND NOT(a.rolsuper OR a.rolbypassrls OR a.rolcreatedb OR a.rolcreaterole OR a.rolinherit OR a.rolreplication)
     AND NOT pg_catalog.has_parameter_privilege(a.oid,'session_replication_role','SET')) FROM api_roles a)
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members m
     WHERE m.member IN(SELECT oid FROM api_roles) OR m.roleid IN(SELECT oid FROM api_roles))
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_parameter_acl p
     CROSS JOIN LATERAL pg_catalog.aclexplode(p.paracl) acl
     WHERE acl.grantee=0 OR acl.grantee IN(SELECT oid FROM api_roles))
 AND pins.runtime_hash=pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(pg_catalog.replace(r.prosrc,E'\r\n',E'\n'),'UTF8')),'hex')
 AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(pg_catalog.replace(b.raw_body,
     '    expected_runtime_hash constant text := '||pg_catalog.quote_literal(pins.runtime_hash)||';',
     '    expected_runtime_hash constant text := ''__RUNTIME_AUDIT_SHA256__'';'),'UTF8')),'hex')
     ='d4709dd884d6d9be5e4307508754a8d2740798cb4dbd5f06f43489cf448af5a8' -- generated publication template SHA-256
 AND (SELECT count(*)=2 AND bool_and(c.relowner=o.oid AND c.relkind='r' AND c.relpersistence='p' AND NOT c.relispartition)
   FROM pg_catalog.pg_class c WHERE c.oid IN(pg_catalog.to_regclass('public."Environments"'),pg_catalog.to_regclass('public."EnrollmentGrantOperations"')))
 AND (SELECT count(*)=1 FROM attachments)
 AND EXISTS(SELECT 1 FROM attachments t
   WHERE t.tgrelid=pg_catalog.to_regclass('public."EnrollmentGrantOperations"') AND t.tgfoid=g.oid
     AND t.tgname='enrollment_grant_operation_00_publication' AND t.tgtype=7 AND t.tgenabled='A'
     AND NOT t.tgisinternal AND t.tgparentid=0 AND NOT t.tgdeferrable AND NOT t.tginitdeferred
     AND t.tgconstraint=0 AND t.tgconstrrelid=0 AND t.tgconstrindid=0
     AND t.tgnargs=0 AND octet_length(t.tgargs)=0 AND t.tgattr::text='' AND t.tgqual IS NULL
     AND t.tgoldtable IS NULL AND t.tgnewtable IS NULL)
 FROM guard g CROSS JOIN owner_role o CROSS JOIN body b CROSS JOIN pins CROSS JOIN runtime r),false) AS is_valid;
