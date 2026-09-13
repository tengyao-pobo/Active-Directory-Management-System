-- Unconsumed function ABI/body/ACL slice; combine with live relation/identity/history validation before use.
WITH owner_role AS (
 SELECT oid FROM pg_catalog.pg_roles WHERE rolname=:'expected_table_owner_role'
), expected(signature,volatility,security_definer,return_type,body_hash) AS (VALUES
-- BEGIN generated readiness function contracts
 ('enrollment_execution.guard_profile4_readiness()','v',false,2279::oid,'2306b5a02f10aebb91219217700dd1372747735406869e931932d6edf5bae674'),
 ('enrollment_execution.profile4_ready()','s',true,16::oid,'53f26f73259061150b1e124a7cdd257fc7a1e30ce86cba0fdda10da55fc6fafc')
-- END generated readiness function contracts
), functions AS (
 SELECT e.*,p.*,l.lanname FROM expected e LEFT JOIN pg_catalog.pg_proc p ON p.oid=pg_catalog.to_regprocedure(e.signature)
 LEFT JOIN pg_catalog.pg_language l ON l.oid=p.prolang
), expected_acl AS (
 SELECT f.oid,acl.grantor,acl.grantee,acl.privilege_type,acl.is_grantable
 FROM functions f CROSS JOIN owner_role o CROSS JOIN LATERAL pg_catalog.aclexplode(pg_catalog.acldefault('f',o.oid)) acl
 WHERE acl.grantee=o.oid
), actual_acl AS (
 SELECT f.oid,acl.grantor,acl.grantee,acl.privilege_type,acl.is_grantable
 FROM functions f CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(f.proacl,pg_catalog.acldefault('f',f.proowner))) acl
)
SELECT COALESCE((SELECT
 pg_catalog.current_setting('search_path') IN('pg_catalog,pg_temp','pg_catalog, pg_temp')
 AND (SELECT count(*)=2 AND bool_and((f.oid IS NOT NULL AND f.proowner=o.oid AND f.lanname='plpgsql' AND f.prokind='f'
   AND f.provolatile::text=f.volatility AND f.prosecdef=f.security_definer AND f.proparallel='u'
   AND f.prorettype=f.return_type AND NOT f.proretset AND NOT f.proisstrict AND NOT f.proleakproof AND f.prosupport=0
   AND f.pronargs=0 AND f.proargtypes::text='' AND f.proallargtypes IS NULL AND f.proargnames IS NULL AND f.proargmodes IS NULL
   AND f.pronargdefaults=0 AND f.proargdefaults IS NULL AND f.provariadic=0 AND f.protrftypes IS NULL
   AND f.probin IS NULL AND f.prosqlbody IS NULL
   AND f.proconfig IS NOT DISTINCT FROM ARRAY['search_path=pg_catalog, pg_temp','row_security=on']
   AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
     pg_catalog.replace(f.prosrc,E'\r\n',E'\n'),'UTF8')),'hex')=f.body_hash) IS TRUE)
  FROM functions f)
 AND (SELECT count(*)=2 FROM pg_catalog.pg_proc p WHERE p.pronamespace=pg_catalog.to_regnamespace('enrollment_execution')
   AND p.proname IN('guard_profile4_readiness','profile4_ready'))
 AND NOT EXISTS(SELECT 1 FROM ((SELECT * FROM expected_acl EXCEPT SELECT * FROM actual_acl)
   UNION ALL (SELECT * FROM actual_acl EXCEPT SELECT * FROM expected_acl)) differences)
 FROM owner_role o),false) AS is_valid;
