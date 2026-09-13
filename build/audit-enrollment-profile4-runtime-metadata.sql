-- Unconsumed locking audit metadata; body and ACL contracts are attested separately.
WITH owner_role AS (
 SELECT oid FROM pg_catalog.pg_roles WHERE rolname=:'expected_table_owner_role'
), expected(signature) AS (VALUES
 ('enrollment_execution.audit_execution_privileges(uuid)'),
 ('enrollment_execution.audit_delivery_privileges(uuid)')
), functions AS (
 SELECT p.*,l.lanname FROM expected e
 LEFT JOIN pg_catalog.pg_proc p ON p.oid=pg_catalog.to_regprocedure(e.signature)
 LEFT JOIN pg_catalog.pg_language l ON l.oid=p.prolang
)
SELECT COALESCE((SELECT count(*)=2 AND bool_and(
 p.oid IS NOT NULL AND p.proowner=o.oid AND p.lanname='plpgsql' AND p.prokind='f'
 AND p.prosecdef AND p.provolatile='v' AND p.proparallel='u'
 AND NOT p.proisstrict AND NOT p.proleakproof AND p.prosupport=0
 AND p.proretset AND p.prorettype=2249 AND p.pronargs=1 AND p.proargtypes::text='2950'
 AND p.proallargtypes IS NOT DISTINCT FROM ARRAY[2950,16,25,21]::oid[]
 AND p.proargnames IS NOT DISTINCT FROM ARRAY['p_environment','is_valid','diagnostic_code','profile_version']::text[]
 AND p.proargmodes IS NOT DISTINCT FROM ARRAY['i','t','t','t']::"char"[]
 AND p.pronargdefaults=0 AND p.proargdefaults IS NULL AND p.provariadic=0 AND p.protrftypes IS NULL
 AND p.probin IS NULL AND p.prosqlbody IS NULL
 AND p.proconfig IS NOT DISTINCT FROM ARRAY['search_path=pg_catalog, pg_temp','row_security=on'])
 FROM functions p CROSS JOIN owner_role o),false)
 AND (SELECT count(*)=2 FROM pg_catalog.pg_proc p
   WHERE p.pronamespace=pg_catalog.to_regnamespace('enrollment_execution')
     AND p.proname IN('audit_execution_privileges','audit_delivery_privileges')) AS is_valid;
