-- Unconsumed exact restricted-owner membership helper and complete applicable SELECT policy set.
WITH owner_role AS (
 SELECT oid FROM pg_catalog.pg_roles WHERE rolname=:'expected_table_owner_role'
), target AS (
 SELECT * FROM pg_catalog.pg_class WHERE oid=pg_catalog.to_regclass('public."Memberships"')
), helper AS (
 SELECT p.*,l.lanname FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_language l ON l.oid=p.prolang
 WHERE p.oid=pg_catalog.to_regprocedure('public.has_environment_membership(uuid,uuid)')
), applicable AS (
 SELECT p.* FROM pg_catalog.pg_policy p CROSS JOIN owner_role o CROSS JOIN target t
 WHERE p.polrelid=t.oid AND p.polcmd IN('r','*')
   AND EXISTS(SELECT 1 FROM pg_catalog.unnest(p.polroles) role_oid
     WHERE role_oid=0 OR pg_catalog.pg_has_role(o.oid,role_oid,'USAGE'))
), helper_grantees AS (
 SELECT oid FROM owner_role
 UNION ALL SELECT r.oid FROM public."DirectoryDatabaseBindings" b JOIN pg_catalog.pg_roles r ON r.rolname=b."LoginRole"
   WHERE b."Purpose"='Api' AND b."ContractVersion"=1 AND b."EnvironmentId" IS NULL AND b."PrincipalId" IS NULL
 UNION ALL SELECT proowner FROM pg_catalog.pg_proc WHERE oid=pg_catalog.to_regprocedure('public.lock_enrollment_grant_plan_context(uuid,uuid,uuid[])')
 UNION ALL SELECT r.oid FROM enrollment_execution.role_reservations binding JOIN pg_catalog.pg_roles r
   ON r.oid=binding.role_oid AND r.rolname=binding.role_name
   WHERE binding.reservation_schema_version=1 AND
     ((binding.capability='EnrollmentGrantExecution' AND binding.role_kind IN('Definer','QueueDefiner'))
       OR (binding.capability='EnrollmentGrantDelivery' AND binding.role_kind='DeliveryDefiner'))
), expected_acl AS (
 SELECT h.oid function_oid,o.oid grantor,g.oid grantee,'EXECUTE'::text privilege_type,false is_grantable
 FROM helper h CROSS JOIN owner_role o CROSS JOIN helper_grantees g
 UNION ALL
 SELECT pg_catalog.to_regprocedure('public.directory_database_access(uuid,uuid)')::oid,o.oid,g.oid,'EXECUTE'::text,false
 FROM owner_role o CROSS JOIN helper_grantees g
 WHERE NOT EXISTS(SELECT 1 FROM enrollment_execution.role_reservations b
   WHERE b.role_oid=g.oid AND b.capability='EnrollmentGrantExecution' AND b.role_kind='QueueDefiner')
), actual_acl AS (
 SELECT p.oid function_oid,a.grantor,a.grantee,a.privilege_type,a.is_grantable
 FROM pg_catalog.pg_proc p CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) a
 WHERE p.oid IN(pg_catalog.to_regprocedure('public.has_environment_membership(uuid,uuid)'),
   pg_catalog.to_regprocedure('public.directory_database_access(uuid,uuid)'))
)
SELECT COALESCE((SELECT
 t.relowner=o.oid AND t.relkind='r' AND t.relpersistence='p' AND NOT t.relispartition AND t.relrowsecurity AND t.relforcerowsecurity
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_inherits i WHERE i.inhrelid=t.oid OR i.inhparent=t.oid)
 AND h.proowner=o.oid AND h.lanname='sql' AND h.prokind='f' AND h.prosecdef AND h.provolatile='s' AND h.proparallel='u'
 AND h.proisstrict AND NOT h.proleakproof AND h.prosupport=0 AND NOT h.proretset AND h.prorettype=16
 AND h.pronargs=2 AND h.proargtypes::text='2950 2950' AND h.proallargtypes IS NULL AND h.proargmodes IS NULL
 AND h.proargnames IS NOT DISTINCT FROM ARRAY['p_environment_id','p_principal_id']::text[]
 AND h.pronargdefaults=0 AND h.proargdefaults IS NULL AND h.provariadic=0 AND h.protrftypes IS NULL
 AND h.probin IS NULL AND h.prosqlbody IS NULL
 AND h.proconfig IS NOT DISTINCT FROM ARRAY['search_path=pg_catalog, pg_temp','row_security=on']
 AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(pg_catalog.replace(h.prosrc,E'\r\n',E'\n'),'UTF8')),'hex')
   ='a7f30b8a933c9731378e1cb8bb75152815012b8fa4e3a05a8a6d9f18db16d148' -- generated membership helper SHA-256
 AND (SELECT count(*)=1 FROM pg_catalog.pg_proc p WHERE p.pronamespace=pg_catalog.to_regnamespace('public') AND p.proname='has_environment_membership')
 -- Until the connector's complete capability profile is composed, any Connector
 -- binding keeps this inactive candidate closed; do not silently trust its row.
 AND NOT EXISTS(SELECT 1 FROM public."DirectoryDatabaseBindings" WHERE "Purpose"='Connector')
 AND (SELECT count(*)=6 AND count(DISTINCT oid)=6 FROM helper_grantees)
 AND (SELECT count(*)=11 FROM expected_acl)
 AND (SELECT count(*)=11 FROM actual_acl)
 AND NOT EXISTS((SELECT * FROM expected_acl EXCEPT SELECT * FROM actual_acl)
   UNION ALL (SELECT * FROM actual_acl EXCEPT SELECT * FROM expected_acl))
 -- The execution/delivery role policies are pinned by the canonical maintenance
 -- audit. Close the remaining PUBLIC write policies and the complete name set here.
 AND NOT EXISTS(
   (SELECT p.polname::text FROM pg_catalog.pg_policy p WHERE p.polrelid=t.oid
    EXCEPT SELECT name FROM (VALUES('member_read'),('member_insert'),('member_update'),('member_delete'),
      ('enrollment_execution_worker_memberships_allow'),('enrollment_execution_worker_memberships_limit'),
      ('enrollment_delivery_memberships_allow'),('enrollment_delivery_memberships_limit'),
      ('enrollment_profile4_membership_owner_select')) names(name))
   UNION ALL
   (SELECT name FROM (VALUES('member_read'),('member_insert'),('member_update'),('member_delete'),
      ('enrollment_execution_worker_memberships_allow'),('enrollment_execution_worker_memberships_limit'),
      ('enrollment_delivery_memberships_allow'),('enrollment_delivery_memberships_limit'),
      ('enrollment_profile4_membership_owner_select')) names(name)
    EXCEPT SELECT p.polname::text FROM pg_catalog.pg_policy p WHERE p.polrelid=t.oid))
 AND (SELECT count(*)=3 AND bool_and(COALESCE(p.polpermissive AND p.polroles=ARRAY[0::oid]
   AND p.polcmd=CASE p.polname WHEN 'member_insert' THEN 'a' WHEN 'member_update' THEN 'w' ELSE 'd' END::"char"
   AND CASE WHEN p.polname='member_insert' THEN p.polqual IS NULL ELSE
     pg_catalog.pg_get_expr(p.polqual,p.polrelid)=$policy$((("EnvironmentId")::text = current_setting('app.environment_id'::text, true)) AND public.has_environment_membership("EnvironmentId", (NULLIF(current_setting('app.principal_id'::text, true), ''::text))::uuid))$policy$ END
   AND CASE WHEN p.polname='member_delete' THEN p.polwithcheck IS NULL ELSE
     pg_catalog.pg_get_expr(p.polwithcheck,p.polrelid)=$policy$((("EnvironmentId")::text = current_setting('app.environment_id'::text, true)) AND public.has_environment_membership("EnvironmentId", (NULLIF(current_setting('app.principal_id'::text, true), ''::text))::uuid))$policy$ END,false))
   FROM pg_catalog.pg_policy p WHERE p.polrelid=t.oid AND p.polname IN('member_insert','member_update','member_delete'))
 AND (SELECT count(*)=2 FROM applicable)
 AND EXISTS(SELECT 1 FROM applicable p WHERE p.polname='enrollment_profile4_membership_owner_select'
   AND p.polcmd='r' AND p.polpermissive AND p.polroles=ARRAY[o.oid] AND pg_catalog.pg_get_expr(p.polqual,p.polrelid)='true' AND p.polwithcheck IS NULL)
 AND EXISTS(SELECT 1 FROM applicable p WHERE p.polname='member_read' AND p.polcmd='r' AND p.polpermissive
   AND p.polroles=ARRAY[0::oid] AND p.polwithcheck IS NULL
   AND pg_catalog.pg_get_expr(p.polqual,p.polrelid)=$policy$(public.has_environment_membership("EnvironmentId", (NULLIF(current_setting('app.principal_id'::text, true), ''::text))::uuid) AND ((("PrincipalId")::text = current_setting('app.principal_id'::text, true)) OR (("EnvironmentId")::text = current_setting('app.environment_id'::text, true))))$policy$)
 FROM target t CROSS JOIN helper h CROSS JOIN owner_role o),false) AS is_valid;
