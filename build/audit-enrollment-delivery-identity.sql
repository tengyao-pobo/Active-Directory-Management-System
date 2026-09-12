-- Staged catalog-only identity slice, not a complete profile4 attestation.
-- Execute inside the profile-locked transaction with search_path=pg_catalog,pg_temp.
-- Shared source embedded into the draft profile by update-enrollment-delivery-catalog-slices.ps1.
-- The enclosing profile must separately attest bindings, role inventories and table ACLs.
WITH plan_helper AS (
  SELECT p.*,l.lanname FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_language l ON l.oid=p.prolang
  WHERE p.oid=pg_catalog.to_regprocedure('public.lock_enrollment_grant_plan_context(uuid,uuid,uuid[])')
), plan_acl AS (
  SELECT acl.* FROM plan_helper p CROSS JOIN LATERAL pg_catalog.aclexplode(
    COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) acl
), api_role AS (
  SELECT r.* FROM pg_catalog.pg_roles r JOIN plan_acl acl ON acl.grantee=r.oid
  WHERE (SELECT count(*)=1 FROM plan_acl) AND acl.privilege_type='EXECUTE' AND NOT acl.is_grantable
    AND acl.grantor=(SELECT proowner FROM plan_helper)
), identities AS (
  SELECT owner_role.oid owner_oid,plan_role.oid plan_oid,execution_role.oid execution_oid,delivery_role.oid delivery_oid,api_role.oid api_oid
  FROM pg_catalog.pg_roles owner_role,pg_catalog.pg_roles plan_role,
    pg_catalog.pg_roles execution_role,pg_catalog.pg_roles delivery_role,api_role
  WHERE owner_role.rolname=:'expected_table_owner_role'
    AND plan_role.rolname=:'enrollment_plan_lock_owner_role'
    AND execution_role.rolname=:'execution_definer_role' AND delivery_role.rolname=:'delivery_definer_role'
), helper AS (
  SELECT p.*,l.lanname FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_language l ON l.oid=p.prolang
  WHERE p.oid=pg_catalog.to_regprocedure('public.api_database_session()')
), policy_contract(relation_name,policy_name,command,permissive,role_kind,expression_hash) AS (VALUES
  ('Principals','enrollment_identity_principals_owner','*',true,'owner','fe2e7aa3a94b94b876d7713f1517686d'),
  ('Sessions','enrollment_identity_sessions_owner','*',true,'owner','fe2e7aa3a94b94b876d7713f1517686d'),
  ('Principals','enrollment_identity_principals_api_read','r',true,'public','708e22a476d7e00ff3ef7fe1441d8797'),
  ('Sessions','enrollment_identity_sessions_api','*',true,'public','1531f6d3d3ecc2ac56c17328212a0876'),
  ('Principals','enrollment_identity_principals_plan_read','r',true,'plan','ce24367043032e870e44adf501cef04d'),
  ('Principals','enrollment_identity_principals_plan_lock','w',true,'plan','84083a1a51bc3bc63ab584fc5a6d9a90'),
  ('Principals','enrollment_identity_principals_execution_read_allow','r',true,'execution','7950fb8cacb9394a69dade55f05249c1'),
  ('Principals','enrollment_identity_principals_execution_read_limit','r',false,'execution','7950fb8cacb9394a69dade55f05249c1'),
  ('Principals','enrollment_identity_principals_execution_lock_allow','w',true,'execution','de5073f7dedeff82c0ba31a4b0af9e3c'),
  ('Principals','enrollment_identity_principals_execution_lock_limit','w',false,'execution','de5073f7dedeff82c0ba31a4b0af9e3c'),
  ('Principals','enrollment_delivery_principals_allow','*',true,'delivery','0f4a674f4193404082084f1ce226feca'),
  ('Principals','enrollment_delivery_principals_limit','*',false,'delivery','0f4a674f4193404082084f1ce226feca'),
  ('Sessions','enrollment_delivery_sessions_allow','r',true,'delivery','7423ae3d79d4de92662ecb4bd3658c57'),
  ('Sessions','enrollment_delivery_sessions_limit','r',false,'delivery','7423ae3d79d4de92662ecb4bd3658c57')
), expected AS (
  SELECT pg_catalog.to_regclass(pg_catalog.format('public.%I',p.relation_name))::oid relation_oid,
    p.policy_name,p.command,p.permissive,
    ARRAY[CASE p.role_kind WHEN 'owner' THEN i.owner_oid WHEN 'plan' THEN i.plan_oid
      WHEN 'execution' THEN i.execution_oid WHEN 'delivery' THEN i.delivery_oid ELSE 0::oid END] roles,
    p.expression_hash FROM policy_contract p CROSS JOIN identities i
), actual AS (
  SELECT p.polrelid relation_oid,p.polname::text policy_name,p.polcmd::text command,
    p.polpermissive permissive,p.polroles roles,
    pg_catalog.md5(COALESCE(pg_catalog.pg_get_expr(p.polqual,p.polrelid),'')||'|'||
      COALESCE(pg_catalog.pg_get_expr(p.polwithcheck,p.polrelid),'')) expression_hash
  FROM pg_catalog.pg_policy p WHERE p.polrelid IN(
    pg_catalog.to_regclass('public."Principals"'),pg_catalog.to_regclass('public."Sessions"'))
    OR p.polname LIKE 'enrollment_identity_%'
), expected_acl AS (
  SELECT owner_oid grantor,owner_oid grantee,'EXECUTE'::text privilege_type,false is_grantable FROM identities
  UNION ALL SELECT owner_oid,0::oid,'EXECUTE',false FROM identities
), actual_acl AS (
  SELECT acl.grantor,acl.grantee,acl.privilege_type,acl.is_grantable
  FROM helper h CROSS JOIN LATERAL pg_catalog.aclexplode(
    COALESCE(h.proacl,pg_catalog.acldefault('f',h.proowner))) acl
), expected_plan_tables(schema_name,table_name,privilege_type,is_grantable) AS (VALUES
  ('public','DirectoryDatabaseBindings','SELECT',false),
  ('public','Environments','SELECT',false),('public','Environments','UPDATE',false),
  ('public','DirectorySync','SELECT',false),('public','DirectorySync','UPDATE',false),
  ('public','DirectoryObjects','SELECT',false),('public','DirectoryObjects','UPDATE',false),
  ('public','Principals','SELECT',false),('public','Principals','UPDATE',false),
  ('public','Memberships','SELECT',false),('public','Memberships','UPDATE',false)
), actual_plan_tables AS (
  SELECT n.nspname::text schema_name,c.relname::text table_name,acl.privilege_type,acl.is_grantable
  FROM identities i CROSS JOIN pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
  CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(c.relacl,pg_catalog.acldefault('r',c.relowner))) acl
  WHERE c.relkind IN('r','p','v','m','f') AND acl.grantee=i.plan_oid
), expected_plan_functions(function_oid,privilege_type,is_grantable) AS (VALUES
  (pg_catalog.to_regprocedure('public.has_environment_membership(uuid,uuid)')::oid,'EXECUTE',false),
  (pg_catalog.to_regprocedure('public.directory_database_access(uuid,uuid)')::oid,'EXECUTE',false)
), actual_plan_functions AS (
  SELECT p.oid function_oid,acl.privilege_type,acl.is_grantable FROM identities i CROSS JOIN pg_catalog.pg_proc p
  CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) acl
  WHERE acl.grantee=i.plan_oid
), actual_plan_schemas AS (
  SELECT n.nspname::text schema_name,acl.privilege_type,acl.is_grantable FROM identities i CROSS JOIN pg_catalog.pg_namespace n
  CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(n.nspacl,pg_catalog.acldefault('n',n.nspowner))) acl
  WHERE acl.grantee=i.plan_oid
), expected_plan_schemas(schema_name,privilege_type,is_grantable) AS (VALUES ('public','USAGE',false))
SELECT COALESCE((SELECT
  pg_catalog.current_setting('search_path') IN('pg_catalog,pg_temp','pg_catalog, pg_temp')
  AND (SELECT count(DISTINCT id)=5 FROM unnest(ARRAY[i.owner_oid,i.plan_oid,i.execution_oid,i.delivery_oid,i.api_oid]) id)
  AND (SELECT r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolbypassrls AND NOT r.rolcreatedb
    AND NOT r.rolcreaterole AND NOT r.rolinherit AND NOT r.rolreplication FROM api_role r)
  AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles r WHERE r.oid IN(i.plan_oid,i.execution_oid,i.delivery_oid)
    AND (r.rolcanlogin OR r.rolsuper OR r.rolbypassrls OR r.rolcreatedb OR r.rolcreaterole OR r.rolinherit OR r.rolreplication))
  AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members m
    WHERE m.member IN(i.plan_oid,i.execution_oid,i.delivery_oid,i.api_oid) OR m.roleid IN(i.plan_oid,i.execution_oid,i.delivery_oid,i.api_oid))
  AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_database d WHERE d.datdba IN(i.plan_oid,i.api_oid))
  AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace n WHERE n.nspowner IN(i.plan_oid,i.api_oid))
  AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c WHERE c.relowner IN(i.plan_oid,i.api_oid))
  AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p WHERE p.proowner=i.api_oid)
  AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c WHERE c.oid IN(
      pg_catalog.to_regclass('public."DirectorySync"'),pg_catalog.to_regclass('public."DirectoryObjects"'))
    AND (pg_catalog.has_table_privilege(i.api_oid,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN')
      OR pg_catalog.has_any_column_privilege(i.api_oid,c.oid,'INSERT,UPDATE,REFERENCES')))
  AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace n CROSS JOIN LATERAL pg_catalog.aclexplode(n.nspacl) acl
    WHERE n.nspname<>'public' AND acl.grantee=i.api_oid)
  AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
    CROSS JOIN LATERAL pg_catalog.aclexplode(c.relacl) acl WHERE n.nspname<>'public' AND acl.grantee=i.api_oid)
  AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid=a.attrelid
    JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL pg_catalog.aclexplode(a.attacl) acl
    WHERE n.nspname<>'public' AND acl.grantee=i.api_oid)
  AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
    CROSS JOIN LATERAL pg_catalog.aclexplode(p.proacl) acl WHERE n.nspname<>'public' AND acl.grantee=i.api_oid)
  AND NOT pg_catalog.has_database_privilege(i.plan_oid,pg_catalog.current_database(),'CREATE')
  AND NOT pg_catalog.has_database_privilege(i.api_oid,pg_catalog.current_database(),'CREATE')
  AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace n WHERE n.nspname NOT IN('pg_catalog','information_schema')
    AND n.nspname !~ '^pg_(toast|temp_)' AND (pg_catalog.has_schema_privilege(i.plan_oid,n.oid,'CREATE')
      OR pg_catalog.has_schema_privilege(i.api_oid,n.oid,'CREATE')))
  AND (SELECT count(*)=1 AND bool_and(p.proowner=i.plan_oid AND p.lanname='plpgsql' AND p.prosecdef
    AND p.provolatile='v' AND p.proparallel='u' AND p.prokind='f' AND NOT p.proretset
    AND NOT p.proisstrict AND NOT p.proleakproof AND p.prorettype='void'::regtype
    AND p.pronargs=3 AND p.proargtypes='2950 2950 2951'::oidvector
    AND p.proargnames=ARRAY['p_environment_id','p_directory_object_id','p_principal_ids']
    AND p.proallargtypes IS NULL AND p.proargmodes IS NULL AND p.pronargdefaults=0
    AND p.provariadic=0 AND p.prosupport=0 AND p.probin IS NULL AND p.prosqlbody IS NULL AND p.proargdefaults IS NULL
    AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']
    AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(pg_catalog.btrim(
      pg_catalog.replace(p.prosrc,E'\r\n',E'\n'),E' \t\r\n'),'UTF8')),'hex')
      ='b9a6befb836015684839e3c4483ec2944c74320e3ab4bc5bc2d3c971fa3dd2bd') FROM plan_helper p)
  AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p WHERE p.proowner=i.plan_oid
    AND p.oid<>pg_catalog.to_regprocedure('public.lock_enrollment_grant_plan_context(uuid,uuid,uuid[])'))
  AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_attribute a CROSS JOIN LATERAL pg_catalog.aclexplode(a.attacl) acl
    WHERE acl.grantee=i.plan_oid)
  AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c
    WHERE CASE WHEN c.relkind='S' THEN pg_catalog.has_sequence_privilege(i.plan_oid,c.oid,'USAGE,SELECT,UPDATE') ELSE false END)
  AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_default_acl defaults CROSS JOIN LATERAL pg_catalog.aclexplode(defaults.defaclacl) acl
    WHERE defaults.defaclobjtype IN('r','S') AND acl.grantee IN(0,i.plan_oid))
  AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname NOT IN('pg_catalog','information_schema') AND n.nspname !~ '^pg_(toast|temp_)'
      AND c.relkind IN('r','p','v','m','f') AND (
        pg_catalog.has_table_privilege(i.plan_oid,c.oid,'INSERT,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN')
        OR pg_catalog.has_any_column_privilege(i.plan_oid,c.oid,'INSERT,REFERENCES')
        OR ((pg_catalog.has_table_privilege(i.plan_oid,c.oid,'SELECT') OR pg_catalog.has_any_column_privilege(i.plan_oid,c.oid,'SELECT'))
          AND (n.nspname<>'public' OR c.relname NOT IN('DirectoryDatabaseBindings','Environments','DirectorySync','DirectoryObjects','Principals','Memberships')))
        OR ((pg_catalog.has_table_privilege(i.plan_oid,c.oid,'UPDATE') OR pg_catalog.has_any_column_privilege(i.plan_oid,c.oid,'UPDATE'))
          AND (n.nspname<>'public' OR c.relname NOT IN('Environments','DirectorySync','DirectoryObjects','Principals','Memberships')))))
  AND (SELECT count(*)=2 AND bool_and(c.relowner=i.owner_oid AND c.relkind='r' AND c.relrowsecurity AND c.relforcerowsecurity
    AND NOT c.relispartition AND c.relpersistence='p')
    FROM pg_catalog.pg_class c WHERE c.oid IN(pg_catalog.to_regclass('public."Principals"'),pg_catalog.to_regclass('public."Sessions"')))
  AND (SELECT count(*)=1 AND bool_and(h.proowner=i.owner_oid AND h.lanname='sql' AND h.prosecdef
    AND h.provolatile='s' AND h.proparallel='u' AND h.prokind='f' AND NOT h.proretset
    AND NOT h.proisstrict AND NOT h.proleakproof AND h.prorettype='boolean'::regtype
    AND h.pronargs=0 AND h.pronargdefaults=0 AND h.proargnames IS NULL AND h.proallargtypes IS NULL
    AND h.proargmodes IS NULL AND h.provariadic=0
    AND h.prosupport=0 AND h.probin IS NULL AND h.prosqlbody IS NULL AND h.proargdefaults IS NULL
    AND h.proconfig=ARRAY['search_path=pg_catalog, pg_temp','row_security=on']
    AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(pg_catalog.btrim(
      pg_catalog.regexp_replace(h.prosrc,'[[:space:]]+',' ','g')),'UTF8')),'hex')
      ='e8f215ff4e1093baf33b3cf72040f99a96f2b5821f4b4593cf760d5a46658d84') FROM helper h)
  AND NOT EXISTS(SELECT 1 FROM ((SELECT * FROM expected EXCEPT SELECT * FROM actual)
    UNION ALL (SELECT * FROM actual EXCEPT SELECT * FROM expected)) difference)
  AND NOT EXISTS(SELECT 1 FROM ((SELECT * FROM expected_acl EXCEPT SELECT * FROM actual_acl)
    UNION ALL (SELECT * FROM actual_acl EXCEPT SELECT * FROM expected_acl)) difference)
  AND NOT EXISTS(SELECT 1 FROM ((SELECT * FROM expected_plan_tables EXCEPT SELECT * FROM actual_plan_tables)
    UNION ALL (SELECT * FROM actual_plan_tables EXCEPT SELECT * FROM expected_plan_tables)) difference)
  AND NOT EXISTS(SELECT 1 FROM ((SELECT * FROM expected_plan_functions EXCEPT SELECT * FROM actual_plan_functions)
    UNION ALL (SELECT * FROM actual_plan_functions EXCEPT SELECT * FROM expected_plan_functions)) difference)
  AND NOT EXISTS(SELECT 1 FROM ((SELECT * FROM expected_plan_schemas EXCEPT SELECT * FROM actual_plan_schemas)
    UNION ALL (SELECT * FROM actual_plan_schemas EXCEPT SELECT * FROM expected_plan_schemas)) difference)
  FROM identities i),false) AS is_valid;
