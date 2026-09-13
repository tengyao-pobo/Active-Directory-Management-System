-- UNCONSUMED current-state plan-definer privilege slice. Requires role/function,
-- full relation structure and RLS policy composition. Future creator defaults
-- remain an installer responsibility; no default privileges are installed here.
-- Catalog-only; run with transaction-local search_path=pg_catalog,pg_temp.
WITH identities AS (
 SELECT c.relowner owner_oid,r.oid api_oid,p.proowner plan_oid
 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 CROSS JOIN pg_catalog.pg_roles r
 JOIN pg_catalog.pg_proc p ON p.proname='lock_enrollment_grant_plan_context' AND p.proargtypes::text='2950 2950 2951'
 JOIN pg_catalog.pg_namespace pn ON pn.oid=p.pronamespace AND pn.nspname='public'
 WHERE n.nspname='public' AND c.relname='Environments' AND r.rolname=SESSION_USER
), expected_tables(table_name,privilege_type) AS (VALUES
 ('DirectoryDatabaseBindings','SELECT'),('Environments','SELECT'),('Environments','UPDATE'),
 ('DirectorySync','SELECT'),('DirectorySync','UPDATE'),('DirectoryObjects','SELECT'),('DirectoryObjects','UPDATE'),
 ('Principals','SELECT'),('Principals','UPDATE'),('Memberships','SELECT'),('Memberships','UPDATE')
), expected_table_acl AS (
 SELECT 'public'::text schema_name,e.table_name,e.privilege_type,i.owner_oid grantor,false is_grantable FROM expected_tables e CROSS JOIN identities i
), actual_table_acl AS (
 SELECT n.nspname::text schema_name,c.relname::text table_name,a.privilege_type,a.grantor,a.is_grantable
 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace CROSS JOIN identities i
 CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(c.relacl,pg_catalog.acldefault('r',c.relowner))) a
 WHERE c.relkind IN('r','p','v','m','f') AND a.grantee=i.plan_oid
), expected_function_acl(name,arguments) AS (VALUES
 ('has_environment_membership','2950 2950'),('directory_database_access','2950 2950')
), actual_function_acl AS (
 SELECT n.nspname::text schema_name,p.proname::text name,p.proargtypes::text arguments,a.grantor,a.is_grantable
 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace CROSS JOIN identities i
 CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) a
 WHERE a.grantee=i.plan_oid AND a.privilege_type='EXECUTE'
), actual_schema_acl AS (
 SELECT n.nspname::text schema_name,a.privilege_type,a.grantor,a.is_grantable
 FROM pg_catalog.pg_namespace n CROSS JOIN identities i
 CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(n.nspacl,pg_catalog.acldefault('n',n.nspowner))) a
 WHERE a.grantee=i.plan_oid
), application_relations AS (
 SELECT c.*,n.nspname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname NOT IN('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%' AND n.nspname NOT LIKE 'pg_temp_%'
), actual_effective_tables AS (
 SELECT c.nspname::text schema_name,c.relname::text table_name,privilege_type
 FROM application_relations c CROSS JOIN identities i
 CROSS JOIN (VALUES('SELECT'),('INSERT'),('UPDATE'),('DELETE'),('TRUNCATE'),('REFERENCES'),('TRIGGER'),('MAINTAIN')) privileges(privilege_type)
 WHERE CASE WHEN c.relkind IN('r','p','v','m','f') THEN pg_catalog.has_table_privilege(i.plan_oid,c.oid,privilege_type) ELSE false END
), actual_effective_columns AS (
 SELECT c.nspname::text schema_name,c.relname::text table_name,a.attname::text column_name,privilege_type
 FROM application_relations c JOIN pg_catalog.pg_attribute a ON a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped
 CROSS JOIN identities i CROSS JOIN (VALUES('SELECT'),('INSERT'),('UPDATE'),('REFERENCES')) privileges(privilege_type)
 WHERE CASE WHEN c.relkind IN('r','p','v','m','f') THEN pg_catalog.has_column_privilege(i.plan_oid,c.oid,a.attnum,privilege_type) ELSE false END
)
SELECT COALESCE((SELECT CURRENT_USER=SESSION_USER
 AND pg_catalog.current_setting('search_path') IN('pg_catalog,pg_temp','pg_catalog, pg_temp')
 AND (SELECT count(*)=6 AND bool_and(c.relkind='r' AND c.relpersistence='p' AND NOT c.relispartition AND c.relowner=i.owner_oid)
   FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
   WHERE n.nspname='public' AND c.relname IN(SELECT table_name FROM expected_tables))
 AND NOT EXISTS((SELECT * FROM expected_table_acl EXCEPT SELECT * FROM actual_table_acl)
   UNION ALL (SELECT * FROM actual_table_acl EXCEPT SELECT * FROM expected_table_acl))
 AND NOT EXISTS((SELECT 'public'::text,name,arguments,i.owner_oid,false FROM expected_function_acl EXCEPT SELECT * FROM actual_function_acl)
   UNION ALL (SELECT * FROM actual_function_acl EXCEPT SELECT 'public'::text,name,arguments,i.owner_oid,false FROM expected_function_acl))
 AND (SELECT count(*)=1 AND bool_and(schema_name='public' AND privilege_type='USAGE' AND grantor=(SELECT nspowner FROM pg_catalog.pg_namespace WHERE nspname='public') AND NOT is_grantable) FROM actual_schema_acl)
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_attribute a CROSS JOIN LATERAL pg_catalog.aclexplode(a.attacl) acl WHERE acl.grantee=i.plan_oid)
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_default_acl d WHERE d.defaclrole=i.plan_oid
   OR EXISTS(SELECT 1 FROM pg_catalog.aclexplode(d.defaclacl) a WHERE a.grantee=i.plan_oid OR (a.grantee=0 AND d.defaclobjtype IN('r','S','f'))))
 AND NOT pg_catalog.has_parameter_privilege(i.plan_oid,'session_replication_role','SET')
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_parameter_acl p CROSS JOIN LATERAL pg_catalog.aclexplode(p.paracl) a WHERE a.grantee IN(0,i.plan_oid))
 AND NOT EXISTS((SELECT 'public'::text,table_name,privilege_type FROM expected_tables EXCEPT SELECT * FROM actual_effective_tables)
   UNION ALL (SELECT * FROM actual_effective_tables EXCEPT SELECT 'public'::text,table_name,privilege_type FROM expected_tables))
 AND NOT EXISTS(SELECT 1 FROM actual_effective_columns a WHERE NOT EXISTS(SELECT 1 FROM expected_tables e
   WHERE a.schema_name='public' AND a.table_name=e.table_name AND a.privilege_type=e.privilege_type))
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c WHERE CASE WHEN c.relkind='S' THEN pg_catalog.has_sequence_privilege(i.plan_oid,c.oid,'USAGE,SELECT,UPDATE') ELSE false END)
 AND pg_catalog.has_schema_privilege(i.plan_oid,'public','USAGE')
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace n WHERE pg_catalog.has_schema_privilege(i.plan_oid,n.oid,'CREATE'))
 AND NOT pg_catalog.has_database_privilege(i.plan_oid,pg_catalog.current_database(),'CREATE')
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
   WHERE n.nspname NOT IN('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%' AND n.nspname NOT LIKE 'pg_temp_%'
     AND pg_catalog.has_function_privilege(i.plan_oid,p.oid,'EXECUTE')
     AND NOT(n.nspname='public' AND ((p.proname IN('has_environment_membership','directory_database_access') AND p.proargtypes::text='2950 2950')
       OR (p.proname='api_database_session' AND p.proargtypes::text=''))))
 FROM identities i),false) AS is_valid;
