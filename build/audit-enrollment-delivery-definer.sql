-- Staged catalog-only privilege slice. Function bodies, identity bindings, RLS and
-- data/trigger contracts must also pass the composed profile before activation.
WITH identity AS (
 SELECT definer.oid definer_oid,owner.oid owner_oid,definer.*
 FROM (SELECT :'delivery_definer_role'::text definer_name,:'expected_table_owner_role'::text owner_name) supplied
 LEFT JOIN pg_catalog.pg_roles definer ON definer.rolname=supplied.definer_name
 LEFT JOIN pg_catalog.pg_roles owner ON owner.rolname=supplied.owner_name
), function_names(signature,owned) AS (VALUES
 ('enrollment_execution.read_grant_status_receipt(uuid,uuid)',true),
 ('enrollment_execution.append_grant_status_observation(uuid,uuid,uuid,text,text,timestamptz,timestamptz,uuid,uuid,uuid,timestamptz,timestamptz,timestamptz,smallint,timestamptz,bytea,bytea)',true),
 ('enrollment_execution.read_grant_delivery(uuid,uuid,uuid,text)',true),
 ('enrollment_execution.acknowledge_grant_delivery(uuid,uuid,uuid,text,bytea,bytea)',true),
 ('enrollment_execution.audit_delivery_privileges(uuid)',false),
 ('enrollment_execution.delivery_worker_scope(uuid,text)',false),
 ('enrollment_execution.read_status_refresh_receipt(uuid,uuid)',false),
 ('enrollment_execution.record_status_observation(uuid,uuid,uuid,text,text,timestamptz,timestamptz,uuid,uuid,uuid,timestamptz,timestamptz,timestamptz,smallint,timestamptz,bytea,bytea)',false),
 ('enrollment_execution.lock_delivery_context(uuid,uuid,uuid,text)',false),
 ('enrollment_execution.get_sealed_delivery(uuid,uuid,uuid,text)',false),
 ('enrollment_execution.ack_sealed_delivery(uuid,uuid,uuid,text,bytea,bytea)',false),
 ('enrollment_execution.has_computer_permission(uuid,uuid,uuid,uuid,text)',false),
 ('enrollment_execution.scope_uuid(text)',false),
 ('public.has_environment_membership(uuid,uuid)',false),
 ('public.directory_database_access(uuid,uuid)',false)
), functions AS (
 SELECT pg_catalog.to_regprocedure(signature)::oid object_oid,owned,
   CASE WHEN owned THEN identity.definer_oid ELSE identity.owner_oid END grantor
 FROM function_names CROSS JOIN identity
), table_names(schema_name,table_name,privilege) AS (VALUES
 ('public','Roles','SELECT'),('public','RolePermissions','SELECT'),('public','Assignments','SELECT'),
 ('public','Scopes','SELECT'),('public','DeviceTagAssignments','SELECT'),
 ('enrollment_execution','issue_results','SELECT'),('enrollment_execution','mint_permits','SELECT'),
 ('enrollment_execution','execution_stops','SELECT'),
 ('enrollment_execution','sealed_envelopes','SELECT'),('enrollment_execution','sealed_envelopes','DELETE'),
 ('enrollment_execution','delivery_acks','SELECT'),('enrollment_execution','delivery_acks','INSERT'),
 ('enrollment_execution','status_observations','SELECT'),('enrollment_execution','status_observations','INSERT')
), tables AS (
 SELECT pg_catalog.to_regclass(pg_catalog.format('%I.%I',schema_name,table_name))::oid object_oid,privilege FROM table_names
), column_names(table_name,privilege,names) AS (VALUES
 ('Environments','SELECT',ARRAY['Id','Version']),('Environments','UPDATE',ARRAY['Name']),
 ('DirectorySync','SELECT',ARRAY['EnvironmentId','Status','Generation','CompletedAt']),('DirectorySync','UPDATE',ARRAY['ErrorCode']),
 ('DirectoryObjects','SELECT',ARRAY['EnvironmentId','Id','Generation','Kind','Department','ParentOuId','OuAncestry']),('DirectoryObjects','UPDATE',ARRAY['Name']),
 ('Principals','SELECT',ARRAY['Id','OperatorId','Enabled']),('Principals','UPDATE',ARRAY['DisplayName']),
 ('Memberships','SELECT',ARRAY['EnvironmentId','PrincipalId','Active']),('Memberships','UPDATE',ARRAY['Active']),
 ('Sessions','SELECT',ARRAY['IdHash','PrincipalId','CreatedAt','LastSeenAt','ExpiresAt','StepUpAt','RevokedAt']),
 ('EnrollmentGrantOperations','SELECT',ARRAY['EnvironmentId','Id','RequesterId','DirectoryObjectId','PlanHash','QueuedAt','AuthorizationNotAfter','RecipientKeyFingerprint','ServerDeviceId','MappingCreatedAt']),
 ('EnrollmentGrantOperations','UPDATE',ARRAY['PlanHash'])
), columns AS (
 SELECT pg_catalog.to_regclass(pg_catalog.format('public.%I',source.table_name))::oid object_oid,
   attribute.attnum::integer sub_id,source.privilege
 FROM column_names source CROSS JOIN LATERAL pg_catalog.unnest(source.names) column_name
 LEFT JOIN pg_catalog.pg_attribute attribute
   ON attribute.attrelid=pg_catalog.to_regclass(pg_catalog.format('public.%I',source.table_name))
   AND attribute.attname=column_name AND attribute.attnum>0 AND NOT attribute.attisdropped
), expected_acl(class_id,object_oid,sub_id,grantor,privilege,grantable) AS (
 SELECT 'pg_catalog.pg_proc'::regclass::oid,object_oid,0,grantor,'EXECUTE',false FROM functions
 UNION ALL SELECT 'pg_catalog.pg_class'::regclass::oid,object_oid,0,identity.owner_oid,privilege,false FROM tables CROSS JOIN identity
 UNION ALL SELECT 'pg_catalog.pg_class'::regclass::oid,object_oid,sub_id,identity.owner_oid,privilege,false FROM columns CROSS JOIN identity
 UNION ALL SELECT 'pg_catalog.pg_namespace'::regclass::oid,namespace.oid,0,identity.owner_oid,'USAGE',false
   FROM identity LEFT JOIN pg_catalog.pg_namespace namespace ON namespace.nspname='enrollment_execution'
), actual_acl AS (
 SELECT 'pg_catalog.pg_proc'::regclass::oid class_id,object.oid object_oid,0 sub_id,acl.grantor,acl.privilege_type privilege,acl.is_grantable grantable
 FROM pg_catalog.pg_proc object CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(object.proacl,pg_catalog.acldefault('f',object.proowner))) acl
 CROSS JOIN identity WHERE acl.grantee=identity.definer_oid
 UNION ALL SELECT 'pg_catalog.pg_class'::regclass::oid,object.oid,0,acl.grantor,acl.privilege_type,acl.is_grantable
 FROM pg_catalog.pg_class object CROSS JOIN LATERAL pg_catalog.aclexplode(object.relacl) acl CROSS JOIN identity WHERE acl.grantee=identity.definer_oid
 UNION ALL SELECT 'pg_catalog.pg_class'::regclass::oid,attribute.attrelid,attribute.attnum::integer,acl.grantor,acl.privilege_type,acl.is_grantable
 FROM pg_catalog.pg_attribute attribute CROSS JOIN LATERAL pg_catalog.aclexplode(attribute.attacl) acl CROSS JOIN identity WHERE acl.grantee=identity.definer_oid
 UNION ALL SELECT 'pg_catalog.pg_namespace'::regclass::oid,namespace.oid,0,acl.grantor,acl.privilege_type,acl.is_grantable
 FROM pg_catalog.pg_namespace namespace CROSS JOIN LATERAL pg_catalog.aclexplode(namespace.nspacl) acl CROSS JOIN identity WHERE acl.grantee=identity.definer_oid
), expected_dependencies AS (
 SELECT DISTINCT (SELECT oid FROM pg_catalog.pg_database WHERE datname=pg_catalog.current_database()) dbid,
   acl.class_id classid,acl.object_oid objid,acl.sub_id objsubid,'a'::"char" deptype FROM expected_acl acl
 WHERE NOT(acl.class_id='pg_catalog.pg_proc'::regclass AND acl.object_oid IN(SELECT object_oid FROM functions WHERE owned))
 UNION ALL SELECT (SELECT oid FROM pg_catalog.pg_database WHERE datname=pg_catalog.current_database()),
   'pg_catalog.pg_proc'::regclass::oid,object_oid,0,'o'::"char" FROM functions WHERE owned
), actual_dependencies AS (
 SELECT dependency.dbid,dependency.classid,dependency.objid,dependency.objsubid,dependency.deptype
 FROM pg_catalog.pg_shdepend dependency CROSS JOIN identity
 WHERE dependency.refclassid='pg_catalog.pg_authid'::regclass AND dependency.refobjid=identity.definer_oid AND dependency.deptype IN('a','o')
), relations AS (
 SELECT relation.* FROM pg_catalog.pg_class relation JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace
 WHERE namespace.nspname NOT IN('pg_catalog','information_schema') AND namespace.nspname NOT LIKE 'pg_toast%'
   AND namespace.nspname NOT LIKE 'pg_temp_%'
)
SELECT COALESCE((SELECT
 identity.definer_oid IS NOT NULL AND identity.owner_oid IS NOT NULL AND identity.definer_oid<>identity.owner_oid
 AND NOT(identity.rolcanlogin OR identity.rolsuper OR identity.rolbypassrls OR identity.rolcreatedb OR identity.rolcreaterole OR identity.rolinherit OR identity.rolreplication)
 AND (SELECT count(*)=1 AND bool_and(namespace.nspowner=identity.owner_oid) FROM pg_catalog.pg_namespace namespace WHERE namespace.nspname='enrollment_execution')
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace namespace CROSS JOIN LATERAL pg_catalog.aclexplode(namespace.nspacl) acl
   WHERE namespace.nspname='enrollment_execution' AND acl.grantee=0)
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members membership WHERE membership.member=identity.definer_oid OR membership.roleid=identity.definer_oid)
 AND (SELECT count(*)=15 AND bool_and(function.oid IS NOT NULL AND function.proowner=expected.grantor)
   FROM functions expected LEFT JOIN pg_catalog.pg_proc function ON function.oid=expected.object_oid)
 AND (SELECT count(*)=14 AND bool_and(object_oid IS NOT NULL) FROM tables)
 AND (SELECT count(*)=42 AND bool_and(object_oid IS NOT NULL AND sub_id IS NOT NULL) FROM columns)
 AND NOT EXISTS(SELECT 1 FROM ((SELECT * FROM expected_acl EXCEPT SELECT * FROM actual_acl)
   UNION ALL (SELECT * FROM actual_acl EXCEPT SELECT * FROM expected_acl)) differences)
 AND NOT EXISTS(SELECT 1 FROM ((SELECT * FROM expected_dependencies EXCEPT SELECT * FROM actual_dependencies)
   UNION ALL (SELECT * FROM actual_dependencies EXCEPT SELECT * FROM expected_dependencies)) differences)
 AND NOT pg_catalog.has_database_privilege(identity.definer_oid,pg_catalog.current_database(),'CREATE')
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace namespace
   WHERE namespace.nspname NOT IN('pg_catalog','information_schema') AND namespace.nspname !~ '^pg_(toast|temp_)'
     AND pg_catalog.has_schema_privilege(identity.definer_oid,namespace.oid,'CREATE'))
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace namespace
   WHERE namespace.nspname NOT IN('pg_catalog','information_schema','public','enrollment_execution') AND namespace.nspname !~ '^pg_(toast|temp_)'
     AND pg_catalog.has_schema_privilege(identity.definer_oid,namespace.oid,'USAGE'))
 AND NOT EXISTS(SELECT 1 FROM relations relation CROSS JOIN LATERAL pg_catalog.aclexplode(relation.relacl) acl WHERE acl.grantee=0)
 AND NOT EXISTS(SELECT 1 FROM relations relation JOIN pg_catalog.pg_attribute attribute ON attribute.attrelid=relation.oid
   CROSS JOIN LATERAL pg_catalog.aclexplode(attribute.attacl) acl WHERE acl.grantee=0)
 AND NOT EXISTS(SELECT 1 FROM relations relation CROSS JOIN (VALUES('SELECT'),('INSERT'),('UPDATE'),('DELETE'),('TRUNCATE'),('REFERENCES'),('TRIGGER'),('MAINTAIN')) privilege(name)
   WHERE relation.relkind IN('r','p','v','m','f') AND pg_catalog.has_table_privilege(identity.definer_oid,relation.oid,privilege.name)
     AND NOT EXISTS(SELECT 1 FROM tables expected WHERE expected.object_oid=relation.oid AND expected.privilege=privilege.name))
 AND NOT EXISTS(SELECT 1 FROM relations relation JOIN pg_catalog.pg_attribute attribute ON attribute.attrelid=relation.oid AND attribute.attnum>0 AND NOT attribute.attisdropped
   CROSS JOIN (VALUES('SELECT'),('INSERT'),('UPDATE'),('REFERENCES')) privilege(name)
   WHERE relation.relkind IN('r','p','v','m','f') AND pg_catalog.has_column_privilege(identity.definer_oid,relation.oid,attribute.attnum,privilege.name)
     AND NOT EXISTS(SELECT 1 FROM tables expected WHERE expected.object_oid=relation.oid AND expected.privilege=privilege.name)
     AND NOT EXISTS(SELECT 1 FROM columns expected WHERE expected.object_oid=relation.oid AND expected.sub_id=attribute.attnum AND expected.privilege=privilege.name))
 AND NOT EXISTS(SELECT 1 FROM relations relation WHERE CASE WHEN relation.relkind='S' THEN pg_catalog.has_sequence_privilege(identity.definer_oid,relation.oid,'SELECT,UPDATE,USAGE') ELSE false END)
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc function JOIN pg_catalog.pg_namespace namespace ON namespace.oid=function.pronamespace
   WHERE namespace.nspname NOT IN('pg_catalog','information_schema') AND namespace.nspname NOT LIKE 'pg_toast%' AND namespace.nspname NOT LIKE 'pg_temp_%'
     AND pg_catalog.has_function_privilege(identity.definer_oid,function.oid,'EXECUTE')
     AND function.oid IS DISTINCT FROM pg_catalog.to_regprocedure('public.api_database_session()')
     AND NOT EXISTS(SELECT 1 FROM functions expected WHERE expected.object_oid=function.oid))
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc function JOIN pg_catalog.pg_namespace namespace ON namespace.oid=function.pronamespace
   CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(function.proacl,pg_catalog.acldefault('f',function.proowner))) acl
   WHERE namespace.nspname NOT IN('pg_catalog','information_schema') AND namespace.nspname !~ '^pg_(toast|temp_)'
     AND acl.grantee=0 AND function.oid IS DISTINCT FROM pg_catalog.to_regprocedure('public.api_database_session()'))
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_default_acl defaults CROSS JOIN LATERAL pg_catalog.aclexplode(defaults.defaclacl) acl
   WHERE acl.grantee IN(0,identity.definer_oid))
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_largeobject_metadata object WHERE pg_catalog.has_largeobject_privilege(identity.definer_oid,object.oid,'SELECT,UPDATE'))
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_parameter_acl parameter CROSS JOIN LATERAL pg_catalog.aclexplode(parameter.paracl) acl
   WHERE acl.grantee IN(0,identity.definer_oid))
 FROM identity),false) AS is_valid;
