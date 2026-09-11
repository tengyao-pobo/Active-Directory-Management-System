\set ON_ERROR_STOP on
BEGIN;

SELECT 1/pg_catalog.count(*) AS capability_isolation_v2_required FROM (SELECT 1 WHERE COALESCE((SELECT
 marker.proowner=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=:'agent_table_owner_role') AND
 marker.proowner=namespace.nspowner AND marker.prolang=(SELECT oid FROM pg_catalog.pg_language WHERE lanname='sql') AND NOT marker.prosecdef AND marker.prokind='f' AND NOT marker.proretset AND
 marker.prorettype='smallint'::pg_catalog.regtype AND marker.pronargs=0 AND marker.proargnames IS NULL AND
 marker.proconfig=ARRAY['search_path=pg_catalog, agent_private, pg_temp']::text[] AND
 pg_catalog.btrim(marker.prosrc)=pg_catalog.btrim('SELECT 2::smallint') AND
 NOT EXISTS(SELECT 1 FROM pg_catalog.aclexplode(COALESCE(marker.proacl,pg_catalog.acldefault('f',marker.proowner))) acl
  WHERE acl.privilege_type<>'EXECUTE' OR acl.grantee<>marker.proowner OR acl.is_grantable)
 FROM pg_catalog.pg_proc marker JOIN pg_catalog.pg_namespace namespace ON namespace.oid=marker.pronamespace
 WHERE marker.oid=pg_catalog.to_regprocedure('agent_private.agent_capability_isolation_profile()')),false)) checked;
SELECT 1/pg_catalog.count(*) AS roles_are_safe_and_unreserved FROM (SELECT 1 WHERE
 :'agent_table_owner_role'<>:'agent_enrollment_target_definer_role' AND
 (SELECT pg_catalog.count(*)=1 FROM pg_catalog.pg_roles role WHERE role.rolname=:'agent_table_owner_role' AND NOT role.rolcanlogin AND NOT role.rolsuper AND NOT role.rolbypassrls AND NOT role.rolcreatedb AND NOT role.rolcreaterole AND NOT role.rolinherit AND NOT role.rolreplication) AND
 (SELECT pg_catalog.count(*)=1 FROM pg_catalog.pg_roles role WHERE role.rolname=:'agent_enrollment_target_definer_role' AND NOT role.rolcanlogin AND NOT role.rolsuper AND NOT role.rolbypassrls AND NOT role.rolcreatedb AND NOT role.rolcreaterole AND NOT role.rolinherit AND NOT role.rolreplication) AND
 NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members member JOIN pg_catalog.pg_roles role ON member.member=role.oid OR member.roleid=role.oid WHERE role.rolname IN(:'agent_table_owner_role',:'agent_enrollment_target_definer_role')) AND
 (SELECT pg_catalog.count(*)=1 FROM pg_catalog.pg_namespace namespace JOIN pg_catalog.pg_roles role ON role.oid=namespace.nspowner WHERE namespace.nspname='agent_private' AND role.rolname=:'agent_table_owner_role') AND
 NOT EXISTS(SELECT 1 FROM pg_catalog.pg_database database JOIN pg_catalog.pg_roles role ON role.oid=database.datdba WHERE role.rolname IN(:'agent_table_owner_role',:'agent_enrollment_target_definer_role')) AND
 NOT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace namespace JOIN pg_catalog.pg_roles role ON role.oid=namespace.nspowner WHERE role.rolname=:'agent_enrollment_target_definer_role') AND
 NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object JOIN pg_catalog.pg_roles role ON role.oid=object.relowner WHERE role.rolname=:'agent_enrollment_target_definer_role') AND
 NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc function JOIN pg_catalog.pg_roles role ON role.oid=function.proowner WHERE role.rolname=:'agent_enrollment_target_definer_role') AND
 NOT EXISTS(SELECT 1 FROM agent_private.agent_capability_roles WHERE role_name=:'agent_enrollment_target_definer_role'::name) AND
 NOT pg_catalog.has_schema_privilege(:'agent_enrollment_target_definer_role','agent_private','CREATE') AND
 NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object JOIN pg_catalog.pg_namespace namespace ON namespace.oid=object.relnamespace WHERE namespace.nspname='agent_private' AND object.relkind IN('r','p','v','m') AND (pg_catalog.has_table_privilege(:'agent_enrollment_target_definer_role',object.oid,'SELECT') OR pg_catalog.has_table_privilege(:'agent_enrollment_target_definer_role',object.oid,'INSERT') OR pg_catalog.has_table_privilege(:'agent_enrollment_target_definer_role',object.oid,'UPDATE') OR pg_catalog.has_table_privilege(:'agent_enrollment_target_definer_role',object.oid,'DELETE') OR pg_catalog.has_table_privilege(:'agent_enrollment_target_definer_role',object.oid,'TRUNCATE') OR pg_catalog.has_table_privilege(:'agent_enrollment_target_definer_role',object.oid,'REFERENCES') OR pg_catalog.has_table_privilege(:'agent_enrollment_target_definer_role',object.oid,'TRIGGER'))) AND
 NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object JOIN pg_catalog.pg_attribute attribute ON attribute.attrelid=object.oid JOIN pg_catalog.pg_namespace namespace ON namespace.oid=object.relnamespace,LATERAL pg_catalog.aclexplode(attribute.attacl) acl JOIN pg_catalog.pg_roles role ON role.oid=acl.grantee WHERE namespace.nspname='agent_private' AND role.rolname=:'agent_enrollment_target_definer_role')) checked;

INSERT INTO agent_private.agent_capability_roles(role_name,capability,role_kind)
VALUES(:'agent_enrollment_target_definer_role'::name,'EnrollmentTargetRead','Definer');
GRANT EXECUTE ON FUNCTION agent_private.agent_role_has_capability(name,text,text) TO :"agent_enrollment_target_definer_role";

CREATE TABLE agent_private.enrollment_target_read_database_bindings(
 login_role name PRIMARY KEY,
 environment_id uuid NOT NULL,
 purpose text NOT NULL CHECK(purpose='ResolveEnrollmentTarget'),
 UNIQUE(environment_id,purpose)
);
ALTER TABLE agent_private.enrollment_target_read_database_bindings OWNER TO :"agent_table_owner_role";
ALTER TABLE agent_private.enrollment_target_read_database_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_private.enrollment_target_read_database_bindings FORCE ROW LEVEL SECURITY;
CREATE POLICY definer_all ON agent_private.enrollment_target_read_database_bindings TO :"agent_table_owner_role" USING(true) WITH CHECK(true);
CREATE POLICY enrollment_target_definer_select ON agent_private.enrollment_target_read_database_bindings FOR SELECT TO :"agent_enrollment_target_definer_role" USING(true);
CREATE POLICY enrollment_target_definer_select ON agent_private.agent_device_directory_bindings FOR SELECT TO :"agent_enrollment_target_definer_role" USING(true);
CREATE POLICY enrollment_target_definer_select ON agent_private.devices FOR SELECT TO :"agent_enrollment_target_definer_role" USING(true);
GRANT USAGE ON SCHEMA agent_private TO :"agent_enrollment_target_definer_role";
GRANT SELECT(login_role,environment_id,purpose) ON agent_private.enrollment_target_read_database_bindings TO :"agent_enrollment_target_definer_role";
GRANT SELECT(environment_id,directory_object_id,device_id,created_at) ON agent_private.agent_device_directory_bindings TO :"agent_enrollment_target_definer_role";
GRANT SELECT(environment_id,device_id,state) ON agent_private.devices TO :"agent_enrollment_target_definer_role";

CREATE FUNCTION agent_private.resolve_enrollment_target(p_expected_environment_id uuid,p_directory_object_id uuid)
RETURNS TABLE(outcome text,diagnostic_code text,environment_id uuid,directory_object_id uuid,device_id uuid,mapping_created_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,agent_private,pg_temp AS $function$
#variable_conflict use_variable
DECLARE v_environment_id uuid;v_mapping record;
BEGIN
 SELECT binding.environment_id INTO v_environment_id FROM agent_private.enrollment_target_read_database_bindings binding
 WHERE binding.login_role=SESSION_USER::name AND binding.purpose='ResolveEnrollmentTarget';
 IF NOT FOUND OR v_environment_id IS DISTINCT FROM p_expected_environment_id THEN
  RETURN QUERY SELECT 'Unauthorized','PrivilegeAuditFailed',NULL::uuid,NULL::uuid,NULL::uuid,NULL::timestamptz;RETURN;
 END IF;
 IF p_directory_object_id IS NULL OR p_directory_object_id='00000000-0000-0000-0000-000000000000'::uuid THEN
  RETURN QUERY SELECT 'InvalidRequest','InvalidDirectoryObject',NULL::uuid,NULL::uuid,NULL::uuid,NULL::timestamptz;RETURN;
 END IF;
 SELECT mapping.device_id,mapping.created_at,device.state INTO v_mapping
 FROM agent_private.agent_device_directory_bindings mapping
 LEFT JOIN agent_private.devices device ON device.environment_id=mapping.environment_id AND device.device_id=mapping.device_id
 WHERE mapping.environment_id=v_environment_id AND mapping.directory_object_id=p_directory_object_id;
 IF NOT FOUND THEN RETURN QUERY SELECT 'MappingRequired','MappingMissing',v_environment_id,p_directory_object_id,NULL::uuid,NULL::timestamptz;RETURN;END IF;
 IF v_mapping.state IS DISTINCT FROM 'Active' THEN RETURN QUERY SELECT 'MappingRequired','DeviceInactive',v_environment_id,p_directory_object_id,NULL::uuid,NULL::timestamptz;RETURN;END IF;
 RETURN QUERY SELECT 'Resolved','None',v_environment_id,p_directory_object_id,v_mapping.device_id,v_mapping.created_at;
END;$function$;
ALTER FUNCTION agent_private.resolve_enrollment_target(uuid,uuid) OWNER TO :"agent_enrollment_target_definer_role";
REVOKE ALL ON FUNCTION agent_private.resolve_enrollment_target(uuid,uuid) FROM PUBLIC;

-- The audit is created below after both public function signatures exist.
CREATE FUNCTION agent_private.audit_enrollment_target_read_privileges(p_expected_environment_id uuid,p_expected_table_owner name,p_expected_function_owner name)
RETURNS TABLE(is_valid boolean,diagnostic_code text,profile_version smallint)
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,agent_private,pg_temp AS $function$
WITH login AS(SELECT role.* FROM pg_catalog.pg_roles role WHERE role.rolname=SESSION_USER),
 function_owner AS(SELECT role.* FROM pg_catalog.pg_roles role WHERE role.rolname=p_expected_function_owner),
 table_owner AS(SELECT role.* FROM pg_catalog.pg_roles role WHERE role.rolname=p_expected_table_owner),
 schema_info AS(SELECT namespace.oid,namespace.nspowner FROM pg_catalog.pg_namespace namespace WHERE namespace.nspname='agent_private'),
 eligible_logins AS(SELECT role.* FROM agent_private.enrollment_target_read_database_bindings binding JOIN pg_catalog.pg_roles role ON role.rolname=binding.login_role WHERE binding.purpose='ResolveEnrollmentTarget'),
 expected_execute(signature) AS(VALUES('agent_private.resolve_enrollment_target(uuid,uuid)'::pg_catalog.regprocedure),('agent_private.audit_enrollment_target_read_privileges(uuid,name,name)'::pg_catalog.regprocedure)),
 expected_function_acl(signature,grantee,is_grantable) AS(SELECT expected.signature,function_owner.oid,false FROM expected_execute expected,function_owner UNION ALL SELECT expected.signature,eligible.oid,false FROM expected_execute expected,eligible_logins eligible),
 actual_function_acl AS(SELECT function.oid::pg_catalog.regprocedure,acl.grantee,acl.is_grantable FROM pg_catalog.pg_proc function,schema_info,LATERAL pg_catalog.aclexplode(COALESCE(function.proacl,pg_catalog.acldefault('f',function.proowner))) acl WHERE function.pronamespace=schema_info.oid AND function.oid=ANY(ARRAY['agent_private.resolve_enrollment_target(uuid,uuid)'::pg_catalog.regprocedure,'agent_private.audit_enrollment_target_read_privileges(uuid,name,name)'::pg_catalog.regprocedure]::oid[]) AND acl.privilege_type='EXECUTE'),
 expected_columns(relname,attname,privilege_type,is_grantable) AS(VALUES
  ('enrollment_target_read_database_bindings','login_role','SELECT',false),('enrollment_target_read_database_bindings','environment_id','SELECT',false),('enrollment_target_read_database_bindings','purpose','SELECT',false),
  ('agent_device_directory_bindings','environment_id','SELECT',false),('agent_device_directory_bindings','directory_object_id','SELECT',false),('agent_device_directory_bindings','device_id','SELECT',false),('agent_device_directory_bindings','created_at','SELECT',false),
  ('devices','environment_id','SELECT',false),('devices','device_id','SELECT',false),('devices','state','SELECT',false)),
 actual_columns AS(SELECT object.relname,attribute.attname,acl.privilege_type,acl.is_grantable FROM pg_catalog.pg_class object JOIN pg_catalog.pg_attribute attribute ON attribute.attrelid=object.oid,schema_info,function_owner,LATERAL pg_catalog.aclexplode(attribute.attacl) acl WHERE object.relnamespace=schema_info.oid AND acl.grantee=function_owner.oid),
 expected_binding_columns(attnum,attname,atttypid,attnotnull) AS(VALUES(1::smallint,'login_role','name'::pg_catalog.regtype::oid,true),(2::smallint,'environment_id','uuid'::pg_catalog.regtype::oid,true),(3::smallint,'purpose','text'::pg_catalog.regtype::oid,true)),
 actual_binding_columns AS(SELECT attribute.attnum,attribute.attname,attribute.atttypid,attribute.attnotnull FROM pg_catalog.pg_attribute attribute WHERE attribute.attrelid='agent_private.enrollment_target_read_database_bindings'::pg_catalog.regclass AND attribute.attnum>0 AND NOT attribute.attisdropped),
 expected_policies(relname) AS(VALUES('enrollment_target_read_database_bindings'),('agent_device_directory_bindings'),('devices')),
 checks AS(SELECT
  (SELECT count(*)=1 FROM login) AND (SELECT count(*)=1 FROM function_owner) AND (SELECT count(*)=1 FROM table_owner) AND
  agent_private.agent_role_has_capability(SESSION_USER::name,'EnrollmentTargetRead','Runtime') AND
  agent_private.agent_role_has_capability(p_expected_function_owner,'EnrollmentTargetRead','Definer') AND
  COALESCE((SELECT marker.proowner=table_owner.oid AND marker.proowner=schema_info.nspowner AND NOT marker.prosecdef AND marker.prolang=(SELECT oid FROM pg_catalog.pg_language WHERE lanname='sql') AND marker.prokind='f' AND NOT marker.proretset AND marker.prorettype='smallint'::pg_catalog.regtype AND marker.pronargs=0 AND marker.proargnames IS NULL AND marker.proconfig=ARRAY['search_path=pg_catalog, agent_private, pg_temp']::text[] AND pg_catalog.btrim(marker.prosrc,E' \t\r\n')='SELECT 2::smallint' AND NOT EXISTS(SELECT 1 FROM pg_catalog.aclexplode(COALESCE(marker.proacl,pg_catalog.acldefault('f',marker.proowner))) acl WHERE acl.privilege_type<>'EXECUTE' OR acl.grantee<>marker.proowner OR acl.is_grantable) FROM pg_catalog.pg_proc marker,table_owner,schema_info WHERE marker.oid=pg_catalog.to_regprocedure('agent_private.agent_capability_isolation_profile()')),false) AND
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
  (SELECT count(*)=1 FROM agent_private.enrollment_target_read_database_bindings binding WHERE binding.login_role=SESSION_USER::name AND binding.environment_id=p_expected_environment_id AND binding.purpose='ResolveEnrollmentTarget') AND
  (SELECT count(*) FROM eligible_logins)=(SELECT count(*) FROM agent_private.enrollment_target_read_database_bindings WHERE purpose='ResolveEnrollmentTarget') AND
  NOT EXISTS(SELECT 1 FROM eligible_logins eligible WHERE NOT eligible.rolcanlogin OR eligible.rolsuper OR eligible.rolbypassrls OR eligible.rolcreatedb OR eligible.rolcreaterole OR eligible.rolinherit OR eligible.rolreplication OR NOT agent_private.agent_role_has_capability(eligible.rolname::name,'EnrollmentTargetRead','Runtime')) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members member,eligible_logins eligible WHERE member.member=eligible.oid OR member.roleid=eligible.oid) AND
  NOT EXISTS(SELECT 1 FROM eligible_logins eligible WHERE EXISTS(SELECT 1 FROM pg_catalog.pg_database database WHERE database.datdba=eligible.oid) OR EXISTS(SELECT 1 FROM pg_catalog.pg_namespace namespace WHERE namespace.nspowner=eligible.oid) OR EXISTS(SELECT 1 FROM pg_catalog.pg_class object WHERE object.relowner=eligible.oid) OR EXISTS(SELECT 1 FROM pg_catalog.pg_proc function WHERE function.proowner=eligible.oid)) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object,schema_info,eligible_logins eligible WHERE object.relnamespace=schema_info.oid AND object.relkind IN('r','p','v','m') AND (pg_catalog.has_table_privilege(eligible.rolname,object.oid,'SELECT') OR pg_catalog.has_table_privilege(eligible.rolname,object.oid,'INSERT') OR pg_catalog.has_table_privilege(eligible.rolname,object.oid,'UPDATE') OR pg_catalog.has_table_privilege(eligible.rolname,object.oid,'DELETE') OR pg_catalog.has_table_privilege(eligible.rolname,object.oid,'TRUNCATE') OR pg_catalog.has_table_privilege(eligible.rolname,object.oid,'REFERENCES') OR pg_catalog.has_table_privilege(eligible.rolname,object.oid,'TRIGGER'))) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object,schema_info,eligible_logins eligible WHERE object.relnamespace=schema_info.oid AND object.relkind='S' AND (pg_catalog.has_sequence_privilege(eligible.rolname,object.oid,'USAGE') OR pg_catalog.has_sequence_privilege(eligible.rolname,object.oid,'SELECT') OR pg_catalog.has_sequence_privilege(eligible.rolname,object.oid,'UPDATE'))) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object JOIN pg_catalog.pg_attribute attribute ON attribute.attrelid=object.oid,schema_info,eligible_logins eligible,LATERAL pg_catalog.aclexplode(attribute.attacl) acl WHERE object.relnamespace=schema_info.oid AND acl.grantee=eligible.oid) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc function,schema_info,eligible_logins eligible WHERE function.pronamespace=schema_info.oid AND pg_catalog.has_function_privilege(eligible.rolname,function.oid,'EXECUTE') AND function.oid<>ALL(ARRAY['agent_private.resolve_enrollment_target(uuid,uuid)'::pg_catalog.regprocedure,'agent_private.audit_enrollment_target_read_privileges(uuid,name,name)'::pg_catalog.regprocedure]::oid[])) AND
  NOT EXISTS(SELECT 1 FROM login WHERE NOT rolcanlogin OR rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole OR rolinherit OR rolreplication) AND
  NOT EXISTS(SELECT 1 FROM function_owner WHERE rolcanlogin OR rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole OR rolinherit OR rolreplication) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members member,login WHERE member.member=login.oid OR member.roleid=login.oid) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members member,function_owner WHERE member.member=function_owner.oid OR member.roleid=function_owner.oid) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_database database,function_owner WHERE database.datdba=function_owner.oid) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace namespace,function_owner WHERE namespace.nspowner=function_owner.oid) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object,function_owner WHERE object.relowner=function_owner.oid) AND
  NOT pg_catalog.has_schema_privilege(SESSION_USER,'agent_private','CREATE') AND NOT pg_catalog.has_schema_privilege(p_expected_function_owner,'agent_private','CREATE') AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object,schema_info WHERE object.relnamespace=schema_info.oid AND object.relkind IN('r','p','v','m') AND (pg_catalog.has_table_privilege(SESSION_USER,object.oid,'SELECT') OR pg_catalog.has_table_privilege(SESSION_USER,object.oid,'INSERT') OR pg_catalog.has_table_privilege(SESSION_USER,object.oid,'UPDATE') OR pg_catalog.has_table_privilege(SESSION_USER,object.oid,'DELETE') OR pg_catalog.has_table_privilege(SESSION_USER,object.oid,'TRUNCATE') OR pg_catalog.has_table_privilege(SESSION_USER,object.oid,'REFERENCES') OR pg_catalog.has_table_privilege(SESSION_USER,object.oid,'TRIGGER'))) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object,schema_info,function_owner WHERE object.relnamespace=schema_info.oid AND object.relkind IN('r','p','v','m') AND (pg_catalog.has_table_privilege(function_owner.rolname,object.oid,'SELECT') OR pg_catalog.has_table_privilege(function_owner.rolname,object.oid,'INSERT') OR pg_catalog.has_table_privilege(function_owner.rolname,object.oid,'UPDATE') OR pg_catalog.has_table_privilege(function_owner.rolname,object.oid,'DELETE') OR pg_catalog.has_table_privilege(function_owner.rolname,object.oid,'TRUNCATE') OR pg_catalog.has_table_privilege(function_owner.rolname,object.oid,'REFERENCES') OR pg_catalog.has_table_privilege(function_owner.rolname,object.oid,'TRIGGER'))) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object,schema_info,function_owner WHERE object.relnamespace=schema_info.oid AND object.relkind='S' AND (pg_catalog.has_sequence_privilege(function_owner.rolname,object.oid,'USAGE') OR pg_catalog.has_sequence_privilege(function_owner.rolname,object.oid,'SELECT') OR pg_catalog.has_sequence_privilege(function_owner.rolname,object.oid,'UPDATE'))) AND
  NOT EXISTS((SELECT * FROM expected_columns EXCEPT SELECT * FROM actual_columns) UNION ALL(SELECT * FROM actual_columns EXCEPT SELECT * FROM expected_columns)) AND
  NOT EXISTS((SELECT * FROM expected_binding_columns EXCEPT SELECT * FROM actual_binding_columns) UNION ALL(SELECT * FROM actual_binding_columns EXCEPT SELECT * FROM expected_binding_columns)) AND
  (SELECT count(*)=1 AND bool_and(constraint_info.conkey=ARRAY[1]::smallint[]) FROM pg_catalog.pg_constraint constraint_info WHERE constraint_info.conrelid='agent_private.enrollment_target_read_database_bindings'::pg_catalog.regclass AND constraint_info.contype='p') AND
  (SELECT count(*)=1 AND bool_and(constraint_info.conkey=ARRAY[2,3]::smallint[]) FROM pg_catalog.pg_constraint constraint_info WHERE constraint_info.conrelid='agent_private.enrollment_target_read_database_bindings'::pg_catalog.regclass AND constraint_info.contype='u') AND
  (SELECT count(*)=1 AND bool_and(pg_catalog.pg_get_expr(constraint_info.conbin,constraint_info.conrelid)='(purpose = ''ResolveEnrollmentTarget''::text)') FROM pg_catalog.pg_constraint constraint_info WHERE constraint_info.conrelid='agent_private.enrollment_target_read_database_bindings'::pg_catalog.regclass AND constraint_info.contype='c') AND
  NOT EXISTS((SELECT * FROM expected_function_acl EXCEPT SELECT * FROM actual_function_acl) UNION ALL(SELECT * FROM actual_function_acl EXCEPT SELECT * FROM expected_function_acl)) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc function,schema_info WHERE function.pronamespace=schema_info.oid AND pg_catalog.has_function_privilege(SESSION_USER,function.oid,'EXECUTE') AND function.oid<>ALL(ARRAY['agent_private.resolve_enrollment_target(uuid,uuid)'::pg_catalog.regprocedure,'agent_private.audit_enrollment_target_read_privileges(uuid,name,name)'::pg_catalog.regprocedure]::oid[])) AND
  (SELECT count(*)=2 AND bool_and(function.proowner=function_owner.oid AND function.prosecdef AND function.proconfig=ARRAY['search_path=pg_catalog, agent_private, pg_temp'] AND pg_catalog.pg_get_function_identity_arguments(function.oid)=CASE function.proname WHEN 'resolve_enrollment_target' THEN 'p_expected_environment_id uuid, p_directory_object_id uuid' ELSE 'p_expected_environment_id uuid, p_expected_table_owner name, p_expected_function_owner name' END AND pg_catalog.pg_get_function_result(function.oid)=CASE function.proname WHEN 'resolve_enrollment_target' THEN 'TABLE(outcome text, diagnostic_code text, environment_id uuid, directory_object_id uuid, device_id uuid, mapping_created_at timestamp with time zone)' ELSE 'TABLE(is_valid boolean, diagnostic_code text, profile_version smallint)' END) FROM pg_catalog.pg_proc function,schema_info,function_owner WHERE function.pronamespace=schema_info.oid AND function.proowner=function_owner.oid) AND
  (SELECT count(*)=1 FROM pg_catalog.pg_class object,schema_info,table_owner WHERE object.relnamespace=schema_info.oid AND object.relname='enrollment_target_read_database_bindings' AND object.relowner=table_owner.oid AND object.relrowsecurity AND object.relforcerowsecurity) AND
  (SELECT count(*)=2 FROM pg_catalog.pg_policy policy JOIN pg_catalog.pg_class object ON object.oid=policy.polrelid,schema_info WHERE object.relnamespace=schema_info.oid AND object.relname='enrollment_target_read_database_bindings') AND
  (SELECT count(*)=1 FROM pg_catalog.pg_policy policy,table_owner WHERE policy.polrelid='agent_private.enrollment_target_read_database_bindings'::pg_catalog.regclass AND policy.polname='definer_all' AND policy.polcmd='*' AND policy.polpermissive AND policy.polroles=ARRAY[table_owner.oid]::oid[] AND pg_catalog.pg_get_expr(policy.polqual,policy.polrelid)='true' AND pg_catalog.pg_get_expr(policy.polwithcheck,policy.polrelid)='true') AND
  NOT EXISTS(SELECT 1 FROM expected_policies expected,function_owner WHERE NOT EXISTS(SELECT 1 FROM pg_catalog.pg_policy policy JOIN pg_catalog.pg_class object ON object.oid=policy.polrelid JOIN pg_catalog.pg_namespace namespace ON namespace.oid=object.relnamespace WHERE namespace.nspname='agent_private' AND object.relname=expected.relname AND policy.polname='enrollment_target_definer_select' AND policy.polcmd='r' AND policy.polpermissive AND policy.polroles=ARRAY[function_owner.oid]::oid[] AND pg_catalog.pg_get_expr(policy.polqual,policy.polrelid)='true' AND policy.polwithcheck IS NULL)) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_policy policy JOIN pg_catalog.pg_class object ON object.oid=policy.polrelid JOIN pg_catalog.pg_namespace namespace ON namespace.oid=object.relnamespace,function_owner WHERE namespace.nspname='agent_private' AND function_owner.oid=ANY(policy.polroles) AND policy.polname='enrollment_target_definer_select' AND object.relname NOT IN(SELECT relname FROM expected_policies)) AND
  (SELECT count(*)=3 AND bool_and(object.relrowsecurity AND object.relforcerowsecurity AND object.relowner=table_owner.oid) FROM pg_catalog.pg_class object,schema_info,table_owner WHERE object.relnamespace=schema_info.oid AND object.relname IN('enrollment_target_read_database_bindings','agent_device_directory_bindings','devices')) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object,schema_info,table_owner,LATERAL pg_catalog.aclexplode(object.relacl) acl WHERE object.relnamespace=schema_info.oid AND object.relname='enrollment_target_read_database_bindings' AND acl.grantee<>table_owner.oid) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object JOIN pg_catalog.pg_attribute attribute ON attribute.attrelid=object.oid,schema_info,function_owner,LATERAL pg_catalog.aclexplode(attribute.attacl) acl WHERE object.relnamespace=schema_info.oid AND object.relname='enrollment_target_read_database_bindings' AND acl.grantee<>function_owner.oid) AND
  NOT EXISTS(SELECT 1 FROM table_owner WHERE rolcanlogin OR rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole OR rolinherit OR rolreplication) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members member,table_owner WHERE member.member=table_owner.oid OR member.roleid=table_owner.oid) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_database database,table_owner WHERE database.datdba=table_owner.oid) AND
  (SELECT count(*)=1 FROM schema_info,table_owner WHERE schema_info.nspowner=table_owner.oid) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object JOIN pg_catalog.pg_attribute attribute ON attribute.attrelid=object.oid,schema_info,login,LATERAL pg_catalog.aclexplode(attribute.attacl) acl WHERE object.relnamespace=schema_info.oid AND acl.grantee IN(0,login.oid))
  AS valid)
SELECT valid,'None'::text,1::smallint FROM checks WHERE valid UNION ALL SELECT false,'PrivilegeAuditFailed',1::smallint FROM checks WHERE NOT valid;
$function$;
ALTER FUNCTION agent_private.audit_enrollment_target_read_privileges(uuid,name,name) OWNER TO :"agent_enrollment_target_definer_role";
REVOKE ALL ON FUNCTION agent_private.audit_enrollment_target_read_privileges(uuid,name,name) FROM PUBLIC;

COMMIT;
