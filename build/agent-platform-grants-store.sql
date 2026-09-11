\set ON_ERROR_STOP on
BEGIN;

SELECT 1/pg_catalog.count(*) AS owners_are_distinct FROM (SELECT 1 WHERE :'agent_table_owner_role'<>:'agent_platform_grant_definer_role') checked;
SELECT 1/pg_catalog.count(*) AS isolation_profile_is_exact FROM (SELECT 1 WHERE COALESCE((SELECT
 profile.proowner=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=:'agent_table_owner_role') AND
 profile.proowner=namespace.nspowner AND profile.prolang=(SELECT oid FROM pg_catalog.pg_language WHERE lanname='sql') AND NOT profile.prosecdef AND profile.prokind='f' AND NOT profile.proretset AND
 profile.prorettype='smallint'::pg_catalog.regtype AND profile.pronargs=0 AND profile.proargnames IS NULL AND
 profile.proconfig=ARRAY['search_path=pg_catalog, agent_private, pg_temp']::text[] AND
 pg_catalog.btrim(profile.prosrc)=pg_catalog.btrim('SELECT 1::smallint') AND
 NOT EXISTS(SELECT 1 FROM pg_catalog.aclexplode(COALESCE(profile.proacl,pg_catalog.acldefault('f',profile.proowner))) acl
  WHERE acl.privilege_type<>'EXECUTE' OR acl.grantee<>profile.proowner OR acl.is_grantable)
 FROM pg_catalog.pg_proc profile JOIN pg_catalog.pg_namespace namespace ON namespace.oid=profile.pronamespace
 WHERE profile.oid=pg_catalog.to_regprocedure('agent_private.platform_grant_isolation_profile()')),false)) checked;
SELECT 1/pg_catalog.count(*) AS prerequisites_are_safe FROM (SELECT 1 WHERE
 (SELECT pg_catalog.count(*)=1 FROM pg_catalog.pg_roles role WHERE role.rolname=:'agent_table_owner_role' AND NOT role.rolcanlogin AND NOT role.rolsuper AND NOT role.rolbypassrls AND NOT role.rolcreatedb AND NOT role.rolcreaterole AND NOT role.rolinherit AND NOT role.rolreplication) AND
 NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members member JOIN pg_catalog.pg_roles role ON member.member=role.oid OR member.roleid=role.oid WHERE role.rolname=:'agent_table_owner_role') AND
 (SELECT pg_catalog.count(*)=1 FROM pg_catalog.pg_namespace namespace JOIN pg_catalog.pg_roles role ON role.oid=namespace.nspowner WHERE namespace.nspname='agent_private' AND role.rolname=:'agent_table_owner_role') AND
 (SELECT pg_catalog.count(*)=6 AND pg_catalog.bool_and(owner.rolname=:'agent_table_owner_role') FROM pg_catalog.pg_class object JOIN pg_catalog.pg_namespace namespace ON namespace.oid=object.relnamespace JOIN pg_catalog.pg_roles owner ON owner.oid=object.relowner WHERE namespace.nspname='agent_private' AND object.relkind='r' AND object.relname=ANY(ARRAY['devices','registrations','enrollment_grants','enrollment_requests','agent_device_directory_bindings','agent_projection_database_bindings'])) AND
 (SELECT pg_catalog.count(*)=1 FROM pg_catalog.pg_roles role WHERE role.rolname=:'agent_platform_grant_definer_role' AND NOT role.rolcanlogin AND NOT role.rolsuper AND NOT role.rolbypassrls AND NOT role.rolcreatedb AND NOT role.rolcreaterole AND NOT role.rolinherit AND NOT role.rolreplication) AND
 NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members member JOIN pg_catalog.pg_roles role ON member.member=role.oid OR member.roleid=role.oid WHERE role.rolname=:'agent_platform_grant_definer_role') AND
 NOT EXISTS(SELECT 1 FROM pg_catalog.pg_database database JOIN pg_catalog.pg_roles role ON role.oid=database.datdba WHERE role.rolname IN(:'agent_table_owner_role',:'agent_platform_grant_definer_role')) AND
 NOT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace namespace JOIN pg_catalog.pg_roles role ON role.oid=namespace.nspowner WHERE role.rolname=:'agent_platform_grant_definer_role') AND
 NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object JOIN pg_catalog.pg_roles role ON role.oid=object.relowner WHERE role.rolname=:'agent_platform_grant_definer_role') AND
 NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc function JOIN pg_catalog.pg_roles role ON role.oid=function.proowner WHERE role.rolname=:'agent_platform_grant_definer_role') AND
 NOT pg_catalog.has_schema_privilege(:'agent_platform_grant_definer_role','agent_private','CREATE') AND
 NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object JOIN pg_catalog.pg_namespace namespace ON namespace.oid=object.relnamespace WHERE namespace.nspname='agent_private' AND object.relkind IN('r','p','v','m') AND (pg_catalog.has_table_privilege(:'agent_platform_grant_definer_role',object.oid,'SELECT') OR pg_catalog.has_table_privilege(:'agent_platform_grant_definer_role',object.oid,'INSERT') OR pg_catalog.has_table_privilege(:'agent_platform_grant_definer_role',object.oid,'UPDATE') OR pg_catalog.has_table_privilege(:'agent_platform_grant_definer_role',object.oid,'DELETE') OR pg_catalog.has_table_privilege(:'agent_platform_grant_definer_role',object.oid,'TRUNCATE') OR pg_catalog.has_table_privilege(:'agent_platform_grant_definer_role',object.oid,'REFERENCES') OR pg_catalog.has_table_privilege(:'agent_platform_grant_definer_role',object.oid,'TRIGGER'))) AND
 NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object JOIN pg_catalog.pg_attribute attribute ON attribute.attrelid=object.oid JOIN pg_catalog.pg_namespace namespace ON namespace.oid=object.relnamespace,LATERAL pg_catalog.aclexplode(attribute.attacl) acl JOIN pg_catalog.pg_roles role ON role.oid=acl.grantee WHERE namespace.nspname='agent_private' AND role.rolname=:'agent_platform_grant_definer_role') AND
 NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object JOIN pg_catalog.pg_namespace namespace ON namespace.oid=object.relnamespace WHERE namespace.nspname='agent_private' AND object.relkind='S' AND (pg_catalog.has_sequence_privilege(:'agent_platform_grant_definer_role',object.oid,'USAGE') OR pg_catalog.has_sequence_privilege(:'agent_platform_grant_definer_role',object.oid,'SELECT') OR pg_catalog.has_sequence_privilege(:'agent_platform_grant_definer_role',object.oid,'UPDATE'))) AND
 NOT EXISTS(SELECT 1 FROM agent_private.agent_database_bindings WHERE login_role=:'agent_platform_grant_definer_role'::name) AND
 NOT EXISTS(SELECT 1 FROM agent_private.enrollment_database_bindings WHERE login_role=:'agent_platform_grant_definer_role'::name) AND
 NOT EXISTS(SELECT 1 FROM agent_private.agent_projection_database_bindings WHERE login_role=:'agent_platform_grant_definer_role'::name)) checked;

CREATE TABLE agent_private.platform_grant_database_bindings(
 login_role name PRIMARY KEY,
 environment_id uuid NOT NULL,
 purpose text NOT NULL CHECK(purpose='IssueInitialGrant'),
 UNIQUE(environment_id,purpose)
);
CREATE TABLE agent_private.platform_grant_receipts(
 environment_id uuid NOT NULL,
 operation_id uuid NOT NULL UNIQUE,
 grant_id uuid NOT NULL,
 directory_object_id uuid NOT NULL,
 device_id uuid NOT NULL,
 mapping_created_at timestamptz NOT NULL,
 token_sha256 bytea NOT NULL CHECK(pg_catalog.octet_length(token_sha256)=32),
 authorization_digest bytea NOT NULL CHECK(pg_catalog.octet_length(authorization_digest)=32),
 created_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL,
 PRIMARY KEY(environment_id,operation_id),
 UNIQUE(environment_id,grant_id),
 CHECK(operation_id<>'00000000-0000-0000-0000-000000000000'::uuid AND grant_id<>'00000000-0000-0000-0000-000000000000'::uuid AND directory_object_id<>'00000000-0000-0000-0000-000000000000'::uuid AND device_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 CHECK(expires_at=created_at+interval '600 seconds'),
 FOREIGN KEY(environment_id,grant_id,device_id) REFERENCES agent_private.enrollment_grants(environment_id,grant_id,device_id),
 FOREIGN KEY(environment_id,device_id) REFERENCES agent_private.devices(environment_id,device_id)
);
ALTER TABLE agent_private.platform_grant_database_bindings OWNER TO :"agent_table_owner_role";
ALTER TABLE agent_private.platform_grant_receipts OWNER TO :"agent_table_owner_role";
ALTER TABLE agent_private.platform_grant_database_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_private.platform_grant_database_bindings FORCE ROW LEVEL SECURITY;
ALTER TABLE agent_private.platform_grant_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_private.platform_grant_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY definer_all ON agent_private.platform_grant_database_bindings TO :"agent_table_owner_role" USING(true) WITH CHECK(true);
CREATE POLICY definer_all ON agent_private.platform_grant_receipts TO :"agent_table_owner_role" USING(true) WITH CHECK(true);
CREATE POLICY platform_grant_definer_select ON agent_private.platform_grant_database_bindings FOR SELECT TO :"agent_platform_grant_definer_role" USING(true);
CREATE POLICY platform_grant_definer_select ON agent_private.platform_grant_receipts FOR SELECT TO :"agent_platform_grant_definer_role" USING(true);
CREATE POLICY platform_grant_definer_insert ON agent_private.platform_grant_receipts FOR INSERT TO :"agent_platform_grant_definer_role" WITH CHECK(true);
CREATE POLICY platform_grant_definer_select ON agent_private.agent_device_directory_bindings FOR SELECT TO :"agent_platform_grant_definer_role" USING(true);
CREATE POLICY platform_grant_definer_select ON agent_private.agent_database_bindings FOR SELECT TO :"agent_platform_grant_definer_role" USING(true);
CREATE POLICY platform_grant_definer_select ON agent_private.enrollment_database_bindings FOR SELECT TO :"agent_platform_grant_definer_role" USING(true);
CREATE POLICY platform_grant_definer_select ON agent_private.agent_projection_database_bindings FOR SELECT TO :"agent_platform_grant_definer_role" USING(true);
CREATE POLICY platform_grant_definer_select ON agent_private.devices FOR SELECT TO :"agent_platform_grant_definer_role" USING(true);
CREATE POLICY platform_grant_definer_select ON agent_private.registrations FOR SELECT TO :"agent_platform_grant_definer_role" USING(true);
CREATE POLICY platform_grant_definer_select ON agent_private.enrollment_requests FOR SELECT TO :"agent_platform_grant_definer_role" USING(true);
CREATE POLICY platform_grant_definer_select ON agent_private.enrollment_grants FOR SELECT TO :"agent_platform_grant_definer_role" USING(true);
CREATE POLICY platform_grant_definer_insert ON agent_private.enrollment_grants FOR INSERT TO :"agent_platform_grant_definer_role" WITH CHECK(true);

GRANT USAGE ON SCHEMA agent_private TO :"agent_platform_grant_definer_role";
GRANT SELECT(login_role,environment_id,purpose) ON agent_private.platform_grant_database_bindings TO :"agent_platform_grant_definer_role";
GRANT SELECT(login_role) ON agent_private.agent_database_bindings TO :"agent_platform_grant_definer_role";
GRANT SELECT(login_role) ON agent_private.enrollment_database_bindings TO :"agent_platform_grant_definer_role";
GRANT SELECT(login_role) ON agent_private.agent_projection_database_bindings TO :"agent_platform_grant_definer_role";
GRANT SELECT(environment_id,operation_id,grant_id,directory_object_id,device_id,mapping_created_at,token_sha256,authorization_digest,created_at,expires_at), INSERT(environment_id,operation_id,grant_id,directory_object_id,device_id,mapping_created_at,token_sha256,authorization_digest,created_at,expires_at) ON agent_private.platform_grant_receipts TO :"agent_platform_grant_definer_role";
GRANT SELECT(environment_id,directory_object_id,device_id,created_at) ON agent_private.agent_device_directory_bindings TO :"agent_platform_grant_definer_role";
GRANT SELECT(environment_id,device_id,state) ON agent_private.devices TO :"agent_platform_grant_definer_role";
GRANT SELECT(environment_id,device_id,state) ON agent_private.registrations TO :"agent_platform_grant_definer_role";
GRANT SELECT(environment_id,device_id,state) ON agent_private.enrollment_requests TO :"agent_platform_grant_definer_role";
GRANT SELECT(environment_id,grant_id,device_id,token_sha256,state), INSERT(environment_id,grant_id,device_id,token_sha256,state,created_at,expires_at) ON agent_private.enrollment_grants TO :"agent_platform_grant_definer_role";

CREATE FUNCTION agent_private.lock_agent_device_directory_binding(p_environment_id uuid,p_directory_object_id uuid)
RETURNS TABLE(device_id uuid,created_at timestamptz)
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,agent_private,pg_temp AS $function$
 SELECT mapping.device_id,mapping.created_at FROM agent_private.agent_device_directory_bindings mapping
 WHERE mapping.environment_id=p_environment_id AND mapping.directory_object_id=p_directory_object_id FOR UPDATE;
$function$;
ALTER FUNCTION agent_private.lock_agent_device_directory_binding(uuid,uuid) OWNER TO :"agent_table_owner_role";
REVOKE ALL ON FUNCTION agent_private.lock_agent_device_directory_binding(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION agent_private.lock_agent_device_directory_binding(uuid,uuid) TO :"agent_platform_grant_definer_role";

CREATE FUNCTION agent_private.lock_agent_device(p_environment_id uuid,p_device_id uuid)
RETURNS TABLE(state text)
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,agent_private,pg_temp AS $function$
 SELECT device.state FROM agent_private.devices device WHERE device.environment_id=p_environment_id AND device.device_id=p_device_id FOR UPDATE;
$function$;
ALTER FUNCTION agent_private.lock_agent_device(uuid,uuid) OWNER TO :"agent_table_owner_role";
REVOKE ALL ON FUNCTION agent_private.lock_agent_device(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION agent_private.lock_agent_device(uuid,uuid) TO :"agent_platform_grant_definer_role";

CREATE FUNCTION agent_private.issue_initial_enrollment_grant(p_expected_environment_id uuid,p_operation_id uuid,p_directory_object_id uuid,p_expected_device_id uuid,p_mapping_created_at timestamptz,p_token_sha256 bytea,p_authorization_digest bytea)
RETURNS TABLE(outcome text,diagnostic_code text,environment_id uuid,operation_id uuid,grant_id uuid,directory_object_id uuid,device_id uuid,mapping_created_at timestamptz,created_at timestamptz,expires_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,agent_private,pg_temp AS $function$
#variable_conflict use_variable
DECLARE v_environment_id uuid;v_receipt agent_private.platform_grant_receipts%ROWTYPE;v_mapping record;v_now timestamptz;v_grant_id uuid;
BEGIN
 SELECT binding.environment_id INTO v_environment_id FROM agent_private.platform_grant_database_bindings binding WHERE binding.login_role=SESSION_USER::name AND binding.purpose='IssueInitialGrant';
 IF NOT FOUND OR p_expected_environment_id IS NULL OR p_expected_environment_id<>v_environment_id THEN RETURN QUERY SELECT 'Unauthorized','PrivilegeAuditFailed',NULL::uuid,NULL::uuid,NULL::uuid,NULL::uuid,NULL::uuid,NULL::timestamptz,NULL::timestamptz,NULL::timestamptz;RETURN;END IF;
 IF p_operation_id IS NULL OR p_operation_id='00000000-0000-0000-0000-000000000000'::uuid OR p_directory_object_id IS NULL OR p_directory_object_id='00000000-0000-0000-0000-000000000000'::uuid OR p_expected_device_id IS NULL OR p_expected_device_id='00000000-0000-0000-0000-000000000000'::uuid OR p_mapping_created_at IS NULL OR p_token_sha256 IS NULL OR pg_catalog.octet_length(p_token_sha256)<>32 OR p_authorization_digest IS NULL OR pg_catalog.octet_length(p_authorization_digest)<>32 THEN
  RETURN QUERY SELECT 'PermanentRejected','InvalidRequest',v_environment_id,p_operation_id,NULL::uuid,p_directory_object_id,p_expected_device_id,p_mapping_created_at,NULL::timestamptz,NULL::timestamptz;RETURN;
 END IF;
 PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('agent-platform-grant-operation-v1:'||p_operation_id::text,7912040301));
 SELECT receipt.* INTO v_receipt FROM agent_private.platform_grant_receipts receipt WHERE receipt.operation_id=p_operation_id;
 IF FOUND THEN
  IF v_receipt.environment_id<>v_environment_id OR v_receipt.directory_object_id<>p_directory_object_id OR v_receipt.device_id<>p_expected_device_id OR v_receipt.mapping_created_at<>p_mapping_created_at OR v_receipt.token_sha256<>p_token_sha256 OR v_receipt.authorization_digest<>p_authorization_digest THEN
   RETURN QUERY SELECT 'OutcomeUnknown','OperationConflict',v_environment_id,p_operation_id,NULL::uuid,p_directory_object_id,p_expected_device_id,p_mapping_created_at,NULL::timestamptz,NULL::timestamptz;RETURN;
  END IF;
  RETURN QUERY SELECT 'AlreadyCreated','None',v_receipt.environment_id,v_receipt.operation_id,v_receipt.grant_id,v_receipt.directory_object_id,v_receipt.device_id,v_receipt.mapping_created_at,v_receipt.created_at,v_receipt.expires_at;RETURN;
 END IF;
 SELECT mapping.device_id,mapping.created_at INTO v_mapping FROM agent_private.lock_agent_device_directory_binding(v_environment_id,p_directory_object_id) mapping;
 IF NOT FOUND OR v_mapping.device_id<>p_expected_device_id OR v_mapping.created_at<>p_mapping_created_at THEN RETURN QUERY SELECT 'PermanentRejected','MappingUnavailable',v_environment_id,p_operation_id,NULL::uuid,p_directory_object_id,p_expected_device_id,p_mapping_created_at,NULL::timestamptz,NULL::timestamptz;RETURN;END IF;
 PERFORM 1 FROM agent_private.lock_agent_device(v_environment_id,p_expected_device_id) device WHERE device.state='Active';
 IF NOT FOUND THEN RETURN QUERY SELECT 'PermanentRejected','DeviceUnavailable',v_environment_id,p_operation_id,NULL::uuid,p_directory_object_id,p_expected_device_id,p_mapping_created_at,NULL::timestamptz,NULL::timestamptz;RETURN;END IF;
 IF EXISTS(SELECT 1 FROM agent_private.registrations registration WHERE registration.environment_id=v_environment_id AND registration.device_id=p_expected_device_id AND registration.state='Active') THEN RETURN QUERY SELECT 'PermanentRejected','EnrollmentAlreadyExists',v_environment_id,p_operation_id,NULL::uuid,p_directory_object_id,p_expected_device_id,p_mapping_created_at,NULL::timestamptz,NULL::timestamptz;RETURN;END IF;
 IF EXISTS(SELECT 1 FROM agent_private.enrollment_requests request WHERE request.environment_id=v_environment_id AND request.device_id=p_expected_device_id AND request.state IN('PendingIssuance','ExternalPending','Issued','OutcomeUnknown')) THEN RETURN QUERY SELECT 'PermanentRejected','EnrollmentInProgress',v_environment_id,p_operation_id,NULL::uuid,p_directory_object_id,p_expected_device_id,p_mapping_created_at,NULL::timestamptz,NULL::timestamptz;RETURN;END IF;
 IF EXISTS(SELECT 1 FROM agent_private.enrollment_grants grant_row WHERE grant_row.environment_id=v_environment_id AND grant_row.device_id=p_expected_device_id AND grant_row.state='Available') THEN RETURN QUERY SELECT 'PermanentRejected','GrantAlreadyAvailable',v_environment_id,p_operation_id,NULL::uuid,p_directory_object_id,p_expected_device_id,p_mapping_created_at,NULL::timestamptz,NULL::timestamptz;RETURN;END IF;
 IF EXISTS(SELECT 1 FROM agent_private.enrollment_grants grant_row WHERE grant_row.token_sha256=p_token_sha256) THEN RETURN QUERY SELECT 'OutcomeUnknown','OperationConflict',v_environment_id,p_operation_id,NULL::uuid,p_directory_object_id,p_expected_device_id,p_mapping_created_at,NULL::timestamptz,NULL::timestamptz;RETURN;END IF;
 v_now:=pg_catalog.clock_timestamp();v_grant_id:=pg_catalog.gen_random_uuid();
 INSERT INTO agent_private.enrollment_grants(environment_id,grant_id,device_id,token_sha256,state,created_at,expires_at) VALUES(v_environment_id,v_grant_id,p_expected_device_id,p_token_sha256,'Available',v_now,v_now+interval '600 seconds');
 INSERT INTO agent_private.platform_grant_receipts(environment_id,operation_id,grant_id,directory_object_id,device_id,mapping_created_at,token_sha256,authorization_digest,created_at,expires_at) VALUES(v_environment_id,p_operation_id,v_grant_id,p_directory_object_id,p_expected_device_id,p_mapping_created_at,p_token_sha256,p_authorization_digest,v_now,v_now+interval '600 seconds');
 RETURN QUERY SELECT 'Created','None',v_environment_id,p_operation_id,v_grant_id,p_directory_object_id,p_expected_device_id,p_mapping_created_at,v_now,v_now+interval '600 seconds';
END;$function$;
ALTER FUNCTION agent_private.issue_initial_enrollment_grant(uuid,uuid,uuid,uuid,timestamptz,bytea,bytea) OWNER TO :"agent_platform_grant_definer_role";
REVOKE ALL ON FUNCTION agent_private.issue_initial_enrollment_grant(uuid,uuid,uuid,uuid,timestamptz,bytea,bytea) FROM PUBLIC;

CREATE FUNCTION agent_private.audit_platform_grant_privileges(p_expected_environment_id uuid,p_expected_table_owner name,p_expected_function_owner name)
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
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_policy policy JOIN pg_catalog.pg_class object ON object.oid=policy.polrelid JOIN pg_catalog.pg_namespace namespace ON namespace.oid=object.relnamespace,function_owner WHERE namespace.nspname='agent_private' AND function_owner.oid=ANY(policy.polroles) AND policy.polname LIKE 'platform_grant_definer_%' AND NOT EXISTS(SELECT 1 FROM expected_policies expected WHERE expected.relname=object.relname AND expected.polname=policy.polname AND expected.polcmd=policy.polcmd)) AND
  (SELECT pg_catalog.count(*)=8 AND pg_catalog.bool_and(object.relrowsecurity AND object.relforcerowsecurity) FROM pg_catalog.pg_class object,schema_info WHERE object.relnamespace=schema_info.oid AND object.relkind='r' AND object.relname=ANY(ARRAY['devices','registrations','enrollment_grants','enrollment_requests','agent_device_directory_bindings','agent_projection_database_bindings','platform_grant_database_bindings','platform_grant_receipts'])) AS valid)
SELECT valid,'None'::text,1::smallint FROM checks WHERE valid
UNION ALL SELECT false,'PrivilegeAuditFailed',1::smallint FROM checks WHERE NOT valid;$function$;
ALTER FUNCTION agent_private.audit_platform_grant_privileges(uuid,name,name) OWNER TO :"agent_platform_grant_definer_role";
REVOKE ALL ON FUNCTION agent_private.audit_platform_grant_privileges(uuid,name,name) FROM PUBLIC;

COMMIT;
