\set ON_ERROR_STOP on
BEGIN;
WITH login AS(SELECT role.* FROM pg_catalog.pg_roles role WHERE role.rolname=:'agent_projection_role'::name),
 function_owner AS(SELECT role.* FROM pg_catalog.pg_roles role WHERE role.rolname=:'agent_projection_definer_role'::name),
 table_owner AS(SELECT role.* FROM pg_catalog.pg_roles role WHERE role.rolname=:'agent_table_owner_role'::name),
 schema_info AS(SELECT namespace.oid,namespace.nspowner FROM pg_catalog.pg_namespace namespace WHERE namespace.nspname='agent_private'),
expected_columns(relname,attname,privilege_type,is_grantable) AS(VALUES
  ('agent_database_bindings','login_role','SELECT',false),('enrollment_database_bindings','login_role','SELECT',false),
  ('agent_projection_database_bindings','login_role','SELECT',false),('agent_projection_database_bindings','environment_id','SELECT',false),('agent_projection_database_bindings','purpose','SELECT',false),
  ('agent_device_directory_bindings','environment_id','SELECT',false),('agent_device_directory_bindings','directory_object_id','SELECT',false),('agent_device_directory_bindings','device_id','SELECT',false),
  ('devices','environment_id','SELECT',false),('devices','device_id','SELECT',false),('devices','state','SELECT',false),('devices','last_seen_at','SELECT',false),
  ('registrations','environment_id','SELECT',false),('registrations','registration_id','SELECT',false),('registrations','device_id','SELECT',false),('registrations','registration_epoch','SELECT',false),('registrations','state','SELECT',false),
  ('inventory_projection','environment_id','SELECT',false),('inventory_projection','device_id','SELECT',false),('inventory_projection','registration_id','SELECT',false),('inventory_projection','registration_epoch','SELECT',false),('inventory_projection','sequence','SELECT',false),('inventory_projection','receipt_id','SELECT',false),('inventory_projection','normalized_payload','SELECT',false),
  ('receipts','environment_id','SELECT',false),('receipts','registration_id','SELECT',false),('receipts','registration_epoch','SELECT',false),('receipts','sequence','SELECT',false),('receipts','receipt_id','SELECT',false),('receipts','device_id','SELECT',false),('receipts','received_at','SELECT',false)),
 actual_columns AS(SELECT object.relname,attribute.attname,acl.privilege_type,acl.is_grantable FROM pg_catalog.pg_class object
  JOIN pg_catalog.pg_attribute attribute ON attribute.attrelid=object.oid,schema_info,function_owner,
  LATERAL pg_catalog.aclexplode(attribute.attacl) acl WHERE object.relnamespace=schema_info.oid AND acl.grantee=function_owner.oid),
 expected_execute(proname) AS(VALUES('read_current_bitlocker_projection'),('read_current_inventory_projection'),('audit_projection_privileges')),
 actual_execute AS(SELECT function.proname FROM pg_catalog.pg_proc function,schema_info WHERE function.pronamespace=schema_info.oid AND
  pg_catalog.has_function_privilege(:'agent_projection_role',function.oid,'EXECUTE')),
 checks AS(SELECT
  (SELECT pg_catalog.count(*)=1 FROM login) AND (SELECT pg_catalog.count(*)=1 FROM function_owner) AND (SELECT pg_catalog.count(*)=1 FROM table_owner) AND
  NOT EXISTS(SELECT 1 FROM login WHERE rolcanlogin=false OR rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole OR rolinherit OR rolreplication) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members membership,login WHERE membership.member=login.oid OR membership.roleid=login.oid) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_database database,login WHERE database.datdba=login.oid) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc function,schema_info,login WHERE function.pronamespace=schema_info.oid AND function.proowner=login.oid) AND
  NOT EXISTS(SELECT 1 FROM agent_private.agent_database_bindings binding WHERE binding.login_role=:'agent_projection_role'::name) AND
  NOT EXISTS(SELECT 1 FROM agent_private.enrollment_database_bindings binding WHERE binding.login_role=:'agent_projection_role'::name) AND
  (SELECT pg_catalog.count(*)=1 FROM agent_private.agent_projection_database_bindings binding WHERE binding.login_role=:'agent_projection_role'::name AND binding.environment_id=:'environment_id'::uuid AND binding.purpose='ReadDeviceProjection') AND
  NOT pg_catalog.has_schema_privilege(:'agent_projection_role','agent_private','CREATE') AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object,schema_info WHERE object.relnamespace=schema_info.oid AND object.relkind IN('r','p','v','m') AND
   (pg_catalog.has_table_privilege(:'agent_projection_role',object.oid,'SELECT') OR pg_catalog.has_table_privilege(:'agent_projection_role',object.oid,'INSERT') OR pg_catalog.has_table_privilege(:'agent_projection_role',object.oid,'UPDATE') OR
    pg_catalog.has_table_privilege(:'agent_projection_role',object.oid,'DELETE') OR pg_catalog.has_table_privilege(:'agent_projection_role',object.oid,'TRUNCATE') OR pg_catalog.has_table_privilege(:'agent_projection_role',object.oid,'REFERENCES') OR pg_catalog.has_table_privilege(:'agent_projection_role',object.oid,'TRIGGER'))) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object JOIN pg_catalog.pg_attribute attribute ON attribute.attrelid=object.oid,
   schema_info,login,LATERAL pg_catalog.aclexplode(attribute.attacl) acl WHERE object.relnamespace=schema_info.oid AND acl.grantee=login.oid) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object JOIN pg_catalog.pg_attribute attribute ON attribute.attrelid=object.oid,
   schema_info,LATERAL pg_catalog.aclexplode(attribute.attacl) acl WHERE object.relnamespace=schema_info.oid AND acl.grantee=0) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object,schema_info WHERE object.relnamespace=schema_info.oid AND object.relkind='S' AND
   (pg_catalog.has_sequence_privilege(:'agent_projection_role',object.oid,'USAGE') OR pg_catalog.has_sequence_privilege(:'agent_projection_role',object.oid,'SELECT') OR pg_catalog.has_sequence_privilege(:'agent_projection_role',object.oid,'UPDATE'))) AND
  NOT EXISTS((SELECT * FROM expected_execute EXCEPT SELECT * FROM actual_execute) UNION ALL(SELECT * FROM actual_execute EXCEPT SELECT * FROM expected_execute)) AND
  NOT EXISTS(SELECT 1 FROM function_owner WHERE rolcanlogin OR rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole OR rolinherit OR rolreplication) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members membership,function_owner WHERE membership.member=function_owner.oid OR membership.roleid=function_owner.oid) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_database database,function_owner WHERE database.datdba=function_owner.oid) AND
  NOT EXISTS(SELECT 1 FROM schema_info,function_owner WHERE schema_info.nspowner=function_owner.oid) AND
  NOT pg_catalog.has_schema_privilege(:'agent_projection_definer_role'::name,'agent_private','CREATE') AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object,schema_info,function_owner WHERE object.relnamespace=schema_info.oid AND object.relowner=function_owner.oid) AND
  (SELECT pg_catalog.count(*)=3 FROM pg_catalog.pg_proc function,schema_info,function_owner WHERE function.pronamespace=schema_info.oid AND function.proowner=function_owner.oid) AND
  NOT EXISTS(SELECT 1 FROM agent_private.agent_database_bindings binding,function_owner WHERE binding.login_role=function_owner.rolname::name) AND
  NOT EXISTS(SELECT 1 FROM agent_private.enrollment_database_bindings binding,function_owner WHERE binding.login_role=function_owner.rolname::name) AND
  NOT EXISTS(SELECT 1 FROM agent_private.agent_projection_database_bindings binding,function_owner WHERE binding.login_role=function_owner.rolname::name) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object,schema_info,function_owner WHERE object.relnamespace=schema_info.oid AND object.relkind IN('r','p','v','m') AND
   (pg_catalog.has_table_privilege(function_owner.rolname,object.oid,'SELECT') OR pg_catalog.has_table_privilege(function_owner.rolname,object.oid,'INSERT') OR pg_catalog.has_table_privilege(function_owner.rolname,object.oid,'UPDATE') OR
    pg_catalog.has_table_privilege(function_owner.rolname,object.oid,'DELETE') OR pg_catalog.has_table_privilege(function_owner.rolname,object.oid,'TRUNCATE') OR pg_catalog.has_table_privilege(function_owner.rolname,object.oid,'REFERENCES') OR pg_catalog.has_table_privilege(function_owner.rolname,object.oid,'TRIGGER'))) AND
  NOT EXISTS((SELECT * FROM expected_columns EXCEPT SELECT * FROM actual_columns) UNION ALL(SELECT * FROM actual_columns EXCEPT SELECT * FROM expected_columns)) AND
  NOT EXISTS(SELECT 1 FROM table_owner WHERE rolcanlogin OR rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole OR rolinherit OR rolreplication) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members membership,table_owner WHERE membership.member=table_owner.oid OR membership.roleid=table_owner.oid) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_database database,table_owner WHERE database.datdba=table_owner.oid) AND
  (SELECT pg_catalog.count(*)=1 FROM schema_info,table_owner WHERE schema_info.nspowner=table_owner.oid) AND
  (SELECT pg_catalog.count(*)=3 AND pg_catalog.bool_and(function.proowner=function_owner.oid AND function.prosecdef AND function.proconfig=ARRAY['search_path=pg_catalog, agent_private, pg_temp']::text[] AND
    pg_catalog.pg_get_function_identity_arguments(function.oid)=CASE function.proname WHEN 'read_current_bitlocker_projection' THEN 'p_environment_id uuid, p_directory_object_id uuid' WHEN 'read_current_inventory_projection' THEN 'p_environment_id uuid, p_directory_object_id uuid' ELSE 'p_expected_environment_id uuid, p_expected_table_owner name, p_expected_function_owner name' END AND
    pg_catalog.pg_get_function_result(function.oid)=CASE function.proname WHEN 'read_current_bitlocker_projection' THEN 'TABLE(outcome text, diagnostic_code text, environment_id uuid, directory_object_id uuid, device_id uuid, registration_id uuid, registration_epoch bigint, sequence bigint, receipt_id uuid, collected_at timestamp with time zone, source_observed_at timestamp with time zone, received_at timestamp with time zone, last_seen_at timestamp with time zone, source text, is_truncated boolean, volumes_json text)' WHEN 'read_current_inventory_projection' THEN 'TABLE(outcome text, diagnostic_code text, environment_id uuid, directory_object_id uuid, device_id uuid, registration_id uuid, registration_epoch bigint, sequence bigint, receipt_id uuid, collected_at timestamp with time zone, received_at timestamp with time zone, last_seen_at timestamp with time zone, basic_json text, software_json text, hardware_json text)' ELSE 'TABLE(is_valid boolean, diagnostic_code text, profile_version smallint)' END)
   FROM pg_catalog.pg_proc function,schema_info,function_owner WHERE function.pronamespace=schema_info.oid AND function.proname IN('read_current_bitlocker_projection','read_current_inventory_projection','audit_projection_privileges')) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc function,schema_info,LATERAL pg_catalog.aclexplode(COALESCE(function.proacl,pg_catalog.acldefault('f',function.proowner))) acl
   WHERE function.pronamespace=schema_info.oid AND function.proname IN('read_current_bitlocker_projection','read_current_inventory_projection','audit_projection_privileges') AND acl.grantee=0 AND acl.privilege_type='EXECUTE') AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc function,schema_info,function_owner,login,
   LATERAL pg_catalog.aclexplode(COALESCE(function.proacl,pg_catalog.acldefault('f',function.proowner))) acl
   WHERE function.pronamespace=schema_info.oid AND function.proname IN('read_current_bitlocker_projection','read_current_inventory_projection','audit_projection_privileges') AND
    acl.privilege_type='EXECUTE' AND (acl.grantee NOT IN(function_owner.oid,login.oid) OR (acl.grantee=login.oid AND acl.is_grantable))) AND
  (SELECT pg_catalog.count(*)=8 AND pg_catalog.bool_and(object.relowner=table_owner.oid AND object.relrowsecurity AND object.relforcerowsecurity)
   FROM pg_catalog.pg_class object,schema_info,table_owner WHERE object.relnamespace=schema_info.oid AND object.relkind='r' AND object.relname IN('agent_database_bindings','enrollment_database_bindings','agent_projection_database_bindings','agent_device_directory_bindings','devices','registrations','inventory_projection','receipts')) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object,schema_info,function_owner WHERE object.relnamespace=schema_info.oid AND
   object.relname IN('agent_database_bindings','enrollment_database_bindings','agent_projection_database_bindings','agent_device_directory_bindings','devices','registrations','inventory_projection','receipts') AND NOT EXISTS(
    SELECT 1 FROM pg_catalog.pg_policy policy WHERE policy.polrelid=object.oid AND policy.polname='projection_definer_select' AND policy.polroles=ARRAY[function_owner.oid]::oid[] AND policy.polcmd='r' AND
     pg_catalog.pg_get_expr(policy.polqual,policy.polrelid)='true' AND policy.polwithcheck IS NULL)) AS valid)
SELECT 1/pg_catalog.count(*) AS exact_v2_preflight FROM checks WHERE checks.valid;
REVOKE ALL ON FUNCTION agent_private.read_current_inventory_projection(uuid,uuid) FROM PUBLIC,:"agent_projection_role";
DROP FUNCTION agent_private.read_current_inventory_projection(uuid,uuid);
DROP FUNCTION agent_private.audit_projection_privileges(uuid,name,name);
ALTER TABLE agent_private.agent_projection_database_bindings DROP CONSTRAINT agent_projection_database_bindings_purpose_check;
UPDATE agent_private.agent_projection_database_bindings SET purpose='ReadBitLocker' WHERE login_role=:'agent_projection_role'::name AND environment_id=:'environment_id'::uuid AND purpose='ReadDeviceProjection';
ALTER TABLE agent_private.agent_projection_database_bindings ADD CONSTRAINT agent_projection_database_bindings_purpose_check CHECK(purpose='ReadBitLocker');

CREATE OR REPLACE FUNCTION agent_private.read_current_bitlocker_projection(p_environment_id uuid,p_directory_object_id uuid)
RETURNS TABLE(outcome text,diagnostic_code text,environment_id uuid,directory_object_id uuid,device_id uuid,
 registration_id uuid,registration_epoch bigint,sequence bigint,receipt_id uuid,collected_at timestamptz,
 source_observed_at timestamptz,received_at timestamptz,last_seen_at timestamptz,source text,is_truncated boolean,volumes_json text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,agent_private,pg_temp AS $function$
#variable_conflict use_variable
DECLARE
 v_device_id uuid;v_device_state text;v_last_seen timestamptz;v_registration_id uuid;v_registration_epoch bigint;
 v_sequence bigint;v_receipt_id uuid;v_received_at timestamptz;
 v_payload jsonb;v_collector jsonb;v_data jsonb;v_volumes jsonb;v_count integer;
 v_collected timestamptz;v_observed timestamptz;
BEGIN
 IF p_environment_id IS NULL OR p_environment_id='00000000-0000-0000-0000-000000000000'::uuid OR
    p_directory_object_id IS NULL OR p_directory_object_id='00000000-0000-0000-0000-000000000000'::uuid OR
    NOT EXISTS(SELECT 1 FROM agent_private.agent_projection_database_bindings binding WHERE
      binding.login_role=SESSION_USER::name AND binding.environment_id=p_environment_id AND binding.purpose='ReadBitLocker') THEN
  RETURN QUERY SELECT 'Unavailable','AuthenticationFailed',p_environment_id,p_directory_object_id,NULL::uuid,NULL::uuid,NULL::bigint,NULL::bigint,NULL::uuid,
    NULL::timestamptz,NULL::timestamptz,NULL::timestamptz,NULL::timestamptz,NULL::text,false,'[]'::text;RETURN;
 END IF;
 SELECT device.device_id,device.state,device.last_seen_at INTO v_device_id,v_device_state,v_last_seen FROM agent_private.agent_device_directory_bindings mapping
 JOIN agent_private.devices device ON device.environment_id=mapping.environment_id AND device.device_id=mapping.device_id
 WHERE mapping.environment_id=p_environment_id AND mapping.directory_object_id=p_directory_object_id;
 IF NOT FOUND THEN
  RETURN QUERY SELECT 'Missing','MappingMissing',p_environment_id,p_directory_object_id,NULL::uuid,NULL::uuid,NULL::bigint,NULL::bigint,NULL::uuid,
    NULL::timestamptz,NULL::timestamptz,NULL::timestamptz,NULL::timestamptz,NULL::text,false,'[]'::text;RETURN;
 END IF;
 IF v_device_state<>'Active' THEN
  RETURN QUERY SELECT 'Missing','DeviceUnavailable',p_environment_id,p_directory_object_id,v_device_id,NULL::uuid,NULL::bigint,NULL::bigint,NULL::uuid,
    NULL::timestamptz,NULL::timestamptz,NULL::timestamptz,v_last_seen,NULL::text,false,'[]'::text;RETURN;
 END IF;
 SELECT registration.registration_id,registration.registration_epoch INTO v_registration_id,v_registration_epoch FROM agent_private.registrations registration WHERE
  registration.environment_id=p_environment_id AND registration.device_id=v_device_id AND registration.state='Active';
 IF NOT FOUND THEN
  RETURN QUERY SELECT 'Missing','RegistrationUnavailable',p_environment_id,p_directory_object_id,v_device_id,NULL::uuid,NULL::bigint,NULL::bigint,NULL::uuid,
    NULL::timestamptz,NULL::timestamptz,NULL::timestamptz,v_last_seen,NULL::text,false,'[]'::text;RETURN;
 END IF;
 SELECT projection.sequence,projection.receipt_id,projection.normalized_payload INTO v_sequence,v_receipt_id,v_payload FROM agent_private.inventory_projection projection WHERE
  projection.environment_id=p_environment_id AND projection.device_id=v_device_id AND
  projection.registration_id=v_registration_id AND projection.registration_epoch=v_registration_epoch;
 IF NOT FOUND THEN
  RETURN QUERY SELECT 'Missing','ProjectionMissing',p_environment_id,p_directory_object_id,v_device_id,v_registration_id,
    v_registration_epoch,NULL::bigint,NULL::uuid,NULL::timestamptz,NULL::timestamptz,NULL::timestamptz,v_last_seen,NULL::text,false,'[]'::text;RETURN;
 END IF;
 SELECT receipt.received_at INTO v_received_at FROM agent_private.receipts receipt WHERE receipt.environment_id=p_environment_id AND
  receipt.device_id=v_device_id AND receipt.registration_id=v_registration_id AND
  receipt.registration_epoch=v_registration_epoch AND receipt.sequence=v_sequence AND receipt.receipt_id=v_receipt_id;
 IF NOT FOUND THEN
  RETURN QUERY SELECT 'Unavailable','ProjectionMalformed',p_environment_id,p_directory_object_id,v_device_id,v_registration_id,
    v_registration_epoch,v_sequence,v_receipt_id,NULL::timestamptz,NULL::timestamptz,NULL::timestamptz,v_last_seen,NULL::text,false,'[]'::text;RETURN;
 END IF;
 IF pg_catalog.octet_length(v_payload::text)>524288 OR pg_catalog.jsonb_typeof(v_payload)<>'object' OR NOT(v_payload ?& ARRAY['SchemaVersion','CollectedAt','Collectors']) OR
    v_payload-ARRAY['SchemaVersion','CollectedAt','Collectors']<>'{}'::jsonb OR v_payload->'SchemaVersion'<>'1'::jsonb OR
    pg_catalog.jsonb_typeof(v_payload->'CollectedAt')<>'string' OR NOT((v_payload->>'CollectedAt')~'^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}([.][0-9]{1,7})?(Z|[+-][0-9]{2}:[0-9]{2})$') OR pg_catalog.jsonb_typeof(v_payload->'Collectors')<>'array' OR
    pg_catalog.jsonb_array_length(v_payload->'Collectors')>32 THEN
  RETURN QUERY SELECT 'Unavailable','ProjectionMalformed',p_environment_id,p_directory_object_id,v_device_id,v_registration_id,
    v_registration_epoch,v_sequence,v_receipt_id,NULL::timestamptz,NULL::timestamptz,v_received_at,v_last_seen,NULL::text,false,'[]'::text;RETURN;
 END IF;
 BEGIN v_collected:=(v_payload->>'CollectedAt')::timestamptz;
 EXCEPTION WHEN OTHERS THEN
  RETURN QUERY SELECT 'Unavailable','ProjectionMalformed',p_environment_id,p_directory_object_id,v_device_id,v_registration_id,
    v_registration_epoch,v_sequence,v_receipt_id,NULL::timestamptz,NULL::timestamptz,v_received_at,v_last_seen,NULL::text,false,'[]'::text;RETURN;
 END;
 IF NOT pg_catalog.isfinite(v_collected) THEN
  RETURN QUERY SELECT 'Unavailable','ProjectionMalformed',p_environment_id,p_directory_object_id,v_device_id,v_registration_id,
    v_registration_epoch,v_sequence,v_receipt_id,NULL::timestamptz,NULL::timestamptz,v_received_at,v_last_seen,NULL::text,false,'[]'::text;RETURN;
 END IF;
 SELECT pg_catalog.count(*),(pg_catalog.jsonb_agg(value))->0 INTO v_count,v_collector FROM pg_catalog.jsonb_array_elements(v_payload->'Collectors') item(value)
  WHERE value->>'Collector'='bitlocker';
 IF v_count=0 THEN
  RETURN QUERY SELECT 'Missing','ProjectionMissing',p_environment_id,p_directory_object_id,v_device_id,v_registration_id,
    v_registration_epoch,v_sequence,v_receipt_id,v_collected,NULL::timestamptz,v_received_at,v_last_seen,NULL::text,false,'[]'::text;RETURN;
 END IF;
 IF v_count<>1 OR pg_catalog.jsonb_typeof(v_collector)<>'object' OR NOT(v_collector ?& ARRAY['Collector','Status','Quality','Source','ObservedAt','Data','ItemCount','ErrorCode']) OR
    v_collector-ARRAY['Collector','Status','Quality','Source','ObservedAt','Data','ItemCount','ErrorCode']<>'{}'::jsonb OR
    pg_catalog.jsonb_typeof(v_collector->'Status')<>'number' OR NOT((v_collector->>'Status')~'^[0-3]$') OR
    pg_catalog.jsonb_typeof(v_collector->'Quality')<>'number' OR NOT((v_collector->>'Quality')~'^[0-3]$') OR
    pg_catalog.jsonb_typeof(v_collector->'ItemCount')<>'number' OR NOT((v_collector->>'ItemCount')~'^[0-9]{1,5}$') OR
    (v_collector->>'ItemCount')::numeric>10000 OR pg_catalog.jsonb_typeof(v_collector->'ObservedAt')<>'string' OR
    NOT((v_collector->>'ObservedAt')~'^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}([.][0-9]{1,7})?(Z|[+-][0-9]{2}:[0-9]{2})$') THEN
  RETURN QUERY SELECT 'Unavailable','ProjectionMalformed',p_environment_id,p_directory_object_id,v_device_id,v_registration_id,
    v_registration_epoch,v_sequence,v_receipt_id,v_collected,NULL::timestamptz,v_received_at,v_last_seen,NULL::text,false,'[]'::text;RETURN;
 END IF;
 BEGIN v_observed:=(v_collector->>'ObservedAt')::timestamptz;
 EXCEPTION WHEN OTHERS THEN
  RETURN QUERY SELECT 'Unavailable','ProjectionMalformed',p_environment_id,p_directory_object_id,v_device_id,v_registration_id,
    v_registration_epoch,v_sequence,v_receipt_id,v_collected,NULL::timestamptz,v_received_at,v_last_seen,NULL::text,false,'[]'::text;RETURN;
 END;
 IF NOT pg_catalog.isfinite(v_observed) THEN
  RETURN QUERY SELECT 'Unavailable','ProjectionMalformed',p_environment_id,p_directory_object_id,v_device_id,v_registration_id,
    v_registration_epoch,v_sequence,v_receipt_id,v_collected,NULL::timestamptz,v_received_at,v_last_seen,NULL::text,false,'[]'::text;RETURN;
 END IF;
 IF (v_collector->>'Status')::integer<>0 OR (v_collector->>'Quality')::integer<>0 THEN
  RETURN QUERY SELECT 'Unavailable','SourceUnavailable',p_environment_id,p_directory_object_id,v_device_id,v_registration_id,
    v_registration_epoch,v_sequence,v_receipt_id,v_collected,v_observed,v_received_at,v_last_seen,NULL::text,false,'[]'::text;RETURN;
 END IF;
 IF pg_catalog.jsonb_typeof(v_collector->'Source')<>'string' OR
    (v_collector->>'Source') IS DISTINCT FROM E'root\\cimv2\\Security\\MicrosoftVolumeEncryption:Win32_EncryptableVolume' OR
    v_collector->'ErrorCode'<>'null'::jsonb OR pg_catalog.jsonb_typeof(v_collector->'Data')<>'object' THEN
  RETURN QUERY SELECT 'Unavailable','ProjectionMalformed',p_environment_id,p_directory_object_id,v_device_id,v_registration_id,
    v_registration_epoch,v_sequence,v_receipt_id,v_collected,v_observed,v_received_at,v_last_seen,NULL::text,false,'[]'::text;RETURN;
 END IF;
 v_data:=v_collector->'Data';
 IF NOT(v_data ?& ARRAY['SchemaVersion','Volumes','IsTruncated','ErrorCode']) OR v_data-ARRAY['SchemaVersion','Volumes','IsTruncated','ErrorCode']<>'{}'::jsonb OR
    v_data->'SchemaVersion'<>'1'::jsonb OR pg_catalog.jsonb_typeof(v_data->'Volumes')<>'array' OR pg_catalog.jsonb_array_length(v_data->'Volumes')>128 OR
    pg_catalog.jsonb_typeof(v_data->'IsTruncated')<>'boolean' OR v_data->'ErrorCode'<>'null'::jsonb OR
    (v_collector->>'ItemCount')::integer<>pg_catalog.jsonb_array_length(v_data->'Volumes') THEN
  RETURN QUERY SELECT 'Unavailable','ProjectionMalformed',p_environment_id,p_directory_object_id,v_device_id,v_registration_id,
    v_registration_epoch,v_sequence,v_receipt_id,v_collected,v_observed,v_received_at,v_last_seen,NULL::text,false,'[]'::text;RETURN;
 END IF;
 IF EXISTS(SELECT 1 FROM pg_catalog.jsonb_array_elements(v_data->'Volumes') volume WHERE pg_catalog.jsonb_typeof(volume)<>'object' OR
   NOT(volume ?& ARRAY['DeviceId','PersistentVolumeId','DriveLetter','VolumeType','ProtectionStatus','ConversionStatus','EncryptionMethod','IsVolumeInitializedForProtection']) OR
   volume-ARRAY['DeviceId','PersistentVolumeId','DriveLetter','VolumeType','ProtectionStatus','ConversionStatus','EncryptionMethod','IsVolumeInitializedForProtection']<>'{}'::jsonb OR
   pg_catalog.jsonb_typeof(volume->'DeviceId')<>'string' OR pg_catalog.length(volume->>'DeviceId') NOT BETWEEN 1 AND 512 OR volume->>'DeviceId'~'[[:cntrl:]]' OR pg_catalog.btrim(volume->>'DeviceId')='' OR
   NOT(volume->'PersistentVolumeId'='null'::jsonb OR (pg_catalog.jsonb_typeof(volume->'PersistentVolumeId')='string' AND pg_catalog.length(volume->>'PersistentVolumeId')<=512 AND NOT(volume->>'PersistentVolumeId'~'[[:cntrl:]]'))) OR
   NOT(volume->'DriveLetter'='null'::jsonb OR (pg_catalog.jsonb_typeof(volume->'DriveLetter')='string' AND volume->>'DriveLetter'~'^[A-Z]:$')) OR
   EXISTS(SELECT 1 FROM pg_catalog.jsonb_each(volume) property WHERE property.key IN('VolumeType','ProtectionStatus','ConversionStatus','EncryptionMethod') AND
     NOT(property.value='null'::jsonb OR (pg_catalog.jsonb_typeof(property.value)='number' AND property.value#>>'{}'~'^[0-9]{1,10}$' AND (property.value#>>'{}')::numeric<=4294967295))) OR
   NOT(volume->'IsVolumeInitializedForProtection'='null'::jsonb OR pg_catalog.jsonb_typeof(volume->'IsVolumeInitializedForProtection')='boolean')) OR
   (SELECT pg_catalog.count(*)<>pg_catalog.count(DISTINCT pg_catalog.lower(volume->>'DeviceId')) FROM pg_catalog.jsonb_array_elements(v_data->'Volumes') volume) THEN
  RETURN QUERY SELECT 'Unavailable','ProjectionMalformed',p_environment_id,p_directory_object_id,v_device_id,v_registration_id,
    v_registration_epoch,v_sequence,v_receipt_id,v_collected,v_observed,v_received_at,v_last_seen,NULL::text,false,'[]'::text;RETURN;
 END IF;
 SELECT COALESCE(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
  'DeviceId',volume->'DeviceId','PersistentVolumeId',volume->'PersistentVolumeId','DriveLetter',volume->'DriveLetter',
  'VolumeType',volume->'VolumeType','ProtectionStatus',volume->'ProtectionStatus','ConversionStatus',volume->'ConversionStatus',
  'EncryptionMethod',volume->'EncryptionMethod','IsVolumeInitializedForProtection',volume->'IsVolumeInitializedForProtection') ORDER BY ordinal),'[]'::jsonb)
 INTO v_volumes FROM pg_catalog.jsonb_array_elements(v_data->'Volumes') WITH ORDINALITY item(volume,ordinal);
 RETURN QUERY SELECT 'Observed','None',p_environment_id,p_directory_object_id,v_device_id,v_registration_id,
  v_registration_epoch,v_sequence,v_receipt_id,v_collected,v_observed,v_received_at,v_last_seen,
  E'root\\cimv2\\Security\\MicrosoftVolumeEncryption:Win32_EncryptableVolume',(v_data->>'IsTruncated')::boolean,v_volumes::text;
END;
$function$;

CREATE OR REPLACE FUNCTION agent_private.audit_projection_privileges(p_expected_environment_id uuid,p_expected_table_owner name,p_expected_function_owner name)
RETURNS TABLE(is_valid boolean,diagnostic_code text)
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,agent_private,pg_temp AS $function$
WITH login AS(SELECT role.* FROM pg_catalog.pg_roles role WHERE role.rolname=SESSION_USER),
 function_owner AS(SELECT role.* FROM pg_catalog.pg_roles role WHERE role.rolname=p_expected_function_owner),
 table_owner AS(SELECT role.* FROM pg_catalog.pg_roles role WHERE role.rolname=p_expected_table_owner),
 schema_info AS(SELECT namespace.oid,namespace.nspowner FROM pg_catalog.pg_namespace namespace WHERE namespace.nspname='agent_private'),
expected_columns(relname,attname,privilege_type,is_grantable) AS(VALUES
  ('agent_database_bindings','login_role','SELECT',false),('enrollment_database_bindings','login_role','SELECT',false),
  ('agent_projection_database_bindings','login_role','SELECT',false),('agent_projection_database_bindings','environment_id','SELECT',false),('agent_projection_database_bindings','purpose','SELECT',false),
  ('agent_device_directory_bindings','environment_id','SELECT',false),('agent_device_directory_bindings','directory_object_id','SELECT',false),('agent_device_directory_bindings','device_id','SELECT',false),
  ('devices','environment_id','SELECT',false),('devices','device_id','SELECT',false),('devices','state','SELECT',false),('devices','last_seen_at','SELECT',false),
  ('registrations','environment_id','SELECT',false),('registrations','registration_id','SELECT',false),('registrations','device_id','SELECT',false),('registrations','registration_epoch','SELECT',false),('registrations','state','SELECT',false),
  ('inventory_projection','environment_id','SELECT',false),('inventory_projection','device_id','SELECT',false),('inventory_projection','registration_id','SELECT',false),('inventory_projection','registration_epoch','SELECT',false),('inventory_projection','sequence','SELECT',false),('inventory_projection','receipt_id','SELECT',false),('inventory_projection','normalized_payload','SELECT',false),
  ('receipts','environment_id','SELECT',false),('receipts','registration_id','SELECT',false),('receipts','registration_epoch','SELECT',false),('receipts','sequence','SELECT',false),('receipts','receipt_id','SELECT',false),('receipts','device_id','SELECT',false),('receipts','received_at','SELECT',false)),
 actual_columns AS(SELECT object.relname,attribute.attname,acl.privilege_type,acl.is_grantable FROM pg_catalog.pg_class object
  JOIN pg_catalog.pg_attribute attribute ON attribute.attrelid=object.oid,schema_info,function_owner,
  LATERAL pg_catalog.aclexplode(attribute.attacl) acl WHERE object.relnamespace=schema_info.oid AND acl.grantee=function_owner.oid),
 expected_execute(proname) AS(VALUES('read_current_bitlocker_projection'),('audit_projection_privileges')),
 actual_execute AS(SELECT function.proname FROM pg_catalog.pg_proc function,schema_info WHERE function.pronamespace=schema_info.oid AND
  pg_catalog.has_function_privilege(SESSION_USER,function.oid,'EXECUTE')),
 checks AS(SELECT
  (SELECT pg_catalog.count(*)=1 FROM login) AND (SELECT pg_catalog.count(*)=1 FROM function_owner) AND (SELECT pg_catalog.count(*)=1 FROM table_owner) AND
  NOT EXISTS(SELECT 1 FROM login WHERE rolcanlogin=false OR rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole OR rolinherit OR rolreplication) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members membership,login WHERE membership.member=login.oid OR membership.roleid=login.oid) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_database database,login WHERE database.datdba=login.oid) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc function,schema_info,login WHERE function.pronamespace=schema_info.oid AND function.proowner=login.oid) AND
  NOT EXISTS(SELECT 1 FROM agent_private.agent_database_bindings binding WHERE binding.login_role=SESSION_USER::name) AND
  NOT EXISTS(SELECT 1 FROM agent_private.enrollment_database_bindings binding WHERE binding.login_role=SESSION_USER::name) AND
  (SELECT pg_catalog.count(*)=1 FROM agent_private.agent_projection_database_bindings binding WHERE binding.login_role=SESSION_USER::name AND binding.environment_id=p_expected_environment_id AND binding.purpose='ReadBitLocker') AND
  NOT pg_catalog.has_schema_privilege(SESSION_USER,'agent_private','CREATE') AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object,schema_info WHERE object.relnamespace=schema_info.oid AND object.relkind IN('r','p','v','m') AND
   (pg_catalog.has_table_privilege(SESSION_USER,object.oid,'SELECT') OR pg_catalog.has_table_privilege(SESSION_USER,object.oid,'INSERT') OR pg_catalog.has_table_privilege(SESSION_USER,object.oid,'UPDATE') OR
    pg_catalog.has_table_privilege(SESSION_USER,object.oid,'DELETE') OR pg_catalog.has_table_privilege(SESSION_USER,object.oid,'TRUNCATE') OR pg_catalog.has_table_privilege(SESSION_USER,object.oid,'REFERENCES') OR pg_catalog.has_table_privilege(SESSION_USER,object.oid,'TRIGGER'))) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object JOIN pg_catalog.pg_attribute attribute ON attribute.attrelid=object.oid,
   schema_info,login,LATERAL pg_catalog.aclexplode(attribute.attacl) acl WHERE object.relnamespace=schema_info.oid AND acl.grantee=login.oid) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object JOIN pg_catalog.pg_attribute attribute ON attribute.attrelid=object.oid,
   schema_info,LATERAL pg_catalog.aclexplode(attribute.attacl) acl WHERE object.relnamespace=schema_info.oid AND acl.grantee=0) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object,schema_info WHERE object.relnamespace=schema_info.oid AND object.relkind='S' AND
   (pg_catalog.has_sequence_privilege(SESSION_USER,object.oid,'USAGE') OR pg_catalog.has_sequence_privilege(SESSION_USER,object.oid,'SELECT') OR pg_catalog.has_sequence_privilege(SESSION_USER,object.oid,'UPDATE'))) AND
  NOT EXISTS((SELECT * FROM expected_execute EXCEPT SELECT * FROM actual_execute) UNION ALL(SELECT * FROM actual_execute EXCEPT SELECT * FROM expected_execute)) AND
  NOT EXISTS(SELECT 1 FROM function_owner WHERE rolcanlogin OR rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole OR rolinherit OR rolreplication) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members membership,function_owner WHERE membership.member=function_owner.oid OR membership.roleid=function_owner.oid) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_database database,function_owner WHERE database.datdba=function_owner.oid) AND
  NOT EXISTS(SELECT 1 FROM schema_info,function_owner WHERE schema_info.nspowner=function_owner.oid) AND
  NOT pg_catalog.has_schema_privilege(p_expected_function_owner,'agent_private','CREATE') AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object,schema_info,function_owner WHERE object.relnamespace=schema_info.oid AND object.relowner=function_owner.oid) AND
  (SELECT pg_catalog.count(*)=2 FROM pg_catalog.pg_proc function,schema_info,function_owner WHERE function.pronamespace=schema_info.oid AND function.proowner=function_owner.oid) AND
  NOT EXISTS(SELECT 1 FROM agent_private.agent_database_bindings binding,function_owner WHERE binding.login_role=function_owner.rolname::name) AND
  NOT EXISTS(SELECT 1 FROM agent_private.enrollment_database_bindings binding,function_owner WHERE binding.login_role=function_owner.rolname::name) AND
  NOT EXISTS(SELECT 1 FROM agent_private.agent_projection_database_bindings binding,function_owner WHERE binding.login_role=function_owner.rolname::name) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object,schema_info,function_owner WHERE object.relnamespace=schema_info.oid AND object.relkind IN('r','p','v','m') AND
   (pg_catalog.has_table_privilege(function_owner.rolname,object.oid,'SELECT') OR pg_catalog.has_table_privilege(function_owner.rolname,object.oid,'INSERT') OR pg_catalog.has_table_privilege(function_owner.rolname,object.oid,'UPDATE') OR
    pg_catalog.has_table_privilege(function_owner.rolname,object.oid,'DELETE') OR pg_catalog.has_table_privilege(function_owner.rolname,object.oid,'TRUNCATE') OR pg_catalog.has_table_privilege(function_owner.rolname,object.oid,'REFERENCES') OR pg_catalog.has_table_privilege(function_owner.rolname,object.oid,'TRIGGER'))) AND
  NOT EXISTS((SELECT * FROM expected_columns EXCEPT SELECT * FROM actual_columns) UNION ALL(SELECT * FROM actual_columns EXCEPT SELECT * FROM expected_columns)) AND
  NOT EXISTS(SELECT 1 FROM table_owner WHERE rolcanlogin OR rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole OR rolinherit OR rolreplication) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members membership,table_owner WHERE membership.member=table_owner.oid OR membership.roleid=table_owner.oid) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_database database,table_owner WHERE database.datdba=table_owner.oid) AND
  (SELECT pg_catalog.count(*)=1 FROM schema_info,table_owner WHERE schema_info.nspowner=table_owner.oid) AND
  (SELECT pg_catalog.count(*)=2 AND pg_catalog.bool_and(function.proowner=function_owner.oid AND function.prosecdef AND function.proconfig=ARRAY['search_path=pg_catalog, agent_private, pg_temp']::text[])
   FROM pg_catalog.pg_proc function,schema_info,function_owner WHERE function.pronamespace=schema_info.oid AND function.proname IN('read_current_bitlocker_projection','audit_projection_privileges')) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc function,schema_info,LATERAL pg_catalog.aclexplode(COALESCE(function.proacl,pg_catalog.acldefault('f',function.proowner))) acl
   WHERE function.pronamespace=schema_info.oid AND function.proname IN('read_current_bitlocker_projection','audit_projection_privileges') AND acl.grantee=0 AND acl.privilege_type='EXECUTE') AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc function,schema_info,function_owner,login,
   LATERAL pg_catalog.aclexplode(COALESCE(function.proacl,pg_catalog.acldefault('f',function.proowner))) acl
   WHERE function.pronamespace=schema_info.oid AND function.proname IN('read_current_bitlocker_projection','audit_projection_privileges') AND
    acl.privilege_type='EXECUTE' AND (acl.grantee NOT IN(function_owner.oid,login.oid) OR (acl.grantee=login.oid AND acl.is_grantable))) AND
  (SELECT pg_catalog.count(*)=8 AND pg_catalog.bool_and(object.relowner=table_owner.oid AND object.relrowsecurity AND object.relforcerowsecurity)
   FROM pg_catalog.pg_class object,schema_info,table_owner WHERE object.relnamespace=schema_info.oid AND object.relkind='r' AND object.relname IN('agent_database_bindings','enrollment_database_bindings','agent_projection_database_bindings','agent_device_directory_bindings','devices','registrations','inventory_projection','receipts')) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object,schema_info,function_owner WHERE object.relnamespace=schema_info.oid AND
   object.relname IN('agent_database_bindings','enrollment_database_bindings','agent_projection_database_bindings','agent_device_directory_bindings','devices','registrations','inventory_projection','receipts') AND NOT EXISTS(
    SELECT 1 FROM pg_catalog.pg_policy policy WHERE policy.polrelid=object.oid AND policy.polname='projection_definer_select' AND policy.polroles=ARRAY[function_owner.oid]::oid[] AND policy.polcmd='r' AND
     pg_catalog.pg_get_expr(policy.polqual,policy.polrelid)='true' AND policy.polwithcheck IS NULL)) AS valid)
SELECT checks.valid,CASE WHEN checks.valid THEN 'None' ELSE 'PrivilegeAuditFailed' END FROM checks;
$function$;


ALTER FUNCTION agent_private.read_current_bitlocker_projection(uuid,uuid) OWNER TO :"agent_projection_definer_role";
ALTER FUNCTION agent_private.audit_projection_privileges(uuid,name,name) OWNER TO :"agent_projection_definer_role";
REVOKE ALL ON FUNCTION agent_private.read_current_bitlocker_projection(uuid,uuid),agent_private.audit_projection_privileges(uuid,name,name) FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA agent_private FROM :"agent_projection_role";
GRANT EXECUTE ON FUNCTION agent_private.read_current_bitlocker_projection(uuid,uuid),agent_private.audit_projection_privileges(uuid,name,name) TO :"agent_projection_role";
WITH login AS(SELECT role.* FROM pg_catalog.pg_roles role WHERE role.rolname=:'agent_projection_role'::name),
 function_owner AS(SELECT role.* FROM pg_catalog.pg_roles role WHERE role.rolname=:'agent_projection_definer_role'::name),
 table_owner AS(SELECT role.* FROM pg_catalog.pg_roles role WHERE role.rolname=:'agent_table_owner_role'::name),
 schema_info AS(SELECT namespace.oid,namespace.nspowner FROM pg_catalog.pg_namespace namespace WHERE namespace.nspname='agent_private'),
expected_columns(relname,attname,privilege_type,is_grantable) AS(VALUES
  ('agent_database_bindings','login_role','SELECT',false),('enrollment_database_bindings','login_role','SELECT',false),
  ('agent_projection_database_bindings','login_role','SELECT',false),('agent_projection_database_bindings','environment_id','SELECT',false),('agent_projection_database_bindings','purpose','SELECT',false),
  ('agent_device_directory_bindings','environment_id','SELECT',false),('agent_device_directory_bindings','directory_object_id','SELECT',false),('agent_device_directory_bindings','device_id','SELECT',false),
  ('devices','environment_id','SELECT',false),('devices','device_id','SELECT',false),('devices','state','SELECT',false),('devices','last_seen_at','SELECT',false),
  ('registrations','environment_id','SELECT',false),('registrations','registration_id','SELECT',false),('registrations','device_id','SELECT',false),('registrations','registration_epoch','SELECT',false),('registrations','state','SELECT',false),
  ('inventory_projection','environment_id','SELECT',false),('inventory_projection','device_id','SELECT',false),('inventory_projection','registration_id','SELECT',false),('inventory_projection','registration_epoch','SELECT',false),('inventory_projection','sequence','SELECT',false),('inventory_projection','receipt_id','SELECT',false),('inventory_projection','normalized_payload','SELECT',false),
  ('receipts','environment_id','SELECT',false),('receipts','registration_id','SELECT',false),('receipts','registration_epoch','SELECT',false),('receipts','sequence','SELECT',false),('receipts','receipt_id','SELECT',false),('receipts','device_id','SELECT',false),('receipts','received_at','SELECT',false)),
 actual_columns AS(SELECT object.relname,attribute.attname,acl.privilege_type,acl.is_grantable FROM pg_catalog.pg_class object
  JOIN pg_catalog.pg_attribute attribute ON attribute.attrelid=object.oid,schema_info,function_owner,
  LATERAL pg_catalog.aclexplode(attribute.attacl) acl WHERE object.relnamespace=schema_info.oid AND acl.grantee=function_owner.oid),
 expected_execute(proname) AS(VALUES('read_current_bitlocker_projection'),('audit_projection_privileges')),
 actual_execute AS(SELECT function.proname FROM pg_catalog.pg_proc function,schema_info WHERE function.pronamespace=schema_info.oid AND
  pg_catalog.has_function_privilege(:'agent_projection_role',function.oid,'EXECUTE')),
 checks AS(SELECT
  (SELECT pg_catalog.count(*)=1 FROM login) AND (SELECT pg_catalog.count(*)=1 FROM function_owner) AND (SELECT pg_catalog.count(*)=1 FROM table_owner) AND
  NOT EXISTS(SELECT 1 FROM login WHERE rolcanlogin=false OR rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole OR rolinherit OR rolreplication) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members membership,login WHERE membership.member=login.oid OR membership.roleid=login.oid) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_database database,login WHERE database.datdba=login.oid) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc function,schema_info,login WHERE function.pronamespace=schema_info.oid AND function.proowner=login.oid) AND
  NOT EXISTS(SELECT 1 FROM agent_private.agent_database_bindings binding WHERE binding.login_role=:'agent_projection_role'::name) AND
  NOT EXISTS(SELECT 1 FROM agent_private.enrollment_database_bindings binding WHERE binding.login_role=:'agent_projection_role'::name) AND
  (SELECT pg_catalog.count(*)=1 FROM agent_private.agent_projection_database_bindings binding WHERE binding.login_role=:'agent_projection_role'::name AND binding.environment_id=:'environment_id'::uuid AND binding.purpose='ReadBitLocker') AND
  NOT pg_catalog.has_schema_privilege(:'agent_projection_role','agent_private','CREATE') AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object,schema_info WHERE object.relnamespace=schema_info.oid AND object.relkind IN('r','p','v','m') AND
   (pg_catalog.has_table_privilege(:'agent_projection_role',object.oid,'SELECT') OR pg_catalog.has_table_privilege(:'agent_projection_role',object.oid,'INSERT') OR pg_catalog.has_table_privilege(:'agent_projection_role',object.oid,'UPDATE') OR
    pg_catalog.has_table_privilege(:'agent_projection_role',object.oid,'DELETE') OR pg_catalog.has_table_privilege(:'agent_projection_role',object.oid,'TRUNCATE') OR pg_catalog.has_table_privilege(:'agent_projection_role',object.oid,'REFERENCES') OR pg_catalog.has_table_privilege(:'agent_projection_role',object.oid,'TRIGGER'))) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object JOIN pg_catalog.pg_attribute attribute ON attribute.attrelid=object.oid,
   schema_info,login,LATERAL pg_catalog.aclexplode(attribute.attacl) acl WHERE object.relnamespace=schema_info.oid AND acl.grantee=login.oid) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object JOIN pg_catalog.pg_attribute attribute ON attribute.attrelid=object.oid,
   schema_info,LATERAL pg_catalog.aclexplode(attribute.attacl) acl WHERE object.relnamespace=schema_info.oid AND acl.grantee=0) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object,schema_info WHERE object.relnamespace=schema_info.oid AND object.relkind='S' AND
   (pg_catalog.has_sequence_privilege(:'agent_projection_role',object.oid,'USAGE') OR pg_catalog.has_sequence_privilege(:'agent_projection_role',object.oid,'SELECT') OR pg_catalog.has_sequence_privilege(:'agent_projection_role',object.oid,'UPDATE'))) AND
  NOT EXISTS((SELECT * FROM expected_execute EXCEPT SELECT * FROM actual_execute) UNION ALL(SELECT * FROM actual_execute EXCEPT SELECT * FROM expected_execute)) AND
  NOT EXISTS(SELECT 1 FROM function_owner WHERE rolcanlogin OR rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole OR rolinherit OR rolreplication) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members membership,function_owner WHERE membership.member=function_owner.oid OR membership.roleid=function_owner.oid) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_database database,function_owner WHERE database.datdba=function_owner.oid) AND
  NOT EXISTS(SELECT 1 FROM schema_info,function_owner WHERE schema_info.nspowner=function_owner.oid) AND
  NOT pg_catalog.has_schema_privilege(:'agent_projection_definer_role'::name,'agent_private','CREATE') AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object,schema_info,function_owner WHERE object.relnamespace=schema_info.oid AND object.relowner=function_owner.oid) AND
  (SELECT pg_catalog.count(*)=2 FROM pg_catalog.pg_proc function,schema_info,function_owner WHERE function.pronamespace=schema_info.oid AND function.proowner=function_owner.oid) AND
  NOT EXISTS(SELECT 1 FROM agent_private.agent_database_bindings binding,function_owner WHERE binding.login_role=function_owner.rolname::name) AND
  NOT EXISTS(SELECT 1 FROM agent_private.enrollment_database_bindings binding,function_owner WHERE binding.login_role=function_owner.rolname::name) AND
  NOT EXISTS(SELECT 1 FROM agent_private.agent_projection_database_bindings binding,function_owner WHERE binding.login_role=function_owner.rolname::name) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object,schema_info,function_owner WHERE object.relnamespace=schema_info.oid AND object.relkind IN('r','p','v','m') AND
   (pg_catalog.has_table_privilege(function_owner.rolname,object.oid,'SELECT') OR pg_catalog.has_table_privilege(function_owner.rolname,object.oid,'INSERT') OR pg_catalog.has_table_privilege(function_owner.rolname,object.oid,'UPDATE') OR
    pg_catalog.has_table_privilege(function_owner.rolname,object.oid,'DELETE') OR pg_catalog.has_table_privilege(function_owner.rolname,object.oid,'TRUNCATE') OR pg_catalog.has_table_privilege(function_owner.rolname,object.oid,'REFERENCES') OR pg_catalog.has_table_privilege(function_owner.rolname,object.oid,'TRIGGER'))) AND
  NOT EXISTS((SELECT * FROM expected_columns EXCEPT SELECT * FROM actual_columns) UNION ALL(SELECT * FROM actual_columns EXCEPT SELECT * FROM expected_columns)) AND
  NOT EXISTS(SELECT 1 FROM table_owner WHERE rolcanlogin OR rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole OR rolinherit OR rolreplication) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members membership,table_owner WHERE membership.member=table_owner.oid OR membership.roleid=table_owner.oid) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_database database,table_owner WHERE database.datdba=table_owner.oid) AND
  (SELECT pg_catalog.count(*)=1 FROM schema_info,table_owner WHERE schema_info.nspowner=table_owner.oid) AND
  (SELECT pg_catalog.count(*)=2 AND pg_catalog.bool_and(function.proowner=function_owner.oid AND function.prosecdef AND function.proconfig=ARRAY['search_path=pg_catalog, agent_private, pg_temp']::text[])
   FROM pg_catalog.pg_proc function,schema_info,function_owner WHERE function.pronamespace=schema_info.oid AND function.proname IN('read_current_bitlocker_projection','audit_projection_privileges')) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc function,schema_info,LATERAL pg_catalog.aclexplode(COALESCE(function.proacl,pg_catalog.acldefault('f',function.proowner))) acl
   WHERE function.pronamespace=schema_info.oid AND function.proname IN('read_current_bitlocker_projection','audit_projection_privileges') AND acl.grantee=0 AND acl.privilege_type='EXECUTE') AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc function,schema_info,function_owner,login,
   LATERAL pg_catalog.aclexplode(COALESCE(function.proacl,pg_catalog.acldefault('f',function.proowner))) acl
   WHERE function.pronamespace=schema_info.oid AND function.proname IN('read_current_bitlocker_projection','audit_projection_privileges') AND
    acl.privilege_type='EXECUTE' AND (acl.grantee NOT IN(function_owner.oid,login.oid) OR (acl.grantee=login.oid AND acl.is_grantable))) AND
  (SELECT pg_catalog.count(*)=8 AND pg_catalog.bool_and(object.relowner=table_owner.oid AND object.relrowsecurity AND object.relforcerowsecurity)
   FROM pg_catalog.pg_class object,schema_info,table_owner WHERE object.relnamespace=schema_info.oid AND object.relkind='r' AND object.relname IN('agent_database_bindings','enrollment_database_bindings','agent_projection_database_bindings','agent_device_directory_bindings','devices','registrations','inventory_projection','receipts')) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class object,schema_info,function_owner WHERE object.relnamespace=schema_info.oid AND
   object.relname IN('agent_database_bindings','enrollment_database_bindings','agent_projection_database_bindings','agent_device_directory_bindings','devices','registrations','inventory_projection','receipts') AND NOT EXISTS(
    SELECT 1 FROM pg_catalog.pg_policy policy WHERE policy.polrelid=object.oid AND policy.polname='projection_definer_select' AND policy.polroles=ARRAY[function_owner.oid]::oid[] AND policy.polcmd='r' AND
     pg_catalog.pg_get_expr(policy.polqual,policy.polrelid)='true' AND policy.polwithcheck IS NULL)) AS valid)
SELECT 1/pg_catalog.count(*) AS exact_v1_postflight FROM checks WHERE checks.valid;
COMMIT;
