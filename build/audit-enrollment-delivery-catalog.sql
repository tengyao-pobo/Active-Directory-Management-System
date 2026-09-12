-- Staged catalog-only attestation. Not yet the pool's embedded audit resource.
-- No application tables are read and no application functions are invoked. The caller
-- must separately invoke the attested internal audit on the same locked transaction.
WITH parameters AS (
 SELECT :'runtime_role'::text runtime_name, :'delivery_definer_role'::text definer_name,
   :'expected_table_owner_role'::text owner_name, :'expected_environment_id'::uuid environment_id,
   :'expected_purpose'::text purpose
), identities AS (
 SELECT parameters.*,runtime.oid runtime_oid,definer.oid definer_oid,owner_role.oid owner_oid
 FROM parameters
 LEFT JOIN pg_catalog.pg_roles runtime ON runtime.rolname=runtime_name
 LEFT JOIN pg_catalog.pg_roles definer ON definer.rolname=definer_name
 LEFT JOIN pg_catalog.pg_roles owner_role ON owner_role.rolname=owner_name
), contracts(signature,owner_kind,volatility,purpose,body_hash,input_types,all_types,arg_names,arg_modes,return_type,returns_set) AS (VALUES
-- BEGIN generated delivery function contracts
 ('enrollment_execution.audit_execution_privileges(pg_catalog.uuid)','owner','s','','cc2d4f619e3025fc904d286c9821a8f9cd550b77f87c419bc2bbda01798acc93','2950',ARRAY[2950,16,25,21]::oid[],ARRAY['p_environment','is_valid','diagnostic_code','profile_version']::text[],ARRAY['i','t','t','t']::"char"[],2249::oid,true),
 ('enrollment_execution.audit_delivery_privileges(pg_catalog.uuid)','owner','s','both','a37b4693ed042c9d9f69555024c87cb5c40705cc60606bff14145b24480b1d9e','2950',ARRAY[2950,16,25,21]::oid[],ARRAY['p_environment','is_valid','diagnostic_code','profile_version']::text[],ARRAY['i','t','t','t']::"char"[],2249::oid,true),
 ('enrollment_execution.delivery_worker_scope(pg_catalog.uuid,pg_catalog.text)','owner','s','','a2abaa5afe86cdf2b548c52e54467b96a16af011f2780bdb8b49e4e1dd7efb8c','2950 25',NULL::oid[],ARRAY['p_environment','p_purpose']::text[],NULL::"char"[],16::oid,false),
 ('enrollment_execution.read_grant_status_receipt(pg_catalog.uuid,pg_catalog.uuid)','definer','v','EnrollmentGrantStatusRefresh','63cc9a1b50e70f66d59ed1a754a54c05aee02259341b8f7b6ed9ecf10256ed78','2950 2950',ARRAY[2950,2950,21,25,2950,2950,2950,2950,2950,1184,1184,1184,21,1184,17,17]::oid[],ARRAY['p_environment','p_operation','contract_version','outcome','environment_id','operation_id','grant_id','directory_object_id','device_id','mapping_created_at','grant_created_at','grant_expires_at','issue_contract_version','mint_permit_not_after','token_sha256','authorization_digest']::text[],ARRAY['i','i','t','t','t','t','t','t','t','t','t','t','t','t','t','t']::"char"[],2249::oid,true),
 ('enrollment_execution.append_grant_status_observation(pg_catalog.uuid,pg_catalog.uuid,pg_catalog.uuid,pg_catalog.text,pg_catalog.text,pg_catalog.timestamptz,pg_catalog.timestamptz,pg_catalog.uuid,pg_catalog.uuid,pg_catalog.uuid,pg_catalog.timestamptz,pg_catalog.timestamptz,pg_catalog.timestamptz,pg_catalog.int2,pg_catalog.timestamptz,pg_catalog.bytea,pg_catalog.bytea)','definer','v','EnrollmentGrantStatusRefresh','545ce0efbc1807b4104a1d5386d328326f1bfc03db98dbcec9ab531f021b03cf','2950 2950 2950 25 25 1184 1184 2950 2950 2950 1184 1184 1184 21 1184 17 17',ARRAY[2950,2950,2950,25,25,1184,1184,2950,2950,2950,1184,1184,1184,21,1184,17,17,21,25,2950,2950,2950,20,25,25,1184,1184,1184,1184]::oid[],ARRAY['p_environment','p_operation','p_observation','p_state','p_diagnostic','p_private_observed_at','p_private_state_changed_at','p_grant','p_directory_object','p_device','p_mapping_created_at','p_grant_created_at','p_grant_expires_at','p_issue_contract','p_mint_permit_not_after','p_token_sha256','p_authorization_digest','contract_version','outcome','observation_id','environment_id','operation_id','sequence','state','diagnostic','private_observed_at','private_state_changed_at','recorded_at','available_until']::text[],ARRAY['i','i','i','i','i','i','i','i','i','i','i','i','i','i','i','i','i','t','t','t','t','t','t','t','t','t','t','t','t']::"char"[],2249::oid,true),
 ('enrollment_execution.read_grant_delivery(pg_catalog.uuid,pg_catalog.uuid,pg_catalog.uuid,pg_catalog.text)','definer','v','EnrollmentGrantDelivery','f80126238164f65f17e8fb933b13799aa2fd6b45a1f3eb58a8f673014fcf5e3b','2950 2950 2950 25',ARRAY[2950,2950,2950,25,21,25,2950,2950,21,17,17,17,1184,1184]::oid[],ARRAY['p_environment','p_operation','p_requester','p_session_hash','contract_version','outcome','environment_id','operation_id','format_version','recipient_fingerprint','ciphertext','ciphertext_sha256','delivery_not_after','queried_at']::text[],ARRAY['i','i','i','i','t','t','t','t','t','t','t','t','t','t']::"char"[],2249::oid,true),
 ('enrollment_execution.acknowledge_grant_delivery(pg_catalog.uuid,pg_catalog.uuid,pg_catalog.uuid,pg_catalog.text,pg_catalog.bytea,pg_catalog.bytea)','definer','v','EnrollmentGrantDelivery','99f68247c9d723dfa7755481005aa7104f93646f6095315ea8439db444668323','2950 2950 2950 25 17 17',ARRAY[2950,2950,2950,25,17,17,21,25]::oid[],ARRAY['p_environment','p_operation','p_requester','p_session_hash','p_recipient_fingerprint','p_ciphertext_sha256','contract_version','outcome']::text[],ARRAY['i','i','i','i','i','i','t','t']::"char"[],2249::oid,true)
-- END generated delivery function contracts
), functions AS (
 SELECT expected.*,function_row.*,language_row.lanname,
   CASE WHEN expected.owner_kind='owner' THEN identity.owner_oid ELSE identity.definer_oid END expected_owner
 FROM contracts expected CROSS JOIN identities identity
 LEFT JOIN pg_catalog.pg_proc function_row ON function_row.oid=pg_catalog.to_regprocedure(expected.signature)
 LEFT JOIN pg_catalog.pg_language language_row ON language_row.oid=function_row.prolang
), wanted_runtime_functions AS (
 SELECT functions.oid,functions.expected_owner FROM functions CROSS JOIN identities identity
 WHERE functions.purpose IN('both',identity.purpose)
), marker AS (
 SELECT function_row.*,language_row.lanname FROM pg_catalog.pg_proc function_row
 JOIN pg_catalog.pg_language language_row ON language_row.oid=function_row.prolang
 WHERE function_row.oid=pg_catalog.to_regprocedure('enrollment_execution.execution_store_profile()')
)
SELECT COALESCE((SELECT
 identity.runtime_oid IS NOT NULL AND identity.definer_oid IS NOT NULL AND identity.owner_oid IS NOT NULL
 AND identity.runtime_oid<>identity.definer_oid AND identity.runtime_oid<>identity.owner_oid AND identity.definer_oid<>identity.owner_oid
 AND identity.runtime_name=SESSION_USER::text AND CURRENT_USER=SESSION_USER
 AND pg_catalog.current_setting('session_replication_role')='origin'
 AND pg_catalog.current_setting('lo_compat_privileges')='off'
 AND identity.environment_id IS NOT NULL AND identity.environment_id<>'00000000-0000-0000-0000-000000000000'::uuid
 AND identity.purpose IN('EnrollmentGrantStatusRefresh','EnrollmentGrantDelivery')
 AND (SELECT count(*)=2 AND bool_and(role.rolcanlogin=(role.oid=identity.runtime_oid)
   AND NOT(role.rolsuper OR role.rolbypassrls OR role.rolcreatedb OR role.rolcreaterole OR role.rolinherit OR role.rolreplication))
   FROM pg_catalog.pg_roles role WHERE role.oid IN(identity.runtime_oid,identity.definer_oid))
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members membership
   WHERE membership.member IN(identity.runtime_oid,identity.definer_oid) OR membership.roleid IN(identity.runtime_oid,identity.definer_oid))
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_shdepend dependency
   WHERE dependency.refclassid='pg_catalog.pg_authid'::regclass AND dependency.deptype='o'
     AND (dependency.refobjid=identity.runtime_oid OR (dependency.refobjid=identity.definer_oid AND NOT (
       dependency.classid='pg_catalog.pg_proc'::regclass AND dependency.dbid=(SELECT oid FROM pg_catalog.pg_database WHERE datname=pg_catalog.current_database())
       AND dependency.objid IN(SELECT oid FROM functions WHERE owner_kind='definer')))))
 AND (SELECT count(*)=1 AND bool_and(namespace.nspowner=identity.owner_oid)
   FROM pg_catalog.pg_namespace namespace WHERE namespace.nspname='enrollment_execution')
 AND (SELECT count(*)=7 AND bool_and(functions.oid IS NOT NULL AND functions.proowner=functions.expected_owner
   AND functions.lanname='plpgsql' AND functions.prokind='f' AND functions.prosecdef
   AND NOT functions.proisstrict AND NOT functions.proleakproof AND functions.prosupport=0
   AND functions.provolatile::text=functions.volatility AND functions.proparallel='u'
   AND functions.proretset=functions.returns_set AND functions.prorettype=functions.return_type
   AND functions.pronargs=pg_catalog.cardinality(pg_catalog.string_to_array(functions.input_types,' '))
   AND functions.proargtypes::text=functions.input_types
   AND functions.proallargtypes IS NOT DISTINCT FROM functions.all_types
   AND functions.proargnames IS NOT DISTINCT FROM functions.arg_names
   AND functions.proargmodes IS NOT DISTINCT FROM functions.arg_modes
   AND functions.pronargdefaults=0 AND functions.proargdefaults IS NULL AND functions.provariadic=0
   AND functions.probin IS NULL AND functions.prosqlbody IS NULL
   AND functions.proconfig IS NOT DISTINCT FROM ARRAY['search_path=pg_catalog, pg_temp','row_security=on']
   AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
     pg_catalog.btrim(pg_catalog.regexp_replace(functions.prosrc,'[[:space:]]+',' ','g')),'UTF8')),'hex')=functions.body_hash)
   FROM functions)
 AND (SELECT count(*)=1 AND bool_and(marker.proowner=identity.owner_oid AND marker.lanname='sql'
   AND marker.prokind='f' AND NOT marker.prosecdef AND NOT marker.proisstrict AND NOT marker.proleakproof
   AND marker.prosupport=0 AND marker.provolatile='i' AND marker.proparallel='s' AND NOT marker.proretset
   AND marker.prorettype=21 AND marker.pronargs=0 AND marker.proargtypes::text=''
   AND marker.proallargtypes IS NULL AND marker.proargnames IS NULL AND marker.proargmodes IS NULL
   AND marker.pronargdefaults=0 AND marker.proargdefaults IS NULL AND marker.provariadic=0
   AND marker.probin IS NULL AND marker.prosqlbody IS NULL
   AND marker.proconfig=ARRAY['search_path=pg_catalog, pg_temp']
   AND pg_catalog.btrim(marker.prosrc,E' \t\r\n')='SELECT 4::smallint') FROM marker)
 AND NOT EXISTS(
   WITH wanted(grantor,grantee,privilege_type,is_grantable) AS (VALUES(identity.owner_oid,identity.owner_oid,'EXECUTE'::text,false)),
   actual AS (SELECT acl.grantor,acl.grantee,acl.privilege_type,acl.is_grantable FROM marker CROSS JOIN LATERAL pg_catalog.aclexplode(
     COALESCE(marker.proacl,pg_catalog.acldefault('f',marker.proowner))) acl)
   SELECT 1 FROM ((SELECT * FROM wanted EXCEPT SELECT * FROM actual) UNION ALL (SELECT * FROM actual EXCEPT SELECT * FROM wanted)) difference)
 AND (SELECT count(*)=3 AND bool_and(oid IS NOT NULL) FROM wanted_runtime_functions)
 AND NOT EXISTS(
   WITH wanted AS (SELECT expected_owner grantor,identity.runtime_oid grantee,'EXECUTE'::text privilege_type,false is_grantable,oid
     FROM wanted_runtime_functions),
   actual AS (SELECT acl.grantor,acl.grantee,acl.privilege_type,acl.is_grantable,function_row.oid
     FROM pg_catalog.pg_proc function_row CROSS JOIN LATERAL pg_catalog.aclexplode(
       COALESCE(function_row.proacl,pg_catalog.acldefault('f',function_row.proowner))) acl WHERE acl.grantee=identity.runtime_oid)
   SELECT 1 FROM ((SELECT * FROM wanted EXCEPT SELECT * FROM actual) UNION ALL (SELECT * FROM actual EXCEPT SELECT * FROM wanted)) difference)
 AND NOT EXISTS(SELECT 1 FROM functions CROSS JOIN LATERAL pg_catalog.aclexplode(
   COALESCE(functions.proacl,pg_catalog.acldefault('f',functions.proowner))) acl
   WHERE acl.grantor<>functions.expected_owner OR acl.privilege_type<>'EXECUTE' OR acl.is_grantable OR acl.grantee=0)
 AND NOT EXISTS(
   WITH database_identity AS (SELECT oid FROM pg_catalog.pg_database WHERE datname=pg_catalog.current_database()),
   wanted(dbid,classid,objid,objsubid) AS (
     SELECT 0::oid,'pg_catalog.pg_database'::regclass::oid,oid,0 FROM database_identity
     UNION ALL SELECT database_identity.oid,'pg_catalog.pg_namespace'::regclass::oid,namespace.oid,0
       FROM database_identity CROSS JOIN pg_catalog.pg_namespace namespace WHERE namespace.nspname='enrollment_execution'
     UNION ALL SELECT database_identity.oid,'pg_catalog.pg_proc'::regclass::oid,functions.oid,0
       FROM database_identity CROSS JOIN wanted_runtime_functions functions),
   actual AS (SELECT dependency.dbid,dependency.classid,dependency.objid,dependency.objsubid FROM pg_catalog.pg_shdepend dependency
     WHERE dependency.refclassid='pg_catalog.pg_authid'::regclass AND dependency.refobjid=identity.runtime_oid AND dependency.deptype='a')
   SELECT 1 FROM ((SELECT * FROM wanted EXCEPT SELECT * FROM actual) UNION ALL (SELECT * FROM actual EXCEPT SELECT * FROM wanted)) difference)
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc function_row JOIN pg_catalog.pg_namespace namespace ON namespace.oid=function_row.pronamespace
   CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(function_row.proacl,pg_catalog.acldefault('f',function_row.proowner))) acl
   WHERE namespace.nspname NOT IN('pg_catalog','information_schema') AND namespace.nspname !~ '^pg_(toast|temp_)'
     AND function_row.prosecdef AND acl.grantee=0 AND (acl.privilege_type<>'EXECUTE' OR acl.is_grantable OR function_row.oid IS DISTINCT FROM
       pg_catalog.to_regprocedure('public.api_database_session()')))
 AND (SELECT count(*)=1 AND bool_and(helper.proowner=identity.owner_oid AND language.lanname='sql'
   AND helper.prokind='f' AND helper.prosecdef AND NOT helper.proisstrict AND NOT helper.proleakproof
   AND helper.prosupport=0 AND helper.provolatile='s' AND helper.proparallel='u' AND NOT helper.proretset
   AND helper.prorettype=16 AND helper.pronargs=0 AND helper.proargtypes::text=''
   AND helper.proallargtypes IS NULL AND helper.proargnames IS NULL AND helper.proargmodes IS NULL
   AND helper.pronargdefaults=0 AND helper.proargdefaults IS NULL AND helper.provariadic=0
   AND helper.probin IS NULL AND helper.prosqlbody IS NULL
   AND helper.proconfig=ARRAY['search_path=pg_catalog, pg_temp','row_security=on']
   AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(pg_catalog.btrim(
     pg_catalog.regexp_replace(helper.prosrc,'[[:space:]]+',' ','g')),'UTF8')),'hex')='e8f215ff4e1093baf33b3cf72040f99a96f2b5821f4b4593cf760d5a46658d84'
   AND NOT EXISTS(
     WITH wanted(grantor,grantee,privilege_type,is_grantable) AS (VALUES
       (identity.owner_oid,identity.owner_oid,'EXECUTE'::text,false),(identity.owner_oid,0::oid,'EXECUTE'::text,false)),
     actual AS (SELECT acl.grantor,acl.grantee,acl.privilege_type,acl.is_grantable
       FROM pg_catalog.aclexplode(COALESCE(helper.proacl,pg_catalog.acldefault('f',helper.proowner))) acl)
     SELECT 1 FROM ((SELECT * FROM wanted EXCEPT SELECT * FROM actual) UNION ALL (SELECT * FROM actual EXCEPT SELECT * FROM wanted)) difference))
   FROM pg_catalog.pg_proc helper JOIN pg_catalog.pg_language language ON language.oid=helper.prolang
   WHERE helper.oid=pg_catalog.to_regprocedure('public.api_database_session()'))
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles role WHERE role.oid IN(identity.runtime_oid,identity.definer_oid)
   AND pg_catalog.has_database_privilege(role.oid,pg_catalog.current_database(),'CREATE'))
 AND pg_catalog.has_database_privilege(identity.runtime_oid,pg_catalog.current_database(),'CONNECT')
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace namespace
   WHERE namespace.nspname NOT IN('pg_catalog','information_schema') AND namespace.nspname !~ '^pg_(toast|temp_)'
     AND (pg_catalog.has_schema_privilege(identity.runtime_oid,namespace.oid,'CREATE')
       OR pg_catalog.has_schema_privilege(identity.definer_oid,namespace.oid,'CREATE')))
 AND pg_catalog.has_schema_privilege(identity.runtime_oid,(SELECT oid FROM pg_catalog.pg_namespace WHERE nspname='enrollment_execution'),'USAGE')
 AND (SELECT count(*)=1 AND bool_and(namespace.nspname='enrollment_execution' AND acl.grantor=identity.owner_oid
   AND acl.privilege_type='USAGE' AND NOT acl.is_grantable)
   FROM pg_catalog.pg_namespace namespace CROSS JOIN LATERAL pg_catalog.aclexplode(namespace.nspacl) acl
   WHERE acl.grantee=identity.runtime_oid)
 AND (SELECT count(*)=1 AND bool_and(acl.grantor=database.datdba AND acl.privilege_type='CONNECT' AND NOT acl.is_grantable)
   FROM pg_catalog.pg_database database CROSS JOIN LATERAL pg_catalog.aclexplode(database.datacl) acl
   WHERE database.datname=pg_catalog.current_database() AND acl.grantee=identity.runtime_oid)
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class relation JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace
   WHERE namespace.nspname NOT IN('pg_catalog','information_schema') AND namespace.nspname !~ '^pg_(toast|temp_)'
     AND CASE WHEN relation.relkind IN('r','p','v','m','f') THEN
       pg_catalog.has_table_privilege(identity.runtime_oid,relation.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN')
       OR pg_catalog.has_any_column_privilege(identity.runtime_oid,relation.oid,'SELECT,INSERT,UPDATE,REFERENCES')
     WHEN relation.relkind='S' THEN pg_catalog.has_sequence_privilege(identity.runtime_oid,relation.oid,'USAGE,SELECT,UPDATE') ELSE false END)
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_default_acl defaults CROSS JOIN LATERAL pg_catalog.aclexplode(defaults.defaclacl) acl
   WHERE defaults.defaclobjtype IN('r','S') AND acl.grantee IN(0,identity.runtime_oid))
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_largeobject_metadata object
   WHERE pg_catalog.has_largeobject_privilege(identity.runtime_oid,object.oid,'SELECT')
     OR pg_catalog.has_largeobject_privilege(identity.runtime_oid,object.oid,'UPDATE'))
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_parameter_acl parameter
   CROSS JOIN LATERAL pg_catalog.aclexplode(parameter.paracl) acl WHERE acl.grantee IN(0,identity.runtime_oid))
 FROM identities identity),false) AS is_valid;
