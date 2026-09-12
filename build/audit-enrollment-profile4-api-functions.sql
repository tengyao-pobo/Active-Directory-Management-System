-- UNCONSUMED API-readable function-root slice, not a full profile or Ready verdict.
-- Caller uses a transaction-local search_path=pg_catalog,pg_temp. No application reads/calls.
WITH identities AS (
 SELECT owner_role.oid owner_oid,api.oid api_oid,
   (SELECT proowner FROM pg_catalog.pg_proc WHERE oid=pg_catalog.to_regprocedure('public.lock_enrollment_grant_plan_context(uuid,uuid,uuid[])')) plan_oid,
   (SELECT p.proowner FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
     WHERE n.nspname='enrollment_execution' AND p.proname='read_execution_record' AND p.proargtypes::text='2950 2950') execution_oid,
   (SELECT p.proowner FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
     WHERE n.nspname='enrollment_execution' AND p.proname='claim_next' AND p.proargtypes::text='2950 2950') queue_oid,
   (SELECT p.proowner FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
     WHERE n.nspname='enrollment_execution' AND p.proname='read_grant_delivery' AND p.proargtypes::text='2950 2950 2950 25') delivery_oid
 FROM pg_catalog.pg_class anchor JOIN pg_catalog.pg_roles owner_role ON owner_role.oid=anchor.relowner
 CROSS JOIN pg_catalog.pg_roles api
 WHERE anchor.oid=pg_catalog.to_regclass('public."Environments"') AND anchor.relkind='r'
   AND anchor.relpersistence='p' AND NOT anchor.relispartition AND api.rolname=SESSION_USER
), expected(signature,language_name,volatility,parallel_code,definer,strict_value,returns_set,return_oid,
 argument_types,argument_names,all_argument_types,argument_modes,configuration,body_hash,acl_kind) AS (VALUES
-- BEGIN generated API function roots
 ('enrollment_execution.execution_store_profile()','sql','i','s',false,false,false,21::oid,'',NULL::text[],NULL::oid[],NULL::"char"[],ARRAY['search_path=pg_catalog, pg_temp']::text[],'59756e9373283c6320c3a2b38a7d251e359de54860a6de9f8d7cc01c18fc8b61','owner'),
 ('enrollment_execution.audit_execution_privileges(uuid)','plpgsql','v','u',true,false,true,2249::oid,'2950',ARRAY['p_environment','is_valid','diagnostic_code','profile_version']::text[],ARRAY[2950,16,25,21]::oid[],ARRAY['i','t','t','t']::"char"[],ARRAY['search_path=pg_catalog, pg_temp','row_security=on']::text[],'4a17d8703cafed7884df3b5621032ce9e4326f4973b845360c6cc6fccab1f4ee','runtime'),
 ('enrollment_execution.audit_delivery_privileges(uuid)','plpgsql','v','u',true,false,true,2249::oid,'2950',ARRAY['p_environment','is_valid','diagnostic_code','profile_version']::text[],ARRAY[2950,16,25,21]::oid[],ARRAY['i','t','t','t']::"char"[],ARRAY['search_path=pg_catalog, pg_temp','row_security=on']::text[],'c9deaaf8e33181324f1d83d41f09edaefb4c65653978361eef250f26f09cd465','runtime'),
 ('enrollment_execution.guard_profile4_publication()','plpgsql','v','u',true,false,false,2279::oid,'',NULL::text[],NULL::oid[],NULL::"char"[],ARRAY['search_path=pg_catalog, pg_temp','row_security=on']::text[],'1788f276fbb79bea8210ec3e0bfca1cdda1fd3f8b84f969ff627b9e15e244718','owner'),
 ('public.api_database_session()','sql','s','u',true,false,false,16::oid,'',NULL::text[],NULL::oid[],NULL::"char"[],ARRAY['search_path=pg_catalog, pg_temp','row_security=on']::text[],'88e963c4aff785056da284398bd54b61535f88c3d7f1b18823b44176504e0a1f','public'),
 ('public.has_environment_membership(uuid,uuid)','sql','s','u',true,true,false,16::oid,'2950 2950',ARRAY['p_environment_id','p_principal_id']::text[],NULL::oid[],NULL::"char"[],ARRAY['search_path=pg_catalog, pg_temp','row_security=on']::text[],'a7f30b8a933c9731378e1cb8bb75152815012b8fa4e3a05a8a6d9f18db16d148','membership'),
 ('public.directory_database_access(uuid,uuid)','sql','s','u',true,false,false,16::oid,'2950 2950',ARRAY['p_environment','p_principal']::text[],NULL::oid[],NULL::"char"[],ARRAY['search_path=pg_catalog, pg_temp','row_security=off']::text[],'fede4f0373b9fa7231ae1e649197364b93934dfa927a1d0af472988e55a52a74','directory')
-- END generated API function roots
), functions AS (
 SELECT e.*,p.*,l.lanname FROM expected e
 LEFT JOIN pg_catalog.pg_namespace n ON n.nspname=pg_catalog.split_part(e.signature,'.',1)
 LEFT JOIN pg_catalog.pg_proc p ON p.pronamespace=n.oid
   AND p.proname=pg_catalog.split_part(pg_catalog.split_part(e.signature,'.',2),'(',1)
   AND p.proargtypes::text=e.argument_types
 LEFT JOIN pg_catalog.pg_language l ON l.oid=p.prolang
), fixed_expected_acl AS (
 SELECT p.oid function_oid,i.owner_oid grantor,g.grantee,'EXECUTE'::text privilege_type,false is_grantable
 FROM functions p CROSS JOIN identities i
 CROSS JOIN LATERAL (
   SELECT i.owner_oid grantee
   UNION ALL SELECT 0::oid WHERE p.acl_kind='public'
   UNION ALL SELECT role_oid FROM pg_catalog.unnest(ARRAY[i.api_oid,i.plan_oid,i.execution_oid,i.queue_oid,i.delivery_oid]) role_oid
     WHERE p.acl_kind='membership' OR (p.acl_kind='directory' AND role_oid<>i.queue_oid)
 ) g WHERE p.acl_kind<>'runtime'
), actual_acl AS (
 SELECT p.oid function_oid,p.acl_kind,a.grantor,a.grantee,a.privilege_type,a.is_grantable
 FROM functions p CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) a
), fixed_actual_acl AS (
 SELECT function_oid,grantor,grantee,privilege_type,is_grantable FROM actual_acl WHERE acl_kind<>'runtime'
)
SELECT COALESCE((SELECT
 CURRENT_USER=SESSION_USER AND pg_catalog.current_setting('search_path') IN('pg_catalog,pg_temp','pg_catalog, pg_temp')
 AND (SELECT count(*)=1 AND bool_and(n.nspowner=i.owner_oid
     AND NOT pg_catalog.has_schema_privilege(i.api_oid,n.oid,'USAGE,CREATE'))
   FROM pg_catalog.pg_namespace n WHERE n.nspname='enrollment_execution')
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace n
   CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(n.nspacl,pg_catalog.acldefault('n',n.nspowner))) a
   WHERE n.nspname='enrollment_execution' AND a.grantee=0)
 AND (SELECT count(*)=6 AND count(DISTINCT id)=6 FROM pg_catalog.unnest(ARRAY[i.owner_oid,i.api_oid,i.plan_oid,i.execution_oid,i.queue_oid,i.delivery_oid]) id)
 AND (SELECT count(*)=6 AND bool_and(r.rolcanlogin=(r.oid IN(i.owner_oid,i.api_oid))
     AND NOT(r.rolsuper OR r.rolbypassrls OR r.rolcreatedb OR r.rolcreaterole OR r.rolinherit OR r.rolreplication))
   FROM pg_catalog.pg_roles r WHERE r.oid IN(i.owner_oid,i.api_oid,i.plan_oid,i.execution_oid,i.queue_oid,i.delivery_oid))
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members m
   WHERE m.member IN(i.owner_oid,i.api_oid,i.plan_oid,i.execution_oid,i.queue_oid,i.delivery_oid)
      OR m.roleid IN(i.owner_oid,i.api_oid,i.plan_oid,i.execution_oid,i.queue_oid,i.delivery_oid))
 AND NOT pg_catalog.has_parameter_privilege(i.api_oid,'session_replication_role','SET')
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_parameter_acl p CROSS JOIN LATERAL pg_catalog.aclexplode(p.paracl) a
   WHERE a.grantee IN(0,i.api_oid))
 AND (SELECT count(*)=7 AND bool_and(COALESCE(
   p.oid IS NOT NULL AND p.proowner=i.owner_oid AND p.lanname=p.language_name AND p.prokind='f'
   AND p.provolatile=p.volatility::"char" AND p.proparallel=p.parallel_code::"char"
   AND p.prosecdef=p.definer AND p.proisstrict=p.strict_value AND p.proretset=p.returns_set AND p.prorettype=p.return_oid
   AND NOT p.proleakproof AND p.prosupport=0 AND p.proargtypes::text=p.argument_types
   AND p.pronargs=pg_catalog.cardinality(p.proargtypes::oid[])
   AND p.proargnames IS NOT DISTINCT FROM p.argument_names AND p.proallargtypes IS NOT DISTINCT FROM p.all_argument_types
   AND p.proargmodes IS NOT DISTINCT FROM p.argument_modes AND p.proconfig IS NOT DISTINCT FROM p.configuration
   AND p.pronargdefaults=0 AND p.proargdefaults IS NULL AND p.provariadic=0 AND p.protrftypes IS NULL
   AND p.probin IS NULL AND p.prosqlbody IS NULL
   AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(pg_catalog.replace(p.prosrc,E'\r\n',E'\n'),'UTF8')),'hex')=p.body_hash
   AND (SELECT count(*)=1 FROM pg_catalog.pg_proc overload WHERE overload.pronamespace=p.pronamespace AND overload.proname=p.proname),false)) FROM functions p)
 AND (SELECT count(*)=15 FROM fixed_expected_acl) AND (SELECT count(*)=15 FROM fixed_actual_acl)
 AND NOT EXISTS((SELECT * FROM fixed_expected_acl EXCEPT SELECT * FROM fixed_actual_acl)
   UNION ALL (SELECT * FROM fixed_actual_acl EXCEPT SELECT * FROM fixed_expected_acl))
 -- The private reservation-derived dynamic ACL is checked by pinned maintenance
 -- at publication. Catalog preflight must still reject PUBLIC/API/grant options.
 AND NOT EXISTS(SELECT 1 FROM functions p WHERE p.acl_kind='runtime'
   AND (pg_catalog.has_function_privilege(i.api_oid,p.oid,'EXECUTE')
     OR NOT EXISTS(SELECT 1 FROM actual_acl a WHERE a.function_oid=p.oid AND a.grantee=i.owner_oid)))
 AND NOT EXISTS(SELECT 1 FROM actual_acl a LEFT JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
   WHERE a.acl_kind='runtime' AND (a.grantor<>i.owner_oid OR a.grantee IN(0,i.api_oid)
     OR a.privilege_type<>'EXECUTE' OR a.is_grantable OR r.oid IS NULL
     OR r.rolsuper OR r.rolbypassrls OR r.rolcreatedb OR r.rolcreaterole OR r.rolinherit OR r.rolreplication
     OR EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members m WHERE m.member=r.oid OR m.roleid=r.oid)))
 FROM identities i),false) AS is_valid;
