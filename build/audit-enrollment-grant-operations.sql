-- Shared by runtime provisioning and the API's embedded, uncached catalog audit.
WITH runtime AS (SELECT * FROM pg_catalog.pg_roles WHERE rolname=:'runtime_role'),
target AS (SELECT * FROM pg_catalog.pg_class WHERE oid='public."EnrollmentGrantOperations"'::regclass),
expected_columns(name,type_name) AS (VALUES
 ('EnvironmentId','uuid'),('Id','uuid'),('PlanId','uuid'),('RequestId','uuid'),('ApprovalId','uuid'),
 ('RequesterId','uuid'),('ApproverId','uuid'),('RequesterOperatorId','uuid'),('ApproverOperatorId','uuid'),
 ('PlanHash','character varying(64)'),('DirectoryObjectId','uuid'),('ServerDeviceId','uuid'),
 ('MappingCreatedAt','timestamp with time zone'),('DirectoryGeneration','uuid'),('EnvironmentVersion','bigint'),
 ('RecipientSpki','bytea'),('RecipientKeyFingerprint','bytea'),('QueuedAt','timestamp with time zone'),
 ('AuthorizationNotAfter','timestamp with time zone')),
actual_columns AS (SELECT a.attname::text AS name,pg_catalog.format_type(a.atttypid,a.atttypmod) AS type_name
 FROM pg_catalog.pg_attribute a,target WHERE a.attrelid=target.oid AND a.attnum>0 AND NOT a.attisdropped AND a.attnotnull),
expected_constraints(definition) AS (VALUES
 ('PRIMARY KEY ("Id")'),
 ('FOREIGN KEY ("EnvironmentId", "ApprovalId", "PlanId", "PlanHash", "ApproverId") REFERENCES "Approvals"("EnvironmentId", "Id", "PlanId", "PlanHash", "ApproverId") ON DELETE RESTRICT'),
 ('FOREIGN KEY ("RecipientKeyFingerprint", "EnvironmentId", "PlanId", "RequesterId", "RequestId") REFERENCES "EnrollmentGrantRecipientReservations"("Fingerprint", "EnvironmentId", "PlanId", "RequesterId", "RequestId") ON DELETE RESTRICT'),
 ('FOREIGN KEY ("EnvironmentId") REFERENCES "Environments"("Id") ON DELETE RESTRICT'),
 ('FOREIGN KEY ("EnvironmentId", "PlanId", "RequesterId", "PlanHash") REFERENCES "Plans"("EnvironmentId", "Id", "RequesterId", "PlanHash") ON DELETE RESTRICT'),
 ('CHECK ("EnvironmentId" <> ''00000000-0000-0000-0000-000000000000''::uuid AND "Id" <> ''00000000-0000-0000-0000-000000000000''::uuid AND "RequestId" <> ''00000000-0000-0000-0000-000000000000''::uuid AND "PlanId" <> ''00000000-0000-0000-0000-000000000000''::uuid AND "ApprovalId" <> ''00000000-0000-0000-0000-000000000000''::uuid AND "RequesterId" <> ''00000000-0000-0000-0000-000000000000''::uuid AND "ApproverId" <> ''00000000-0000-0000-0000-000000000000''::uuid AND "RequesterOperatorId" <> ''00000000-0000-0000-0000-000000000000''::uuid AND "ApproverOperatorId" <> ''00000000-0000-0000-0000-000000000000''::uuid AND "DirectoryObjectId" <> ''00000000-0000-0000-0000-000000000000''::uuid AND "ServerDeviceId" <> ''00000000-0000-0000-0000-000000000000''::uuid AND "DirectoryGeneration" <> ''00000000-0000-0000-0000-000000000000''::uuid)'),
 ('CHECK ("RequesterId" <> "ApproverId" AND "RequesterOperatorId" <> "ApproverOperatorId")'),
 ('CHECK ("PlanHash"::text ~ ''^[0-9a-f]{64}$''::text)'),
 ('CHECK (octet_length("RecipientKeyFingerprint") = 32 AND octet_length("RecipientSpki") >= 1 AND octet_length("RecipientSpki") <= 512)'),
 ('CHECK (isfinite("MappingCreatedAt") AND isfinite("QueuedAt") AND isfinite("AuthorizationNotAfter") AND "MappingCreatedAt" <= "QueuedAt" AND "QueuedAt" < "AuthorizationNotAfter" AND "AuthorizationNotAfter" <= ("QueuedAt" + ''00:10:00''::interval))'),
 ('CHECK ("EnvironmentVersion" > 0)')),
actual_constraints AS (SELECT pg_catalog.pg_get_constraintdef(c.oid,true) AS definition FROM pg_catalog.pg_constraint c,target
 WHERE c.conrelid=target.oid AND c.contype IN ('p','f','c') AND c.convalidated AND NOT c.condeferrable AND NOT c.condeferred),
expected_indexes(columns,is_primary) AS (VALUES
 (ARRAY['Id'],true),(ARRAY['EnvironmentId','PlanId'],false),(ARRAY['EnvironmentId','ApprovalId'],false),(ARRAY['RecipientKeyFingerprint'],false)),
actual_indexes AS (SELECT ARRAY(SELECT a.attname::text FROM pg_catalog.unnest(i.indkey) WITH ORDINALITY k(attnum,ord)
 JOIN pg_catalog.pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=k.attnum ORDER BY k.ord) AS columns,i.indisprimary AS is_primary
 FROM pg_catalog.pg_index i,target WHERE i.indrelid=target.oid AND i.indisunique AND i.indisvalid AND i.indisready
 AND i.indpred IS NULL AND i.indexprs IS NULL AND i.indnkeyatts=i.indnatts),
actual_acl AS (SELECT a.grantee,a.privilege_type,a.is_grantable FROM target
 CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(target.relacl,pg_catalog.acldefault('r',target.relowner))) a
 WHERE a.grantee<>target.relowner),
expected_anchor_functions(name,body_hash) AS (VALUES
 ('guard_enrollment_grant_queued_plan','9f512ab9a91c03ec1e6a83dc02610011f7edf5c2fd83d44ac4c7f35b7630b8c1'),
 ('guard_enrollment_grant_plan_child','51754c0c18f36458af4050f84ce398cf44047e9c7f0b3cf42ddecd407d5f555a'),
 ('guard_enrollment_grant_operation_parent','ca589dc3bd8d3564edbe67d05b996c2b73d7bc726b2c22fec05dab51cef5d191'),
 ('guard_enrollment_grant_outbox_anchor','d1b1ffe039cb98aa9eefcd1d07ad9477da79350f88584a257efa6f2b62eb015f'),
 ('validate_enrollment_grant_queue_anchor',CASE WHEN
    (SELECT pg_catalog.btrim(prosrc,E' \t\r\n') FROM pg_catalog.pg_proc
     WHERE pronamespace=(SELECT oid FROM pg_catalog.pg_namespace WHERE nspname='enrollment_execution') AND proname='execution_store_profile' AND pronargs=0)='SELECT 3::smallint'
    THEN 'dd8064d70027f2b4ae9070970e54aa183e1f70bb4c8798b64f751673de59ee27'
    ELSE '7c6f273e7eb359289dc69e4e7a0d7d95efd951f93cccc464c3da56e553e61d7c' END)),
anchor_functions AS (SELECT p.*,l.lanname,e.body_hash FROM pg_catalog.pg_proc p
 JOIN pg_catalog.pg_language l ON l.oid=p.prolang
 JOIN expected_anchor_functions e ON p.pronamespace='public'::regnamespace AND p.proname=e.name),
expected_anchor_triggers(table_name,name,type_code,function_name,deferred) AS (VALUES
 ('Plans','enrollment_grant_queued_plan_immutable',31,'guard_enrollment_grant_queued_plan',false),
 ('PlanItems','enrollment_grant_plan_items_anchor',31,'guard_enrollment_grant_plan_child',false),
 ('Approvals','enrollment_grant_approvals_anchor',31,'guard_enrollment_grant_plan_child',false),
 ('EnrollmentGrantOperations','enrollment_grant_operation_parent',7,'guard_enrollment_grant_operation_parent',false),
 ('Outbox','enrollment_grant_outbox_anchor',31,'guard_enrollment_grant_outbox_anchor',false),
 ('Plans','enrollment_grant_plan_anchor_consistent',21,'validate_enrollment_grant_queue_anchor',true),
 ('EnrollmentGrantOperations','enrollment_grant_operation_anchor_consistent',5,'validate_enrollment_grant_queue_anchor',true),
 ('Outbox','enrollment_grant_outbox_anchor_consistent',29,'validate_enrollment_grant_queue_anchor',true)),
valid_anchor_triggers AS (SELECT e.* FROM expected_anchor_triggers e
 JOIN pg_catalog.pg_class c ON c.relnamespace='public'::regnamespace AND c.relname=e.table_name
 JOIN pg_catalog.pg_trigger t ON t.tgrelid=c.oid AND t.tgname=e.name
 JOIN anchor_functions f ON f.oid=t.tgfoid AND f.proname=e.function_name
 WHERE NOT t.tgisinternal AND t.tgenabled='O' AND t.tgtype=e.type_code AND t.tgnargs=0
 AND t.tgqual IS NULL AND t.tgattr=''::int2vector AND t.tgoldtable IS NULL AND t.tgnewtable IS NULL
 AND t.tgdeferrable=e.deferred AND t.tginitdeferred=e.deferred
 AND (CASE WHEN e.deferred THEN EXISTS(SELECT 1 FROM pg_catalog.pg_constraint k
     WHERE k.oid=t.tgconstraint AND k.conrelid=c.oid AND k.contype='t' AND k.condeferrable AND k.condeferred)
     ELSE t.tgconstraint=0 END)),
reject_function AS (SELECT p.*,l.lanname FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_language l ON l.oid=p.prolang
 WHERE p.oid='public.reject_enrollment_grant_operation_mutation()'::regprocedure),
execution_profile AS (SELECT COALESCE((SELECT count(*)=1 AND bool_and(l.lanname='sql' AND NOT p.prosecdef
 AND p.provolatile='i' AND p.proparallel='s' AND NOT p.proretset AND p.prorettype='smallint'::regtype
 AND p.pronargs=0 AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']
 AND p.proowner=(SELECT relowner FROM target) AND pg_catalog.btrim(p.prosrc,E' \t\r\n') IN('SELECT 2::smallint','SELECT 3::smallint'))
 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_language l ON l.oid=p.prolang
 JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
 WHERE n.nspname='enrollment_execution' AND p.proname='execution_store_profile' AND p.pronargs=0)
 AND (SELECT count(*)=1 AND bool_and(l.lanname='plpgsql' AND p.prosecdef AND p.provolatile='s' AND p.proparallel='u'
   AND p.proowner=(SELECT relowner FROM target) AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp','row_security=on']
   AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
     pg_catalog.btrim(pg_catalog.regexp_replace(p.prosrc,'[[:space:]]+',' ','g')),'UTF8')),'hex')
     =CASE (SELECT pg_catalog.btrim(marker.prosrc,E' \t\r\n') FROM pg_catalog.pg_proc marker
              WHERE marker.pronamespace=(SELECT oid FROM pg_catalog.pg_namespace WHERE nspname='enrollment_execution') AND marker.proname='execution_store_profile' AND marker.pronargs=0)
        WHEN 'SELECT 2::smallint' THEN '8ed83a1a4736e9caab7c0a9c32ef8b2e53b48dbdcf184824a8436d3fc33d3da3'
        WHEN 'SELECT 3::smallint' THEN 'b25732a9b6d2e524f4263ff4826ece6625420ca522d28f3b0aeb9fe3f1df4f80'
        ELSE '' END)
  FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_language l ON l.oid=p.prolang
  JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
  WHERE n.nspname='enrollment_execution' AND p.proname='audit_execution_privileges' AND p.proargtypes='2950'::oidvector),false) installed),
execution_definer AS (SELECT r.oid FROM pg_catalog.pg_proc p
 JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace JOIN pg_catalog.pg_roles r ON r.oid=p.proowner,execution_profile profile
 WHERE profile.installed AND n.nspname='enrollment_execution' AND p.proname='read_execution_record'
   AND p.pronargs=2 AND p.proargtypes='2950 2950'::oidvector AND NOT r.rolcanlogin AND NOT r.rolsuper
   AND NOT r.rolbypassrls AND NOT r.rolcreatedb AND NOT r.rolcreaterole AND NOT r.rolinherit AND NOT r.rolreplication),
execution_queue_definer AS (SELECT r.oid FROM pg_catalog.pg_proc p
 JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace JOIN pg_catalog.pg_roles r ON r.oid=p.proowner,execution_profile profile
 WHERE profile.installed AND pg_catalog.btrim((SELECT prosrc FROM pg_catalog.pg_proc
       WHERE pronamespace=(SELECT oid FROM pg_catalog.pg_namespace WHERE nspname='enrollment_execution') AND proname='execution_store_profile' AND pronargs=0),E' \t\r\n')='SELECT 3::smallint'
   AND n.nspname='enrollment_execution' AND p.proname='claim_next' AND p.proargtypes='2950 2950'::oidvector
   AND NOT r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolbypassrls AND NOT r.rolcreatedb
   AND NOT r.rolcreaterole AND NOT r.rolinherit AND NOT r.rolreplication),
execution_operation_policies AS (SELECT p.* FROM pg_catalog.pg_policy p,execution_definer d,target
 WHERE p.polrelid=target.oid AND p.polroles=ARRAY[d.oid]
   AND p.polname IN('enrollment_execution_worker_operations_allow','enrollment_execution_worker_operations_limit')),
execution_queue_operation_policies AS (SELECT p.* FROM pg_catalog.pg_policy p,execution_queue_definer d,target
 WHERE p.polrelid=target.oid AND p.polroles=ARRAY[d.oid]
   AND p.polname IN('enrollment_execution_queue_operations_allow','enrollment_execution_queue_operations_limit')),
verified AS (SELECT COALESCE(
 (SELECT count(*)=1 AND bool_and(rolcanlogin AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolinherit AND NOT rolreplication) FROM runtime) AND
 NOT EXISTS(SELECT 1 FROM runtime r JOIN pg_catalog.pg_auth_members m ON m.roleid=r.oid OR m.member=r.oid) AND
 (SELECT count(*)=1 AND bool_and(relkind='r' AND relrowsecurity AND relforcerowsecurity AND
    relowner=(SELECT relowner FROM pg_catalog.pg_class WHERE oid='public."Plans"'::regclass) AND relowner<>(SELECT oid FROM runtime)) FROM target) AND
 NOT EXISTS(SELECT * FROM expected_columns EXCEPT SELECT * FROM actual_columns) AND
 NOT EXISTS(SELECT * FROM actual_columns EXCEPT SELECT * FROM expected_columns) AND
 (SELECT count(*)=19 FROM pg_catalog.pg_attribute a,target WHERE a.attrelid=target.oid AND a.attnum>0 AND NOT a.attisdropped) AND
 NOT EXISTS(SELECT 1 FROM pg_catalog.pg_attribute a,target WHERE a.attrelid=target.oid AND (a.attidentity<>'' OR a.attgenerated<>'' OR a.atthasdef)) AND
 NOT EXISTS(SELECT * FROM expected_constraints EXCEPT SELECT * FROM actual_constraints) AND
 NOT EXISTS(SELECT * FROM actual_constraints EXCEPT SELECT * FROM expected_constraints) AND
 (SELECT count(*)=12 FROM pg_catalog.pg_constraint c,target WHERE c.conrelid=target.oid AND c.contype<>'n') AND
 NOT EXISTS(SELECT * FROM expected_indexes EXCEPT SELECT * FROM actual_indexes) AND
 NOT EXISTS(SELECT * FROM actual_indexes EXCEPT SELECT * FROM expected_indexes) AND
 (SELECT count(*)=4 FROM pg_catalog.pg_index i,target WHERE i.indrelid=target.oid AND i.indisunique) AND
 (SELECT count(*)=2 AND bool_and(grantee=(SELECT oid FROM runtime) AND privilege_type IN ('SELECT','INSERT') AND NOT is_grantable) FROM actual_acl) AND
 (SELECT count(DISTINCT privilege_type)=2 FROM actual_acl) AND
 (SELECT CASE WHEN profile.installed THEN NOT EXISTS(
      WITH expected(name,privilege_type) AS (SELECT name,'SELECT' FROM expected_columns UNION ALL VALUES('PlanHash','UPDATE')),
      actual AS (SELECT a.attname::text name,acl.privilege_type::text privilege_type
        FROM pg_catalog.pg_attribute a,target CROSS JOIN LATERAL pg_catalog.aclexplode(a.attacl) acl
        WHERE a.attrelid=target.oid AND acl.grantee=(SELECT oid FROM execution_definer) AND NOT acl.is_grantable),
      difference AS ((SELECT * FROM expected EXCEPT SELECT * FROM actual) UNION ALL (SELECT * FROM actual EXCEPT SELECT * FROM expected))
      SELECT 1 FROM difference)
    AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_attribute a,target CROSS JOIN LATERAL pg_catalog.aclexplode(a.attacl) acl
      WHERE a.attrelid=target.oid AND (acl.grantee NOT IN((SELECT oid FROM execution_definer),(SELECT oid FROM execution_queue_definer)) OR acl.is_grantable))
    AND (CASE WHEN pg_catalog.btrim((SELECT prosrc FROM pg_catalog.pg_proc
          WHERE pronamespace=(SELECT oid FROM pg_catalog.pg_namespace WHERE nspname='enrollment_execution') AND proname='execution_store_profile' AND pronargs=0),E' \t\r\n')='SELECT 3::smallint'
      THEN NOT EXISTS(
        WITH expected(name,privilege_type) AS (VALUES('EnvironmentId','SELECT'),('Id','SELECT'),('QueuedAt','SELECT')),
        actual AS (SELECT a.attname::text,acl.privilege_type::text FROM pg_catalog.pg_attribute a,target
          CROSS JOIN LATERAL pg_catalog.aclexplode(a.attacl) acl
          WHERE a.attrelid=target.oid AND acl.grantee=(SELECT oid FROM execution_queue_definer) AND NOT acl.is_grantable)
        SELECT 1 FROM ((SELECT * FROM expected EXCEPT SELECT * FROM actual)
          UNION ALL (SELECT * FROM actual EXCEPT SELECT * FROM expected)) difference)
      ELSE NOT EXISTS(SELECT 1 FROM pg_catalog.pg_attribute a,target CROSS JOIN LATERAL pg_catalog.aclexplode(a.attacl) acl
        WHERE a.attrelid=target.oid AND acl.grantee<>(SELECT oid FROM execution_definer)) END)
    ELSE NOT EXISTS(SELECT 1 FROM pg_catalog.pg_attribute a,target CROSS JOIN LATERAL pg_catalog.aclexplode(a.attacl) acl
      WHERE a.attrelid=target.oid) END FROM execution_profile profile) AND
 (SELECT count(*)=CASE WHEN pg_catalog.btrim((SELECT prosrc FROM pg_catalog.pg_proc
       WHERE pronamespace=(SELECT oid FROM pg_catalog.pg_namespace WHERE nspname='enrollment_execution') AND proname='execution_store_profile' AND pronargs=0),E' \t\r\n')='SELECT 3::smallint' THEN 5
      WHEN (SELECT installed FROM execution_profile) THEN 3 ELSE 1 END FROM pg_catalog.pg_policy p,target WHERE p.polrelid=target.oid) AND
 (SELECT count(*)=1 FROM pg_catalog.pg_policy p,target WHERE p.polrelid=target.oid AND p.polname='environment_enrollment_grant_operations'
    AND p.polcmd='*' AND p.polpermissive AND p.polroles=ARRAY[0::oid]
    AND pg_catalog.pg_get_expr(p.polqual,p.polrelid)=pg_catalog.pg_get_expr(p.polwithcheck,p.polrelid)
    AND pg_catalog.pg_get_expr(p.polqual,p.polrelid)='((("EnvironmentId")::text = current_setting(''app.environment_id''::text, true)) AND ("RequesterId" = (NULLIF(current_setting(''app.principal_id''::text, true), ''''::text))::uuid) AND has_environment_membership("EnvironmentId", (NULLIF(current_setting(''app.principal_id''::text, true), ''''::text))::uuid))') AND
 (SELECT NOT installed OR (SELECT count(*)=2 AND bool_and(polcmd='*'
      AND ((polname='enrollment_execution_worker_operations_allow' AND polpermissive)
        OR (polname='enrollment_execution_worker_operations_limit' AND NOT polpermissive))
      AND pg_catalog.pg_get_expr(polqual,polrelid)=pg_catalog.pg_get_expr(polwithcheck,polrelid)
      AND pg_catalog.md5(COALESCE(pg_catalog.pg_get_expr(polqual,polrelid),'')||'|'||
                         COALESCE(pg_catalog.pg_get_expr(polwithcheck,polrelid),''))='b36fd52c8f5d4554c711240c8bfbf7b1')
      FROM execution_operation_policies) FROM execution_profile) AND
 (SELECT CASE WHEN pg_catalog.btrim((SELECT prosrc FROM pg_catalog.pg_proc
       WHERE pronamespace=(SELECT oid FROM pg_catalog.pg_namespace WHERE nspname='enrollment_execution') AND proname='execution_store_profile' AND pronargs=0),E' \t\r\n') IS DISTINCT FROM 'SELECT 3::smallint' THEN true
   ELSE (SELECT count(*)=2 AND bool_and(polcmd='*'
      AND ((polname='enrollment_execution_queue_operations_allow' AND polpermissive)
        OR (polname='enrollment_execution_queue_operations_limit' AND NOT polpermissive))
      AND polqual IS NOT NULL AND polwithcheck IS NULL) FROM execution_queue_operation_policies) END) AND
 (SELECT count(*)=CASE WHEN (SELECT installed FROM execution_profile) THEN 4 ELSE 3 END FROM pg_catalog.pg_trigger t,target
    WHERE t.tgrelid=target.oid AND NOT t.tgisinternal) AND
 (SELECT count(*)=8 FROM valid_anchor_triggers) AND
 NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c,runtime r
    WHERE c.relnamespace='public'::regnamespace AND c.relname IN ('Plans','PlanItems','Approvals','Outbox')
    AND (pg_catalog.has_table_privilege(r.oid,c.oid,'TRUNCATE') OR pg_catalog.has_table_privilege(r.oid,c.oid,'TRIGGER'))) AND
 NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_class c ON c.oid=t.tgrelid
    WHERE c.relnamespace='public'::regnamespace AND c.relname IN ('Plans','PlanItems','Approvals','Outbox')
    AND NOT t.tgisinternal AND NOT EXISTS(SELECT 1 FROM expected_anchor_triggers e
        WHERE e.table_name=c.relname AND e.name=t.tgname)
    AND NOT ((SELECT installed FROM execution_profile) AND (
      (c.relname='Plans' AND t.tgname='enrollment_execution_worker_plan_guard') OR
      (c.relname='Outbox' AND t.tgname='enrollment_execution_worker_outbox_guard') OR
      (c.relname='EnrollmentGrantOperations' AND t.tgname='enrollment_execution_worker_operation_guard') OR
      (c.relname='Outbox' AND t.tgname='work_queue_outbox_consistent'
        AND pg_catalog.btrim((SELECT prosrc FROM pg_catalog.pg_proc
          WHERE pronamespace=(SELECT oid FROM pg_catalog.pg_namespace WHERE nspname='enrollment_execution') AND proname='execution_store_profile' AND pronargs=0),E' \t\r\n')='SELECT 3::smallint'
        AND t.tgfoid=(SELECT oid FROM pg_catalog.pg_proc WHERE pronamespace=(SELECT oid FROM pg_catalog.pg_namespace WHERE nspname='enrollment_execution') AND proname='validate_work_queue' AND pronargs=0)
        AND t.tgtype=21 AND t.tgdeferrable AND t.tginitdeferred)))) AND
 (SELECT count(*)=5 AND bool_and(lanname='plpgsql' AND NOT prosecdef AND provolatile='v' AND proparallel='u'
    AND prokind='f' AND NOT proretset AND prorettype='trigger'::regtype AND pronargs=0 AND proargtypes=''::oidvector
    AND proargnames IS NULL AND proallargtypes IS NULL AND proargmodes IS NULL
    AND proconfig=ARRAY['search_path=pg_catalog, pg_temp'] AND proowner=(SELECT relowner FROM target)
    AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
        pg_catalog.btrim(pg_catalog.regexp_replace(prosrc,'[[:space:]]+',' ','g')),'UTF8')),'hex')=body_hash)
    FROM anchor_functions) AND
 (SELECT count(*)=5 AND bool_and(acl.grantee=f.proowner AND acl.privilege_type='EXECUTE' AND NOT acl.is_grantable)
    FROM anchor_functions f CROSS JOIN LATERAL pg_catalog.aclexplode(
        COALESCE(f.proacl,pg_catalog.acldefault('f',f.proowner))) acl) AND
 (SELECT count(*)=1 FROM pg_catalog.pg_trigger t,target WHERE t.tgrelid=target.oid AND NOT t.tgisinternal
    AND t.tgname='enrollment_grant_operations_immutable' AND t.tgenabled='O' AND t.tgtype=27 AND t.tgnargs=0 AND t.tgqual IS NULL
    AND t.tgfoid=(SELECT oid FROM reject_function)) AND
 (SELECT count(*)=1 AND bool_and(lanname='plpgsql' AND NOT prosecdef AND provolatile='v' AND proparallel='u' AND prokind='f' AND NOT proretset
    AND prorettype='trigger'::regtype AND pronargs=0 AND proargtypes=''::oidvector AND proargnames IS NULL AND proallargtypes IS NULL AND proargmodes IS NULL
    AND proconfig=ARRAY['search_path=pg_catalog, public, pg_temp'] AND proowner=(SELECT relowner FROM target)
    AND pg_catalog.btrim(pg_catalog.regexp_replace(prosrc,'[[:space:]]+',' ','g'))='BEGIN RAISE EXCEPTION USING ERRCODE=''55000'', MESSAGE=''Enrollment grant operations are immutable.''; END') FROM reject_function) AND
 (SELECT count(*)=1 AND bool_and(acl.grantee=f.proowner AND acl.privilege_type='EXECUTE' AND NOT acl.is_grantable) FROM reject_function f
    CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(f.proacl,pg_catalog.acldefault('f',f.proowner))) acl) AND
 EXISTS(SELECT 1 FROM pg_catalog.pg_constraint WHERE conrelid='public."Plans"'::regclass AND conname='enrollment_grant_only_dedicated_queue'
    AND contype='c' AND convalidated AND pg_catalog.pg_get_constraintdef(oid,true)='CHECK ("State" <> 5 OR "Action" = ''agent-enrollment.initial-grant.v1''::text)'),false) AS valid)
SELECT CASE WHEN valid THEN 1 ELSE 1/(pg_catalog.pg_backend_pid()-pg_catalog.pg_backend_pid()) END AS "Value" FROM verified;
