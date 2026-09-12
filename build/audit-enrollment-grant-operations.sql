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
reject_function AS (SELECT p.*,l.lanname FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_language l ON l.oid=p.prolang
 WHERE p.oid='public.reject_enrollment_grant_operation_mutation()'::regprocedure),
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
 (SELECT count(*)=11 FROM pg_catalog.pg_constraint c,target WHERE c.conrelid=target.oid AND c.contype<>'n') AND
 NOT EXISTS(SELECT * FROM expected_indexes EXCEPT SELECT * FROM actual_indexes) AND
 NOT EXISTS(SELECT * FROM actual_indexes EXCEPT SELECT * FROM expected_indexes) AND
 (SELECT count(*)=4 FROM pg_catalog.pg_index i,target WHERE i.indrelid=target.oid AND i.indisunique) AND
 (SELECT count(*)=2 AND bool_and(grantee=(SELECT oid FROM runtime) AND privilege_type IN ('SELECT','INSERT') AND NOT is_grantable) FROM actual_acl) AND
 (SELECT count(DISTINCT privilege_type)=2 FROM actual_acl) AND
 NOT EXISTS(SELECT 1 FROM pg_catalog.pg_attribute a,target CROSS JOIN LATERAL pg_catalog.aclexplode(a.attacl) acl WHERE a.attrelid=target.oid) AND
 (SELECT count(*)=1 FROM pg_catalog.pg_policy p,target WHERE p.polrelid=target.oid) AND
 (SELECT count(*)=1 FROM pg_catalog.pg_policy p,target WHERE p.polrelid=target.oid AND p.polname='environment_enrollment_grant_operations'
    AND p.polcmd='*' AND p.polpermissive AND p.polroles=ARRAY[0::oid]
    AND pg_catalog.pg_get_expr(p.polqual,p.polrelid)=pg_catalog.pg_get_expr(p.polwithcheck,p.polrelid)
    AND pg_catalog.pg_get_expr(p.polqual,p.polrelid)='((("EnvironmentId")::text = current_setting(''app.environment_id''::text, true)) AND ("RequesterId" = (NULLIF(current_setting(''app.principal_id''::text, true), ''''::text))::uuid) AND has_environment_membership("EnvironmentId", (NULLIF(current_setting(''app.principal_id''::text, true), ''''::text))::uuid))') AND
 (SELECT count(*)=1 FROM pg_catalog.pg_trigger t,target WHERE t.tgrelid=target.oid AND NOT t.tgisinternal) AND
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
