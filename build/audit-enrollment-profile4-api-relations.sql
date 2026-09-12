-- UNCONSUMED public relation slice; compose with function/role/policy/trigger contracts.
-- Catalog-only under a preceding transaction-local search_path=pg_catalog,pg_temp.
WITH identities AS (
 SELECT c.relowner owner_oid,r.oid api_oid,
   (SELECT p.proowner FROM pg_catalog.pg_proc p WHERE p.oid=pg_catalog.to_regprocedure('public.lock_enrollment_grant_plan_context(uuid,uuid,uuid[])')) plan_oid,
   (SELECT p.proowner FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
     WHERE n.nspname='enrollment_execution' AND p.proname='read_execution_record' AND p.proargtypes::text='2950 2950') execution_oid,
   (SELECT p.proowner FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
     WHERE n.nspname='enrollment_execution' AND p.proname='claim_next' AND p.proargtypes::text='2950 2950') queue_oid,
   (SELECT p.proowner FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
     WHERE n.nspname='enrollment_execution' AND p.proname='read_grant_delivery' AND p.proargtypes::text='2950 2950 2950 25') delivery_oid
 FROM pg_catalog.pg_class c CROSS JOIN pg_catalog.pg_roles r
 WHERE c.oid=pg_catalog.to_regclass('public."Environments"') AND r.rolname=SESSION_USER
), relations AS (
 SELECT c.* FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='public' AND c.relname IN('EnrollmentGrantOperations','EnrollmentGrantRecipientReservations','Memberships')
), expected_columns(table_name,position,name,type_oid,type_modifier,collation_oid) AS (VALUES
-- BEGIN generated API relation columns
 ('EnrollmentGrantOperations',1,'Id',2950::oid,-1,0::oid),
 ('EnrollmentGrantOperations',2,'EnvironmentId',2950::oid,-1,0::oid),
 ('EnrollmentGrantOperations',3,'PlanId',2950::oid,-1,0::oid),
 ('EnrollmentGrantOperations',4,'RequestId',2950::oid,-1,0::oid),
 ('EnrollmentGrantOperations',5,'ApprovalId',2950::oid,-1,0::oid),
 ('EnrollmentGrantOperations',6,'RequesterId',2950::oid,-1,0::oid),
 ('EnrollmentGrantOperations',7,'ApproverId',2950::oid,-1,0::oid),
 ('EnrollmentGrantOperations',8,'RequesterOperatorId',2950::oid,-1,0::oid),
 ('EnrollmentGrantOperations',9,'ApproverOperatorId',2950::oid,-1,0::oid),
 ('EnrollmentGrantOperations',10,'PlanHash',1043::oid,68,pg_catalog.to_regcollation('pg_catalog."default"')::oid),
 ('EnrollmentGrantOperations',11,'DirectoryObjectId',2950::oid,-1,0::oid),
 ('EnrollmentGrantOperations',12,'ServerDeviceId',2950::oid,-1,0::oid),
 ('EnrollmentGrantOperations',13,'MappingCreatedAt',1184::oid,-1,0::oid),
 ('EnrollmentGrantOperations',14,'DirectoryGeneration',2950::oid,-1,0::oid),
 ('EnrollmentGrantOperations',15,'EnvironmentVersion',20::oid,-1,0::oid),
 ('EnrollmentGrantOperations',16,'RecipientSpki',17::oid,-1,0::oid),
 ('EnrollmentGrantOperations',17,'RecipientKeyFingerprint',17::oid,-1,0::oid),
 ('EnrollmentGrantOperations',18,'QueuedAt',1184::oid,-1,0::oid),
 ('EnrollmentGrantOperations',19,'AuthorizationNotAfter',1184::oid,-1,0::oid),
 ('EnrollmentGrantRecipientReservations',1,'Fingerprint',17::oid,-1,0::oid),
 ('EnrollmentGrantRecipientReservations',2,'EnvironmentId',2950::oid,-1,0::oid),
 ('EnrollmentGrantRecipientReservations',3,'PlanId',2950::oid,-1,0::oid),
 ('EnrollmentGrantRecipientReservations',4,'RequesterId',2950::oid,-1,0::oid),
 ('EnrollmentGrantRecipientReservations',5,'RequestId',2950::oid,-1,0::oid),
 ('EnrollmentGrantRecipientReservations',6,'RequestDigest',17::oid,-1,0::oid),
 ('EnrollmentGrantRecipientReservations',7,'CreatedAt',1184::oid,-1,0::oid),
 ('Memberships',1,'EnvironmentId',2950::oid,-1,0::oid),
 ('Memberships',2,'PrincipalId',2950::oid,-1,0::oid),
 ('Memberships',3,'Active',16::oid,-1,0::oid)
-- END generated API relation columns
), actual_columns AS (
 SELECT c.relname::text table_name,a.attnum::integer position,a.attname::text name,a.atttypid type_oid,a.atttypmod type_modifier,a.attcollation collation_oid
 FROM relations c JOIN pg_catalog.pg_attribute a ON a.attrelid=c.oid
 WHERE a.attnum>0 AND NOT a.attisdropped AND a.attnotnull AND a.attidentity='' AND a.attgenerated='' AND NOT a.atthasdef
   AND NOT a.atthasmissing AND a.attmissingval IS NULL
), operation_constraints(definition) AS (VALUES
-- BEGIN generated API operation constraints
 ('PRIMARY KEY ("Id")'),
 ('FOREIGN KEY ("EnvironmentId", "ApprovalId", "PlanId", "PlanHash", "ApproverId") REFERENCES public."Approvals"("EnvironmentId", "Id", "PlanId", "PlanHash", "ApproverId") ON DELETE RESTRICT'),
 ('FOREIGN KEY ("RecipientKeyFingerprint", "EnvironmentId", "PlanId", "RequesterId", "RequestId") REFERENCES public."EnrollmentGrantRecipientReservations"("Fingerprint", "EnvironmentId", "PlanId", "RequesterId", "RequestId") ON DELETE RESTRICT'),
 ('FOREIGN KEY ("EnvironmentId") REFERENCES public."Environments"("Id") ON DELETE RESTRICT'),
 ('FOREIGN KEY ("EnvironmentId", "PlanId", "RequesterId", "PlanHash") REFERENCES public."Plans"("EnvironmentId", "Id", "RequesterId", "PlanHash") ON DELETE RESTRICT'),
 ('CHECK ("EnvironmentId" <> ''00000000-0000-0000-0000-000000000000''::uuid AND "Id" <> ''00000000-0000-0000-0000-000000000000''::uuid AND "RequestId" <> ''00000000-0000-0000-0000-000000000000''::uuid AND "PlanId" <> ''00000000-0000-0000-0000-000000000000''::uuid AND "ApprovalId" <> ''00000000-0000-0000-0000-000000000000''::uuid AND "RequesterId" <> ''00000000-0000-0000-0000-000000000000''::uuid AND "ApproverId" <> ''00000000-0000-0000-0000-000000000000''::uuid AND "RequesterOperatorId" <> ''00000000-0000-0000-0000-000000000000''::uuid AND "ApproverOperatorId" <> ''00000000-0000-0000-0000-000000000000''::uuid AND "DirectoryObjectId" <> ''00000000-0000-0000-0000-000000000000''::uuid AND "ServerDeviceId" <> ''00000000-0000-0000-0000-000000000000''::uuid AND "DirectoryGeneration" <> ''00000000-0000-0000-0000-000000000000''::uuid)'),
 ('CHECK ("RequesterId" <> "ApproverId" AND "RequesterOperatorId" <> "ApproverOperatorId")'),
 ('CHECK ("PlanHash"::text ~ ''^[0-9a-f]{64}$''::text)'),
 ('CHECK (octet_length("RecipientKeyFingerprint") = 32 AND octet_length("RecipientSpki") >= 1 AND octet_length("RecipientSpki") <= 512)'),
 ('CHECK (isfinite("MappingCreatedAt") AND isfinite("QueuedAt") AND isfinite("AuthorizationNotAfter") AND "MappingCreatedAt" <= "QueuedAt" AND "QueuedAt" < "AuthorizationNotAfter" AND "AuthorizationNotAfter" <= ("QueuedAt" + ''00:10:00''::interval))'),
 ('CHECK ("EnvironmentVersion" > 0)')
-- END generated API operation constraints
), expected_constraints(table_name,definition) AS (
 SELECT 'EnrollmentGrantOperations',definition FROM operation_constraints UNION ALL VALUES
 ('Memberships','PRIMARY KEY ("EnvironmentId", "PrincipalId")'),
 ('Memberships','FOREIGN KEY ("EnvironmentId") REFERENCES public."Environments"("Id") ON DELETE RESTRICT'),
 ('Memberships','FOREIGN KEY ("PrincipalId") REFERENCES public."Principals"("Id") ON DELETE RESTRICT'),
 ('EnrollmentGrantRecipientReservations','PRIMARY KEY ("Fingerprint")'),
 ('EnrollmentGrantRecipientReservations','UNIQUE ("Fingerprint", "EnvironmentId", "PlanId", "RequesterId", "RequestId")'),
 ('EnrollmentGrantRecipientReservations','FOREIGN KEY ("EnvironmentId", "PlanId") REFERENCES public."Plans"("EnvironmentId", "Id") ON DELETE RESTRICT'),
 ('EnrollmentGrantRecipientReservations','CHECK (octet_length("Fingerprint") = 32)'),
 ('EnrollmentGrantRecipientReservations','CHECK (octet_length("RequestDigest") = 32)'),
 ('EnrollmentGrantRecipientReservations','CHECK ("EnvironmentId" <> ''00000000-0000-0000-0000-000000000000''::uuid AND "PlanId" <> ''00000000-0000-0000-0000-000000000000''::uuid AND "RequesterId" <> ''00000000-0000-0000-0000-000000000000''::uuid AND "RequestId" <> ''00000000-0000-0000-0000-000000000000''::uuid)')
), actual_constraints AS (
 SELECT c.relname::text table_name,pg_catalog.pg_get_constraintdef(k.oid,true) definition
 FROM relations c JOIN pg_catalog.pg_constraint k ON k.conrelid=c.oid
 WHERE k.contype IN('p','u','f','c') AND k.convalidated AND k.conenforced AND NOT k.condeferrable AND NOT k.condeferred
   AND k.conislocal AND k.coninhcount=0 AND k.conparentid=0
), expected_indexes(table_name,columns,is_primary,is_unique) AS (VALUES
 ('EnrollmentGrantOperations',ARRAY['Id'],true,true),
 ('EnrollmentGrantOperations',ARRAY['EnvironmentId','PlanId'],false,true),
 ('EnrollmentGrantOperations',ARRAY['EnvironmentId','ApprovalId'],false,true),
 ('EnrollmentGrantOperations',ARRAY['RecipientKeyFingerprint'],false,true),
 ('EnrollmentGrantOperations',ARRAY['EnvironmentId','ApprovalId','PlanId','PlanHash','ApproverId'],false,false),
 ('EnrollmentGrantOperations',ARRAY['EnvironmentId','PlanId','RequesterId','PlanHash'],false,false),
 ('EnrollmentGrantOperations',ARRAY['RecipientKeyFingerprint','EnvironmentId','PlanId','RequesterId','RequestId'],false,false),
 ('EnrollmentGrantRecipientReservations',ARRAY['Fingerprint'],true,true),
 ('EnrollmentGrantRecipientReservations',ARRAY['EnvironmentId','PlanId'],false,true),
 ('EnrollmentGrantRecipientReservations',ARRAY['EnvironmentId','RequesterId','RequestId'],false,true),
 ('EnrollmentGrantRecipientReservations',ARRAY['Fingerprint','EnvironmentId','PlanId','RequesterId','RequestId'],false,true),
 ('Memberships',ARRAY['EnvironmentId','PrincipalId'],true,true),
 ('Memberships',ARRAY['PrincipalId'],false,false)
), actual_indexes AS (
 SELECT c.relname::text table_name,ARRAY(SELECT a.attname::text FROM pg_catalog.unnest(idx.indkey) WITH ORDINALITY key(attnum,position)
   JOIN pg_catalog.pg_attribute a ON a.attrelid=c.oid AND a.attnum=key.attnum ORDER BY key.position) columns,idx.indisprimary is_primary,idx.indisunique is_unique
 FROM relations c JOIN pg_catalog.pg_index idx ON idx.indrelid=c.oid
 JOIN pg_catalog.pg_class index_relation ON index_relation.oid=idx.indexrelid JOIN pg_catalog.pg_am am ON am.oid=index_relation.relam
 WHERE idx.indisvalid AND idx.indisready AND idx.indislive AND idx.indimmediate AND NOT idx.indnullsnotdistinct
   AND NOT idx.indcheckxmin AND NOT idx.indisreplident AND NOT idx.indisclustered AND NOT idx.indisexclusion
   AND idx.indpred IS NULL AND idx.indexprs IS NULL AND idx.indnkeyatts=idx.indnatts AND am.amname='btree'
   AND NOT EXISTS(SELECT 1 FROM pg_catalog.unnest(idx.indoption) option WHERE option<>0)
   AND NOT EXISTS(SELECT 1 FROM ROWS FROM(pg_catalog.unnest(idx.indkey),pg_catalog.unnest(idx.indclass),pg_catalog.unnest(idx.indcollation)) key(attnum,class_oid,collation_oid)
     JOIN pg_catalog.pg_attribute a ON a.attrelid=c.oid AND a.attnum=key.attnum
     JOIN pg_catalog.pg_opclass op ON op.oid=key.class_oid JOIN pg_catalog.pg_namespace ns ON ns.oid=op.opcnamespace
     WHERE ns.nspname<>'pg_catalog' OR op.opcmethod<>index_relation.relam OR key.collation_oid<>a.attcollation
       OR op.opcname<>CASE a.atttypid WHEN 2950 THEN 'uuid_ops' WHEN 17 THEN 'bytea_ops' WHEN 1043 THEN 'text_ops' ELSE '' END)
), expected_table_acl AS (
 SELECT c.oid relation_oid,i.owner_oid grantor,i.owner_oid grantee,p.privilege_type,false is_grantable
 FROM relations c CROSS JOIN identities i CROSS JOIN (VALUES('SELECT'),('INSERT'),('UPDATE'),('DELETE'),('TRUNCATE'),('REFERENCES'),('TRIGGER'),('MAINTAIN')) p(privilege_type)
 UNION ALL SELECT c.oid,i.owner_oid,i.api_oid,p.privilege_type,false FROM relations c CROSS JOIN identities i
 CROSS JOIN (VALUES('SELECT'),('INSERT'),('UPDATE'),('DELETE')) p(privilege_type)
 WHERE c.relname='Memberships' OR p.privilege_type IN('SELECT','INSERT')
 UNION ALL SELECT c.oid,i.owner_oid,i.plan_oid,p.privilege_type,false FROM relations c CROSS JOIN identities i
 CROSS JOIN (VALUES('SELECT'),('UPDATE')) p(privilege_type) WHERE c.relname='Memberships'
), actual_table_acl AS (
 SELECT c.oid relation_oid,a.* FROM relations c CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(c.relacl,pg_catalog.acldefault('r',c.relowner))) a
), expected_column_acl AS (
 SELECT c.oid relation_oid,e.name,i.owner_oid grantor,i.execution_oid grantee,'SELECT'::text privilege_type,false is_grantable
 FROM expected_columns e JOIN relations c ON c.relname=e.table_name CROSS JOIN identities i
 UNION ALL SELECT c.oid,e.name,i.owner_oid,i.execution_oid,'UPDATE',false FROM expected_columns e JOIN relations c ON c.relname=e.table_name CROSS JOIN identities i
 WHERE (e.table_name='Memberships' AND e.name='Active') OR (e.table_name='EnrollmentGrantOperations' AND e.name='PlanHash')
 UNION ALL SELECT c.oid,e.name,i.owner_oid,i.queue_oid,'SELECT',false FROM expected_columns e JOIN relations c ON c.relname=e.table_name CROSS JOIN identities i
 WHERE e.table_name='EnrollmentGrantOperations' AND e.name IN('EnvironmentId','Id','QueuedAt')
 UNION ALL SELECT c.oid,e.name,i.owner_oid,i.delivery_oid,'SELECT',false FROM expected_columns e JOIN relations c ON c.relname=e.table_name CROSS JOIN identities i
 WHERE e.table_name='Memberships' OR (e.table_name='EnrollmentGrantOperations' AND e.name IN('EnvironmentId','Id','RequesterId','DirectoryObjectId','PlanHash','QueuedAt','AuthorizationNotAfter','RecipientKeyFingerprint','ServerDeviceId','MappingCreatedAt'))
 UNION ALL SELECT c.oid,e.name,i.owner_oid,i.delivery_oid,'UPDATE',false FROM expected_columns e JOIN relations c ON c.relname=e.table_name CROSS JOIN identities i
 WHERE (e.table_name='Memberships' AND e.name='Active') OR (e.table_name='EnrollmentGrantOperations' AND e.name='PlanHash')
), actual_column_acl AS (
 SELECT c.oid relation_oid,a.attname::text name,acl.* FROM relations c JOIN pg_catalog.pg_attribute a ON a.attrelid=c.oid
 CROSS JOIN LATERAL pg_catalog.aclexplode(a.attacl) acl
)
SELECT COALESCE((SELECT CURRENT_USER=SESSION_USER
 AND pg_catalog.current_setting('search_path') IN('pg_catalog,pg_temp','pg_catalog, pg_temp')
 AND (SELECT count(*)=6 AND count(DISTINCT id)=6 FROM pg_catalog.unnest(ARRAY[i.owner_oid,i.api_oid,i.plan_oid,i.execution_oid,i.queue_oid,i.delivery_oid]) id)
 AND (SELECT count(*)=3 AND bool_and(c.relkind='r' AND c.relpersistence='p' AND NOT c.relispartition AND c.relowner=i.owner_oid
   AND c.relrowsecurity AND c.relforcerowsecurity AND c.reloftype=0 AND c.relreplident='d'
   AND c.relam=(SELECT oid FROM pg_catalog.pg_am WHERE amname='heap')) FROM relations c)
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_inherits h JOIN relations c ON c.oid IN(h.inhrelid,h.inhparent))
 -- relhasrules is a lazy positive hint; inspect actual rules so DROP RULE restores validity.
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_rewrite rule JOIN relations c ON c.oid=rule.ev_class)
 AND (SELECT count(*)=29 FROM pg_catalog.pg_attribute a JOIN relations c ON c.oid=a.attrelid WHERE a.attnum>0)
 AND NOT EXISTS((SELECT * FROM expected_columns EXCEPT SELECT * FROM actual_columns) UNION ALL (SELECT * FROM actual_columns EXCEPT SELECT * FROM expected_columns))
 AND (SELECT count(*)=20 FROM actual_constraints)
 AND (SELECT count(*)=20 FROM pg_catalog.pg_constraint k JOIN relations c ON c.oid=k.conrelid WHERE k.contype IN('p','u','f','c'))
 AND (SELECT count(*)=29 AND bool_and(k.convalidated AND k.conenforced AND NOT k.condeferrable AND NOT k.condeferred
   AND k.conislocal AND k.coninhcount=0 AND k.conparentid=0) FROM pg_catalog.pg_constraint k JOIN relations c ON c.oid=k.conrelid WHERE k.contype='n')
 AND NOT EXISTS((SELECT * FROM expected_constraints EXCEPT SELECT * FROM actual_constraints) UNION ALL (SELECT * FROM actual_constraints EXCEPT SELECT * FROM expected_constraints))
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_constraint k JOIN relations c ON c.oid=k.conrelid WHERE k.contype NOT IN('p','u','f','c','n','t'))
 AND (SELECT count(*)=13 FROM pg_catalog.pg_index idx JOIN relations c ON c.oid=idx.indrelid)
 AND NOT EXISTS((SELECT * FROM expected_indexes EXCEPT SELECT * FROM actual_indexes) UNION ALL (SELECT * FROM actual_indexes EXCEPT SELECT * FROM expected_indexes))
 AND (SELECT count(*)=34 FROM expected_table_acl) AND (SELECT count(*)=34 FROM actual_table_acl)
 AND NOT EXISTS((SELECT * FROM expected_table_acl EXCEPT SELECT * FROM actual_table_acl) UNION ALL (SELECT * FROM actual_table_acl EXCEPT SELECT * FROM expected_table_acl))
 AND (SELECT count(*)=49 FROM expected_column_acl) AND (SELECT count(*)=49 FROM actual_column_acl)
 AND NOT EXISTS((SELECT * FROM expected_column_acl EXCEPT SELECT * FROM actual_column_acl) UNION ALL (SELECT * FROM actual_column_acl EXCEPT SELECT * FROM expected_column_acl))
 FROM identities i),false) AS is_valid;
