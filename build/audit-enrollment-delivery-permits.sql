-- Unconsumed mint-permit structure slice; not a complete profile or activation gate.
-- The enclosing profile must also attest function bodies, policies, identities and ACLs.
WITH target AS (
 SELECT * FROM pg_catalog.pg_class WHERE oid=pg_catalog.to_regclass('enrollment_execution.mint_permits')
), owner_role AS (
 SELECT oid FROM pg_catalog.pg_roles WHERE rolname=:'expected_table_owner_role'
), expected_columns(position,name,type_oid,required,collation_oid) AS (VALUES
 (1,'operation_id',2950::oid,true,0::oid),(2,'format_version',21,true,0),
 (3,'issued_at',1184,true,0),(4,'not_after',1184,true,0),(5,'token_sha256',17,true,0),
 (6,'recipient_fingerprint',17,true,0),(7,'ciphertext_sha256',17,true,0),(8,'authorization_digest',17,true,0)), actual_columns AS (
 SELECT a.attnum::integer,a.attname::text,a.atttypid,a.attnotnull,a.attcollation
 FROM pg_catalog.pg_attribute a JOIN target t ON t.oid=a.attrelid WHERE a.attnum>0 AND NOT a.attisdropped
), expected_constraints(name,type,keys,definition) AS (VALUES
 ('mint_permits_operation_id_not_null','n',ARRAY[1]::smallint[],'NOT NULL operation_id'),
 ('mint_permits_format_version_not_null','n',ARRAY[2]::smallint[],'NOT NULL format_version'),
 ('mint_permits_issued_at_not_null','n',ARRAY[3]::smallint[],'NOT NULL issued_at'),
 ('mint_permits_not_after_not_null','n',ARRAY[4]::smallint[],'NOT NULL not_after'),
 ('mint_permits_token_sha256_not_null','n',ARRAY[5]::smallint[],'NOT NULL token_sha256'),
 ('mint_permits_recipient_fingerprint_not_null','n',ARRAY[6]::smallint[],'NOT NULL recipient_fingerprint'),
 ('mint_permits_ciphertext_sha256_not_null','n',ARRAY[7]::smallint[],'NOT NULL ciphertext_sha256'),
 ('mint_permits_authorization_digest_not_null','n',ARRAY[8]::smallint[],'NOT NULL authorization_digest'),
 ('mint_permits_pkey','p',ARRAY[1]::smallint[],'PRIMARY KEY (operation_id)'),
 ('mint_permits_token_sha256_key','u',ARRAY[5]::smallint[],'UNIQUE (token_sha256)'),
 ('mint_permits_operation_id_fkey','f',ARRAY[1]::smallint[],'FOREIGN KEY (operation_id) REFERENCES public."EnrollmentGrantOperations"("Id") ON DELETE RESTRICT'),
 ('mint_permits_format_version_check','c',ARRAY[2]::smallint[],'CHECK (format_version = 1)'),
 ('mint_permit_time','c',ARRAY[3,4]::smallint[],$d$CHECK (isfinite(issued_at) AND isfinite(not_after) AND issued_at < not_after AND not_after <= (issued_at + '00:01:00'::interval))$d$),
 ('mint_permits_token_sha256_check','c',ARRAY[5]::smallint[],'CHECK (octet_length(token_sha256) = 32)'),
 ('mint_permits_recipient_fingerprint_check','c',ARRAY[6]::smallint[],'CHECK (octet_length(recipient_fingerprint) = 32)'),
 ('mint_permits_ciphertext_sha256_check','c',ARRAY[7]::smallint[],'CHECK (octet_length(ciphertext_sha256) = 32)'),
 ('mint_permits_authorization_digest_check','c',ARRAY[8]::smallint[],'CHECK (octet_length(authorization_digest) = 32)'),
 ('mint_permits_consistent','t',NULL::smallint[],'TRIGGER DEFERRABLE INITIALLY DEFERRED'),
 ('mint_permits_stop_consistent','t',NULL::smallint[],'TRIGGER DEFERRABLE INITIALLY DEFERRED')), actual_constraints AS (
 SELECT c.conname::text,c.contype::text,c.conkey,pg_catalog.pg_get_constraintdef(c.oid,true)
 FROM pg_catalog.pg_constraint c JOIN target t ON t.oid=c.conrelid
), expected_indexes(name,keys,primary_index) AS (VALUES
 ('mint_permits_pkey','1',true),('mint_permits_token_sha256_key','5',false)
), actual_indexes AS (
 SELECT c.relname::text,i.indkey::text,i.indisprimary FROM pg_catalog.pg_index i JOIN target t ON t.oid=i.indrelid
 JOIN pg_catalog.pg_class c ON c.oid=i.indexrelid
), expected_foreign_keys(name,child_oid,parent_oid,index_oid,parent_column) AS (VALUES
 ('mint_permits_operation_id_fkey',pg_catalog.to_regclass('enrollment_execution.mint_permits')::oid,pg_catalog.to_regclass('public."EnrollmentGrantOperations"')::oid,pg_catalog.to_regclass('public."PK_EnrollmentGrantOperations"')::oid,'Id'),
 ('sealed_envelopes_operation_id_fkey',pg_catalog.to_regclass('enrollment_execution.sealed_envelopes')::oid,pg_catalog.to_regclass('enrollment_execution.mint_permits')::oid,pg_catalog.to_regclass('enrollment_execution.mint_permits_pkey')::oid,'operation_id'),
 ('issue_results_operation_id_fkey',pg_catalog.to_regclass('enrollment_execution.issue_results')::oid,pg_catalog.to_regclass('enrollment_execution.mint_permits')::oid,pg_catalog.to_regclass('enrollment_execution.mint_permits_pkey')::oid,'operation_id')
), foreign_keys AS (
 SELECT c.* FROM pg_catalog.pg_constraint c WHERE c.contype='f'
 AND (c.conrelid=pg_catalog.to_regclass('enrollment_execution.mint_permits') OR c.confrelid=pg_catalog.to_regclass('enrollment_execution.mint_permits'))), user_trigger_names(table_name,name,signature,type,deferred) AS (VALUES
 ('mint_permits','mint_permits_immutable','enrollment_execution.reject_history_mutation()',27,false),
 ('mint_permits','mint_permits_consistent','enrollment_execution.validate_journal()',5,true),
 ('mint_permits','mint_permits_stop_consistent','enrollment_execution.validate_execution_stop()',5,true),
 ('mint_permits','mint_permits_stop_boundary','enrollment_execution.lock_execution_stop_boundary()',7,false)), expected_user_triggers AS (
 SELECT pg_catalog.to_regclass(pg_catalog.format('enrollment_execution.%I',table_name))::oid relation_oid,
   name,pg_catalog.to_regprocedure(signature)::oid function_oid,type,deferred FROM user_trigger_names
), actual_user_triggers AS (
 SELECT trigger.* FROM pg_catalog.pg_trigger trigger
 WHERE NOT trigger.tgisinternal AND (trigger.tgrelid=pg_catalog.to_regclass('enrollment_execution.mint_permits')
   OR trigger.tgname IN(SELECT name FROM user_trigger_names))), expected_fk_triggers(constraint_oid,relation_oid,function_oid,type) AS (
 SELECT fk.oid,fk.conrelid,pg_catalog.to_regprocedure('pg_catalog."RI_FKey_check_ins"()')::oid,5 FROM foreign_keys fk
 UNION ALL SELECT fk.oid,fk.conrelid,pg_catalog.to_regprocedure('pg_catalog."RI_FKey_check_upd"()')::oid,17 FROM foreign_keys fk
 UNION ALL SELECT fk.oid,fk.confrelid,pg_catalog.to_regprocedure('pg_catalog."RI_FKey_restrict_del"()')::oid,9 FROM foreign_keys fk
 UNION ALL SELECT fk.oid,fk.confrelid,pg_catalog.to_regprocedure('pg_catalog."RI_FKey_noaction_upd"()')::oid,17 FROM foreign_keys fk
)
SELECT COALESCE((SELECT
 pg_catalog.current_setting('search_path') IN('pg_catalog,pg_temp','pg_catalog, pg_temp')
 AND t.relowner=o.oid AND t.relkind='r' AND t.relpersistence='p' AND NOT t.relispartition
 AND t.relam=(SELECT oid FROM pg_catalog.pg_am WHERE amname='heap')
 AND t.relrowsecurity AND t.relforcerowsecurity AND t.relreplident='d'
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_inherits i WHERE i.inhrelid=t.oid OR i.inhparent=t.oid)
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_rewrite r WHERE r.ev_class=t.oid)
 AND (SELECT count(*)=3 FROM foreign_keys)
 AND NOT EXISTS(SELECT name,child_oid,parent_oid,index_oid FROM expected_foreign_keys EXCEPT
   SELECT conname::text,conrelid,confrelid,conindid FROM foreign_keys)
 AND NOT EXISTS(SELECT conname::text,conrelid,confrelid,conindid FROM foreign_keys EXCEPT
   SELECT name,child_oid,parent_oid,index_oid FROM expected_foreign_keys)
 AND NOT EXISTS(SELECT 1 FROM foreign_keys c JOIN pg_catalog.pg_class child ON child.oid=c.conrelid
   WHERE c.connamespace<>child.relnamespace OR NOT c.convalidated OR NOT c.conenforced OR c.condeferrable OR c.condeferred
     OR NOT c.conislocal OR NOT c.connoinherit OR c.coninhcount<>0 OR c.conparentid<>0 OR c.contypid<>0 OR c.conperiod
     OR c.conkey IS DISTINCT FROM ARRAY[1]::smallint[] OR c.confkey IS DISTINCT FROM ARRAY[1]::smallint[]
     OR c.confmatchtype<>'s' OR c.confupdtype<>'a' OR c.confdeltype<>'r' OR c.confdelsetcols IS NOT NULL
     OR c.conpfeqop IS DISTINCT FROM ARRAY['pg_catalog.=(uuid,uuid)'::regoperator::oid]
     OR c.conppeqop IS DISTINCT FROM ARRAY['pg_catalog.=(uuid,uuid)'::regoperator::oid]
     OR c.conffeqop IS DISTINCT FROM ARRAY['pg_catalog.=(uuid,uuid)'::regoperator::oid]
     OR c.conexclop IS NOT NULL OR c.conbin IS NOT NULL)
 AND NOT EXISTS(SELECT 1 FROM expected_foreign_keys e WHERE NOT EXISTS(
   SELECT 1 FROM pg_catalog.pg_attribute a WHERE a.attrelid=e.child_oid AND a.attnum=1 AND a.attname='operation_id'
     AND a.atttypid=2950 AND a.attnotnull AND NOT a.attisdropped))
 AND NOT EXISTS(SELECT 1 FROM expected_foreign_keys e WHERE NOT EXISTS(
   SELECT 1 FROM pg_catalog.pg_attribute a WHERE a.attrelid=e.parent_oid AND a.attnum=1 AND a.attname=e.parent_column
     AND a.atttypid=2950 AND a.attnotnull AND NOT a.attisdropped))
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_attribute a WHERE a.attrelid=t.oid AND a.attnum>0
   AND (a.attisdropped OR a.atttypmod<>-1 OR a.attndims<>0 OR a.atthasdef OR a.attidentity<>'' OR a.attgenerated<>'' OR NOT a.attislocal OR a.attinhcount<>0))
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_attrdef d WHERE d.adrelid=t.oid)
 AND NOT EXISTS(SELECT 1 FROM ((SELECT * FROM expected_columns EXCEPT SELECT * FROM actual_columns)
   UNION ALL (SELECT * FROM actual_columns EXCEPT SELECT * FROM expected_columns)) differences)
 AND NOT EXISTS(SELECT 1 FROM ((SELECT * FROM expected_constraints EXCEPT SELECT * FROM actual_constraints)
   UNION ALL (SELECT * FROM actual_constraints EXCEPT SELECT * FROM expected_constraints)) differences)
 AND NOT EXISTS(SELECT 1 FROM ((SELECT * FROM expected_indexes EXCEPT SELECT * FROM actual_indexes)
   UNION ALL (SELECT * FROM actual_indexes EXCEPT SELECT * FROM expected_indexes)) differences)
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_constraint c WHERE c.conrelid=t.oid
   AND (NOT c.convalidated OR NOT c.conenforced OR c.condeferrable IS DISTINCT FROM (c.contype='t') OR c.condeferred IS DISTINCT FROM (c.contype='t') OR NOT c.conislocal OR c.coninhcount<>0 OR c.conparentid<>0
     OR c.conperiod OR c.connoinherit IS DISTINCT FROM (c.contype IN('p','u','f','t')) OR c.confdelsetcols IS NOT NULL
     OR (c.contype IN('c','n','t') AND c.conindid<>0)
     OR (c.contype IN('p','u') AND c.conindid IS DISTINCT FROM pg_catalog.to_regclass(pg_catalog.format('enrollment_execution.%I',c.conname)))
     OR (c.contype<>'f' AND (c.confrelid<>0 OR c.confkey IS NOT NULL OR c.confmatchtype<>' ' OR c.confupdtype<>' ' OR c.confdeltype<>' '
       OR c.conpfeqop IS NOT NULL OR c.conppeqop IS NOT NULL OR c.conffeqop IS NOT NULL))
     OR (c.contype='f' AND (c.confrelid IS DISTINCT FROM pg_catalog.to_regclass('public."EnrollmentGrantOperations"')
       OR c.confkey IS DISTINCT FROM ARRAY[1]::smallint[] OR c.conindid IS DISTINCT FROM pg_catalog.to_regclass('public."PK_EnrollmentGrantOperations"')
       OR c.confmatchtype<>'s' OR c.confupdtype<>'a' OR c.confdeltype<>'r'
       OR c.conpfeqop IS DISTINCT FROM ARRAY['pg_catalog.=(uuid,uuid)'::regoperator::oid]
       OR c.conppeqop IS DISTINCT FROM ARRAY['pg_catalog.=(uuid,uuid)'::regoperator::oid]
       OR c.conffeqop IS DISTINCT FROM ARRAY['pg_catalog.=(uuid,uuid)'::regoperator::oid]))))
 AND NOT EXISTS(SELECT 1 FROM foreign_keys fk WHERE NOT EXISTS(
   SELECT 1 FROM pg_catalog.pg_index referenced WHERE referenced.indexrelid=fk.conindid
     AND referenced.indrelid=fk.confrelid AND referenced.indisprimary AND referenced.indisunique
     AND referenced.indisvalid AND referenced.indisready AND referenced.indislive AND NOT referenced.indcheckxmin
     AND referenced.indnkeyatts=1 AND referenced.indnatts=1 AND referenced.indkey::text='1'
     AND referenced.indexprs IS NULL AND referenced.indpred IS NULL))
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class c ON c.oid=i.indexrelid WHERE i.indrelid=t.oid
   AND (NOT i.indisvalid OR NOT i.indisready OR NOT i.indislive OR i.indcheckxmin OR NOT i.indisunique OR NOT i.indimmediate OR i.indisexclusion
     OR i.indnullsnotdistinct OR i.indisreplident OR i.indisclustered OR i.indnkeyatts<>i.indnatts OR i.indexprs IS NOT NULL OR i.indpred IS NOT NULL
     OR c.relowner<>o.oid OR c.relnamespace<>t.relnamespace OR c.relkind<>'i' OR c.relpersistence<>'p' OR c.relispartition
     OR c.relam<>(SELECT oid FROM pg_catalog.pg_am WHERE amname='btree')
     OR i.indnatts<>1
     OR EXISTS(SELECT 1 FROM pg_catalog.generate_series(0,i.indnatts-1) position
       WHERE i.indoption[position] IS DISTINCT FROM 0::smallint OR i.indcollation[position] IS DISTINCT FROM 0::oid
         OR i.indclass[position] IS DISTINCT FROM (SELECT op.oid FROM pg_catalog.pg_opclass op JOIN pg_catalog.pg_namespace n ON n.oid=op.opcnamespace
           WHERE n.nspname='pg_catalog' AND op.opcmethod=c.relam AND op.opcname=CASE WHEN c.relname='mint_permits_pkey' THEN 'uuid_ops' ELSE 'bytea_ops' END))))
 AND (SELECT count(*)=4 FROM actual_user_triggers)
 AND NOT EXISTS(SELECT * FROM expected_user_triggers EXCEPT
   SELECT tgrelid,tgname::text,tgfoid,tgtype::integer,tgdeferrable FROM actual_user_triggers)
 AND NOT EXISTS(SELECT tgrelid,tgname::text,tgfoid,tgtype::integer,tgdeferrable FROM actual_user_triggers EXCEPT
   SELECT * FROM expected_user_triggers)
 AND NOT EXISTS(SELECT 1 FROM actual_user_triggers trigger
   WHERE trigger.tgconstrrelid<>0 OR trigger.tgconstrindid<>0 OR trigger.tgdeferrable<>trigger.tginitdeferred
     OR (NOT trigger.tgdeferrable AND trigger.tgconstraint<>0)
     OR (trigger.tgdeferrable AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_constraint c
       JOIN pg_catalog.pg_class relation ON relation.oid=c.conrelid WHERE c.oid=trigger.tgconstraint
       AND c.conrelid=trigger.tgrelid AND c.conname=trigger.tgname AND c.connamespace=relation.relnamespace
       AND c.contype='t' AND c.condeferrable AND c.condeferred AND c.convalidated AND c.conenforced AND c.conislocal
       AND c.coninhcount=0 AND c.connoinherit AND NOT c.conperiod AND c.contypid=0 AND c.conparentid=0
       AND c.conkey IS NULL AND c.confkey IS NULL AND c.conindid=0 AND c.confrelid=0 AND c.confdelsetcols IS NULL
       AND c.conpfeqop IS NULL AND c.conppeqop IS NULL AND c.conffeqop IS NULL AND c.conexclop IS NULL AND c.conbin IS NULL
       AND c.confmatchtype=' ' AND c.confupdtype=' ' AND c.confdeltype=' '
       AND pg_catalog.pg_get_constraintdef(c.oid,true)='TRIGGER DEFERRABLE INITIALLY DEFERRED'
       AND (SELECT count(*)=1 FROM pg_catalog.pg_trigger attached WHERE attached.tgconstraint=c.oid))))
 AND NOT EXISTS(SELECT 1 FROM expected_user_triggers expected WHERE expected.deferred
   AND (SELECT count(*) FROM pg_catalog.pg_constraint c WHERE c.conrelid=expected.relation_oid AND c.conname=expected.name)<>1) AND (SELECT count(*)=12 FROM pg_catalog.pg_trigger trigger WHERE trigger.tgconstraint IN(SELECT oid FROM foreign_keys))
 AND NOT EXISTS(SELECT * FROM expected_fk_triggers EXCEPT
   SELECT trigger.tgconstraint,trigger.tgrelid,trigger.tgfoid,trigger.tgtype::integer FROM pg_catalog.pg_trigger trigger WHERE trigger.tgconstraint IN(SELECT oid FROM foreign_keys))
 AND NOT EXISTS(SELECT trigger.tgconstraint,trigger.tgrelid,trigger.tgfoid,trigger.tgtype::integer FROM pg_catalog.pg_trigger trigger WHERE trigger.tgconstraint IN(SELECT oid FROM foreign_keys) EXCEPT SELECT * FROM expected_fk_triggers)
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger trigger JOIN foreign_keys fk ON fk.oid=trigger.tgconstraint
   WHERE NOT trigger.tgisinternal OR trigger.tgconstrindid IS DISTINCT FROM fk.conindid
     OR trigger.tgconstrrelid IS DISTINCT FROM CASE WHEN trigger.tgrelid=fk.conrelid THEN fk.confrelid ELSE fk.conrelid END)
 AND (SELECT count(*)=6 FROM pg_catalog.pg_trigger trigger WHERE trigger.tgrelid=t.oid AND trigger.tgisinternal)
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger trigger WHERE trigger.tgrelid=t.oid AND trigger.tgisinternal
   AND trigger.tgconstraint NOT IN(SELECT oid FROM foreign_keys))
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger trigger WHERE (trigger.oid IN(SELECT oid FROM actual_user_triggers) OR trigger.tgrelid=t.oid OR trigger.tgconstraint IN(SELECT oid FROM foreign_keys))
   AND (trigger.tgenabled<>'O' OR (trigger.tgisinternal AND (trigger.tgdeferrable OR trigger.tginitdeferred)) OR trigger.tgnargs<>0 OR trigger.tgattr::text<>''
     OR trigger.tgargs<>''::bytea OR trigger.tgqual IS NOT NULL OR trigger.tgoldtable IS NOT NULL OR trigger.tgnewtable IS NOT NULL OR trigger.tgparentid<>0))
 FROM target t CROSS JOIN owner_role o),false) AS is_valid;
