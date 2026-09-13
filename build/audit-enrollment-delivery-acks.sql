-- Unconsumed acknowledgement structure slice; not a complete profile or activation gate.
-- The enclosing profile must also attest function bodies, policies, identities and ACLs.
WITH target AS (
 SELECT * FROM pg_catalog.pg_class WHERE oid=pg_catalog.to_regclass('enrollment_execution.delivery_acks')
), owner_role AS (
 SELECT oid FROM pg_catalog.pg_roles WHERE rolname=:'expected_table_owner_role'
), expected_columns(position,name,type_oid,required,collation_oid) AS (VALUES
 (1,'operation_id',2950::oid,true,0::oid),(2,'requester_id',2950,true,0),
 (3,'ciphertext_sha256',17,true,0),(4,'token_sha256',17,true,0),(5,'acknowledged_at',1184,true,0)), actual_columns AS (
 SELECT a.attnum::integer,a.attname::text,a.atttypid,a.attnotnull,a.attcollation
 FROM pg_catalog.pg_attribute a JOIN target t ON t.oid=a.attrelid WHERE a.attnum>0 AND NOT a.attisdropped
), expected_constraints(name,type,keys,definition) AS (VALUES
 ('delivery_acks_operation_id_not_null','n',ARRAY[1]::smallint[],'NOT NULL operation_id'),
 ('delivery_acks_requester_id_not_null','n',ARRAY[2]::smallint[],'NOT NULL requester_id'),
 ('delivery_acks_ciphertext_sha256_not_null','n',ARRAY[3]::smallint[],'NOT NULL ciphertext_sha256'),
 ('delivery_acks_token_sha256_not_null','n',ARRAY[4]::smallint[],'NOT NULL token_sha256'),
 ('delivery_acks_acknowledged_at_not_null','n',ARRAY[5]::smallint[],'NOT NULL acknowledged_at'),
 ('delivery_acks_pkey','p',ARRAY[1]::smallint[],'PRIMARY KEY (operation_id)'),
 ('delivery_acks_operation_id_fkey','f',ARRAY[1]::smallint[],'FOREIGN KEY (operation_id) REFERENCES enrollment_execution.issue_results(operation_id) ON DELETE RESTRICT'),
 ('delivery_acks_requester_id_check','c',ARRAY[2]::smallint[],$d$CHECK (requester_id <> '00000000-0000-0000-0000-000000000000'::uuid)$d$),
 ('delivery_acks_ciphertext_sha256_check','c',ARRAY[3]::smallint[],'CHECK (octet_length(ciphertext_sha256) = 32)'),
 ('delivery_acks_token_sha256_check','c',ARRAY[4]::smallint[],'CHECK (octet_length(token_sha256) = 32)'),
 ('delivery_acks_acknowledged_at_check','c',ARRAY[5]::smallint[],'CHECK (isfinite(acknowledged_at))'),
 ('delivery_acks_consistent','t',NULL::smallint[],'TRIGGER DEFERRABLE INITIALLY DEFERRED'),
 ('delivery_acks_stop_consistent','t',NULL::smallint[],'TRIGGER DEFERRABLE INITIALLY DEFERRED')), actual_constraints AS (
 SELECT c.conname::text,c.contype::text,c.conkey,pg_catalog.pg_get_constraintdef(c.oid,true)
 FROM pg_catalog.pg_constraint c JOIN target t ON t.oid=c.conrelid
), expected_indexes(name,keys,primary_index) AS (VALUES
 ('delivery_acks_pkey','1',true)
), actual_indexes AS (
 SELECT c.relname::text,i.indkey::text,i.indisprimary FROM pg_catalog.pg_index i JOIN target t ON t.oid=i.indrelid
 JOIN pg_catalog.pg_class c ON c.oid=i.indexrelid
), foreign_key AS (
 SELECT c.* FROM pg_catalog.pg_constraint c JOIN target t ON t.oid=c.conrelid WHERE c.conname='delivery_acks_operation_id_fkey'
), user_trigger_names(table_name,name,signature,type,deferred) AS (VALUES
 ('delivery_acks','delivery_acks_immutable','enrollment_execution.reject_history_mutation()',27,false),
 ('delivery_acks','delivery_acks_consistent','enrollment_execution.validate_journal()',5,true),
 ('delivery_acks','delivery_acks_stop_consistent','enrollment_execution.validate_execution_stop()',5,true)), expected_user_triggers AS (
 SELECT pg_catalog.to_regclass(pg_catalog.format('enrollment_execution.%I',table_name))::oid relation_oid,
   name,pg_catalog.to_regprocedure(signature)::oid function_oid,type,deferred FROM user_trigger_names
), actual_user_triggers AS (
 SELECT trigger.* FROM pg_catalog.pg_trigger trigger
 WHERE NOT trigger.tgisinternal AND (trigger.tgrelid=pg_catalog.to_regclass('enrollment_execution.delivery_acks')
   OR trigger.tgname IN(SELECT name FROM user_trigger_names))), expected_fk_triggers(relation_oid,function_oid,type) AS (
 SELECT t.oid,pg_catalog.to_regprocedure('pg_catalog."RI_FKey_check_ins"()')::oid,5 FROM target t
 UNION ALL SELECT t.oid,pg_catalog.to_regprocedure('pg_catalog."RI_FKey_check_upd"()')::oid,17 FROM target t
 UNION ALL SELECT pg_catalog.to_regclass('enrollment_execution.issue_results')::oid,pg_catalog.to_regprocedure('pg_catalog."RI_FKey_restrict_del"()')::oid,9
 UNION ALL SELECT pg_catalog.to_regclass('enrollment_execution.issue_results')::oid,pg_catalog.to_regprocedure('pg_catalog."RI_FKey_noaction_upd"()')::oid,17
)
SELECT COALESCE((SELECT
 pg_catalog.current_setting('search_path') IN('pg_catalog,pg_temp','pg_catalog, pg_temp')
 AND t.relowner=o.oid AND t.relkind='r' AND t.relpersistence='p' AND NOT t.relispartition
 AND t.relam=(SELECT oid FROM pg_catalog.pg_am WHERE amname='heap')
 AND t.relrowsecurity AND t.relforcerowsecurity AND t.relreplident='d'
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_inherits i WHERE i.inhrelid=t.oid OR i.inhparent=t.oid)
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_rewrite r WHERE r.ev_class=t.oid)
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_constraint c WHERE c.confrelid=t.oid)
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
     OR c.conperiod OR c.connoinherit IS DISTINCT FROM (c.contype IN('p','f','t')) OR c.confdelsetcols IS NOT NULL
     OR (c.contype IN('c','n','t') AND c.conindid<>0)
     OR (c.contype='p' AND c.conindid IS DISTINCT FROM pg_catalog.to_regclass(pg_catalog.format('enrollment_execution.%I',c.conname)))
     OR (c.contype<>'f' AND (c.confrelid<>0 OR c.confkey IS NOT NULL OR c.confmatchtype<>' ' OR c.confupdtype<>' ' OR c.confdeltype<>' '
       OR c.conpfeqop IS NOT NULL OR c.conppeqop IS NOT NULL OR c.conffeqop IS NOT NULL))
     OR (c.contype='f' AND (c.confrelid IS DISTINCT FROM pg_catalog.to_regclass('enrollment_execution.issue_results')
       OR c.confkey IS DISTINCT FROM ARRAY[1]::smallint[] OR c.conindid IS DISTINCT FROM pg_catalog.to_regclass('enrollment_execution.issue_results_pkey')
       OR c.confmatchtype<>'s' OR c.confupdtype<>'a' OR c.confdeltype<>'r'
       OR c.conpfeqop IS DISTINCT FROM ARRAY['pg_catalog.=(uuid,uuid)'::regoperator::oid]
       OR c.conppeqop IS DISTINCT FROM ARRAY['pg_catalog.=(uuid,uuid)'::regoperator::oid]
       OR c.conffeqop IS DISTINCT FROM ARRAY['pg_catalog.=(uuid,uuid)'::regoperator::oid]))))
 AND EXISTS(SELECT 1 FROM foreign_key fk JOIN pg_catalog.pg_index referenced ON referenced.indexrelid=fk.conindid
   WHERE referenced.indrelid=fk.confrelid AND referenced.indisprimary AND referenced.indisunique
     AND referenced.indisvalid AND referenced.indisready AND referenced.indislive AND NOT referenced.indcheckxmin
     AND referenced.indnkeyatts=1 AND referenced.indnatts=1 AND referenced.indkey::text='1'
     AND referenced.indexprs IS NULL AND referenced.indpred IS NULL)
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class c ON c.oid=i.indexrelid WHERE i.indrelid=t.oid
   AND (NOT i.indisvalid OR NOT i.indisready OR NOT i.indislive OR i.indcheckxmin OR NOT i.indisunique OR NOT i.indimmediate OR i.indisexclusion
     OR i.indnullsnotdistinct OR i.indisreplident OR i.indisclustered OR i.indnkeyatts<>i.indnatts OR i.indexprs IS NOT NULL OR i.indpred IS NOT NULL
     OR c.relowner<>o.oid OR c.relnamespace<>t.relnamespace OR c.relkind<>'i' OR c.relpersistence<>'p' OR c.relispartition
     OR c.relam<>(SELECT oid FROM pg_catalog.pg_am WHERE amname='btree')
     OR i.indnatts<>1
     OR EXISTS(SELECT 1 FROM pg_catalog.generate_series(0,i.indnatts-1) position
       WHERE i.indoption[position] IS DISTINCT FROM 0::smallint OR i.indcollation[position] IS DISTINCT FROM 0::oid
         OR i.indclass[position] IS DISTINCT FROM (SELECT op.oid FROM pg_catalog.pg_opclass op JOIN pg_catalog.pg_namespace n ON n.oid=op.opcnamespace
           WHERE n.nspname='pg_catalog' AND op.opcmethod=c.relam AND op.opcname=CASE WHEN position=0 THEN 'uuid_ops' ELSE 'int8_ops' END))))
 AND (SELECT count(*)=3 FROM actual_user_triggers)
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
   AND (SELECT count(*) FROM pg_catalog.pg_constraint c WHERE c.conrelid=expected.relation_oid AND c.conname=expected.name)<>1) AND (SELECT count(*)=4 FROM pg_catalog.pg_trigger trigger WHERE trigger.tgconstraint=(SELECT oid FROM foreign_key))
 AND NOT EXISTS(SELECT * FROM expected_fk_triggers EXCEPT
   SELECT trigger.tgrelid,trigger.tgfoid,trigger.tgtype::integer FROM pg_catalog.pg_trigger trigger WHERE trigger.tgconstraint=(SELECT oid FROM foreign_key))
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger trigger WHERE trigger.tgconstraint=(SELECT oid FROM foreign_key)
   AND (NOT trigger.tgisinternal OR NOT EXISTS(SELECT 1 FROM expected_fk_triggers e WHERE e.relation_oid=trigger.tgrelid AND e.function_oid=trigger.tgfoid AND e.type=trigger.tgtype)
     OR trigger.tgconstrindid IS DISTINCT FROM (SELECT conindid FROM foreign_key)
     OR trigger.tgconstrrelid IS DISTINCT FROM CASE WHEN trigger.tgrelid=t.oid THEN (SELECT confrelid FROM foreign_key) ELSE t.oid END))
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger trigger WHERE trigger.tgrelid=t.oid AND trigger.tgisinternal
   AND trigger.tgconstraint IS DISTINCT FROM (SELECT oid FROM foreign_key))
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger trigger WHERE (trigger.oid IN(SELECT oid FROM actual_user_triggers) OR trigger.tgrelid=t.oid OR trigger.tgconstraint=(SELECT oid FROM foreign_key))
   AND (trigger.tgenabled<>'O' OR (trigger.tgisinternal AND (trigger.tgdeferrable OR trigger.tginitdeferred)) OR trigger.tgnargs<>0 OR trigger.tgattr::text<>''
     OR trigger.tgargs<>''::bytea OR trigger.tgqual IS NOT NULL OR trigger.tgoldtable IS NOT NULL OR trigger.tgnewtable IS NOT NULL OR trigger.tgparentid<>0))
 FROM target t CROSS JOIN owner_role o),false) AS is_valid;
