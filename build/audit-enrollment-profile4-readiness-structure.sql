-- Unconsumed readiness relation structure/ACL slice. Function bodies and metadata require separate attestation.
WITH target AS (
 SELECT * FROM pg_catalog.pg_class WHERE oid=pg_catalog.to_regclass('enrollment_execution.profile4_readiness')
), owner_role AS (
 SELECT oid FROM pg_catalog.pg_roles WHERE rolname=:'expected_table_owner_role'
), expected_columns(position,name,type_oid,required,collation_oid) AS (VALUES
 (1,'singleton',16::oid,true,0::oid),(2,'profile_version',21,true,0),(3,'generation',20,true,0),
 (4,'installation_nonce',2950,true,0),(5,'attestation_manifest_sha256',17,true,0),(6,'state',25,true,950),
 (7,'pending_at',1184,true,0),(8,'ready_at',1184,false,0),(9,'ready_by',19,false,950)
), actual_columns AS (
 SELECT a.attnum::integer,a.attname::text,a.atttypid,a.attnotnull,a.attcollation
 FROM pg_catalog.pg_attribute a JOIN target t ON t.oid=a.attrelid WHERE a.attnum>0 AND NOT a.attisdropped
), expected_constraints(name,type,keys,definition) AS (
 SELECT 'profile4_readiness_'||name||'_not_null','n',ARRAY[position]::smallint[],'NOT NULL '||name
 FROM expected_columns WHERE required
 UNION ALL VALUES
 ('profile4_readiness_pkey','p',ARRAY[1]::smallint[],'PRIMARY KEY (singleton)'),
 ('profile4_readiness_singleton_check','c',ARRAY[1]::smallint[],'CHECK (singleton)'),
 ('profile4_readiness_profile_version_check','c',ARRAY[2]::smallint[],'CHECK (profile_version = 4)'),
 ('profile4_readiness_generation_check','c',ARRAY[3]::smallint[],'CHECK (generation > 0)'),
 ('profile4_readiness_installation_nonce_check','c',ARRAY[4]::smallint[],$d$CHECK (installation_nonce <> '00000000-0000-0000-0000-000000000000'::uuid)$d$),
 ('profile4_readiness_attestation_manifest_sha256_check','c',ARRAY[5]::smallint[],'CHECK (octet_length(attestation_manifest_sha256) = 32)'),
 ('profile4_readiness_state_check','c',ARRAY[6]::smallint[],$d$CHECK (state = ANY (ARRAY['PendingHistoryAudit'::text, 'Ready'::text]))$d$),
 ('profile4_readiness_pending_at_check','c',ARRAY[7]::smallint[],'CHECK (isfinite(pending_at))'),
 ('profile4_readiness_ready_at_check','c',ARRAY[8]::smallint[],'CHECK (isfinite(ready_at))'),
 ('profile4_readiness_shape','c',ARRAY[6,8,9,7]::smallint[],$d$CHECK (state = 'PendingHistoryAudit'::text AND ready_at IS NULL AND ready_by IS NULL OR state = 'Ready'::text AND ready_at IS NOT NULL AND ready_by IS NOT NULL AND ready_by <> ''::name AND ready_at >= pending_at)$d$)
), actual_constraints AS (
 SELECT c.conname::text,c.contype::text,c.conkey,pg_catalog.pg_get_constraintdef(c.oid,true)
 FROM pg_catalog.pg_constraint c JOIN target t ON t.oid=c.conrelid
), actual_acl AS (
 SELECT acl.grantor,acl.grantee,acl.privilege_type,acl.is_grantable
 FROM target t CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(t.relacl,pg_catalog.acldefault('r',t.relowner))) acl
), expected_acl AS (
 SELECT acl.grantor,acl.grantee,acl.privilege_type,acl.is_grantable
 FROM owner_role o CROSS JOIN LATERAL pg_catalog.aclexplode(pg_catalog.acldefault('r',o.oid)) acl
), actual_triggers AS (
 SELECT * FROM pg_catalog.pg_trigger WHERE tgrelid=pg_catalog.to_regclass('enrollment_execution.profile4_readiness')
   OR tgname='profile4_readiness_transition'
)
SELECT COALESCE((SELECT
 pg_catalog.current_setting('search_path') IN('pg_catalog,pg_temp','pg_catalog, pg_temp')
 AND t.relowner=o.oid AND t.relkind='r' AND t.relpersistence='p' AND NOT t.relispartition
 AND t.relam=(SELECT oid FROM pg_catalog.pg_am WHERE amname='heap')
 AND NOT t.relrowsecurity AND NOT t.relforcerowsecurity AND t.relreplident='d'
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_inherits i WHERE i.inhrelid=t.oid OR i.inhparent=t.oid)
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_rewrite r WHERE r.ev_class=t.oid)
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_policy p WHERE p.polrelid=t.oid)
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_constraint c WHERE c.confrelid=t.oid)
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_attribute a WHERE a.attrelid=t.oid AND a.attnum>0
   AND (a.attisdropped OR a.atttypmod<>-1 OR a.attndims<>0 OR a.atthasdef OR a.attidentity<>'' OR a.attgenerated<>'' OR NOT a.attislocal OR a.attinhcount<>0 OR a.attacl IS NOT NULL))
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_attrdef d WHERE d.adrelid=t.oid)
 AND NOT EXISTS(SELECT 1 FROM ((SELECT * FROM expected_columns EXCEPT SELECT * FROM actual_columns)
   UNION ALL (SELECT * FROM actual_columns EXCEPT SELECT * FROM expected_columns)) differences)
 AND NOT EXISTS(SELECT 1 FROM ((SELECT * FROM expected_constraints EXCEPT SELECT * FROM actual_constraints)
   UNION ALL (SELECT * FROM actual_constraints EXCEPT SELECT * FROM expected_constraints)) differences)
 AND NOT EXISTS(SELECT 1 FROM ((SELECT * FROM expected_acl EXCEPT SELECT * FROM actual_acl)
   UNION ALL (SELECT * FROM actual_acl EXCEPT SELECT * FROM expected_acl)) differences)
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_constraint c WHERE c.conrelid=t.oid
   AND (NOT c.convalidated OR NOT c.conenforced OR c.condeferrable OR c.condeferred OR NOT c.conislocal OR c.coninhcount<>0 OR c.conparentid<>0
     OR c.conperiod OR c.connoinherit IS DISTINCT FROM (c.contype='p') OR c.confdelsetcols IS NOT NULL
     OR (c.contype IN('c','n') AND c.conindid<>0)
     OR (c.contype='p' AND c.conindid IS DISTINCT FROM pg_catalog.to_regclass('enrollment_execution.profile4_readiness_pkey'))
     OR c.confrelid<>0 OR c.confkey IS NOT NULL OR c.confmatchtype<>' ' OR c.confupdtype<>' ' OR c.confdeltype<>' '
     OR c.conpfeqop IS NOT NULL OR c.conppeqop IS NOT NULL OR c.conffeqop IS NOT NULL))
 AND (SELECT count(*)=1 FROM pg_catalog.pg_index i WHERE i.indrelid=t.oid)
 AND EXISTS(SELECT 1 FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class c ON c.oid=i.indexrelid WHERE i.indrelid=t.oid
   AND c.oid=pg_catalog.to_regclass('enrollment_execution.profile4_readiness_pkey')
   AND i.indisvalid AND i.indisready AND i.indislive AND NOT i.indcheckxmin AND i.indisunique AND i.indisprimary AND i.indimmediate
   AND NOT i.indisexclusion AND NOT i.indnullsnotdistinct AND NOT i.indisreplident AND NOT i.indisclustered
   AND i.indnkeyatts=1 AND i.indnatts=1 AND i.indkey::text='1' AND i.indexprs IS NULL AND i.indpred IS NULL
   AND c.relowner=o.oid AND c.relnamespace=t.relnamespace AND c.relkind='i' AND c.relpersistence='p' AND NOT c.relispartition
   AND c.relam=(SELECT oid FROM pg_catalog.pg_am WHERE amname='btree')
   AND i.indoption[0]=0 AND i.indcollation[0]=0
   AND i.indclass[0]=(SELECT op.oid FROM pg_catalog.pg_opclass op JOIN pg_catalog.pg_namespace n ON n.oid=op.opcnamespace
      WHERE n.nspname='pg_catalog' AND op.opcmethod=c.relam AND op.opcname='bool_ops'))
 AND (SELECT count(*)=1 FROM actual_triggers)
 AND EXISTS(SELECT 1 FROM actual_triggers trigger WHERE trigger.tgrelid=t.oid AND trigger.tgname='profile4_readiness_transition'
   AND trigger.tgfoid=pg_catalog.to_regprocedure('enrollment_execution.guard_profile4_readiness()')
   AND trigger.tgtype=27 AND trigger.tgenabled='O' AND NOT trigger.tgisinternal AND trigger.tgparentid=0
   AND NOT trigger.tgdeferrable AND NOT trigger.tginitdeferred AND trigger.tgconstraint=0 AND trigger.tgconstrrelid=0 AND trigger.tgconstrindid=0
   AND trigger.tgnargs=0 AND octet_length(trigger.tgargs)=0 AND trigger.tgattr::text='' AND trigger.tgqual IS NULL
   AND trigger.tgoldtable IS NULL AND trigger.tgnewtable IS NULL)
 FROM target t CROSS JOIN owner_role o),false) AS is_valid;
