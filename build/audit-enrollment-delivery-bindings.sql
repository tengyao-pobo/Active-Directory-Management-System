-- Staged catalog-only profile4 binding structure; not an activation gate.
-- Shared source embedded into the draft profile by update-enrollment-delivery-catalog-slices.ps1.
-- The enclosing profile separately attests role/binding rows, ACLs and helper bodies.
-- Run under the deployment lock with search_path=pg_catalog,pg_temp.
WITH target AS (
  SELECT c.* FROM pg_catalog.pg_class c
  WHERE c.oid=pg_catalog.to_regclass('public."DirectoryDatabaseBindings"')
), owner_role AS (
  SELECT oid FROM pg_catalog.pg_roles WHERE rolname=:'expected_table_owner_role'
), expected_columns(position,name,type_oid,required,collation_oid,default_expression) AS (VALUES
  (1,'LoginRole','name'::regtype::oid,true,'pg_catalog."C"'::regcollation::oid,NULL::text),
  (2,'Purpose','text'::regtype::oid,true,'pg_catalog."default"'::regcollation::oid,NULL::text),
  (3,'EnvironmentId','uuid'::regtype::oid,false,0::oid,NULL::text),
  (4,'PrincipalId','uuid'::regtype::oid,false,0::oid,NULL::text),
  (5,'ContractVersion','smallint'::regtype::oid,true,0::oid,'1')),
actual_columns AS (
  SELECT a.attnum::integer position,a.attname::text name,a.atttypid type_oid,a.attnotnull required,
    a.attcollation collation_oid,pg_catalog.pg_get_expr(d.adbin,d.adrelid) default_expression
  FROM pg_catalog.pg_attribute a JOIN target t ON t.oid=a.attrelid
  LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
  WHERE a.attnum>0 AND NOT a.attisdropped
), expected_indexes(name,definition) AS (VALUES
  ('DirectoryDatabaseBindings_pkey','CREATE UNIQUE INDEX "DirectoryDatabaseBindings_pkey" ON public."DirectoryDatabaseBindings" USING btree ("LoginRole")'),
  ('enrollment_execution_environment_login','CREATE UNIQUE INDEX enrollment_execution_environment_login ON public."DirectoryDatabaseBindings" USING btree ("EnvironmentId") WHERE ("Purpose" = ''EnrollmentGrantExecution''::text)'),
  ('enrollment_grant_status_environment_login','CREATE UNIQUE INDEX enrollment_grant_status_environment_login ON public."DirectoryDatabaseBindings" USING btree ("EnvironmentId") WHERE ("Purpose" = ''EnrollmentGrantStatusRefresh''::text)'),
  ('enrollment_grant_delivery_environment_login','CREATE UNIQUE INDEX enrollment_grant_delivery_environment_login ON public."DirectoryDatabaseBindings" USING btree ("EnvironmentId") WHERE ("Purpose" = ''EnrollmentGrantDelivery''::text)')),
actual_indexes AS (
  SELECT c.relname::text name,pg_catalog.pg_get_indexdef(c.oid) definition
  FROM pg_catalog.pg_index i JOIN target t ON t.oid=i.indrelid
  JOIN pg_catalog.pg_class c ON c.oid=i.indexrelid
), expected_constraints(name,definition) AS (VALUES
  ('DirectoryDatabaseBindings_LoginRole_not_null','NOT NULL "LoginRole"'),
  ('DirectoryDatabaseBindings_Purpose_not_null','NOT NULL "Purpose"'),
  ('DirectoryDatabaseBindings_ContractVersion_not_null','NOT NULL "ContractVersion"'),
  ('DirectoryDatabaseBindings_pkey','PRIMARY KEY ("LoginRole")'),
  ('DirectoryDatabaseBindings_EnvironmentId_fkey','FOREIGN KEY ("EnvironmentId") REFERENCES public."Environments"("Id")'),
  ('DirectoryDatabaseBindings_PrincipalId_fkey','FOREIGN KEY ("PrincipalId") REFERENCES public."Principals"("Id")'),
  ('directory_database_binding_purpose',$definition$CHECK (("Purpose" = ANY (ARRAY['Api'::text, 'Connector'::text, 'EnrollmentGrantExecution'::text, 'EnrollmentGrantStatusRefresh'::text, 'EnrollmentGrantDelivery'::text])))$definition$),
  ('directory_database_binding_shape',$definition$CHECK (((("Purpose" = 'Api'::text) AND ("ContractVersion" = 1) AND ("EnvironmentId" IS NULL) AND ("PrincipalId" IS NULL)) OR (("Purpose" = 'Connector'::text) AND ("ContractVersion" = 1) AND ("EnvironmentId" IS NOT NULL) AND ("PrincipalId" IS NOT NULL)) OR (("Purpose" = 'EnrollmentGrantExecution'::text) AND ("ContractVersion" = 2) AND ("EnvironmentId" IS NOT NULL) AND ("PrincipalId" IS NULL) AND ("EnvironmentId" <> '00000000-0000-0000-0000-000000000000'::uuid)) OR (("Purpose" = ANY (ARRAY['EnrollmentGrantStatusRefresh'::text, 'EnrollmentGrantDelivery'::text])) AND ("ContractVersion" = 1) AND ("EnvironmentId" IS NOT NULL) AND ("PrincipalId" IS NULL) AND ("EnvironmentId" <> '00000000-0000-0000-0000-000000000000'::uuid))))$definition$)),
actual_constraints AS (
  SELECT c.conname::text name,pg_catalog.pg_get_constraintdef(c.oid) definition
  FROM pg_catalog.pg_constraint c JOIN target t ON t.oid=c.conrelid
)
SELECT COALESCE((SELECT
  pg_catalog.current_setting('search_path') IN('pg_catalog,pg_temp','pg_catalog, pg_temp')
  AND t.relowner=o.oid AND t.relkind='r' AND t.relpersistence='p' AND NOT t.relispartition
  AND t.relam=(SELECT oid FROM pg_catalog.pg_am WHERE amname='heap')
  AND NOT t.relrowsecurity AND NOT t.relforcerowsecurity AND t.relreplident='d'
  AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_inherits i WHERE i.inhrelid=t.oid OR i.inhparent=t.oid)
  AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_attribute a WHERE a.attrelid=t.oid AND a.attnum>0
    AND (a.attisdropped OR a.atttypmod<>-1 OR a.attndims<>0 OR a.attidentity<>'' OR a.attgenerated<>'' OR NOT a.attislocal OR a.attinhcount<>0
      OR a.atthasdef IS DISTINCT FROM (a.attnum=5)))
  AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_constraint c WHERE c.conrelid=t.oid
    AND (NOT c.convalidated OR NOT c.conenforced OR c.condeferrable OR c.condeferred OR NOT c.conislocal OR c.coninhcount<>0 OR c.conparentid<>0
      OR c.conperiod OR c.connoinherit IS DISTINCT FROM (c.contype IN('p','f'))
      OR c.contype IS DISTINCT FROM CASE
        WHEN c.conname IN('DirectoryDatabaseBindings_LoginRole_not_null','DirectoryDatabaseBindings_Purpose_not_null','DirectoryDatabaseBindings_ContractVersion_not_null') THEN 'n'::"char"
        WHEN c.conname='DirectoryDatabaseBindings_pkey' THEN 'p'::"char"
        WHEN c.conname IN('DirectoryDatabaseBindings_EnvironmentId_fkey','DirectoryDatabaseBindings_PrincipalId_fkey') THEN 'f'::"char"
        ELSE 'c'::"char" END
      OR c.confdelsetcols IS NOT NULL
      OR c.conkey IS DISTINCT FROM CASE c.conname
        WHEN 'DirectoryDatabaseBindings_LoginRole_not_null' THEN ARRAY[1]::smallint[]
        WHEN 'DirectoryDatabaseBindings_Purpose_not_null' THEN ARRAY[2]::smallint[]
        WHEN 'DirectoryDatabaseBindings_ContractVersion_not_null' THEN ARRAY[5]::smallint[]
        WHEN 'DirectoryDatabaseBindings_pkey' THEN ARRAY[1]::smallint[]
        WHEN 'DirectoryDatabaseBindings_EnvironmentId_fkey' THEN ARRAY[3]::smallint[]
        WHEN 'DirectoryDatabaseBindings_PrincipalId_fkey' THEN ARRAY[4]::smallint[]
        WHEN 'directory_database_binding_purpose' THEN ARRAY[2]::smallint[]
        WHEN 'directory_database_binding_shape' THEN ARRAY[2,5,3,4]::smallint[] END
      OR (c.contype='p' AND c.conindid IS DISTINCT FROM pg_catalog.to_regclass('public."DirectoryDatabaseBindings_pkey"'))
      OR (c.contype IN('c','n') AND c.conindid<>0)
      OR (c.contype<>'f' AND (c.confrelid<>0 OR c.confkey IS NOT NULL
        OR c.confmatchtype<>' ' OR c.confupdtype<>' ' OR c.confdeltype<>' '
        OR c.conpfeqop IS NOT NULL OR c.conppeqop IS NOT NULL OR c.conffeqop IS NOT NULL))
      OR (c.contype='f' AND (c.confmatchtype<>'s' OR c.confupdtype<>'a' OR c.confdeltype<>'a'
        OR c.conpfeqop IS DISTINCT FROM ARRAY['pg_catalog.=(uuid,uuid)'::regoperator::oid]
        OR c.conppeqop IS DISTINCT FROM ARRAY['pg_catalog.=(uuid,uuid)'::regoperator::oid]
        OR c.conffeqop IS DISTINCT FROM ARRAY['pg_catalog.=(uuid,uuid)'::regoperator::oid]
        OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_index referenced_index
          WHERE referenced_index.indexrelid=c.conindid AND referenced_index.indrelid=c.confrelid AND referenced_index.indisprimary
            AND referenced_index.indnkeyatts=1 AND referenced_index.indnatts=1)
        OR c.confrelid IS DISTINCT FROM CASE c.conname WHEN 'DirectoryDatabaseBindings_EnvironmentId_fkey'
          THEN pg_catalog.to_regclass('public."Environments"') ELSE pg_catalog.to_regclass('public."Principals"') END
        OR c.confkey IS DISTINCT FROM ARRAY[(SELECT a.attnum FROM pg_catalog.pg_attribute a
          WHERE a.attrelid=c.confrelid AND a.attname='Id' AND NOT a.attisdropped)]::smallint[]))))
  AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class c ON c.oid=i.indexrelid
    WHERE i.indrelid=t.oid AND (NOT i.indisvalid OR NOT i.indisready OR NOT i.indislive OR NOT i.indisunique
      OR NOT i.indimmediate OR i.indisexclusion OR i.indnullsnotdistinct OR i.indisreplident OR i.indnkeyatts<>1 OR i.indnatts<>1
      OR c.relowner<>o.oid OR c.relnamespace<>t.relnamespace OR c.relkind<>'i' OR c.relpersistence<>'p' OR c.relispartition
      OR c.relam<>(SELECT oid FROM pg_catalog.pg_am WHERE amname='btree')
      OR i.indisprimary IS DISTINCT FROM (c.relname='DirectoryDatabaseBindings_pkey')
      OR i.indkey[0]<>CASE WHEN c.relname='DirectoryDatabaseBindings_pkey' THEN 1 ELSE 3 END
      OR i.indexprs IS NOT NULL OR i.indoption[0]<>0
      OR i.indcollation[0]<>CASE WHEN c.relname='DirectoryDatabaseBindings_pkey' THEN 'pg_catalog."C"'::regcollation::oid ELSE 0::oid END
      OR i.indclass[0] IS DISTINCT FROM (SELECT op.oid FROM pg_catalog.pg_opclass op
        JOIN pg_catalog.pg_namespace n ON n.oid=op.opcnamespace
        WHERE n.nspname='pg_catalog' AND op.opcmethod=c.relam
          AND op.opcname=CASE WHEN c.relname='DirectoryDatabaseBindings_pkey' THEN 'name_ops' ELSE 'uuid_ops' END)))
  AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_rewrite r WHERE r.ev_class=t.oid)
  AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_policy p WHERE p.polrelid=t.oid)
  AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_constraint incoming WHERE incoming.confrelid=t.oid)
  AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger trigger WHERE trigger.tgrelid=t.oid
    AND (NOT trigger.tgisinternal OR trigger.tgenabled<>'O'))
  AND NOT EXISTS(SELECT 1 FROM ((SELECT * FROM expected_columns EXCEPT SELECT * FROM actual_columns)
    UNION ALL (SELECT * FROM actual_columns EXCEPT SELECT * FROM expected_columns)) difference)
  AND NOT EXISTS(SELECT 1 FROM ((SELECT * FROM expected_indexes EXCEPT SELECT * FROM actual_indexes)
    UNION ALL (SELECT * FROM actual_indexes EXCEPT SELECT * FROM expected_indexes)) difference)
  AND NOT EXISTS(SELECT 1 FROM ((SELECT * FROM expected_constraints EXCEPT SELECT * FROM actual_constraints)
    UNION ALL (SELECT * FROM actual_constraints EXCEPT SELECT * FROM expected_constraints)) difference)
  FROM target t CROSS JOIN owner_role o),false) AS is_valid;
