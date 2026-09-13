-- UNCONSUMED trigger slice. Requires composed role/function/relation/policy/privilege contracts.
-- Catalog-only with a preceding transaction-local search_path=pg_catalog,pg_temp.
WITH owner_role AS (SELECT relowner oid FROM pg_catalog.pg_class WHERE oid=pg_catalog.to_regclass('public."Environments"')),
contracts(name,definer,configuration,body_hash) AS (VALUES
-- BEGIN generated API trigger functions
 ('public.guard_operator_identity',false,NULL::text[],'45ef17451405636f02fffac57230e729c6060c7be52111fe67d4269401bd9280'),
 ('public.reject_enrollment_grant_reservation_mutation',false,ARRAY['search_path=pg_catalog, public, pg_temp']::text[],'11e0cba329d92938ddd1aceb7bff516232c65150a3c608d1beb993a8040aa583'),
 ('public.reject_enrollment_grant_operation_mutation',false,ARRAY['search_path=pg_catalog, public, pg_temp']::text[],'02fbef410663ae99c38206a8c6d15e859404ad0d90957ba1d9b5dc886135572a'),
 ('public.guard_enrollment_grant_queued_plan',false,ARRAY['search_path=pg_catalog, pg_temp']::text[],'0f8e2bb9ef2da1789d6555a207968d1f550359709f053efcc96cadb71590aacf'),
 ('public.guard_enrollment_grant_plan_child',false,ARRAY['search_path=pg_catalog, pg_temp']::text[],'da7636a8bfd3cf3d390f6d4a0d690a61c7f4a38531ba6e5bf980839b6ae12d35'),
 ('public.guard_enrollment_grant_operation_parent',false,ARRAY['search_path=pg_catalog, pg_temp']::text[],'f9d24668031f6aa90693fe542c795fcce5c2f21cb1c299472c3cbbaa57ec912e'),
 ('public.guard_enrollment_grant_outbox_anchor',false,ARRAY['search_path=pg_catalog, pg_temp']::text[],'11f82663693e51b988bdf76fb3544daef24a5db772b57a4e32203b0badedbde9'),
 ('public.validate_enrollment_grant_queue_anchor',false,ARRAY['search_path=pg_catalog, pg_temp']::text[],'63cb47a2cc7c70aa36c71d05425f641120998e66fd17693317da4edcc86ec957'),
 ('enrollment_execution.reject_worker_update',true,ARRAY['search_path=pg_catalog, pg_temp','row_security=on']::text[],'90e52f5d0756e9ae2c7b09aa4303e83a531ed1c7d4ebe3d040246a32c1112b6c'),
 ('enrollment_execution.reject_delivery_update',true,ARRAY['search_path=pg_catalog, pg_temp','row_security=on']::text[],'db42dee8e6621ac3c6993c4d79f44fa78b1f1729d2a3248462e38d182adede6d'),
 ('enrollment_execution.validate_work_queue',true,ARRAY['search_path=pg_catalog, pg_temp','row_security=on']::text[],'402021895e1899870d1523ffe40f5a23e3795f10d624c9a961d7a6ade4fb4a5d'),
 ('enrollment_execution.guard_profile4_publication',true,ARRAY['search_path=pg_catalog, pg_temp','row_security=on']::text[],'1788f276fbb79bea8210ec3e0bfca1cdda1fd3f8b84f969ff627b9e15e244718')
-- END generated API trigger functions
), functions AS (
 SELECT e.*,p.*,l.lanname FROM contracts e
 LEFT JOIN pg_catalog.pg_namespace n ON n.nspname=pg_catalog.split_part(e.name,'.',1)
 LEFT JOIN pg_catalog.pg_proc p ON p.pronamespace=n.oid AND p.proname=pg_catalog.split_part(e.name,'.',2) AND p.proargtypes::text=''
 LEFT JOIN pg_catalog.pg_language l ON l.oid=p.prolang
), expected_public(table_name,trigger_name,function_name,type_code,deferred,enabled) AS (VALUES
 ('Principals','operator_identity_immutable','public.guard_operator_identity',19,false,'O'),
 ('Environments','enrollment_execution_worker_environment_guard','enrollment_execution.reject_worker_update',19,false,'O'),
 ('DirectorySync','enrollment_execution_worker_sync_guard','enrollment_execution.reject_worker_update',19,false,'O'),
 ('DirectoryObjects','enrollment_execution_worker_directory_guard','enrollment_execution.reject_worker_update',19,false,'O'),
 ('Principals','enrollment_execution_worker_principal_guard','enrollment_execution.reject_worker_update',19,false,'O'),
 ('Memberships','enrollment_execution_worker_membership_guard','enrollment_execution.reject_worker_update',19,false,'O'),
 ('Plans','enrollment_execution_worker_plan_guard','enrollment_execution.reject_worker_update',19,false,'O'),
 ('EnrollmentGrantOperations','enrollment_execution_worker_operation_guard','enrollment_execution.reject_worker_update',19,false,'O'),
 ('Outbox','enrollment_execution_worker_outbox_guard','enrollment_execution.reject_worker_update',19,false,'O'),
 ('Environments','enrollment_delivery_environment_guard','enrollment_execution.reject_delivery_update',19,false,'O'),
 ('DirectorySync','enrollment_delivery_sync_guard','enrollment_execution.reject_delivery_update',19,false,'O'),
 ('DirectoryObjects','enrollment_delivery_directory_guard','enrollment_execution.reject_delivery_update',19,false,'O'),
 ('Principals','enrollment_delivery_principal_guard','enrollment_execution.reject_delivery_update',19,false,'O'),
 ('Memberships','enrollment_delivery_membership_guard','enrollment_execution.reject_delivery_update',19,false,'O'),
 ('EnrollmentGrantOperations','enrollment_delivery_operation_guard','enrollment_execution.reject_delivery_update',19,false,'O'),
 ('Plans','enrollment_grant_queued_plan_immutable','public.guard_enrollment_grant_queued_plan',31,false,'O'),
 ('PlanItems','enrollment_grant_plan_items_anchor','public.guard_enrollment_grant_plan_child',31,false,'O'),
 ('Approvals','enrollment_grant_approvals_anchor','public.guard_enrollment_grant_plan_child',31,false,'O'),
 ('EnrollmentGrantOperations','enrollment_grant_operation_parent','public.guard_enrollment_grant_operation_parent',7,false,'O'),
 ('Outbox','enrollment_grant_outbox_anchor','public.guard_enrollment_grant_outbox_anchor',31,false,'O'),
 ('Plans','enrollment_grant_plan_anchor_consistent','public.validate_enrollment_grant_queue_anchor',21,true,'O'),
 ('EnrollmentGrantOperations','enrollment_grant_operation_anchor_consistent','public.validate_enrollment_grant_queue_anchor',5,true,'O'),
 ('Outbox','enrollment_grant_outbox_anchor_consistent','public.validate_enrollment_grant_queue_anchor',29,true,'O'),
 ('Outbox','work_queue_outbox_consistent','enrollment_execution.validate_work_queue',21,true,'O'),
 ('EnrollmentGrantOperations','enrollment_grant_operations_immutable','public.reject_enrollment_grant_operation_mutation',27,false,'O'),
 ('EnrollmentGrantRecipientReservations','enrollment_grant_recipient_reservations_immutable','public.reject_enrollment_grant_reservation_mutation',27,false,'O'),
 ('EnrollmentGrantOperations','enrollment_grant_operation_00_publication','enrollment_execution.guard_profile4_publication',7,false,'A')
), expected AS (
 SELECT 'public'::text schema_name,e.* FROM expected_public e
 UNION ALL SELECT 'enrollment_execution','work_queue','work_queue_consistent','enrollment_execution.validate_work_queue',21,true,'O'
), relations AS (
 SELECT c.* FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 WHERE EXISTS(SELECT 1 FROM expected e WHERE e.schema_name=n.nspname AND e.table_name=c.relname)
), attachments AS (
 SELECT e.*,c.oid relation_oid,f.oid function_oid,t.* FROM expected e
 LEFT JOIN relations c ON c.relname=e.table_name AND c.relnamespace=(SELECT oid FROM pg_catalog.pg_namespace WHERE nspname=e.schema_name) LEFT JOIN functions f ON f.name=e.function_name
 LEFT JOIN pg_catalog.pg_trigger t ON t.tgrelid=c.oid AND t.tgname=e.trigger_name
), foreign_keys AS (
 SELECT k.* FROM pg_catalog.pg_constraint k JOIN relations c ON c.oid=k.conrelid
 WHERE c.relname IN('EnrollmentGrantOperations','EnrollmentGrantRecipientReservations','Memberships') AND k.contype='f'
), ri_functions AS (
 SELECT p.proname,p.oid FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
 WHERE n.nspname='pg_catalog' AND p.proname IN('RI_FKey_check_ins','RI_FKey_check_upd','RI_FKey_restrict_del','RI_FKey_noaction_upd')
 AND p.proargtypes::text='' AND p.pronargs=0 AND p.prorettype=2279 AND p.prokind='f'
), expected_ri AS (
 SELECT k.oid constraint_oid,k.conindid index_oid,k.conrelid relation_oid,k.confrelid other_oid,
   (SELECT oid FROM ri_functions WHERE proname='RI_FKey_check_ins') function_oid,5 type_code FROM foreign_keys k
 UNION ALL SELECT k.oid,k.conindid,k.conrelid,k.confrelid,(SELECT oid FROM ri_functions WHERE proname='RI_FKey_check_upd'),17 FROM foreign_keys k
 UNION ALL SELECT k.oid,k.conindid,k.confrelid,k.conrelid,(SELECT oid FROM ri_functions WHERE proname='RI_FKey_restrict_del'),9 FROM foreign_keys k
 UNION ALL SELECT k.oid,k.conindid,k.confrelid,k.conrelid,(SELECT oid FROM ri_functions WHERE proname='RI_FKey_noaction_upd'),17 FROM foreign_keys k
), actual_ri AS (
 SELECT t.tgconstraint constraint_oid,t.tgconstrindid index_oid,t.tgrelid relation_oid,t.tgconstrrelid other_oid,t.tgfoid function_oid,t.tgtype::integer type_code
 FROM pg_catalog.pg_trigger t WHERE t.tgconstraint IN(SELECT oid FROM foreign_keys)
   AND t.tgisinternal AND t.tgenabled='O' AND NOT t.tgdeferrable AND NOT t.tginitdeferred
   AND t.tgnargs=0 AND t.tgargs=''::bytea AND t.tgattr::text='' AND t.tgqual IS NULL
   AND t.tgoldtable IS NULL AND t.tgnewtable IS NULL AND t.tgparentid=0
)
SELECT COALESCE((SELECT CURRENT_USER=SESSION_USER
 AND pg_catalog.current_setting('search_path') IN('pg_catalog,pg_temp','pg_catalog, pg_temp')
 AND (SELECT count(*)=12 AND bool_and(c.relowner=o.oid AND c.relkind='r' AND c.relpersistence='p' AND NOT c.relispartition) FROM relations c)
 AND (SELECT count(*)=12 AND bool_and(COALESCE(p.oid IS NOT NULL AND p.proowner=o.oid AND p.lanname='plpgsql'
   AND p.prokind='f' AND p.prosecdef=p.definer AND p.provolatile='v' AND p.proparallel='u' AND NOT p.proisstrict
   AND NOT p.proleakproof AND p.prosupport=0 AND NOT p.proretset AND p.prorettype=2279 AND p.pronargs=0 AND p.proargtypes::text=''
   AND p.proargnames IS NULL AND p.proallargtypes IS NULL AND p.proargmodes IS NULL AND p.pronargdefaults=0 AND p.proargdefaults IS NULL
   AND p.provariadic=0 AND p.protrftypes IS NULL AND p.probin IS NULL AND p.prosqlbody IS NULL
   AND p.proconfig IS NOT DISTINCT FROM p.configuration
   AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(pg_catalog.replace(p.prosrc,E'\r\n',E'\n'),'UTF8')),'hex')=p.body_hash
   AND (SELECT count(*)=1 FROM pg_catalog.pg_proc extra WHERE extra.pronamespace=p.pronamespace AND extra.proname=p.proname)
   AND (SELECT count(*)=1 AND bool_and(a.grantor=o.oid AND a.grantee=o.oid AND a.privilege_type='EXECUTE' AND NOT a.is_grantable)
     FROM pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) a),false)) FROM functions p)
 AND (SELECT count(*)=28 AND bool_and(COALESCE(t.oid IS NOT NULL AND NOT t.tgisinternal AND t.tgfoid=t.function_oid
   AND t.tgtype=t.type_code AND t.tgenabled=t.enabled::"char" AND t.tgdeferrable=t.deferred AND t.tginitdeferred=t.deferred
   AND t.tgnargs=0 AND t.tgargs=''::bytea AND t.tgattr::text='' AND t.tgqual IS NULL AND t.tgoldtable IS NULL AND t.tgnewtable IS NULL
   AND t.tgparentid=0 AND t.tgconstrrelid=0 AND t.tgconstrindid=0
   AND CASE WHEN t.deferred THEN EXISTS(SELECT 1 FROM pg_catalog.pg_constraint k WHERE k.oid=t.tgconstraint AND k.conrelid=t.relation_oid
       AND k.conname=t.trigger_name AND k.contype='t' AND k.condeferrable AND k.condeferred AND k.convalidated AND k.conenforced
       AND k.conislocal AND k.coninhcount=0 AND k.conparentid=0 AND k.confrelid=0 AND k.contypid=0 AND k.conindid=0
       AND k.connamespace=(SELECT relnamespace FROM relations c WHERE c.oid=t.relation_oid) AND k.connoinherit AND NOT k.conperiod
       AND k.conkey IS NULL AND k.confkey IS NULL AND k.confdelsetcols IS NULL AND k.conpfeqop IS NULL AND k.conppeqop IS NULL
       AND k.conffeqop IS NULL AND k.conexclop IS NULL AND k.conbin IS NULL AND k.confmatchtype=' ' AND k.confupdtype=' ' AND k.confdeltype=' '
       AND pg_catalog.pg_get_constraintdef(k.oid,true)='TRIGGER DEFERRABLE INITIALLY DEFERRED'
       AND (SELECT count(*)=1 FROM pg_catalog.pg_trigger a WHERE a.tgconstraint=k.oid)
       AND (SELECT count(*)=1 FROM pg_catalog.pg_constraint a WHERE a.conrelid=t.relation_oid AND a.conname=t.trigger_name))
     ELSE t.tgconstraint=0 END,false)) FROM attachments t)
 AND (SELECT count(*)=27 FROM pg_catalog.pg_trigger t JOIN relations c ON c.oid=t.tgrelid WHERE NOT t.tgisinternal AND c.relnamespace=(SELECT oid FROM pg_catalog.pg_namespace WHERE nspname='public'))
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger t JOIN functions f ON f.oid=t.tgfoid
   WHERE NOT EXISTS(SELECT 1 FROM attachments a WHERE a.oid=t.oid))
 AND (SELECT count(*)=4 AND count(DISTINCT proname)=4 FROM ri_functions)
 AND (SELECT count(*)=7 FROM foreign_keys)
 AND (SELECT count(*)=28 FROM pg_catalog.pg_trigger t WHERE t.tgconstraint IN(SELECT oid FROM foreign_keys))
 AND NOT EXISTS((SELECT * FROM expected_ri EXCEPT SELECT * FROM actual_ri) UNION ALL (SELECT * FROM actual_ri EXCEPT SELECT * FROM expected_ri))
 FROM owner_role o),false) AS is_valid;
