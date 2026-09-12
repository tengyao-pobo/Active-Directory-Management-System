-- UNCONSUMED policy slice. Compose with exact function, role, relation, ACL and trigger contracts.
-- Catalog-only under a preceding transaction-local search_path=pg_catalog,pg_temp.
WITH identities AS (
 SELECT c.relowner owner_oid,
   (SELECT p.proowner FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
     WHERE n.nspname='enrollment_execution' AND p.proname='read_execution_record' AND p.proargtypes::text='2950 2950') execution_oid,
   (SELECT p.proowner FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
     WHERE n.nspname='enrollment_execution' AND p.proname='claim_next' AND p.proargtypes::text='2950 2950') queue_oid,
   (SELECT p.proowner FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
     WHERE n.nspname='enrollment_execution' AND p.proname='read_grant_delivery' AND p.proargtypes::text='2950 2950 2950 25') delivery_oid
 FROM pg_catalog.pg_class c WHERE c.oid=pg_catalog.to_regclass('public."Environments"')
), expressions(name,expression) AS (VALUES
 ('true','true'),
 ('api_membership_read',$policy$(public.has_environment_membership("EnvironmentId", (NULLIF(current_setting('app.principal_id'::text, true), ''::text))::uuid) AND ((("PrincipalId")::text = current_setting('app.principal_id'::text, true)) OR (("EnvironmentId")::text = current_setting('app.environment_id'::text, true))))$policy$),
 ('api_membership_write',$policy$((("EnvironmentId")::text = current_setting('app.environment_id'::text, true)) AND public.has_environment_membership("EnvironmentId", (NULLIF(current_setting('app.principal_id'::text, true), ''::text))::uuid))$policy$),
 ('api_operations',$policy$((("EnvironmentId")::text = current_setting('app.environment_id'::text, true)) AND ("RequesterId" = (NULLIF(current_setting('app.principal_id'::text, true), ''::text))::uuid) AND public.has_environment_membership("EnvironmentId", (NULLIF(current_setting('app.principal_id'::text, true), ''::text))::uuid))$policy$),
 ('execution_operations',$policy$(("EnvironmentId" = (NULLIF(current_setting('app.execution_environment_id'::text, true), ''::text))::uuid) AND ("Id" = (NULLIF(current_setting('app.execution_operation_id'::text, true), ''::text))::uuid))$policy$),
 ('queue_operations',$policy$(("EnvironmentId" = (NULLIF(current_setting('app.execution_environment_id'::text, true), ''::text))::uuid) AND ((NULLIF(current_setting('app.execution_operation_id'::text, true), ''::text) IS NULL) OR ("Id" = (NULLIF(current_setting('app.execution_operation_id'::text, true), ''::text))::uuid)))$policy$),
 ('delivery_operations',$policy$(("EnvironmentId" = (NULLIF(current_setting('app.delivery_environment_id'::text, true), ''::text))::uuid) AND ("Id" = (NULLIF(current_setting('app.delivery_operation_id'::text, true), ''::text))::uuid))$policy$),
 ('execution_memberships',$policy$(("EnvironmentId" = (NULLIF(current_setting('app.execution_environment_id'::text, true), ''::text))::uuid) AND ("PrincipalId" = ANY (ARRAY[(NULLIF(current_setting('app.execution_requester_id'::text, true), ''::text))::uuid, (NULLIF(current_setting('app.execution_approver_id'::text, true), ''::text))::uuid])))$policy$),
 ('delivery_memberships',$policy$(("EnvironmentId" = (NULLIF(current_setting('app.delivery_environment_id'::text, true), ''::text))::uuid) AND ("PrincipalId" = (NULLIF(current_setting('app.delivery_requester_id'::text, true), ''::text))::uuid))$policy$),
 ('execution_reservations',$policy$(("EnvironmentId" = (NULLIF(current_setting('app.execution_environment_id'::text, true), ''::text))::uuid) AND ("PlanId" = (NULLIF(current_setting('app.execution_plan_id'::text, true), ''::text))::uuid))$policy$)
), contracts(table_name,policy_name,command,permissive,role_kind,qual_name,check_name) AS (VALUES
 ('EnrollmentGrantOperations','environment_enrollment_grant_operations','*',true,'public','api_operations','api_operations'),
 ('EnrollmentGrantOperations','enrollment_execution_worker_operations_allow','*',true,'execution','execution_operations','execution_operations'),
 ('EnrollmentGrantOperations','enrollment_execution_worker_operations_limit','*',false,'execution','execution_operations','execution_operations'),
 ('EnrollmentGrantOperations','enrollment_execution_queue_operations_allow','*',true,'queue','queue_operations',NULL),
 ('EnrollmentGrantOperations','enrollment_execution_queue_operations_limit','*',false,'queue','queue_operations',NULL),
 ('EnrollmentGrantOperations','enrollment_delivery_operations_allow','*',true,'delivery','delivery_operations','delivery_operations'),
 ('EnrollmentGrantOperations','enrollment_delivery_operations_limit','*',false,'delivery','delivery_operations','delivery_operations'),
 ('Memberships','member_read','r',true,'public','api_membership_read',NULL),
 ('Memberships','member_insert','a',true,'public',NULL,'api_membership_write'),
 ('Memberships','member_update','w',true,'public','api_membership_write','api_membership_write'),
 ('Memberships','member_delete','d',true,'public','api_membership_write',NULL),
 ('Memberships','enrollment_execution_worker_memberships_allow','*',true,'execution','execution_memberships','execution_memberships'),
 ('Memberships','enrollment_execution_worker_memberships_limit','*',false,'execution','execution_memberships','execution_memberships'),
 ('Memberships','enrollment_delivery_memberships_allow','*',true,'delivery','delivery_memberships','delivery_memberships'),
 ('Memberships','enrollment_delivery_memberships_limit','*',false,'delivery','delivery_memberships','delivery_memberships'),
 ('Memberships','enrollment_profile4_membership_owner_select','r',true,'owner','true',NULL),
 ('EnrollmentGrantRecipientReservations','environment_enrollment_grant_recipient_reservations','*',true,'public','api_membership_write','api_membership_write'),
 ('EnrollmentGrantRecipientReservations','enrollment_execution_worker_reservations_allow','r',true,'execution','execution_reservations',NULL),
 ('EnrollmentGrantRecipientReservations','enrollment_execution_worker_reservations_limit','r',false,'execution','execution_reservations',NULL)
), relations AS (
 SELECT c.* FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='public' AND c.relname IN('EnrollmentGrantOperations','Memberships','EnrollmentGrantRecipientReservations')
), expected AS (
 SELECT c.table_name,c.policy_name,c.command::"char" command,c.permissive,
   ARRAY[CASE c.role_kind WHEN 'public' THEN 0::oid WHEN 'owner' THEN i.owner_oid
     WHEN 'execution' THEN i.execution_oid WHEN 'queue' THEN i.queue_oid WHEN 'delivery' THEN i.delivery_oid END] roles,
   q.expression qual_expression,w.expression check_expression
 FROM contracts c CROSS JOIN identities i
 LEFT JOIN expressions q ON q.name=c.qual_name LEFT JOIN expressions w ON w.name=c.check_name
), actual AS (
 SELECT c.relname::text table_name,p.polname::text policy_name,p.polcmd command,p.polpermissive permissive,p.polroles roles,
   pg_catalog.pg_get_expr(p.polqual,p.polrelid) qual_expression,pg_catalog.pg_get_expr(p.polwithcheck,p.polrelid) check_expression
 FROM relations c JOIN pg_catalog.pg_policy p ON p.polrelid=c.oid
)
SELECT COALESCE((SELECT CURRENT_USER=SESSION_USER
 AND pg_catalog.current_setting('search_path') IN('pg_catalog,pg_temp','pg_catalog, pg_temp')
 AND (SELECT count(*)=4 AND count(DISTINCT id)=4 FROM pg_catalog.unnest(ARRAY[i.owner_oid,i.execution_oid,i.queue_oid,i.delivery_oid]) id)
 AND (SELECT count(*)=3 AND bool_and(c.relkind='r' AND c.relpersistence='p' AND NOT c.relispartition
     AND c.relowner=i.owner_oid AND c.relrowsecurity AND c.relforcerowsecurity) FROM relations c)
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_inherits h JOIN relations c ON c.oid IN(h.inhrelid,h.inhparent))
 AND (SELECT count(*)=19 FROM expected) AND (SELECT count(*)=19 FROM actual)
 AND NOT EXISTS((SELECT * FROM expected EXCEPT SELECT * FROM actual)
   UNION ALL (SELECT * FROM actual EXCEPT SELECT * FROM expected))
 FROM identities i),false) AS is_valid;
