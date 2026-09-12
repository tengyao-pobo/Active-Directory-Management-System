-- Included only by provision-enrollment-execution.sql while holding the exclusive profile lock.

CREATE FUNCTION enrollment_execution.reject_worker_update() RETURNS trigger
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET row_security=on AS $function$
BEGIN
    IF EXISTS (SELECT 1 FROM public."DirectoryDatabaseBindings"
          WHERE "LoginRole"=SESSION_USER AND "Purpose"='EnrollmentGrantExecution' AND "ContractVersion"=2)
       OR EXISTS (SELECT 1 FROM enrollment_execution.role_reservations
          WHERE role_name=SESSION_USER::name AND capability='EnrollmentGrantExecution' AND role_kind='Runtime') THEN
        IF TG_TABLE_SCHEMA='public' AND TG_TABLE_NAME='Outbox' AND TG_OP='UPDATE'
            AND OLD."EventType"='EnrollmentGrantExecutionRequested'
            AND NEW."EventType"=OLD."EventType" AND NEW."EnvironmentId"=OLD."EnvironmentId"
            AND NEW."Id"=OLD."Id" AND NEW."Version"=OLD."Version"
            AND NEW."Payload"=OLD."Payload" AND NEW."CreatedAt"=OLD."CreatedAt"
            AND NEW."Attempts">=OLD."Attempts"
            AND (NEW."DeliveredAt" IS NOT DISTINCT FROM OLD."DeliveredAt"
              OR (OLD."DeliveredAt" IS NULL AND NEW."DeliveredAt" IS NOT NULL
                AND isfinite(NEW."DeliveredAt") AND NEW."DeliveredAt">=statement_timestamp()
                AND NEW."DeliveredAt"<=clock_timestamp())) THEN
            RETURN NEW;
        END IF;
        RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='Enrollment execution worker cannot mutate authoritative state.';
    END IF;
    RETURN NEW;
END
$function$;
REVOKE ALL ON FUNCTION enrollment_execution.reject_worker_update() FROM PUBLIC;
ALTER FUNCTION enrollment_execution.reject_worker_update() OWNER TO :"expected_table_owner_role";

CREATE TRIGGER enrollment_execution_worker_environment_guard BEFORE UPDATE ON public."Environments"
    FOR EACH ROW EXECUTE FUNCTION enrollment_execution.reject_worker_update();
CREATE TRIGGER enrollment_execution_worker_sync_guard BEFORE UPDATE ON public."DirectorySync"
    FOR EACH ROW EXECUTE FUNCTION enrollment_execution.reject_worker_update();
CREATE TRIGGER enrollment_execution_worker_directory_guard BEFORE UPDATE ON public."DirectoryObjects"
    FOR EACH ROW EXECUTE FUNCTION enrollment_execution.reject_worker_update();
CREATE TRIGGER enrollment_execution_worker_principal_guard BEFORE UPDATE ON public."Principals"
    FOR EACH ROW EXECUTE FUNCTION enrollment_execution.reject_worker_update();
CREATE TRIGGER enrollment_execution_worker_membership_guard BEFORE UPDATE ON public."Memberships"
    FOR EACH ROW EXECUTE FUNCTION enrollment_execution.reject_worker_update();
CREATE TRIGGER enrollment_execution_worker_plan_guard BEFORE UPDATE ON public."Plans"
    FOR EACH ROW EXECUTE FUNCTION enrollment_execution.reject_worker_update();
CREATE TRIGGER enrollment_execution_worker_operation_guard BEFORE UPDATE ON public."EnrollmentGrantOperations"
    FOR EACH ROW EXECUTE FUNCTION enrollment_execution.reject_worker_update();
CREATE TRIGGER enrollment_execution_worker_outbox_guard BEFORE UPDATE ON public."Outbox"
    FOR EACH ROW EXECUTE FUNCTION enrollment_execution.reject_worker_update();

-- The permissive policy makes a worker-visible row available; the restrictive policy prevents
-- an unrelated PUBLIC policy from widening that row set for the execution definer.
CREATE POLICY enrollment_execution_worker_environments_allow ON public."Environments" AS PERMISSIVE FOR ALL TO :"execution_definer_role"
    USING ("Id"=nullif(current_setting('app.execution_environment_id',true),'')::uuid)
    WITH CHECK ("Id"=nullif(current_setting('app.execution_environment_id',true),'')::uuid);
CREATE POLICY enrollment_execution_worker_environments_limit ON public."Environments" AS RESTRICTIVE FOR ALL TO :"execution_definer_role"
    USING ("Id"=nullif(current_setting('app.execution_environment_id',true),'')::uuid)
    WITH CHECK ("Id"=nullif(current_setting('app.execution_environment_id',true),'')::uuid);
CREATE POLICY enrollment_execution_worker_sync_allow ON public."DirectorySync" AS PERMISSIVE FOR ALL TO :"execution_definer_role"
    USING ("EnvironmentId"=nullif(current_setting('app.execution_environment_id',true),'')::uuid)
    WITH CHECK ("EnvironmentId"=nullif(current_setting('app.execution_environment_id',true),'')::uuid);
CREATE POLICY enrollment_execution_worker_sync_limit ON public."DirectorySync" AS RESTRICTIVE FOR ALL TO :"execution_definer_role"
    USING ("EnvironmentId"=nullif(current_setting('app.execution_environment_id',true),'')::uuid)
    WITH CHECK ("EnvironmentId"=nullif(current_setting('app.execution_environment_id',true),'')::uuid);
CREATE POLICY enrollment_execution_worker_directory_allow ON public."DirectoryObjects" AS PERMISSIVE FOR ALL TO :"execution_definer_role"
    USING ("EnvironmentId"=nullif(current_setting('app.execution_environment_id',true),'')::uuid
        AND "Id"=nullif(current_setting('app.execution_directory_id',true),'')::uuid)
    WITH CHECK ("EnvironmentId"=nullif(current_setting('app.execution_environment_id',true),'')::uuid
        AND "Id"=nullif(current_setting('app.execution_directory_id',true),'')::uuid);
CREATE POLICY enrollment_execution_worker_directory_limit ON public."DirectoryObjects" AS RESTRICTIVE FOR ALL TO :"execution_definer_role"
    USING ("EnvironmentId"=nullif(current_setting('app.execution_environment_id',true),'')::uuid
        AND "Id"=nullif(current_setting('app.execution_directory_id',true),'')::uuid)
    WITH CHECK ("EnvironmentId"=nullif(current_setting('app.execution_environment_id',true),'')::uuid
        AND "Id"=nullif(current_setting('app.execution_directory_id',true),'')::uuid);
CREATE POLICY enrollment_execution_worker_memberships_allow ON public."Memberships" AS PERMISSIVE FOR ALL TO :"execution_definer_role"
    USING ("EnvironmentId"=nullif(current_setting('app.execution_environment_id',true),'')::uuid
        AND "PrincipalId" IN (nullif(current_setting('app.execution_requester_id',true),'')::uuid,
            nullif(current_setting('app.execution_approver_id',true),'')::uuid))
    WITH CHECK ("EnvironmentId"=nullif(current_setting('app.execution_environment_id',true),'')::uuid
        AND "PrincipalId" IN (nullif(current_setting('app.execution_requester_id',true),'')::uuid,
            nullif(current_setting('app.execution_approver_id',true),'')::uuid));
CREATE POLICY enrollment_execution_worker_memberships_limit ON public."Memberships" AS RESTRICTIVE FOR ALL TO :"execution_definer_role"
    USING ("EnvironmentId"=nullif(current_setting('app.execution_environment_id',true),'')::uuid
        AND "PrincipalId" IN (nullif(current_setting('app.execution_requester_id',true),'')::uuid,
            nullif(current_setting('app.execution_approver_id',true),'')::uuid))
    WITH CHECK ("EnvironmentId"=nullif(current_setting('app.execution_environment_id',true),'')::uuid
        AND "PrincipalId" IN (nullif(current_setting('app.execution_requester_id',true),'')::uuid,
            nullif(current_setting('app.execution_approver_id',true),'')::uuid));

CREATE POLICY enrollment_execution_worker_plans_allow ON public."Plans" AS PERMISSIVE FOR ALL TO :"execution_definer_role"
    USING ("EnvironmentId"=nullif(current_setting('app.execution_environment_id',true),'')::uuid AND "Id"=nullif(current_setting('app.execution_plan_id',true),'')::uuid)
    WITH CHECK ("EnvironmentId"=nullif(current_setting('app.execution_environment_id',true),'')::uuid AND "Id"=nullif(current_setting('app.execution_plan_id',true),'')::uuid);
CREATE POLICY enrollment_execution_worker_plans_limit ON public."Plans" AS RESTRICTIVE FOR ALL TO :"execution_definer_role"
    USING ("EnvironmentId"=nullif(current_setting('app.execution_environment_id',true),'')::uuid AND "Id"=nullif(current_setting('app.execution_plan_id',true),'')::uuid)
    WITH CHECK ("EnvironmentId"=nullif(current_setting('app.execution_environment_id',true),'')::uuid AND "Id"=nullif(current_setting('app.execution_plan_id',true),'')::uuid);
CREATE POLICY enrollment_execution_worker_items_allow ON public."PlanItems" AS PERMISSIVE FOR SELECT TO :"execution_definer_role"
    USING ("EnvironmentId"=nullif(current_setting('app.execution_environment_id',true),'')::uuid AND "PlanId"=nullif(current_setting('app.execution_plan_id',true),'')::uuid);
CREATE POLICY enrollment_execution_worker_items_limit ON public."PlanItems" AS RESTRICTIVE FOR SELECT TO :"execution_definer_role"
    USING ("EnvironmentId"=nullif(current_setting('app.execution_environment_id',true),'')::uuid AND "PlanId"=nullif(current_setting('app.execution_plan_id',true),'')::uuid);
CREATE POLICY enrollment_execution_worker_approvals_allow ON public."Approvals" AS PERMISSIVE FOR SELECT TO :"execution_definer_role"
    USING ("EnvironmentId"=nullif(current_setting('app.execution_environment_id',true),'')::uuid AND "PlanId"=nullif(current_setting('app.execution_plan_id',true),'')::uuid
        AND "Id"=nullif(current_setting('app.execution_approval_id',true),'')::uuid);
CREATE POLICY enrollment_execution_worker_approvals_limit ON public."Approvals" AS RESTRICTIVE FOR SELECT TO :"execution_definer_role"
    USING ("EnvironmentId"=nullif(current_setting('app.execution_environment_id',true),'')::uuid AND "PlanId"=nullif(current_setting('app.execution_plan_id',true),'')::uuid
        AND "Id"=nullif(current_setting('app.execution_approval_id',true),'')::uuid);
CREATE POLICY enrollment_execution_worker_reservations_allow ON public."EnrollmentGrantRecipientReservations" AS PERMISSIVE FOR SELECT TO :"execution_definer_role"
    USING ("EnvironmentId"=nullif(current_setting('app.execution_environment_id',true),'')::uuid AND "PlanId"=nullif(current_setting('app.execution_plan_id',true),'')::uuid);
CREATE POLICY enrollment_execution_worker_reservations_limit ON public."EnrollmentGrantRecipientReservations" AS RESTRICTIVE FOR SELECT TO :"execution_definer_role"
    USING ("EnvironmentId"=nullif(current_setting('app.execution_environment_id',true),'')::uuid AND "PlanId"=nullif(current_setting('app.execution_plan_id',true),'')::uuid);
CREATE POLICY enrollment_execution_worker_operations_allow ON public."EnrollmentGrantOperations" AS PERMISSIVE FOR ALL TO :"execution_definer_role"
    USING ("EnvironmentId"=nullif(current_setting('app.execution_environment_id',true),'')::uuid AND "Id"=nullif(current_setting('app.execution_operation_id',true),'')::uuid)
    WITH CHECK ("EnvironmentId"=nullif(current_setting('app.execution_environment_id',true),'')::uuid AND "Id"=nullif(current_setting('app.execution_operation_id',true),'')::uuid);
CREATE POLICY enrollment_execution_worker_operations_limit ON public."EnrollmentGrantOperations" AS RESTRICTIVE FOR ALL TO :"execution_definer_role"
    USING ("EnvironmentId"=nullif(current_setting('app.execution_environment_id',true),'')::uuid AND "Id"=nullif(current_setting('app.execution_operation_id',true),'')::uuid)
    WITH CHECK ("EnvironmentId"=nullif(current_setting('app.execution_environment_id',true),'')::uuid AND "Id"=nullif(current_setting('app.execution_operation_id',true),'')::uuid);
CREATE POLICY enrollment_execution_worker_outbox_allow ON public."Outbox" AS PERMISSIVE FOR ALL TO :"execution_definer_role"
    USING ("EnvironmentId"=nullif(current_setting('app.execution_environment_id',true),'')::uuid AND "Id"=nullif(current_setting('app.execution_operation_id',true),'')::uuid
        AND "EventType"='EnrollmentGrantExecutionRequested')
    WITH CHECK ("EnvironmentId"=nullif(current_setting('app.execution_environment_id',true),'')::uuid AND "Id"=nullif(current_setting('app.execution_operation_id',true),'')::uuid
        AND "EventType"='EnrollmentGrantExecutionRequested');
CREATE POLICY enrollment_execution_worker_outbox_limit ON public."Outbox" AS RESTRICTIVE FOR ALL TO :"execution_definer_role"
    USING ("EnvironmentId"=nullif(current_setting('app.execution_environment_id',true),'')::uuid AND "Id"=nullif(current_setting('app.execution_operation_id',true),'')::uuid
        AND "EventType"='EnrollmentGrantExecutionRequested')
    WITH CHECK ("EnvironmentId"=nullif(current_setting('app.execution_environment_id',true),'')::uuid AND "Id"=nullif(current_setting('app.execution_operation_id',true),'')::uuid
        AND "EventType"='EnrollmentGrantExecutionRequested');

-- Authority tables are all narrowed by the immutable operation environment. Joins in the fixed
-- owner helpers further bind role, scope and target identifiers.
CREATE POLICY enrollment_execution_worker_roles_allow ON public."Roles" AS PERMISSIVE FOR SELECT TO :"execution_definer_role"
    USING ("EnvironmentId"=nullif(current_setting('app.execution_environment_id',true),'')::uuid);
CREATE POLICY enrollment_execution_worker_roles_limit ON public."Roles" AS RESTRICTIVE FOR SELECT TO :"execution_definer_role"
    USING ("EnvironmentId"=nullif(current_setting('app.execution_environment_id',true),'')::uuid);
CREATE POLICY enrollment_execution_worker_role_permissions_allow ON public."RolePermissions" AS PERMISSIVE FOR SELECT TO :"execution_definer_role"
    USING ("EnvironmentId"=nullif(current_setting('app.execution_environment_id',true),'')::uuid);
CREATE POLICY enrollment_execution_worker_role_permissions_limit ON public."RolePermissions" AS RESTRICTIVE FOR SELECT TO :"execution_definer_role"
    USING ("EnvironmentId"=nullif(current_setting('app.execution_environment_id',true),'')::uuid);
CREATE POLICY enrollment_execution_worker_assignments_allow ON public."Assignments" AS PERMISSIVE FOR SELECT TO :"execution_definer_role"
    USING ("EnvironmentId"=nullif(current_setting('app.execution_environment_id',true),'')::uuid);
CREATE POLICY enrollment_execution_worker_assignments_limit ON public."Assignments" AS RESTRICTIVE FOR SELECT TO :"execution_definer_role"
    USING ("EnvironmentId"=nullif(current_setting('app.execution_environment_id',true),'')::uuid);
CREATE POLICY enrollment_execution_worker_scopes_allow ON public."Scopes" AS PERMISSIVE FOR SELECT TO :"execution_definer_role"
    USING ("EnvironmentId"=nullif(current_setting('app.execution_environment_id',true),'')::uuid);
CREATE POLICY enrollment_execution_worker_scopes_limit ON public."Scopes" AS RESTRICTIVE FOR SELECT TO :"execution_definer_role"
    USING ("EnvironmentId"=nullif(current_setting('app.execution_environment_id',true),'')::uuid);
CREATE POLICY enrollment_execution_worker_tag_assignments_allow ON public."DeviceTagAssignments" AS PERMISSIVE FOR SELECT TO :"execution_definer_role"
    USING ("EnvironmentId"=nullif(current_setting('app.execution_environment_id',true),'')::uuid);
CREATE POLICY enrollment_execution_worker_tag_assignments_limit ON public."DeviceTagAssignments" AS RESTRICTIVE FOR SELECT TO :"execution_definer_role"
    USING ("EnvironmentId"=nullif(current_setting('app.execution_environment_id',true),'')::uuid);

CREATE POLICY enrollment_execution_worker_permits_allow ON enrollment_execution.mint_permits AS PERMISSIVE FOR ALL TO :"execution_definer_role"
    USING (operation_id=nullif(current_setting('app.execution_operation_id',true),'')::uuid)
    WITH CHECK (operation_id=nullif(current_setting('app.execution_operation_id',true),'')::uuid);
CREATE POLICY enrollment_execution_worker_permits_limit ON enrollment_execution.mint_permits AS RESTRICTIVE FOR ALL TO :"execution_definer_role"
    USING (operation_id=nullif(current_setting('app.execution_operation_id',true),'')::uuid)
    WITH CHECK (operation_id=nullif(current_setting('app.execution_operation_id',true),'')::uuid);
CREATE POLICY enrollment_execution_worker_envelopes_allow ON enrollment_execution.sealed_envelopes AS PERMISSIVE FOR ALL TO :"execution_definer_role"
    USING (operation_id=nullif(current_setting('app.execution_operation_id',true),'')::uuid)
    WITH CHECK (operation_id=nullif(current_setting('app.execution_operation_id',true),'')::uuid);
CREATE POLICY enrollment_execution_worker_envelopes_limit ON enrollment_execution.sealed_envelopes AS RESTRICTIVE FOR ALL TO :"execution_definer_role"
    USING (operation_id=nullif(current_setting('app.execution_operation_id',true),'')::uuid)
    WITH CHECK (operation_id=nullif(current_setting('app.execution_operation_id',true),'')::uuid);
CREATE POLICY enrollment_execution_worker_results_allow ON enrollment_execution.issue_results AS PERMISSIVE FOR ALL TO :"execution_definer_role"
    USING (operation_id=nullif(current_setting('app.execution_operation_id',true),'')::uuid)
    WITH CHECK (operation_id=nullif(current_setting('app.execution_operation_id',true),'')::uuid);
CREATE POLICY enrollment_execution_worker_results_limit ON enrollment_execution.issue_results AS RESTRICTIVE FOR ALL TO :"execution_definer_role"
    USING (operation_id=nullif(current_setting('app.execution_operation_id',true),'')::uuid)
    WITH CHECK (operation_id=nullif(current_setting('app.execution_operation_id',true),'')::uuid);
CREATE POLICY enrollment_execution_worker_acks_allow ON enrollment_execution.delivery_acks AS PERMISSIVE FOR SELECT TO :"execution_definer_role"
    USING (operation_id=nullif(current_setting('app.execution_operation_id',true),'')::uuid);
CREATE POLICY enrollment_execution_worker_acks_limit ON enrollment_execution.delivery_acks AS RESTRICTIVE FOR SELECT TO :"execution_definer_role"
    USING (operation_id=nullif(current_setting('app.execution_operation_id',true),'')::uuid);
CREATE POLICY enrollment_execution_worker_stops_allow ON enrollment_execution.execution_stops AS PERMISSIVE FOR ALL TO :"execution_definer_role"
    USING (operation_id=nullif(current_setting('app.execution_operation_id',true),'')::uuid)
    WITH CHECK (operation_id=nullif(current_setting('app.execution_operation_id',true),'')::uuid);
CREATE POLICY enrollment_execution_worker_stops_limit ON enrollment_execution.execution_stops AS RESTRICTIVE FOR ALL TO :"execution_definer_role"
    USING (operation_id=nullif(current_setting('app.execution_operation_id',true),'')::uuid)
    WITH CHECK (operation_id=nullif(current_setting('app.execution_operation_id',true),'')::uuid);

CREATE POLICY enrollment_execution_queue_operations_allow ON public."EnrollmentGrantOperations" AS PERMISSIVE FOR ALL TO :"execution_queue_definer_role"
    USING ("EnvironmentId"=nullif(current_setting('app.execution_environment_id',true),'')::uuid
       AND (nullif(current_setting('app.execution_operation_id',true),'') IS NULL
         OR "Id"=nullif(current_setting('app.execution_operation_id',true),'')::uuid));
CREATE POLICY enrollment_execution_queue_operations_limit ON public."EnrollmentGrantOperations" AS RESTRICTIVE FOR ALL TO :"execution_queue_definer_role"
    USING ("EnvironmentId"=nullif(current_setting('app.execution_environment_id',true),'')::uuid
       AND (nullif(current_setting('app.execution_operation_id',true),'') IS NULL
         OR "Id"=nullif(current_setting('app.execution_operation_id',true),'')::uuid));
CREATE POLICY enrollment_execution_queue_outbox_allow ON public."Outbox" AS PERMISSIVE FOR ALL TO :"execution_queue_definer_role"
    USING ("EnvironmentId"=nullif(current_setting('app.execution_environment_id',true),'')::uuid
       AND "EventType"='EnrollmentGrantExecutionRequested'
       AND (nullif(current_setting('app.execution_operation_id',true),'') IS NULL
         OR "Id"=nullif(current_setting('app.execution_operation_id',true),'')::uuid))
    WITH CHECK ("EnvironmentId"=nullif(current_setting('app.execution_environment_id',true),'')::uuid
       AND "EventType"='EnrollmentGrantExecutionRequested'
       AND "Id"=nullif(current_setting('app.execution_operation_id',true),'')::uuid);
CREATE POLICY enrollment_execution_queue_outbox_limit ON public."Outbox" AS RESTRICTIVE FOR ALL TO :"execution_queue_definer_role"
    USING ("EnvironmentId"=nullif(current_setting('app.execution_environment_id',true),'')::uuid
       AND "EventType"='EnrollmentGrantExecutionRequested'
       AND (nullif(current_setting('app.execution_operation_id',true),'') IS NULL
         OR "Id"=nullif(current_setting('app.execution_operation_id',true),'')::uuid))
    WITH CHECK ("EnvironmentId"=nullif(current_setting('app.execution_environment_id',true),'')::uuid
       AND "EventType"='EnrollmentGrantExecutionRequested'
       AND "Id"=nullif(current_setting('app.execution_operation_id',true),'')::uuid);
CREATE POLICY enrollment_execution_queue_work_allow ON enrollment_execution.work_queue AS PERMISSIVE FOR ALL TO :"execution_queue_definer_role"
    USING (environment_id=nullif(current_setting('app.execution_environment_id',true),'')::uuid
       AND (nullif(current_setting('app.execution_operation_id',true),'') IS NULL
         OR operation_id=nullif(current_setting('app.execution_operation_id',true),'')::uuid))
    WITH CHECK (environment_id=nullif(current_setting('app.execution_environment_id',true),'')::uuid);
CREATE POLICY enrollment_execution_queue_work_limit ON enrollment_execution.work_queue AS RESTRICTIVE FOR ALL TO :"execution_queue_definer_role"
    USING (environment_id=nullif(current_setting('app.execution_environment_id',true),'')::uuid
       AND (nullif(current_setting('app.execution_operation_id',true),'') IS NULL
         OR operation_id=nullif(current_setting('app.execution_operation_id',true),'')::uuid))
    WITH CHECK (environment_id=nullif(current_setting('app.execution_environment_id',true),'')::uuid);
CREATE POLICY enrollment_execution_queue_leases_allow ON enrollment_execution.claim_leases AS PERMISSIVE FOR ALL TO :"execution_queue_definer_role"
    USING (environment_id=nullif(current_setting('app.execution_environment_id',true),'')::uuid
         OR claim_token=nullif(current_setting('app.execution_claim_token',true),'')::uuid)
    WITH CHECK (environment_id=nullif(current_setting('app.execution_environment_id',true),'')::uuid
       AND claim_token=nullif(current_setting('app.execution_claim_token',true),'')::uuid);
CREATE POLICY enrollment_execution_queue_leases_limit ON enrollment_execution.claim_leases AS RESTRICTIVE FOR ALL TO :"execution_queue_definer_role"
    USING (environment_id=nullif(current_setting('app.execution_environment_id',true),'')::uuid
         OR claim_token=nullif(current_setting('app.execution_claim_token',true),'')::uuid)
    WITH CHECK (environment_id=nullif(current_setting('app.execution_environment_id',true),'')::uuid
       AND claim_token=nullif(current_setting('app.execution_claim_token',true),'')::uuid);
CREATE POLICY enrollment_execution_queue_results_allow ON enrollment_execution.issue_results AS PERMISSIVE FOR SELECT TO :"execution_queue_definer_role"
    USING (operation_id=nullif(current_setting('app.execution_operation_id',true),'')::uuid);
CREATE POLICY enrollment_execution_queue_results_limit ON enrollment_execution.issue_results AS RESTRICTIVE FOR SELECT TO :"execution_queue_definer_role"
    USING (operation_id=nullif(current_setting('app.execution_operation_id',true),'')::uuid);
CREATE POLICY enrollment_execution_queue_stops_allow ON enrollment_execution.execution_stops AS PERMISSIVE FOR SELECT TO :"execution_queue_definer_role"
    USING (operation_id=nullif(current_setting('app.execution_operation_id',true),'')::uuid);
CREATE POLICY enrollment_execution_queue_stops_limit ON enrollment_execution.execution_stops AS RESTRICTIVE FOR SELECT TO :"execution_queue_definer_role"
    USING (operation_id=nullif(current_setting('app.execution_operation_id',true),'')::uuid);

CREATE CONSTRAINT TRIGGER work_queue_outbox_consistent AFTER INSERT OR UPDATE ON public."Outbox"
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
    EXECUTE FUNCTION enrollment_execution.validate_work_queue();

CREATE OR REPLACE FUNCTION enrollment_execution.audit_execution_privileges(p_environment uuid)
RETURNS TABLE(is_valid boolean,diagnostic_code text,profile_version smallint)
LANGUAGE plpgsql STABLE PARALLEL UNSAFE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET row_security=on AS $function$
DECLARE
    table_owner oid;
    definer oid;
    runtime oid;
    queue_definer oid;
    delivery_definer oid;
    status_runtime oid;
    delivery_runtime oid;
    ok boolean;
    private_registry oid;
    private_marker oid;
BEGIN
    SELECT c.relowner INTO table_owner FROM pg_catalog.pg_class c
        WHERE c.oid='enrollment_execution.role_reservations'::regclass;
    SELECT r.role_oid INTO definer FROM enrollment_execution.role_reservations r
        WHERE r.capability='EnrollmentGrantExecution' AND r.role_kind='Definer';
    SELECT r.role_oid INTO queue_definer FROM enrollment_execution.role_reservations r
        WHERE r.capability='EnrollmentGrantExecution' AND r.role_kind='QueueDefiner';
    SELECT r.role_oid INTO delivery_definer FROM enrollment_execution.role_reservations r
        WHERE r.capability='EnrollmentGrantDelivery' AND r.role_kind='DeliveryDefiner';
    SELECT role.oid INTO runtime
    FROM public."DirectoryDatabaseBindings" b JOIN pg_catalog.pg_roles role ON role.rolname=b."LoginRole"
    JOIN enrollment_execution.role_reservations reservation
      ON reservation.role_name=b."LoginRole" AND reservation.role_oid=role.oid
      AND reservation.capability='EnrollmentGrantExecution' AND reservation.role_kind='Runtime'
    WHERE b."Purpose"='EnrollmentGrantExecution' AND b."ContractVersion"=2
      AND b."EnvironmentId"=p_environment AND b."PrincipalId" IS NULL;
    SELECT role.oid INTO status_runtime FROM public."DirectoryDatabaseBindings" binding
    JOIN pg_catalog.pg_roles role ON role.rolname=binding."LoginRole"
    JOIN enrollment_execution.role_reservations reservation
      ON reservation.role_name=binding."LoginRole" AND reservation.role_oid=role.oid
      AND reservation.capability='EnrollmentGrantDelivery' AND reservation.role_kind='StatusRuntime'
    WHERE binding."Purpose"='EnrollmentGrantStatusRefresh' AND binding."ContractVersion"=1
      AND binding."EnvironmentId"=p_environment AND binding."PrincipalId" IS NULL;
    SELECT role.oid INTO delivery_runtime FROM public."DirectoryDatabaseBindings" binding
    JOIN pg_catalog.pg_roles role ON role.rolname=binding."LoginRole"
    JOIN enrollment_execution.role_reservations reservation
      ON reservation.role_name=binding."LoginRole" AND reservation.role_oid=role.oid
      AND reservation.capability='EnrollmentGrantDelivery' AND reservation.role_kind='DeliveryRuntime'
    WHERE binding."Purpose"='EnrollmentGrantDelivery' AND binding."ContractVersion"=1
      AND binding."EnvironmentId"=p_environment AND binding."PrincipalId" IS NULL;

    ok := p_environment IS NOT NULL AND p_environment<>'00000000-0000-0000-0000-000000000000'::uuid
      AND pg_catalog.current_setting('session_replication_role')='origin'
      AND pg_catalog.current_setting('lo_compat_privileges')='off'
      AND table_owner IS NOT NULL AND definer IS NOT NULL AND queue_definer IS NOT NULL AND runtime IS NOT NULL
      AND delivery_definer IS NOT NULL AND (status_runtime IS NULL)=(delivery_runtime IS NULL)
      AND (SELECT count(*)=1 FROM enrollment_execution.role_reservations
           WHERE capability='EnrollmentGrantExecution' AND role_kind='Definer')
      AND (SELECT count(*)=1 FROM enrollment_execution.role_reservations
           WHERE capability='EnrollmentGrantExecution' AND role_kind='QueueDefiner')
      AND (SELECT count(*)=1 FROM enrollment_execution.role_reservations
           WHERE capability='EnrollmentGrantDelivery' AND role_kind='DeliveryDefiner')
      AND (SELECT count(*)=1 FROM public."DirectoryDatabaseBindings"
           WHERE "Purpose"='EnrollmentGrantExecution' AND "ContractVersion"=2
             AND "EnvironmentId"=p_environment AND "PrincipalId" IS NULL)
      AND NOT EXISTS (
          SELECT 1 FROM enrollment_execution.role_reservations reservation
          LEFT JOIN pg_catalog.pg_roles role ON role.oid=reservation.role_oid AND role.rolname=reservation.role_name
          WHERE role.oid IS NULL OR reservation.capability NOT IN('EnrollmentGrantExecution','EnrollmentGrantDelivery')
             OR reservation.reservation_schema_version<>1
             OR (reservation.role_kind IN('Runtime','StatusRuntime','DeliveryRuntime')) IS DISTINCT FROM role.rolcanlogin
             OR (reservation.capability='EnrollmentGrantExecution') IS DISTINCT FROM (reservation.role_kind IN('Runtime','Definer','QueueDefiner'))
             OR (reservation.capability='EnrollmentGrantDelivery') IS DISTINCT FROM (reservation.role_kind IN('DeliveryDefiner','StatusRuntime','DeliveryRuntime'))
             OR role.rolsuper OR role.rolbypassrls OR role.rolcreatedb OR role.rolcreaterole
             OR role.rolinherit OR role.rolreplication OR role.oid=table_owner
             OR EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members m WHERE m.roleid=role.oid OR m.member=role.oid))
      AND NOT EXISTS(SELECT 1 FROM enrollment_execution.role_reservations reservation
          WHERE reservation.role_kind='Runtime' AND NOT EXISTS(SELECT 1 FROM public."DirectoryDatabaseBindings" binding
            WHERE binding."LoginRole"=reservation.role_name AND binding."Purpose"='EnrollmentGrantExecution'
              AND binding."ContractVersion"=2 AND binding."EnvironmentId" IS NOT NULL AND binding."PrincipalId" IS NULL))
      AND NOT EXISTS(SELECT 1 FROM public."DirectoryDatabaseBindings" binding
          WHERE binding."Purpose"='EnrollmentGrantExecution' AND NOT EXISTS(SELECT 1 FROM enrollment_execution.role_reservations reservation
            WHERE reservation.role_name=binding."LoginRole" AND reservation.role_kind='Runtime'
              AND reservation.capability='EnrollmentGrantExecution' AND reservation.reservation_schema_version=1))
      AND NOT EXISTS(SELECT 1 FROM enrollment_execution.role_reservations reservation
          WHERE reservation.role_kind IN('StatusRuntime','DeliveryRuntime') AND NOT EXISTS(
            SELECT 1 FROM public."DirectoryDatabaseBindings" binding
            WHERE binding."LoginRole"=reservation.role_name
              AND binding."Purpose"=CASE reservation.role_kind WHEN 'StatusRuntime' THEN 'EnrollmentGrantStatusRefresh'
                    ELSE 'EnrollmentGrantDelivery' END
              AND binding."ContractVersion"=1 AND binding."EnvironmentId" IS NOT NULL AND binding."PrincipalId" IS NULL))
      AND NOT EXISTS(SELECT 1 FROM public."DirectoryDatabaseBindings" binding
          WHERE binding."Purpose" IN('EnrollmentGrantStatusRefresh','EnrollmentGrantDelivery') AND NOT EXISTS(
            SELECT 1 FROM enrollment_execution.role_reservations reservation
            WHERE reservation.role_name=binding."LoginRole" AND reservation.capability='EnrollmentGrantDelivery'
              AND reservation.role_kind=CASE binding."Purpose" WHEN 'EnrollmentGrantStatusRefresh' THEN 'StatusRuntime'
                    ELSE 'DeliveryRuntime' END AND reservation.reservation_schema_version=1))
      AND NOT EXISTS(SELECT 1 FROM public."DirectoryDatabaseBindings" binding
          WHERE binding."Purpose" IN('EnrollmentGrantStatusRefresh','EnrollmentGrantDelivery')
          GROUP BY binding."EnvironmentId" HAVING count(*)<>2)
      AND EXISTS(SELECT 1 FROM pg_catalog.pg_index index_row JOIN pg_catalog.pg_class index_class ON index_class.oid=index_row.indexrelid
          WHERE index_class.relname='enrollment_execution_environment_login'
            AND index_row.indrelid='public."DirectoryDatabaseBindings"'::regclass AND index_row.indisunique
            AND index_row.indisvalid AND index_row.indisready AND index_row.indpred IS NOT NULL
            AND pg_catalog.pg_get_expr(index_row.indpred,index_row.indrelid)='("Purpose" = ''EnrollmentGrantExecution''::text)')
      AND EXISTS(SELECT 1 FROM pg_catalog.pg_index index_row JOIN pg_catalog.pg_class index_class ON index_class.oid=index_row.indexrelid
          WHERE index_class.relname='enrollment_grant_status_environment_login'
            AND index_row.indrelid='public."DirectoryDatabaseBindings"'::regclass AND index_row.indisunique
            AND index_row.indisvalid AND index_row.indisready AND index_row.indpred IS NOT NULL
            AND pg_catalog.pg_get_expr(index_row.indpred,index_row.indrelid)='("Purpose" = ''EnrollmentGrantStatusRefresh''::text)')
      AND EXISTS(SELECT 1 FROM pg_catalog.pg_index index_row JOIN pg_catalog.pg_class index_class ON index_class.oid=index_row.indexrelid
          WHERE index_class.relname='enrollment_grant_delivery_environment_login'
            AND index_row.indrelid='public."DirectoryDatabaseBindings"'::regclass AND index_row.indisunique
            AND index_row.indisvalid AND index_row.indisready AND index_row.indpred IS NOT NULL
            AND pg_catalog.pg_get_expr(index_row.indpred,index_row.indrelid)='("Purpose" = ''EnrollmentGrantDelivery''::text)')
      ;

    SELECT c.oid INTO private_registry FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='agent_private' AND c.relname='agent_capability_roles';
    SELECT p.oid INTO private_marker FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
      WHERE n.nspname='agent_private' AND p.proname='agent_capability_isolation_profile' LIMIT 1;
    ok := ok AND private_registry IS NULL AND private_marker IS NULL;

    -- The deliberately separate structural checks keep malformed catalog rows from being accepted
    -- even when the owner-only RLS boundary still hides them from ordinary callers.
    ok := ok
      AND (SELECT count(*)=5 AND bool_and(a.attnotnull AND a.attidentity='' AND a.attgenerated='')
           FROM pg_catalog.pg_attribute a WHERE a.attrelid='enrollment_execution.role_reservations'::regclass
             AND a.attnum>0 AND NOT a.attisdropped)
      AND (SELECT c.relowner=table_owner AND c.relrowsecurity AND c.relforcerowsecurity AND c.relkind='r'
           FROM pg_catalog.pg_class c WHERE c.oid='enrollment_execution.role_reservations'::regclass)
      AND (SELECT count(*)=1 FROM pg_catalog.pg_policy p
           WHERE p.polrelid='enrollment_execution.role_reservations'::regclass
             AND p.polname='enrollment_execution_reservation_owner' AND p.polcmd='*'
             AND p.polpermissive AND p.polroles=ARRAY[table_owner]
             AND pg_catalog.pg_get_expr(p.polqual,p.polrelid)='true'
             AND pg_catalog.pg_get_expr(p.polwithcheck,p.polrelid)='true')
      AND (SELECT count(*)=1 FROM pg_catalog.pg_policy p
           WHERE p.polrelid='enrollment_execution.role_reservations'::regclass)
      AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c
          CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(c.relacl,pg_catalog.acldefault('r',c.relowner))) acl
          WHERE c.oid='enrollment_execution.role_reservations'::regclass AND acl.grantee<>table_owner)
      AND NOT EXISTS(
        WITH expected(definition) AS (VALUES
          ('PRIMARY KEY (role_name)'),('UNIQUE (role_oid)'),
          ('CHECK (capability = ANY (ARRAY[''EnrollmentGrantExecution''::text, ''EnrollmentGrantDelivery''::text]))'),('CHECK (reservation_schema_version = 1)'),
          ('CHECK (capability = ''EnrollmentGrantExecution''::text AND (role_kind = ANY (ARRAY[''Runtime''::text, ''Definer''::text, ''QueueDefiner''::text])) OR capability = ''EnrollmentGrantDelivery''::text AND (role_kind = ANY (ARRAY[''DeliveryDefiner''::text, ''StatusRuntime''::text, ''DeliveryRuntime''::text])))'),
          ('CHECK (btrim(role_name::text) <> ''''::text)'),('CHECK (role_oid <> 0::oid)')),
        actual AS (SELECT pg_catalog.pg_get_constraintdef(c.oid,true) definition FROM pg_catalog.pg_constraint c
          WHERE c.conrelid='enrollment_execution.role_reservations'::regclass AND c.contype IN('p','u','c') AND c.convalidated)
        SELECT 1 FROM ((SELECT * FROM expected EXCEPT SELECT * FROM actual)
                       UNION ALL (SELECT * FROM actual EXCEPT SELECT * FROM expected)) difference);

    ok := ok
      AND EXISTS(SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_language l ON l.oid=p.prolang
          WHERE p.oid='enrollment_execution.execution_store_profile()'::regprocedure
            AND p.proowner=table_owner AND l.lanname='sql' AND NOT p.prosecdef AND p.provolatile='i'
            AND p.proparallel='s' AND p.prokind='f' AND NOT p.proretset AND p.prorettype='smallint'::regtype
            AND p.pronargs=0 AND p.proargnames IS NULL AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']
            AND pg_catalog.btrim(p.prosrc,E' \t\r\n')='SELECT 4::smallint')
      AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p
          CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) acl
          WHERE p.oid='enrollment_execution.execution_store_profile()'::regprocedure
            AND (acl.grantee<>table_owner OR acl.privilege_type<>'EXECUTE' OR acl.is_grantable));

    ok := ok AND NOT EXISTS (
        WITH expected(signature,owner_oid,security_definer,strict_value,language_name,volatility,parallel_code,with_rls,body_hash) AS (VALUES
          ('enrollment_execution.read_record(uuid,uuid)',table_owner,false,false,'sql','s','u',false,'73351f798b74238a43dd2add4b014cd74f31006f8aa94b9c97ce07cbc649311d'),
          ('enrollment_execution.authorization_digest(public."EnrollmentGrantOperations",smallint,timestamptz,timestamptz,bytea,bytea,bytea)',table_owner,false,true,'plpgsql','i','u',false,'3349c5c5548d5fe2a86bbae19fe43205f3673d40d0d4fcc333da506c3cd27580'),
          ('enrollment_execution.lock_plan_context(uuid,uuid)',table_owner,false,false,'plpgsql','v','u',false,'fe4f7c5b9e1f3d7d3473f07ba572dfc6aad6f3daedee42549fa19dfb14d98b9a'),
          ('enrollment_execution.scope_uuid(text)',table_owner,false,false,'plpgsql','i','u',false,'a7dd6ec2c76752765dd101c860b90d7b27db09de8865db291e555ca1ae96e72b'),
          ('enrollment_execution.has_computer_permission(uuid,uuid,uuid,uuid,text)',table_owner,false,false,'sql','s','u',false,'c3fb51c2382305ee8d2da5b40221261edd9978c0a3c3d3eab0ac86929221d4a2'),
          ('enrollment_execution.current_authority_matches(public."EnrollmentGrantOperations",timestamptz)',table_owner,false,false,'sql','s','u',false,'c79d26d0612c8ce0bacd13de10e9fe4b03eefe8679eb8b5aa4555c7a65dd6f71'),
          ('enrollment_execution.store_candidate(uuid,uuid,text,bytea,bytea,bytea)',table_owner,false,false,'plpgsql','v','u',false,'0403f86046e3b1896538232dd17ff7cd124a61901d23031146cdb31d175b7cba'),
          ('enrollment_execution.store_result(uuid,uuid,bytea,text,text,uuid,uuid,uuid,uuid,timestamptz,timestamptz,timestamptz,smallint,timestamptz,bytea,bytea)',table_owner,false,false,'plpgsql','v','u',false,'12047650d35da8f6b90b12de80b51cb0e79cb6ed84b1c4e63358c24e177debc0'),
          ('enrollment_execution.store_quarantine(uuid,uuid,bytea,text)',table_owner,false,false,'plpgsql','v','u',false,'7ea3dfa0ad6294076d83d0fec449cbdda1e142e4fadcf55db27f81beef704739'),
          ('enrollment_execution.worker_scope(uuid)',definer,false,false,'plpgsql','s','u',false,'98214f62b088dec4e8b97ee7d01a96c61b5d422924367b903a99ccf932c923be'),
          ('enrollment_execution.read_execution_record(uuid,uuid)',definer,true,false,'plpgsql','v','u',true,'2f3912f5ed9c772e69ced062acaadb43d7c162a3f13ae10af45086c65fc393af'),
          ('enrollment_execution.read_and_lock_plan_context(uuid,uuid)',definer,true,false,'plpgsql','v','u',true,'65799fd04794c614c6cf323b0125ff20b490c17bac4bb9eafa528cb416097af6'),
          ('enrollment_execution.authorize_and_store_candidate(uuid,uuid,text,bytea,bytea,bytea)',definer,true,false,'plpgsql','v','u',true,'34bc89d3bfbd3cdc55e52ce7ab9cd6f6cf6735b9ac7a15ad8cee4b9b3c064449'),
          ('enrollment_execution.record_execution_result(uuid,uuid,bytea,text,text,uuid,uuid,uuid,uuid,timestamptz,timestamptz,timestamptz,smallint,timestamptz,bytea,bytea)',definer,true,false,'plpgsql','v','u',true,'659c0cb518bc415193080105b9cbd504e1cb8a27592e124166b27937c4a0fdbf'),
          ('enrollment_execution.quarantine_execution(uuid,uuid,bytea,text)',definer,true,false,'plpgsql','v','u',true,'d49af3d745e3d6878926e39a8cdc2354695350be3e1a512f996289d00b0c13f8')),
        actual AS (
          SELECT e.*,p.oid,p.proowner,p.prosecdef,p.proisstrict,l.lanname,p.provolatile,p.proparallel,p.proconfig,
            pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
              pg_catalog.btrim(pg_catalog.regexp_replace(p.prosrc,'[[:space:]]+',' ','g')),'UTF8')),'hex') actual_hash
          FROM expected e LEFT JOIN pg_catalog.pg_proc p ON p.oid=pg_catalog.to_regprocedure(e.signature)
          LEFT JOIN pg_catalog.pg_language l ON l.oid=p.prolang)
        SELECT 1 FROM actual a WHERE a.oid IS NULL OR a.proowner<>a.owner_oid OR a.prosecdef<>a.security_definer OR a.proisstrict<>a.strict_value
          OR a.lanname<>a.language_name OR a.provolatile<>a.volatility OR a.proparallel<>a.parallel_code
          OR a.proconfig<>CASE WHEN a.with_rls THEN ARRAY['search_path=pg_catalog, pg_temp','row_security=on']
                              ELSE ARRAY['search_path=pg_catalog, pg_temp'] END
          OR a.actual_hash<>a.body_hash);

    -- Runtime roles have only CONNECT, schema USAGE and the six wrappers. Effective PUBLIC
    -- relation privileges are included because they are privileges of every LOGIN.
    -- function and policy grants are checked by the external profile query as a set.
    ok := ok
      AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p WHERE p.proowner=runtime)
      AND (SELECT count(*)=6 FROM pg_catalog.pg_proc p WHERE p.proowner=definer AND p.oid IN(
          'enrollment_execution.worker_scope(uuid)'::regprocedure,
          'enrollment_execution.read_execution_record(uuid,uuid)'::regprocedure,
          'enrollment_execution.read_and_lock_plan_context(uuid,uuid)'::regprocedure,
          'enrollment_execution.authorize_and_store_candidate(uuid,uuid,text,bytea,bytea,bytea)'::regprocedure,
          'enrollment_execution.record_execution_result(uuid,uuid,bytea,text,text,uuid,uuid,uuid,uuid,timestamptz,timestamptz,timestamptz,smallint,timestamptz,bytea,bytea)'::regprocedure,
          'enrollment_execution.quarantine_execution(uuid,uuid,bytea,text)'::regprocedure))
      AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p WHERE p.proowner=definer AND p.oid NOT IN(
          'enrollment_execution.worker_scope(uuid)'::regprocedure,
          'enrollment_execution.read_execution_record(uuid,uuid)'::regprocedure,
          'enrollment_execution.read_and_lock_plan_context(uuid,uuid)'::regprocedure,
          'enrollment_execution.authorize_and_store_candidate(uuid,uuid,text,bytea,bytea,bytea)'::regprocedure,
          'enrollment_execution.record_execution_result(uuid,uuid,bytea,text,text,uuid,uuid,uuid,uuid,timestamptz,timestamptz,timestamptz,smallint,timestamptz,bytea,bytea)'::regprocedure,
          'enrollment_execution.quarantine_execution(uuid,uuid,bytea,text)'::regprocedure))
      AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c
          CROSS JOIN LATERAL pg_catalog.aclexplode(c.relacl) acl
          WHERE acl.grantee=runtime)
      AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_attribute a
          CROSS JOIN LATERAL pg_catalog.aclexplode(a.attacl) acl WHERE acl.grantee=runtime)
      AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c
          WHERE CASE WHEN c.relkind='S' THEN pg_catalog.has_sequence_privilege(runtime,c.oid,'USAGE,SELECT,UPDATE') ELSE false END)
      AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
          WHERE n.nspname IN('public','enrollment_execution') AND c.relkind IN('r','p','v','m','f')
            AND pg_catalog.has_table_privilege(runtime,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'))
      AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
          WHERE n.nspname IN('public','enrollment_execution') AND c.relkind IN('r','p','v','m','f')
            AND pg_catalog.has_any_column_privilege(runtime,c.oid,'SELECT,INSERT,UPDATE,REFERENCES'))
      AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
          WHERE n.nspname IN('public','enrollment_execution')
            AND CASE WHEN c.relkind='S' THEN pg_catalog.has_sequence_privilege(runtime,c.oid,'USAGE,SELECT,UPDATE') ELSE false END)
      AND NOT pg_catalog.has_database_privilege(runtime,pg_catalog.current_database(),'CREATE')
      AND NOT pg_catalog.has_schema_privilege(runtime,'public','CREATE')
      AND NOT pg_catalog.has_schema_privilege(runtime,'enrollment_execution','CREATE')
      AND (SELECT count(*)=9 FROM pg_catalog.pg_proc p
          CROSS JOIN LATERAL pg_catalog.aclexplode(p.proacl) acl
          WHERE acl.grantee=runtime AND acl.privilege_type='EXECUTE' AND NOT acl.is_grantable
            AND p.oid IN ('enrollment_execution.read_execution_record(uuid,uuid)'::regprocedure,
              'enrollment_execution.read_and_lock_plan_context(uuid,uuid)'::regprocedure,
              'enrollment_execution.authorize_and_store_candidate(uuid,uuid,text,bytea,bytea,bytea)'::regprocedure,
              'enrollment_execution.record_execution_result(uuid,uuid,bytea,text,text,uuid,uuid,uuid,uuid,timestamptz,timestamptz,timestamptz,smallint,timestamptz,bytea,bytea)'::regprocedure,
              'enrollment_execution.quarantine_execution(uuid,uuid,bytea,text)'::regprocedure,
              'enrollment_execution.claim_next(uuid,uuid)'::regprocedure,
              'enrollment_execution.defer_claim(uuid,uuid,uuid,text)'::regprocedure,
              'enrollment_execution.complete_claim(uuid,uuid,uuid)'::regprocedure,
              'enrollment_execution.audit_execution_privileges(uuid)'::regprocedure))
      AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p
          CROSS JOIN LATERAL pg_catalog.aclexplode(p.proacl) acl
          WHERE acl.grantee=runtime AND (acl.privilege_type<>'EXECUTE' OR acl.is_grantable OR p.oid NOT IN (
              'enrollment_execution.read_execution_record(uuid,uuid)'::regprocedure,
              'enrollment_execution.read_and_lock_plan_context(uuid,uuid)'::regprocedure,
              'enrollment_execution.authorize_and_store_candidate(uuid,uuid,text,bytea,bytea,bytea)'::regprocedure,
              'enrollment_execution.record_execution_result(uuid,uuid,bytea,text,text,uuid,uuid,uuid,uuid,timestamptz,timestamptz,timestamptz,smallint,timestamptz,bytea,bytea)'::regprocedure,
              'enrollment_execution.quarantine_execution(uuid,uuid,bytea,text)'::regprocedure,
              'enrollment_execution.claim_next(uuid,uuid)'::regprocedure,
              'enrollment_execution.defer_claim(uuid,uuid,uuid,text)'::regprocedure,
              'enrollment_execution.complete_claim(uuid,uuid,uuid)'::regprocedure,
              'enrollment_execution.audit_execution_privileges(uuid)'::regprocedure)));

    ok := ok AND NOT EXISTS(
      WITH callable(function_oid) AS (VALUES
        ('enrollment_execution.read_execution_record(uuid,uuid)'::regprocedure::oid),
        ('enrollment_execution.read_and_lock_plan_context(uuid,uuid)'::regprocedure::oid),
        ('enrollment_execution.authorize_and_store_candidate(uuid,uuid,text,bytea,bytea,bytea)'::regprocedure::oid),
        ('enrollment_execution.record_execution_result(uuid,uuid,bytea,text,text,uuid,uuid,uuid,uuid,timestamptz,timestamptz,timestamptz,smallint,timestamptz,bytea,bytea)'::regprocedure::oid),
        ('enrollment_execution.quarantine_execution(uuid,uuid,bytea,text)'::regprocedure::oid)),
      runtime_roles(role_oid) AS (SELECT role_oid FROM enrollment_execution.role_reservations WHERE role_kind='Runtime'),
      expected(function_oid,grantee) AS (
        SELECT function_oid,definer FROM callable UNION ALL SELECT function_oid,role_oid FROM callable CROSS JOIN runtime_roles
        UNION ALL SELECT 'enrollment_execution.worker_scope(uuid)'::regprocedure::oid,definer
        UNION ALL SELECT 'enrollment_execution.audit_execution_privileges(uuid)'::regprocedure::oid,table_owner
        UNION ALL SELECT 'enrollment_execution.audit_execution_privileges(uuid)'::regprocedure::oid,definer
        UNION ALL SELECT 'enrollment_execution.audit_execution_privileges(uuid)'::regprocedure::oid,queue_definer
        UNION ALL SELECT 'enrollment_execution.audit_execution_privileges(uuid)'::regprocedure::oid,role_oid FROM runtime_roles),
      actual AS (SELECT p.oid function_oid,acl.grantee FROM pg_catalog.pg_proc p
        CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) acl
        WHERE p.oid IN(SELECT function_oid FROM callable UNION SELECT 'enrollment_execution.worker_scope(uuid)'::regprocedure::oid
          UNION SELECT 'enrollment_execution.audit_execution_privileges(uuid)'::regprocedure::oid)
          AND acl.privilege_type='EXECUTE' AND NOT acl.is_grantable)
      SELECT 1 FROM ((SELECT * FROM expected EXCEPT SELECT * FROM actual)
                       UNION ALL (SELECT * FROM actual EXCEPT SELECT * FROM expected)) difference);

    ok := ok
      AND NOT EXISTS(
        WITH expected(table_oid,privilege_type) AS (VALUES
          ('enrollment_execution.mint_permits'::regclass::oid,'SELECT'),('enrollment_execution.mint_permits'::regclass::oid,'INSERT'),
          ('enrollment_execution.sealed_envelopes'::regclass::oid,'SELECT'),('enrollment_execution.sealed_envelopes'::regclass::oid,'INSERT'),('enrollment_execution.sealed_envelopes'::regclass::oid,'DELETE'),
          ('enrollment_execution.issue_results'::regclass::oid,'SELECT'),('enrollment_execution.issue_results'::regclass::oid,'INSERT'),
          ('enrollment_execution.delivery_acks'::regclass::oid,'SELECT'),
          ('enrollment_execution.execution_stops'::regclass::oid,'SELECT'),('enrollment_execution.execution_stops'::regclass::oid,'INSERT')),
        actual AS (SELECT c.oid table_oid,acl.privilege_type::text FROM pg_catalog.pg_class c
          CROSS JOIN LATERAL pg_catalog.aclexplode(c.relacl) acl WHERE acl.grantee=definer AND NOT acl.is_grantable)
        SELECT 1 FROM ((SELECT * FROM expected EXCEPT SELECT * FROM actual)
                       UNION ALL (SELECT * FROM actual EXCEPT SELECT * FROM expected)) difference)
      AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c
        CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(c.relacl,pg_catalog.acldefault('r',c.relowner))) acl
        WHERE c.oid IN('enrollment_execution.work_queue'::regclass,'enrollment_execution.claim_leases'::regclass)
          AND (acl.grantee NOT IN(table_owner,queue_definer) OR acl.is_grantable))
      AND NOT EXISTS(
        WITH expected(function_oid) AS (VALUES
          ('enrollment_execution.read_record(uuid,uuid)'::regprocedure::oid),
          ('enrollment_execution.authorization_digest(public."EnrollmentGrantOperations",smallint,timestamptz,timestamptz,bytea,bytea,bytea)'::regprocedure::oid),
          ('enrollment_execution.lock_plan_context(uuid,uuid)'::regprocedure::oid),('enrollment_execution.scope_uuid(text)'::regprocedure::oid),
          ('enrollment_execution.has_computer_permission(uuid,uuid,uuid,uuid,text)'::regprocedure::oid),
          ('enrollment_execution.current_authority_matches(public."EnrollmentGrantOperations",timestamptz)'::regprocedure::oid),
          ('enrollment_execution.store_candidate(uuid,uuid,text,bytea,bytea,bytea)'::regprocedure::oid),
          ('enrollment_execution.store_result(uuid,uuid,bytea,text,text,uuid,uuid,uuid,uuid,timestamptz,timestamptz,timestamptz,smallint,timestamptz,bytea,bytea)'::regprocedure::oid),
          ('enrollment_execution.store_quarantine(uuid,uuid,bytea,text)'::regprocedure::oid),
          ('enrollment_execution.audit_execution_privileges(uuid)'::regprocedure::oid),
          ('public.has_environment_membership(uuid,uuid)'::regprocedure::oid),
          ('public.directory_database_access(uuid,uuid)'::regprocedure::oid),
          ('enrollment_execution.worker_scope(uuid)'::regprocedure::oid),
          ('enrollment_execution.read_execution_record(uuid,uuid)'::regprocedure::oid),
          ('enrollment_execution.read_and_lock_plan_context(uuid,uuid)'::regprocedure::oid),
          ('enrollment_execution.authorize_and_store_candidate(uuid,uuid,text,bytea,bytea,bytea)'::regprocedure::oid),
          ('enrollment_execution.record_execution_result(uuid,uuid,bytea,text,text,uuid,uuid,uuid,uuid,timestamptz,timestamptz,timestamptz,smallint,timestamptz,bytea,bytea)'::regprocedure::oid),
          ('enrollment_execution.quarantine_execution(uuid,uuid,bytea,text)'::regprocedure::oid)),
        actual AS (SELECT p.oid function_oid FROM pg_catalog.pg_proc p
          CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) acl
          WHERE acl.grantee=definer AND acl.privilege_type='EXECUTE' AND NOT acl.is_grantable)
        SELECT 1 FROM ((SELECT * FROM expected EXCEPT SELECT * FROM actual)
                       UNION ALL (SELECT * FROM actual EXCEPT SELECT * FROM expected)) difference)
      AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p
        CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) acl
        WHERE acl.grantee=definer AND (acl.privilege_type<>'EXECUTE' OR acl.is_grantable));

    -- BEGIN delivery policy callee metadata
    ok := ok AND (SELECT count(*)=2 AND bool_and(p.proowner=table_owner AND l.lanname='sql'
        AND p.prosecdef AND p.provolatile='s' AND p.proparallel='u' AND NOT p.proretset
        AND p.prokind='f' AND p.prorettype='boolean'::regtype
        AND p.proisstrict=(p.proname='has_environment_membership') AND NOT p.proleakproof
        AND p.pronargs=2 AND p.proargtypes='2950 2950'::oidvector
        AND p.proargnames=CASE p.proname WHEN 'has_environment_membership' THEN ARRAY['p_environment_id','p_principal_id']
          ELSE ARRAY['p_environment','p_principal'] END
        AND p.proallargtypes IS NULL AND p.proargmodes IS NULL AND p.pronargdefaults=0 AND p.provariadic=0
        AND p.prosupport=0 AND p.probin IS NULL AND p.prosqlbody IS NULL AND p.proargdefaults IS NULL
        AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp','row_security=off']
        AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
          pg_catalog.btrim(pg_catalog.regexp_replace(p.prosrc,'[[:space:]]+',' ','g')),'UTF8')),'hex')
          =CASE p.proname WHEN 'has_environment_membership' THEN 'c9529f8fad835c8125509e539be576a576a94e7d03660e67023392b7e951ae4c'
                          ELSE '9822d3a40ee96593c8aad915ac6ca454868274347f5a6e30fab61eeca60752a4' END)
      FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_language l ON l.oid=p.prolang
      WHERE p.oid IN(pg_catalog.to_regprocedure('public.has_environment_membership(uuid,uuid)'),
                     pg_catalog.to_regprocedure('public.directory_database_access(uuid,uuid)')));
    -- END delivery policy callee metadata

    ok := ok AND NOT EXISTS(
      WITH specification AS (SELECT '{
        "DirectoryDatabaseBindings":{"s":["LoginRole","Purpose","ContractVersion","EnvironmentId","PrincipalId"],"u":[]},
        "Environments":{"s":["Id","Version"],"u":["Name"]},
        "DirectorySync":{"s":["EnvironmentId","Status","Generation","CompletedAt"],"u":["ErrorCode"]},
        "DirectoryObjects":{"s":["EnvironmentId","Id","Generation","Kind","Department","ParentOuId","OuAncestry"],"u":["Name"]},
        "Principals":{"s":["Id","OperatorId","Enabled"],"u":["DisplayName"]},
        "Memberships":{"s":["EnvironmentId","PrincipalId","Active"],"u":["Active"]},
        "Plans":{"s":["EnvironmentId","Id","RequesterId","Action","ImmutablePlanJson","PlanHash","PolicyVersion","ExpiresAt","State","Reason"],"u":["Reason"]},
        "PlanItems":{"s":["EnvironmentId","PlanId","Id","TargetId","ExpectedVersion"],"u":[]},
        "Approvals":{"s":["EnvironmentId","Id","PlanId","PlanHash","ApproverId","ApprovedAt","ExpiresAt"],"u":[]},
        "EnrollmentGrantRecipientReservations":{"s":["Fingerprint","EnvironmentId","PlanId","RequesterId","RequestId","RequestDigest","CreatedAt"],"u":[]},
        "EnrollmentGrantOperations":{"s":["EnvironmentId","Id","PlanId","RequestId","ApprovalId","RequesterId","ApproverId","RequesterOperatorId","ApproverOperatorId","PlanHash","DirectoryObjectId","ServerDeviceId","MappingCreatedAt","DirectoryGeneration","EnvironmentVersion","RecipientSpki","RecipientKeyFingerprint","QueuedAt","AuthorizationNotAfter"],"u":["PlanHash"]},
        "Outbox":{"s":["EnvironmentId","Id","EventType","Version","Payload","CreatedAt","DeliveredAt","Attempts"],"u":["Attempts","DeliveredAt"]},
        "Roles":{"s":["EnvironmentId","Id","BuiltInKind"],"u":[]},
        "RolePermissions":{"s":["EnvironmentId","RoleId","Permission"],"u":[]},
        "Assignments":{"s":["EnvironmentId","PrincipalId","RoleId","ScopeId"],"u":[]},
        "Scopes":{"s":["EnvironmentId","Id","Kind","Value","IncludeDescendants"],"u":[]},
        "DeviceTagAssignments":{"s":["EnvironmentId","TagId","ObjectId"],"u":[]}
      }'::jsonb value),
      expected AS (
        SELECT entry.key::text table_name,column_name,'SELECT'::text privilege_type
          FROM specification CROSS JOIN LATERAL pg_catalog.jsonb_each(value) entry
          CROSS JOIN LATERAL pg_catalog.jsonb_array_elements_text(entry.value->'s') column_name
        UNION ALL
        SELECT entry.key::text,column_name,'UPDATE'::text
          FROM specification CROSS JOIN LATERAL pg_catalog.jsonb_each(value) entry
          CROSS JOIN LATERAL pg_catalog.jsonb_array_elements_text(entry.value->'u') column_name),
      actual AS (SELECT c.relname::text table_name,a.attname::text column_name,acl.privilege_type::text
        FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid=a.attrelid
        CROSS JOIN LATERAL pg_catalog.aclexplode(a.attacl) acl
        WHERE acl.grantee=definer AND NOT acl.is_grantable)
      SELECT 1 FROM ((SELECT * FROM expected EXCEPT SELECT * FROM actual)
                       UNION ALL (SELECT * FROM actual EXCEPT SELECT * FROM expected)) difference);

    ok := ok AND NOT EXISTS(
      WITH expected(table_name,stem,command_code,expression_hash) AS (VALUES
       ('Environments','environments','*','72848ad21aa1e3d408e6077dc673f6cc'),
       ('DirectorySync','sync','*','c9bf590d9490f246c077b184bca72bd3'),
       ('DirectoryObjects','directory','*','398c3366e0c18d8a80c458efa4753e71'),
       ('Memberships','memberships','*','2430497aa2e8047febe8ccafba64f2be'),
       ('Plans','plans','*','1fb7b4a7af54f5d87697f90a5b94412b'),('PlanItems','items','r','158b72978f11ad4651c98e8dbe14e0c0'),
       ('Approvals','approvals','r','3d014e1fcee9fe3d3c3c26bfa134c28d'),
       ('EnrollmentGrantRecipientReservations','reservations','r','158b72978f11ad4651c98e8dbe14e0c0'),
       ('EnrollmentGrantOperations','operations','*','b36fd52c8f5d4554c711240c8bfbf7b1'),
       ('Outbox','outbox','*','5bf0f5fde4d3ef224fe8663c330d023d'),
       ('Roles','roles','r','e6f72a9bf9d21b456839016ca443b6a2'),('RolePermissions','role_permissions','r','e6f72a9bf9d21b456839016ca443b6a2'),
       ('Assignments','assignments','r','e6f72a9bf9d21b456839016ca443b6a2'),('Scopes','scopes','r','e6f72a9bf9d21b456839016ca443b6a2'),
       ('DeviceTagAssignments','tag_assignments','r','e6f72a9bf9d21b456839016ca443b6a2'),
       ('mint_permits','permits','*','f944b2ad874efb598b54ab652e73a4f8'),('sealed_envelopes','envelopes','*','f944b2ad874efb598b54ab652e73a4f8'),
       ('issue_results','results','*','f944b2ad874efb598b54ab652e73a4f8'),('delivery_acks','acks','r','367e9d4e206baca6b6386de916a9cdb1'),
       ('execution_stops','stops','*','f944b2ad874efb598b54ab652e73a4f8')),
      actual AS (SELECT c.relname::text table_name,p.polname,p.polcmd::text,p.polpermissive,p.polroles,
          pg_catalog.md5(COALESCE(pg_catalog.pg_get_expr(p.polqual,p.polrelid),'')||'|'||
                         COALESCE(pg_catalog.pg_get_expr(p.polwithcheck,p.polrelid),'')) expression_hash
        FROM pg_catalog.pg_policy p JOIN pg_catalog.pg_class c ON c.oid=p.polrelid
        WHERE p.polname LIKE 'enrollment_execution_worker_%'),
      wanted AS (SELECT table_name,'enrollment_execution_worker_'||stem||'_allow' polname,command_code polcmd,true polpermissive,ARRAY[definer] polroles,expression_hash FROM expected
        UNION ALL SELECT table_name,'enrollment_execution_worker_'||stem||'_limit',command_code,false,ARRAY[definer],expression_hash FROM expected)
      SELECT 1 FROM ((SELECT * FROM wanted EXCEPT SELECT * FROM actual)
                     UNION ALL (SELECT * FROM actual EXCEPT SELECT * FROM wanted)) difference)
      AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_policy p
        WHERE definer=ANY(p.polroles) AND p.polname NOT LIKE 'enrollment_execution_worker_%'
          AND NOT (p.polrelid='public."Principals"'::regclass AND p.polname IN(
            'enrollment_identity_principals_execution_read_allow','enrollment_identity_principals_execution_read_limit',
            'enrollment_identity_principals_execution_lock_allow','enrollment_identity_principals_execution_lock_limit')))
      AND (SELECT count(*)=8 FROM pg_catalog.pg_trigger t
        WHERE NOT t.tgisinternal AND t.tgname LIKE 'enrollment_execution_worker_%'
          AND t.tgenabled='O' AND t.tgtype=19
          AND t.tgfoid='enrollment_execution.reject_worker_update()'::regprocedure)
      AND EXISTS(SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_language l ON l.oid=p.prolang
        WHERE p.oid='enrollment_execution.reject_worker_update()'::regprocedure
          AND p.proowner=table_owner AND l.lanname='plpgsql' AND p.prosecdef AND p.provolatile='v' AND p.proparallel='u'
          AND NOT p.proretset AND p.prorettype='trigger'::regtype AND p.pronargs=0 AND p.proisstrict=false
          AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp','row_security=on']
          AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
            pg_catalog.btrim(pg_catalog.regexp_replace(p.prosrc,'[[:space:]]+',' ','g')),'UTF8')),'hex')
             ='d1ec22104428fc1116f5bf38a102d177535b147cdb935dac0be207aef342548a')
      AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p
        CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) acl
        WHERE p.oid='enrollment_execution.reject_worker_update()'::regprocedure
          AND (acl.grantee<>table_owner OR acl.privilege_type<>'EXECUTE' OR acl.is_grantable));

    ok := ok
      AND (SELECT count(*)=4 FROM pg_catalog.pg_proc p WHERE p.proowner=queue_definer AND p.oid IN(
          'enrollment_execution.queue_worker_scope(uuid)'::regprocedure,
          'enrollment_execution.claim_next(uuid,uuid)'::regprocedure,
          'enrollment_execution.defer_claim(uuid,uuid,uuid,text)'::regprocedure,
          'enrollment_execution.complete_claim(uuid,uuid,uuid)'::regprocedure))
      AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p WHERE p.proowner=queue_definer AND p.oid NOT IN(
          'enrollment_execution.queue_worker_scope(uuid)'::regprocedure,
          'enrollment_execution.claim_next(uuid,uuid)'::regprocedure,
          'enrollment_execution.defer_claim(uuid,uuid,uuid,text)'::regprocedure,
          'enrollment_execution.complete_claim(uuid,uuid,uuid)'::regprocedure))
      AND NOT EXISTS(
        WITH expected(signature,owner_oid,security_definer,with_rls,volatility,body_hash) AS (VALUES
          ('enrollment_execution.guard_work_queue()',table_owner,false,false,'v','ff0696df19dbf6a84bb013d1b09a3b46ebcea741f9c13ec81a3f1e11dce32fe9'),
          ('enrollment_execution.validate_work_queue()',table_owner,true,true,'v','42856db068ea7434ab55cc414b8172d1552d701d9f6029085fd13a5b51aab1aa'),
          ('enrollment_execution.claim_next_work(uuid,uuid)',table_owner,false,false,'v','ac30e75b4c12d81ce1fe1487aa81adec0277b8c01f98ac4cad7651bed3d78a1d'),
          ('enrollment_execution.defer_work_claim(uuid,uuid,uuid,text)',table_owner,false,false,'v','d5dbc6f35566e700b1445369cf126cb6befb0e600a991d5cfa1425241fdb5ed2'),
          ('enrollment_execution.complete_work_claim(uuid,uuid,uuid)',table_owner,false,false,'v','8ef05062db0c3903c82d224672ec898954b11e28e4506bf8d7af1052f7f9c618'),
          ('enrollment_execution.queue_worker_scope(uuid)',queue_definer,false,false,'s','350f3dc7c48f2869848a2fc67e320f0a67e507caba08d3651e71ab9e2a1e18ea'),
          ('enrollment_execution.claim_next(uuid,uuid)',queue_definer,true,true,'v','2bf10374af74a53631cc3cf49ca5915d94faceeb2f5784376a1ea149240c52d8'),
          ('enrollment_execution.defer_claim(uuid,uuid,uuid,text)',queue_definer,true,true,'v','37f9afac59b8e9ca87d5a8bd2db4d245fae98046195c2d47e68e7117063dc216'),
          ('enrollment_execution.complete_claim(uuid,uuid,uuid)',queue_definer,true,true,'v','25cc765b56bc15a05e01ad306c354fe5ed245c3622a3fb22589e14e35a60c37e')),
        actual AS (SELECT expected.*,p.oid,p.proowner,p.prosecdef,p.proisstrict,l.lanname,p.provolatile,p.proparallel,p.proconfig,
            pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
              pg_catalog.btrim(pg_catalog.regexp_replace(p.prosrc,'[[:space:]]+',' ','g')),'UTF8')),'hex') actual_hash
          FROM expected LEFT JOIN pg_catalog.pg_proc p ON p.oid=pg_catalog.to_regprocedure(expected.signature)
          LEFT JOIN pg_catalog.pg_language l ON l.oid=p.prolang)
        SELECT 1 FROM actual WHERE oid IS NULL OR proowner<>owner_oid OR prosecdef<>security_definer
          OR proisstrict OR lanname<>'plpgsql' OR provolatile::text<>volatility OR proparallel<>'u'
          OR proconfig<>CASE WHEN with_rls THEN ARRAY['search_path=pg_catalog, pg_temp','row_security=on']
                            ELSE ARRAY['search_path=pg_catalog, pg_temp'] END
          OR actual_hash<>body_hash)
      AND (SELECT count(*)=2 AND bool_and(c.relowner=table_owner AND c.relkind='r'
              AND c.relrowsecurity AND c.relforcerowsecurity)
           FROM pg_catalog.pg_class c WHERE c.oid IN(
              'enrollment_execution.work_queue'::regclass,'enrollment_execution.claim_leases'::regclass))
      AND (SELECT pg_catalog.string_agg(a.attname||':'||a.atttypid::regtype::text||':'||a.attnotnull::text,',' ORDER BY a.attnum)
           FROM pg_catalog.pg_attribute a WHERE a.attrelid='enrollment_execution.work_queue'::regclass
             AND a.attnum>0 AND NOT a.attisdropped)
          ='environment_id:uuid:true,operation_id:uuid:true,state:text:true,attempt:integer:true,next_attempt_at:timestamp with time zone:true,active_claim_token:uuid:false,last_transition_token:uuid:false,last_defer_reason:text:false,completed_at:timestamp with time zone:false,seeded_at:timestamp with time zone:true'
      AND (SELECT pg_catalog.string_agg(a.attname||':'||a.atttypid::regtype::text||':'||a.attnotnull::text,',' ORDER BY a.attnum)
           FROM pg_catalog.pg_attribute a WHERE a.attrelid='enrollment_execution.claim_leases'::regclass
             AND a.attnum>0 AND NOT a.attisdropped)
          ='claim_token:uuid:true,environment_id:uuid:true,operation_id:uuid:true,attempt:integer:true,claimed_at:timestamp with time zone:true,lease_until:timestamp with time zone:true'
      AND (SELECT count(*)=6 AND pg_catalog.md5(pg_catalog.string_agg(
             pg_catalog.pg_get_constraintdef(k.oid,true),'|' ORDER BY pg_catalog.pg_get_constraintdef(k.oid,true) COLLATE "C"))
             ='a42221f3aae7fd575b78fc30e8fae6e0'
           FROM pg_catalog.pg_constraint k WHERE k.conrelid='enrollment_execution.claim_leases'::regclass
             AND k.contype IN('p','u','f','c') AND k.convalidated)
      AND (SELECT count(*)=8 AND pg_catalog.md5(pg_catalog.string_agg(
             pg_catalog.pg_get_constraintdef(k.oid,true),'|' ORDER BY pg_catalog.pg_get_constraintdef(k.oid,true) COLLATE "C"))
             ='447fd57a3088d4e09acf78470ff0c59b'
           FROM pg_catalog.pg_constraint k WHERE k.conrelid='enrollment_execution.work_queue'::regclass
             AND k.contype IN('p','u','f','c') AND k.convalidated)
      AND NOT EXISTS(
        WITH expected(table_name,trigger_name,type_code,function_name,deferred_value) AS (VALUES
          ('work_queue','work_queue_guard',31,'enrollment_execution.guard_work_queue()',false),
          ('work_queue','work_queue_consistent',21,'enrollment_execution.validate_work_queue()',true),
          ('claim_leases','claim_leases_immutable',27,'enrollment_execution.reject_history_mutation()',false)),
        actual AS (SELECT c.relname::text,t.tgname::text,t.tgtype,t.tgfoid::regprocedure::text,t.tgdeferrable
          FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_class c ON c.oid=t.tgrelid
          WHERE t.tgrelid IN('enrollment_execution.work_queue'::regclass,'enrollment_execution.claim_leases'::regclass)
            AND NOT t.tgisinternal AND t.tgenabled='O')
        SELECT 1 FROM ((SELECT * FROM expected EXCEPT SELECT * FROM actual)
                       UNION ALL (SELECT * FROM actual EXCEPT SELECT * FROM expected)) difference)
      AND NOT EXISTS(
        WITH expected(table_name,policy_name,command_code,permissive_value,expression_hash) AS (VALUES
          ('EnrollmentGrantOperations','enrollment_execution_queue_operations_allow','*',true,'5556c1517920a9f5b6050ab51d13d5e6'),
          ('EnrollmentGrantOperations','enrollment_execution_queue_operations_limit','*',false,'5556c1517920a9f5b6050ab51d13d5e6'),
          ('Outbox','enrollment_execution_queue_outbox_allow','*',true,'3d58adb52734dd82ac5d154b67922a9e'),
          ('Outbox','enrollment_execution_queue_outbox_limit','*',false,'3d58adb52734dd82ac5d154b67922a9e'),
          ('work_queue','enrollment_execution_queue_work_allow','*',true,'29db1f6e19f17b334a3c09d522304884'),
          ('work_queue','enrollment_execution_queue_work_limit','*',false,'29db1f6e19f17b334a3c09d522304884'),
          ('claim_leases','enrollment_execution_queue_leases_allow','*',true,'1b87c54a864523d0410a0a4bd7d79676'),
          ('claim_leases','enrollment_execution_queue_leases_limit','*',false,'1b87c54a864523d0410a0a4bd7d79676'),
          ('issue_results','enrollment_execution_queue_results_allow','r',true,'367e9d4e206baca6b6386de916a9cdb1'),
          ('issue_results','enrollment_execution_queue_results_limit','r',false,'367e9d4e206baca6b6386de916a9cdb1'),
          ('execution_stops','enrollment_execution_queue_stops_allow','r',true,'367e9d4e206baca6b6386de916a9cdb1'),
          ('execution_stops','enrollment_execution_queue_stops_limit','r',false,'367e9d4e206baca6b6386de916a9cdb1')),
        actual AS (SELECT c.relname::text,p.polname::text,p.polcmd::text,p.polpermissive,
            pg_catalog.md5(COALESCE(pg_catalog.pg_get_expr(p.polqual,p.polrelid),'')||'|'||
              COALESCE(pg_catalog.pg_get_expr(p.polwithcheck,p.polrelid),''))
          FROM pg_catalog.pg_policy p JOIN pg_catalog.pg_class c ON c.oid=p.polrelid
          WHERE p.polname LIKE 'enrollment_execution_queue_%' AND p.polroles=ARRAY[queue_definer])
        SELECT 1 FROM ((SELECT * FROM expected EXCEPT SELECT * FROM actual)
                       UNION ALL (SELECT * FROM actual EXCEPT SELECT * FROM expected)) difference)
      AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_policy p WHERE queue_definer=ANY(p.polroles)
             AND p.polname NOT LIKE 'enrollment_execution_queue_%')
      AND (SELECT count(*)=1 FROM pg_catalog.pg_trigger t
           WHERE t.tgrelid='public."Outbox"'::regclass AND t.tgname='work_queue_outbox_consistent'
             AND NOT t.tgisinternal AND t.tgenabled='O' AND t.tgtype=21
             AND t.tgqual IS NULL AND t.tgnargs=0 AND t.tgattr=''::int2vector
             AND t.tgoldtable IS NULL AND t.tgnewtable IS NULL AND t.tgdeferrable AND t.tginitdeferred
             AND EXISTS(SELECT 1 FROM pg_catalog.pg_constraint k WHERE k.oid=t.tgconstraint
                 AND k.conrelid=t.tgrelid AND k.contype='t' AND k.condeferrable AND k.condeferred)
             AND t.tgfoid='enrollment_execution.validate_work_queue()'::regprocedure)
      AND NOT EXISTS(
        WITH expected(table_oid,privilege_type) AS (VALUES
          ('enrollment_execution.work_queue'::regclass::oid,'SELECT'),
          ('enrollment_execution.work_queue'::regclass::oid,'INSERT'),
          ('enrollment_execution.work_queue'::regclass::oid,'UPDATE'),
          ('enrollment_execution.claim_leases'::regclass::oid,'SELECT'),
          ('enrollment_execution.claim_leases'::regclass::oid,'INSERT'),
          ('enrollment_execution.issue_results'::regclass::oid,'SELECT'),
          ('enrollment_execution.execution_stops'::regclass::oid,'SELECT')),
        actual AS (SELECT c.oid,acl.privilege_type::text FROM pg_catalog.pg_class c
          CROSS JOIN LATERAL pg_catalog.aclexplode(c.relacl) acl
          WHERE acl.grantee=queue_definer AND NOT acl.is_grantable)
        SELECT 1 FROM ((SELECT * FROM expected EXCEPT SELECT * FROM actual)
                       UNION ALL (SELECT * FROM actual EXCEPT SELECT * FROM expected)) difference)
      AND NOT EXISTS(
        WITH expected(table_oid,column_name,privilege_type) AS (VALUES
          ('public."DirectoryDatabaseBindings"'::regclass::oid,'LoginRole','SELECT'),
          ('public."DirectoryDatabaseBindings"'::regclass::oid,'Purpose','SELECT'),
          ('public."DirectoryDatabaseBindings"'::regclass::oid,'ContractVersion','SELECT'),
          ('public."DirectoryDatabaseBindings"'::regclass::oid,'EnvironmentId','SELECT'),
          ('public."DirectoryDatabaseBindings"'::regclass::oid,'PrincipalId','SELECT'),
          ('public."EnrollmentGrantOperations"'::regclass::oid,'EnvironmentId','SELECT'),
          ('public."EnrollmentGrantOperations"'::regclass::oid,'Id','SELECT'),
          ('public."EnrollmentGrantOperations"'::regclass::oid,'QueuedAt','SELECT'),
          ('public."Outbox"'::regclass::oid,'EnvironmentId','SELECT'),
          ('public."Outbox"'::regclass::oid,'Id','SELECT'),
          ('public."Outbox"'::regclass::oid,'EventType','SELECT'),
          ('public."Outbox"'::regclass::oid,'Version','SELECT'),
          ('public."Outbox"'::regclass::oid,'Payload','SELECT'),
          ('public."Outbox"'::regclass::oid,'CreatedAt','SELECT'),
          ('public."Outbox"'::regclass::oid,'DeliveredAt','SELECT'),
          ('public."Outbox"'::regclass::oid,'Attempts','SELECT'),
          ('public."Outbox"'::regclass::oid,'Attempts','UPDATE'),
          ('public."Outbox"'::regclass::oid,'DeliveredAt','UPDATE')),
        actual AS (SELECT a.attrelid,a.attname::text,acl.privilege_type::text
          FROM pg_catalog.pg_attribute a CROSS JOIN LATERAL pg_catalog.aclexplode(a.attacl) acl
          WHERE acl.grantee=queue_definer AND NOT acl.is_grantable)
        SELECT 1 FROM ((SELECT * FROM expected EXCEPT SELECT * FROM actual)
                       UNION ALL (SELECT * FROM actual EXCEPT SELECT * FROM expected)) difference)
      AND NOT EXISTS(
        WITH expected(function_oid) AS (VALUES
          ('enrollment_execution.queue_worker_scope(uuid)'::regprocedure::oid),
          ('public.has_environment_membership(uuid,uuid)'::regprocedure::oid),
          ('enrollment_execution.claim_next(uuid,uuid)'::regprocedure::oid),
          ('enrollment_execution.defer_claim(uuid,uuid,uuid,text)'::regprocedure::oid),
          ('enrollment_execution.complete_claim(uuid,uuid,uuid)'::regprocedure::oid),
          ('enrollment_execution.claim_next_work(uuid,uuid)'::regprocedure::oid),
          ('enrollment_execution.defer_work_claim(uuid,uuid,uuid,text)'::regprocedure::oid),
          ('enrollment_execution.complete_work_claim(uuid,uuid,uuid)'::regprocedure::oid),
          ('enrollment_execution.audit_execution_privileges(uuid)'::regprocedure::oid)),
        actual AS (SELECT p.oid FROM pg_catalog.pg_proc p
          CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) acl
          WHERE acl.grantee=queue_definer AND acl.privilege_type='EXECUTE' AND NOT acl.is_grantable)
        SELECT 1 FROM ((SELECT * FROM expected EXCEPT SELECT * FROM actual)
                       UNION ALL (SELECT * FROM actual EXCEPT SELECT * FROM expected)) difference)
      AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p
        CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) acl
        WHERE acl.grantee=queue_definer AND (acl.privilege_type<>'EXECUTE' OR acl.is_grantable))
      AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class relation
        CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(relation.relacl,pg_catalog.acldefault('r',relation.relowner))) acl
        WHERE acl.grantee=queue_definer AND acl.is_grantable)
      AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_attribute attribute
        CROSS JOIN LATERAL pg_catalog.aclexplode(attribute.attacl) acl
        WHERE acl.grantee=queue_definer AND acl.is_grantable);

    -- Profile4 delivery family: one shared NOLOGIN definer is always installed. Each environment
    -- has either no delivery bindings or one exact status/delivery LOGIN pair.
    ok := ok
      AND (SELECT count(*)=4 FROM pg_catalog.pg_proc function_row WHERE function_row.proowner=delivery_definer
        AND function_row.oid IN(
          'enrollment_execution.read_grant_status_receipt(uuid,uuid)'::regprocedure,
          'enrollment_execution.append_grant_status_observation(uuid,uuid,uuid,text,text,timestamptz,timestamptz,uuid,uuid,uuid,timestamptz,timestamptz,timestamptz,smallint,timestamptz,bytea,bytea)'::regprocedure,
          'enrollment_execution.read_grant_delivery(uuid,uuid,uuid,text)'::regprocedure,
          'enrollment_execution.acknowledge_grant_delivery(uuid,uuid,uuid,text,bytea,bytea)'::regprocedure))
      AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc function_row WHERE function_row.proowner=delivery_definer
        AND function_row.oid NOT IN(
          'enrollment_execution.read_grant_status_receipt(uuid,uuid)'::regprocedure,
          'enrollment_execution.append_grant_status_observation(uuid,uuid,uuid,text,text,timestamptz,timestamptz,uuid,uuid,uuid,timestamptz,timestamptz,timestamptz,smallint,timestamptz,bytea,bytea)'::regprocedure,
          'enrollment_execution.read_grant_delivery(uuid,uuid,uuid,text)'::regprocedure,
          'enrollment_execution.acknowledge_grant_delivery(uuid,uuid,uuid,text,bytea,bytea)'::regprocedure))
      -- BEGIN generated delivery internal functions
      AND NOT EXISTS(
        WITH expected(signature,owner_oid,language,volatility,security_definer,with_rls,body_hash,input_count,input_types,all_types,arg_names,arg_modes,return_type,returns_set) AS (VALUES
          ('enrollment_execution.guard_status_observation()',table_owner,'plpgsql','v',false,false,'205fb0e014963548e6ed954ef2680df39de239c5a94893e79079009986c63c17',0,'',NULL::oid[],NULL::text[],NULL::"char"[],2279::oid,false),
          ('enrollment_execution.record_status_observation(pg_catalog.uuid,pg_catalog.uuid,pg_catalog.uuid,pg_catalog.text,pg_catalog.text,pg_catalog.timestamptz,pg_catalog.timestamptz,pg_catalog.uuid,pg_catalog.uuid,pg_catalog.uuid,pg_catalog.timestamptz,pg_catalog.timestamptz,pg_catalog.timestamptz,pg_catalog.int2,pg_catalog.timestamptz,pg_catalog.bytea,pg_catalog.bytea)',table_owner,'plpgsql','v',false,false,'16e7ce5bada9c6ad5cd54a083fc2f5064300bfa0f1b1591ec5d7a1f328b83e10',17,'2950 2950 2950 25 25 1184 1184 2950 2950 2950 1184 1184 1184 21 1184 17 17',ARRAY[2950,2950,2950,25,25,1184,1184,2950,2950,2950,1184,1184,1184,21,1184,17,17,21,25,2950,2950,2950,20,25,25,1184,1184,1184,1184]::oid[],ARRAY['p_environment','p_operation','p_observation','p_state','p_diagnostic','p_private_observed_at','p_private_state_changed_at','p_grant','p_directory_object','p_device','p_mapping_created_at','p_grant_created_at','p_grant_expires_at','p_issue_contract','p_mint_permit_not_after','p_token_sha256','p_authorization_digest','contract_version','outcome','observation_id','environment_id','operation_id','sequence','state','diagnostic','private_observed_at','private_state_changed_at','recorded_at','available_until']::text[],ARRAY['i','i','i','i','i','i','i','i','i','i','i','i','i','i','i','i','i','t','t','t','t','t','t','t','t','t','t','t','t']::"char"[],2249::oid,true),
          ('enrollment_execution.read_status_refresh_receipt(pg_catalog.uuid,pg_catalog.uuid)',table_owner,'plpgsql','v',false,false,'b140b5dbe814117c4a1214fe4f86d2b595069b35f81a74f94afb061108d9e26f',2,'2950 2950',ARRAY[2950,2950,21,25,2950,2950,2950,2950,2950,1184,1184,1184,21,1184,17,17]::oid[],ARRAY['p_environment','p_operation','contract_version','outcome','environment_id','operation_id','grant_id','directory_object_id','device_id','mapping_created_at','grant_created_at','grant_expires_at','issue_contract_version','mint_permit_not_after','token_sha256','authorization_digest']::text[],ARRAY['i','i','t','t','t','t','t','t','t','t','t','t','t','t','t','t']::"char"[],2249::oid,true),
          ('enrollment_execution.lock_delivery_context(pg_catalog.uuid,pg_catalog.uuid,pg_catalog.uuid,pg_catalog.text)',table_owner,'plpgsql','v',false,false,'2773f0caa2d5ccdb20d5192bcefc5ef4d848004424b52bd43c746ef2abdd806b',4,'2950 2950 2950 25',ARRAY[2950,2950,2950,25,16,1184]::oid[],ARRAY['p_environment','p_operation','p_requester','p_session_hash','authorized','checked_at']::text[],ARRAY['i','i','i','i','t','t']::"char"[],2249::oid,true),
          ('enrollment_execution.get_sealed_delivery(pg_catalog.uuid,pg_catalog.uuid,pg_catalog.uuid,pg_catalog.text)',table_owner,'plpgsql','v',false,false,'49ac0d54d67374f2e26c4bb1ad57c7ccdd15096da5b013ee1175002b04fefa53',4,'2950 2950 2950 25',ARRAY[2950,2950,2950,25,21,25,2950,2950,21,17,17,17,1184,1184]::oid[],ARRAY['p_environment','p_operation','p_requester','p_session_hash','contract_version','outcome','environment_id','operation_id','format_version','recipient_fingerprint','ciphertext','ciphertext_sha256','delivery_not_after','queried_at']::text[],ARRAY['i','i','i','i','t','t','t','t','t','t','t','t','t','t']::"char"[],2249::oid,true),
          ('enrollment_execution.ack_sealed_delivery(pg_catalog.uuid,pg_catalog.uuid,pg_catalog.uuid,pg_catalog.text,pg_catalog.bytea,pg_catalog.bytea)',table_owner,'plpgsql','v',false,false,'85a3d6f503a90f067a7d94cffaf3fc03f6f3b1adb84db92a40110c721454ab24',6,'2950 2950 2950 25 17 17',ARRAY[2950,2950,2950,25,17,17,21,25]::oid[],ARRAY['p_environment','p_operation','p_requester','p_session_hash','p_recipient_fingerprint','p_ciphertext_sha256','contract_version','outcome']::text[],ARRAY['i','i','i','i','i','i','t','t']::"char"[],2249::oid,true),
          ('enrollment_execution.delivery_worker_scope(pg_catalog.uuid,pg_catalog.text)',table_owner,'plpgsql','s',true,true,'a2abaa5afe86cdf2b548c52e54467b96a16af011f2780bdb8b49e4e1dd7efb8c',2,'2950 25',NULL::oid[],ARRAY['p_environment','p_purpose']::text[],NULL::"char"[],16::oid,false),
          ('enrollment_execution.read_grant_status_receipt(pg_catalog.uuid,pg_catalog.uuid)',delivery_definer,'plpgsql','v',true,true,'63cc9a1b50e70f66d59ed1a754a54c05aee02259341b8f7b6ed9ecf10256ed78',2,'2950 2950',ARRAY[2950,2950,21,25,2950,2950,2950,2950,2950,1184,1184,1184,21,1184,17,17]::oid[],ARRAY['p_environment','p_operation','contract_version','outcome','environment_id','operation_id','grant_id','directory_object_id','device_id','mapping_created_at','grant_created_at','grant_expires_at','issue_contract_version','mint_permit_not_after','token_sha256','authorization_digest']::text[],ARRAY['i','i','t','t','t','t','t','t','t','t','t','t','t','t','t','t']::"char"[],2249::oid,true),
          ('enrollment_execution.append_grant_status_observation(pg_catalog.uuid,pg_catalog.uuid,pg_catalog.uuid,pg_catalog.text,pg_catalog.text,pg_catalog.timestamptz,pg_catalog.timestamptz,pg_catalog.uuid,pg_catalog.uuid,pg_catalog.uuid,pg_catalog.timestamptz,pg_catalog.timestamptz,pg_catalog.timestamptz,pg_catalog.int2,pg_catalog.timestamptz,pg_catalog.bytea,pg_catalog.bytea)',delivery_definer,'plpgsql','v',true,true,'545ce0efbc1807b4104a1d5386d328326f1bfc03db98dbcec9ab531f021b03cf',17,'2950 2950 2950 25 25 1184 1184 2950 2950 2950 1184 1184 1184 21 1184 17 17',ARRAY[2950,2950,2950,25,25,1184,1184,2950,2950,2950,1184,1184,1184,21,1184,17,17,21,25,2950,2950,2950,20,25,25,1184,1184,1184,1184]::oid[],ARRAY['p_environment','p_operation','p_observation','p_state','p_diagnostic','p_private_observed_at','p_private_state_changed_at','p_grant','p_directory_object','p_device','p_mapping_created_at','p_grant_created_at','p_grant_expires_at','p_issue_contract','p_mint_permit_not_after','p_token_sha256','p_authorization_digest','contract_version','outcome','observation_id','environment_id','operation_id','sequence','state','diagnostic','private_observed_at','private_state_changed_at','recorded_at','available_until']::text[],ARRAY['i','i','i','i','i','i','i','i','i','i','i','i','i','i','i','i','i','t','t','t','t','t','t','t','t','t','t','t','t']::"char"[],2249::oid,true),
          ('enrollment_execution.read_grant_delivery(pg_catalog.uuid,pg_catalog.uuid,pg_catalog.uuid,pg_catalog.text)',delivery_definer,'plpgsql','v',true,true,'f80126238164f65f17e8fb933b13799aa2fd6b45a1f3eb58a8f673014fcf5e3b',4,'2950 2950 2950 25',ARRAY[2950,2950,2950,25,21,25,2950,2950,21,17,17,17,1184,1184]::oid[],ARRAY['p_environment','p_operation','p_requester','p_session_hash','contract_version','outcome','environment_id','operation_id','format_version','recipient_fingerprint','ciphertext','ciphertext_sha256','delivery_not_after','queried_at']::text[],ARRAY['i','i','i','i','t','t','t','t','t','t','t','t','t','t']::"char"[],2249::oid,true),
          ('enrollment_execution.acknowledge_grant_delivery(pg_catalog.uuid,pg_catalog.uuid,pg_catalog.uuid,pg_catalog.text,pg_catalog.bytea,pg_catalog.bytea)',delivery_definer,'plpgsql','v',true,true,'99f68247c9d723dfa7755481005aa7104f93646f6095315ea8439db444668323',6,'2950 2950 2950 25 17 17',ARRAY[2950,2950,2950,25,17,17,21,25]::oid[],ARRAY['p_environment','p_operation','p_requester','p_session_hash','p_recipient_fingerprint','p_ciphertext_sha256','contract_version','outcome']::text[],ARRAY['i','i','i','i','i','i','t','t']::"char"[],2249::oid,true),
          ('enrollment_execution.reject_delivery_update()',table_owner,'plpgsql','v',true,true,'279e969ccd38a161d13a2dad55009fd9e759ee9fd9e9b615dbb834ba4abfeb76',0,'',NULL::oid[],NULL::text[],NULL::"char"[],2279::oid,false),
          ('enrollment_execution.audit_delivery_privileges(pg_catalog.uuid)',table_owner,'plpgsql','s',true,true,'a37b4693ed042c9d9f69555024c87cb5c40705cc60606bff14145b24480b1d9e',1,'2950',ARRAY[2950,16,25,21]::oid[],ARRAY['p_environment','is_valid','diagnostic_code','profile_version']::text[],ARRAY['i','t','t','t']::"char"[],2249::oid,true),
          ('enrollment_execution.scope_uuid(pg_catalog.text)',table_owner,'plpgsql','i',false,false,'a7dd6ec2c76752765dd101c860b90d7b27db09de8865db291e555ca1ae96e72b',1,'25',NULL::oid[],ARRAY['p_value']::text[],NULL::"char"[],2950::oid,false),
          ('enrollment_execution.has_computer_permission(pg_catalog.uuid,pg_catalog.uuid,pg_catalog.uuid,pg_catalog.uuid,pg_catalog.text)',table_owner,'sql','s',false,false,'c3fb51c2382305ee8d2da5b40221261edd9978c0a3c3d3eab0ac86929221d4a2',5,'2950 2950 2950 2950 25',NULL::oid[],ARRAY['p_environment','p_principal','p_directory','p_generation','p_permission']::text[],NULL::"char"[],16::oid,false),
          ('enrollment_execution.reject_history_mutation()',table_owner,'plpgsql','v',false,false,'e35b27ac9bb227452ced5ccc67f6a40faec5d609a324b3d1a1d7f455486b8edd',0,'',NULL::oid[],NULL::text[],NULL::"char"[],2279::oid,false),
          ('enrollment_execution.validate_journal()',table_owner,'plpgsql','v',false,false,'7645db08f557045f5cbd8654fdb514ee480de1e1e62fe0db293a1dcc07ed611e',0,'',NULL::oid[],NULL::text[],NULL::"char"[],2279::oid,false),
          ('enrollment_execution.validate_execution_stop()',table_owner,'plpgsql','v',false,false,'ae1fe7dbafa00dd9723331deb6b9206eb6cf6b331fcc0337ecc538ea7a682531',0,'',NULL::oid[],NULL::text[],NULL::"char"[],2279::oid,false),
          ('enrollment_execution.lock_execution_stop_boundary()',table_owner,'plpgsql','v',false,false,'927270395474475368a9c838ce22c09e0be8b6a749d03848ab1cd4c8e6e61918',0,'',NULL::oid[],NULL::text[],NULL::"char"[],2279::oid,false)),
        actual AS (SELECT expected.*,function_row.*,language_row.lanname
          FROM expected LEFT JOIN pg_catalog.pg_proc function_row ON function_row.oid=pg_catalog.to_regprocedure(expected.signature)
          LEFT JOIN pg_catalog.pg_language language_row ON language_row.oid=function_row.prolang)
        SELECT 1 FROM actual WHERE oid IS NULL OR proowner<>owner_oid OR lanname<>language
          OR prokind<>'f' OR prosecdef<>security_definer OR proisstrict OR proleakproof OR prosupport<>0
          OR provolatile::text<>volatility OR proparallel<>'u' OR proretset<>returns_set OR prorettype<>return_type
          OR pronargs<>input_count OR proargtypes::text<>input_types
          OR proallargtypes IS DISTINCT FROM all_types OR proargnames IS DISTINCT FROM arg_names OR proargmodes IS DISTINCT FROM arg_modes
          OR pronargdefaults<>0 OR proargdefaults IS NOT NULL OR provariadic<>0 OR probin IS NOT NULL OR prosqlbody IS NOT NULL
          OR proconfig IS DISTINCT FROM CASE WHEN with_rls THEN ARRAY['search_path=pg_catalog, pg_temp','row_security=on']
                                            ELSE ARRAY['search_path=pg_catalog, pg_temp'] END
          OR pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(pg_catalog.btrim(
               pg_catalog.regexp_replace(prosrc,'[[:space:]]+',' ','g')),'UTF8')),'hex')<>body_hash
        UNION ALL
        SELECT 1 FROM pg_catalog.pg_proc extra JOIN pg_catalog.pg_namespace ns ON ns.oid=extra.pronamespace
        WHERE ns.nspname='enrollment_execution'
          AND extra.proname IN(SELECT pg_catalog.split_part(pg_catalog.split_part(signature,'.',2),'(',1) FROM expected)
          AND NOT EXISTS(SELECT 1 FROM expected WHERE pg_catalog.to_regprocedure(signature)=extra.oid))
      -- END generated delivery internal functions
      AND NOT EXISTS(
        WITH expected(grantor,grantee,privilege_type,is_grantable) AS (VALUES
          (table_owner,table_owner,'EXECUTE',false),(table_owner,delivery_definer,'EXECUTE',false)),
        actual AS (SELECT acl.grantor,acl.grantee,acl.privilege_type,acl.is_grantable
          FROM pg_catalog.pg_proc function_row CROSS JOIN LATERAL pg_catalog.aclexplode(
            COALESCE(function_row.proacl,pg_catalog.acldefault('f',function_row.proowner))) acl
          WHERE function_row.oid=pg_catalog.to_regprocedure('enrollment_execution.delivery_worker_scope(uuid,text)'))
        SELECT 1 FROM ((SELECT * FROM expected EXCEPT SELECT * FROM actual)
          UNION ALL (SELECT * FROM actual EXCEPT SELECT * FROM expected)) difference)
      AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class relation
        WHERE relation.oid IN('public."DirectoryDatabaseBindings"'::regclass,
            'enrollment_execution.role_reservations'::regclass)
          AND (pg_catalog.has_table_privilege(delivery_definer,relation.oid,
                 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
            OR pg_catalog.has_any_column_privilege(delivery_definer,relation.oid,'SELECT,INSERT,UPDATE,REFERENCES')))
      ;

    -- BEGIN exact delivery structure
    -- Compare complete sets, including relation identity, rather than trusting counts or names.
    ok := ok AND NOT EXISTS(
      WITH relations(schema_name,relation_name,suffix,command,expression_hash) AS (VALUES
        ('public','Environments','environment','*','5029fb82c8841b4be18f827b6ff65014'),
        ('public','DirectorySync','sync','*','5805dc21c720e17a48c0383e19d23d8c'),
        ('public','DirectoryObjects','directory','*','5805dc21c720e17a48c0383e19d23d8c'),
        ('public','Principals','principals','*','0f4a674f4193404082084f1ce226feca'),
        ('public','Memberships','memberships','*','c822931371f49937c75216d468de40b6'),
        ('public','EnrollmentGrantOperations','operations','*','398cc8e9984a655fc7a95d8ffa62f33f'),
        ('public','Sessions','sessions','r','7423ae3d79d4de92662ecb4bd3658c57'),
        ('public','Roles','roles','r','dd406c6c90bc4ad9cb66f14eb686cf93'),
        ('public','RolePermissions','role_permissions','r','dd406c6c90bc4ad9cb66f14eb686cf93'),
        ('public','Assignments','assignments','r','dd406c6c90bc4ad9cb66f14eb686cf93'),
        ('public','Scopes','scopes','r','dd406c6c90bc4ad9cb66f14eb686cf93'),
        ('public','DeviceTagAssignments','tag_assignments','r','dd406c6c90bc4ad9cb66f14eb686cf93'),
        ('enrollment_execution','issue_results','results','r','16061f7fe3d1e9c443f8c14c547153db'),
        ('enrollment_execution','mint_permits','permits','r','5fe22733f49093eedfbf3801bc66cdf5'),
        ('enrollment_execution','sealed_envelopes','envelopes','*','5fe22733f49093eedfbf3801bc66cdf5'),
        ('enrollment_execution','delivery_acks','acks','*','52b42cd1fccdb1036665767ed5daa164'),
        ('enrollment_execution','status_observations','status','*','2c6961144391bc85dbfa6ef17383a52b')),
      expected AS (
        SELECT pg_catalog.to_regclass(pg_catalog.format('%I.%I',r.schema_name,r.relation_name))::oid relation_oid,
          'enrollment_delivery_'||r.suffix||'_'||variant.suffix policy_name,
          r.command,variant.permissive,ARRAY[delivery_definer] roles,r.expression_hash
        FROM relations r CROSS JOIN (VALUES('allow',true),('limit',false)) variant(suffix,permissive)),
      actual AS (
        SELECT p.polrelid relation_oid,p.polname::text policy_name,p.polcmd::text command,
          p.polpermissive permissive,p.polroles roles,
          pg_catalog.md5(COALESCE(pg_catalog.pg_get_expr(p.polqual,p.polrelid),'')||'|'||
            COALESCE(pg_catalog.pg_get_expr(p.polwithcheck,p.polrelid),'')) expression_hash
        FROM pg_catalog.pg_policy p
        WHERE p.polname LIKE 'enrollment_delivery_%' OR delivery_definer=ANY(p.polroles)),
      differences AS (
        (SELECT * FROM expected EXCEPT SELECT * FROM actual)
        UNION ALL (SELECT * FROM actual EXCEPT SELECT * FROM expected))
      SELECT 1 FROM differences
      UNION ALL
      SELECT 1 FROM relations r LEFT JOIN pg_catalog.pg_class c
        ON c.oid=pg_catalog.to_regclass(pg_catalog.format('%I.%I',r.schema_name,r.relation_name))
      WHERE c.oid IS NULL OR c.relowner IS DISTINCT FROM table_owner OR c.relkind<>'r'
        OR NOT c.relrowsecurity OR NOT c.relforcerowsecurity)
    AND NOT EXISTS(
      WITH expected(relation_oid,trigger_name) AS (VALUES
        (pg_catalog.to_regclass('public."Environments"')::oid,'enrollment_delivery_environment_guard'),
        (pg_catalog.to_regclass('public."DirectorySync"')::oid,'enrollment_delivery_sync_guard'),
        (pg_catalog.to_regclass('public."DirectoryObjects"')::oid,'enrollment_delivery_directory_guard'),
        (pg_catalog.to_regclass('public."Principals"')::oid,'enrollment_delivery_principal_guard'),
        (pg_catalog.to_regclass('public."Memberships"')::oid,'enrollment_delivery_membership_guard'),
        (pg_catalog.to_regclass('public."EnrollmentGrantOperations"')::oid,'enrollment_delivery_operation_guard')),
      actual AS (
        SELECT t.tgrelid relation_oid,t.tgname::text trigger_name FROM pg_catalog.pg_trigger t
        WHERE t.tgname LIKE 'enrollment_delivery_%'
          AND NOT t.tgisinternal AND t.tgenabled='O' AND t.tgtype=19
          AND t.tgfoid=pg_catalog.to_regprocedure('enrollment_execution.reject_delivery_update()')
          AND t.tgqual IS NULL AND t.tgnargs=0 AND t.tgattr=''::int2vector
          AND t.tgoldtable IS NULL AND t.tgnewtable IS NULL AND t.tgconstraint=0
          AND NOT t.tgdeferrable AND NOT t.tginitdeferred AND t.tgparentid=0),
      all_named AS (SELECT t.tgrelid relation_oid,t.tgname::text trigger_name
        FROM pg_catalog.pg_trigger t WHERE t.tgname LIKE 'enrollment_delivery_%'
          OR t.tgfoid=pg_catalog.to_regprocedure('enrollment_execution.reject_delivery_update()'))
      SELECT 1 FROM ((SELECT * FROM expected EXCEPT SELECT * FROM actual)
        UNION ALL (SELECT * FROM all_named EXCEPT SELECT * FROM expected)) differences);
    -- END exact delivery structure

    -- BEGIN generated delivery catalog slices
    -- Source: audit-enrollment-delivery-bindings.sql
    ok := ok AND (
WITH target AS (
  SELECT c.* FROM pg_catalog.pg_class c
  WHERE c.oid=pg_catalog.to_regclass('public."DirectoryDatabaseBindings"')
), owner_role AS (
  SELECT oid FROM pg_catalog.pg_roles WHERE rolname=pg_catalog.pg_get_userbyid(table_owner)
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
  FROM target t CROSS JOIN owner_role o),false) AS is_valid
    );
    -- Source: audit-enrollment-delivery-identity.sql
    ok := ok AND (
WITH plan_helper AS (
  SELECT p.*,l.lanname FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_language l ON l.oid=p.prolang
  WHERE p.oid=pg_catalog.to_regprocedure('public.lock_enrollment_grant_plan_context(uuid,uuid,uuid[])')
), plan_acl AS (
  SELECT acl.* FROM plan_helper p CROSS JOIN LATERAL pg_catalog.aclexplode(
    COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) acl
), api_role AS (
  SELECT r.* FROM pg_catalog.pg_roles r JOIN plan_acl acl ON acl.grantee=r.oid
  WHERE (SELECT count(*)=1 FROM plan_acl) AND acl.privilege_type='EXECUTE' AND NOT acl.is_grantable
    AND acl.grantor=(SELECT proowner FROM plan_helper)
), identities AS (
  SELECT owner_role.oid owner_oid,plan_role.oid plan_oid,execution_role.oid execution_oid,delivery_role.oid delivery_oid,api_role.oid api_oid
  FROM pg_catalog.pg_roles owner_role,pg_catalog.pg_roles plan_role,
    pg_catalog.pg_roles execution_role,pg_catalog.pg_roles delivery_role,api_role
  WHERE owner_role.rolname=pg_catalog.pg_get_userbyid(table_owner)
    AND plan_role.rolname=(SELECT pg_catalog.pg_get_userbyid(plan_helper.proowner) FROM pg_catalog.pg_proc plan_helper WHERE plan_helper.oid=pg_catalog.to_regprocedure('public.lock_enrollment_grant_plan_context(uuid,uuid,uuid[])'))
    AND execution_role.rolname=pg_catalog.pg_get_userbyid(definer) AND delivery_role.rolname=pg_catalog.pg_get_userbyid(delivery_definer)
), helper AS (
  SELECT p.*,l.lanname FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_language l ON l.oid=p.prolang
  WHERE p.oid=pg_catalog.to_regprocedure('public.api_database_session()')
), policy_contract(relation_name,policy_name,command,permissive,role_kind,expression_hash) AS (VALUES
  ('Principals','enrollment_identity_principals_owner','*',true,'owner','fe2e7aa3a94b94b876d7713f1517686d'),
  ('Sessions','enrollment_identity_sessions_owner','*',true,'owner','fe2e7aa3a94b94b876d7713f1517686d'),
  ('Principals','enrollment_identity_principals_api_read','r',true,'public','708e22a476d7e00ff3ef7fe1441d8797'),
  ('Sessions','enrollment_identity_sessions_api','*',true,'public','1531f6d3d3ecc2ac56c17328212a0876'),
  ('Principals','enrollment_identity_principals_plan_read','r',true,'plan','ce24367043032e870e44adf501cef04d'),
  ('Principals','enrollment_identity_principals_plan_lock','w',true,'plan','84083a1a51bc3bc63ab584fc5a6d9a90'),
  ('Principals','enrollment_identity_principals_execution_read_allow','r',true,'execution','7950fb8cacb9394a69dade55f05249c1'),
  ('Principals','enrollment_identity_principals_execution_read_limit','r',false,'execution','7950fb8cacb9394a69dade55f05249c1'),
  ('Principals','enrollment_identity_principals_execution_lock_allow','w',true,'execution','de5073f7dedeff82c0ba31a4b0af9e3c'),
  ('Principals','enrollment_identity_principals_execution_lock_limit','w',false,'execution','de5073f7dedeff82c0ba31a4b0af9e3c'),
  ('Principals','enrollment_delivery_principals_allow','*',true,'delivery','0f4a674f4193404082084f1ce226feca'),
  ('Principals','enrollment_delivery_principals_limit','*',false,'delivery','0f4a674f4193404082084f1ce226feca'),
  ('Sessions','enrollment_delivery_sessions_allow','r',true,'delivery','7423ae3d79d4de92662ecb4bd3658c57'),
  ('Sessions','enrollment_delivery_sessions_limit','r',false,'delivery','7423ae3d79d4de92662ecb4bd3658c57')
), expected AS (
  SELECT pg_catalog.to_regclass(pg_catalog.format('public.%I',p.relation_name))::oid relation_oid,
    p.policy_name,p.command,p.permissive,
    ARRAY[CASE p.role_kind WHEN 'owner' THEN i.owner_oid WHEN 'plan' THEN i.plan_oid
      WHEN 'execution' THEN i.execution_oid WHEN 'delivery' THEN i.delivery_oid ELSE 0::oid END] roles,
    p.expression_hash FROM policy_contract p CROSS JOIN identities i
), actual AS (
  SELECT p.polrelid relation_oid,p.polname::text policy_name,p.polcmd::text command,
    p.polpermissive permissive,p.polroles roles,
    pg_catalog.md5(COALESCE(pg_catalog.pg_get_expr(p.polqual,p.polrelid),'')||'|'||
      COALESCE(pg_catalog.pg_get_expr(p.polwithcheck,p.polrelid),'')) expression_hash
  FROM pg_catalog.pg_policy p WHERE p.polrelid IN(
    pg_catalog.to_regclass('public."Principals"'),pg_catalog.to_regclass('public."Sessions"'))
    OR p.polname LIKE 'enrollment_identity_%'
), expected_acl AS (
  SELECT owner_oid grantor,owner_oid grantee,'EXECUTE'::text privilege_type,false is_grantable FROM identities
  UNION ALL SELECT owner_oid,0::oid,'EXECUTE',false FROM identities
), actual_acl AS (
  SELECT acl.grantor,acl.grantee,acl.privilege_type,acl.is_grantable
  FROM helper h CROSS JOIN LATERAL pg_catalog.aclexplode(
    COALESCE(h.proacl,pg_catalog.acldefault('f',h.proowner))) acl
), expected_plan_tables(schema_name,table_name,privilege_type,is_grantable) AS (VALUES
  ('public','DirectoryDatabaseBindings','SELECT',false),
  ('public','Environments','SELECT',false),('public','Environments','UPDATE',false),
  ('public','DirectorySync','SELECT',false),('public','DirectorySync','UPDATE',false),
  ('public','DirectoryObjects','SELECT',false),('public','DirectoryObjects','UPDATE',false),
  ('public','Principals','SELECT',false),('public','Principals','UPDATE',false),
  ('public','Memberships','SELECT',false),('public','Memberships','UPDATE',false)
), actual_plan_tables AS (
  SELECT n.nspname::text schema_name,c.relname::text table_name,acl.privilege_type,acl.is_grantable
  FROM identities i CROSS JOIN pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
  CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(c.relacl,pg_catalog.acldefault('r',c.relowner))) acl
  WHERE c.relkind IN('r','p','v','m','f') AND acl.grantee=i.plan_oid
), expected_plan_functions(function_oid,privilege_type,is_grantable) AS (VALUES
  (pg_catalog.to_regprocedure('public.has_environment_membership(uuid,uuid)')::oid,'EXECUTE',false),
  (pg_catalog.to_regprocedure('public.directory_database_access(uuid,uuid)')::oid,'EXECUTE',false)
), actual_plan_functions AS (
  SELECT p.oid function_oid,acl.privilege_type,acl.is_grantable FROM identities i CROSS JOIN pg_catalog.pg_proc p
  CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) acl
  WHERE acl.grantee=i.plan_oid
), actual_plan_schemas AS (
  SELECT n.nspname::text schema_name,acl.privilege_type,acl.is_grantable FROM identities i CROSS JOIN pg_catalog.pg_namespace n
  CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(n.nspacl,pg_catalog.acldefault('n',n.nspowner))) acl
  WHERE acl.grantee=i.plan_oid
), expected_plan_schemas(schema_name,privilege_type,is_grantable) AS (VALUES ('public','USAGE',false))
SELECT COALESCE((SELECT
  pg_catalog.current_setting('search_path') IN('pg_catalog,pg_temp','pg_catalog, pg_temp')
  AND (SELECT count(DISTINCT id)=5 FROM unnest(ARRAY[i.owner_oid,i.plan_oid,i.execution_oid,i.delivery_oid,i.api_oid]) id)
  AND (SELECT r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolbypassrls AND NOT r.rolcreatedb
    AND NOT r.rolcreaterole AND NOT r.rolinherit AND NOT r.rolreplication FROM api_role r)
  AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles r WHERE r.oid IN(i.plan_oid,i.execution_oid,i.delivery_oid)
    AND (r.rolcanlogin OR r.rolsuper OR r.rolbypassrls OR r.rolcreatedb OR r.rolcreaterole OR r.rolinherit OR r.rolreplication))
  AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members m
    WHERE m.member IN(i.plan_oid,i.execution_oid,i.delivery_oid,i.api_oid) OR m.roleid IN(i.plan_oid,i.execution_oid,i.delivery_oid,i.api_oid))
  AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_database d WHERE d.datdba IN(i.plan_oid,i.api_oid))
  AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace n WHERE n.nspowner IN(i.plan_oid,i.api_oid))
  AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c WHERE c.relowner IN(i.plan_oid,i.api_oid))
  AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p WHERE p.proowner=i.api_oid)
  AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c WHERE c.oid IN(
      pg_catalog.to_regclass('public."DirectorySync"'),pg_catalog.to_regclass('public."DirectoryObjects"'))
    AND (pg_catalog.has_table_privilege(i.api_oid,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN')
      OR pg_catalog.has_any_column_privilege(i.api_oid,c.oid,'INSERT,UPDATE,REFERENCES')))
  AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace n CROSS JOIN LATERAL pg_catalog.aclexplode(n.nspacl) acl
    WHERE n.nspname<>'public' AND acl.grantee=i.api_oid)
  AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
    CROSS JOIN LATERAL pg_catalog.aclexplode(c.relacl) acl WHERE n.nspname<>'public' AND acl.grantee=i.api_oid)
  AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid=a.attrelid
    JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL pg_catalog.aclexplode(a.attacl) acl
    WHERE n.nspname<>'public' AND acl.grantee=i.api_oid)
  AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
    CROSS JOIN LATERAL pg_catalog.aclexplode(p.proacl) acl WHERE n.nspname<>'public' AND acl.grantee=i.api_oid)
  AND NOT pg_catalog.has_database_privilege(i.plan_oid,pg_catalog.current_database(),'CREATE')
  AND NOT pg_catalog.has_database_privilege(i.api_oid,pg_catalog.current_database(),'CREATE')
  AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace n WHERE n.nspname NOT IN('pg_catalog','information_schema')
    AND n.nspname !~ '^pg_(toast|temp_)' AND (pg_catalog.has_schema_privilege(i.plan_oid,n.oid,'CREATE')
      OR pg_catalog.has_schema_privilege(i.api_oid,n.oid,'CREATE')))
  AND (SELECT count(*)=1 AND bool_and(p.proowner=i.plan_oid AND p.lanname='plpgsql' AND p.prosecdef
    AND p.provolatile='v' AND p.proparallel='u' AND p.prokind='f' AND NOT p.proretset
    AND NOT p.proisstrict AND NOT p.proleakproof AND p.prorettype='void'::regtype
    AND p.pronargs=3 AND p.proargtypes='2950 2950 2951'::oidvector
    AND p.proargnames=ARRAY['p_environment_id','p_directory_object_id','p_principal_ids']
    AND p.proallargtypes IS NULL AND p.proargmodes IS NULL AND p.pronargdefaults=0
    AND p.provariadic=0 AND p.prosupport=0 AND p.probin IS NULL AND p.prosqlbody IS NULL AND p.proargdefaults IS NULL
    AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']
    AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(pg_catalog.btrim(
      pg_catalog.replace(p.prosrc,E'\r\n',E'\n'),E' \t\r\n'),'UTF8')),'hex')
      ='b9a6befb836015684839e3c4483ec2944c74320e3ab4bc5bc2d3c971fa3dd2bd') FROM plan_helper p)
  AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p WHERE p.proowner=i.plan_oid
    AND p.oid<>pg_catalog.to_regprocedure('public.lock_enrollment_grant_plan_context(uuid,uuid,uuid[])'))
  AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_attribute a CROSS JOIN LATERAL pg_catalog.aclexplode(a.attacl) acl
    WHERE acl.grantee=i.plan_oid)
  AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c
    WHERE CASE WHEN c.relkind='S' THEN pg_catalog.has_sequence_privilege(i.plan_oid,c.oid,'USAGE,SELECT,UPDATE') ELSE false END)
  AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_default_acl defaults CROSS JOIN LATERAL pg_catalog.aclexplode(defaults.defaclacl) acl
    WHERE defaults.defaclobjtype IN('r','S') AND acl.grantee IN(0,i.plan_oid))
  AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname NOT IN('pg_catalog','information_schema') AND n.nspname !~ '^pg_(toast|temp_)'
      AND c.relkind IN('r','p','v','m','f') AND (
        pg_catalog.has_table_privilege(i.plan_oid,c.oid,'INSERT,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN')
        OR pg_catalog.has_any_column_privilege(i.plan_oid,c.oid,'INSERT,REFERENCES')
        OR ((pg_catalog.has_table_privilege(i.plan_oid,c.oid,'SELECT') OR pg_catalog.has_any_column_privilege(i.plan_oid,c.oid,'SELECT'))
          AND (n.nspname<>'public' OR c.relname NOT IN('DirectoryDatabaseBindings','Environments','DirectorySync','DirectoryObjects','Principals','Memberships')))
        OR ((pg_catalog.has_table_privilege(i.plan_oid,c.oid,'UPDATE') OR pg_catalog.has_any_column_privilege(i.plan_oid,c.oid,'UPDATE'))
          AND (n.nspname<>'public' OR c.relname NOT IN('Environments','DirectorySync','DirectoryObjects','Principals','Memberships')))))
  AND (SELECT count(*)=2 AND bool_and(c.relowner=i.owner_oid AND c.relkind='r' AND c.relrowsecurity AND c.relforcerowsecurity
    AND NOT c.relispartition AND c.relpersistence='p')
    FROM pg_catalog.pg_class c WHERE c.oid IN(pg_catalog.to_regclass('public."Principals"'),pg_catalog.to_regclass('public."Sessions"')))
  AND (SELECT count(*)=1 AND bool_and(h.proowner=i.owner_oid AND h.lanname='sql' AND h.prosecdef
    AND h.provolatile='s' AND h.proparallel='u' AND h.prokind='f' AND NOT h.proretset
    AND NOT h.proisstrict AND NOT h.proleakproof AND h.prorettype='boolean'::regtype
    AND h.pronargs=0 AND h.pronargdefaults=0 AND h.proargnames IS NULL AND h.proallargtypes IS NULL
    AND h.proargmodes IS NULL AND h.provariadic=0
    AND h.prosupport=0 AND h.probin IS NULL AND h.prosqlbody IS NULL AND h.proargdefaults IS NULL
    AND h.proconfig=ARRAY['search_path=pg_catalog, pg_temp','row_security=on']
    AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(pg_catalog.btrim(
      pg_catalog.regexp_replace(h.prosrc,'[[:space:]]+',' ','g')),'UTF8')),'hex')
      ='e8f215ff4e1093baf33b3cf72040f99a96f2b5821f4b4593cf760d5a46658d84') FROM helper h)
  AND NOT EXISTS(SELECT 1 FROM ((SELECT * FROM expected EXCEPT SELECT * FROM actual)
    UNION ALL (SELECT * FROM actual EXCEPT SELECT * FROM expected)) difference)
  AND NOT EXISTS(SELECT 1 FROM ((SELECT * FROM expected_acl EXCEPT SELECT * FROM actual_acl)
    UNION ALL (SELECT * FROM actual_acl EXCEPT SELECT * FROM expected_acl)) difference)
  AND NOT EXISTS(SELECT 1 FROM ((SELECT * FROM expected_plan_tables EXCEPT SELECT * FROM actual_plan_tables)
    UNION ALL (SELECT * FROM actual_plan_tables EXCEPT SELECT * FROM expected_plan_tables)) difference)
  AND NOT EXISTS(SELECT 1 FROM ((SELECT * FROM expected_plan_functions EXCEPT SELECT * FROM actual_plan_functions)
    UNION ALL (SELECT * FROM actual_plan_functions EXCEPT SELECT * FROM expected_plan_functions)) difference)
  AND NOT EXISTS(SELECT 1 FROM ((SELECT * FROM expected_plan_schemas EXCEPT SELECT * FROM actual_plan_schemas)
    UNION ALL (SELECT * FROM actual_plan_schemas EXCEPT SELECT * FROM expected_plan_schemas)) difference)
  FROM identities i),false) AS is_valid
    );
    -- END generated delivery catalog slices

    -- BEGIN delivery API binding identity
    -- Catalog-only checks derive the sole API grantee. This owner-only data check
    -- binds it to exactly one API identity and excludes a bound plan-lock owner.
    ok := ok AND (SELECT count(*)=1 AND bool_and(binding."ContractVersion"=1
      AND binding."EnvironmentId" IS NULL AND binding."PrincipalId" IS NULL AND role.oid IS NOT NULL
      AND EXISTS(SELECT 1 FROM pg_catalog.pg_proc helper CROSS JOIN LATERAL pg_catalog.aclexplode(
        COALESCE(helper.proacl,pg_catalog.acldefault('f',helper.proowner))) acl
        WHERE helper.oid=pg_catalog.to_regprocedure('public.lock_enrollment_grant_plan_context(uuid,uuid,uuid[])')
          AND acl.grantee=role.oid AND acl.privilege_type='EXECUTE' AND NOT acl.is_grantable))
      FROM public."DirectoryDatabaseBindings" binding LEFT JOIN pg_catalog.pg_roles role ON role.rolname=binding."LoginRole"
      WHERE binding."Purpose"='Api')
      AND NOT EXISTS(SELECT 1 FROM public."DirectoryDatabaseBindings" binding JOIN pg_catalog.pg_roles role ON role.rolname=binding."LoginRole"
        JOIN pg_catalog.pg_proc helper ON helper.proowner=role.oid
        WHERE helper.oid=pg_catalog.to_regprocedure('public.lock_enrollment_grant_plan_context(uuid,uuid,uuid[])'));
    -- END delivery API binding identity

    -- BEGIN delivery runtime relation privileges
    -- System catalogs have ordinary PUBLIC read privileges. Reject effective access
    -- to application relations in every schema for every reserved delivery runtime.
    ok := ok AND NOT EXISTS(
      SELECT 1 FROM enrollment_execution.role_reservations reservation
      LEFT JOIN pg_catalog.pg_roles runtime_role ON runtime_role.oid=reservation.role_oid
        AND runtime_role.rolname=reservation.role_name
      WHERE reservation.capability='EnrollmentGrantDelivery'
        AND reservation.role_kind IN('StatusRuntime','DeliveryRuntime')
        AND CASE WHEN runtime_role.oid IS NULL THEN true ELSE
          pg_catalog.has_database_privilege(runtime_role.oid,pg_catalog.current_database(),'CREATE')
          OR EXISTS(SELECT 1 FROM pg_catalog.pg_default_acl defaults
            CROSS JOIN LATERAL pg_catalog.aclexplode(defaults.defaclacl) acl
            WHERE defaults.defaclobjtype IN('r','S') AND acl.grantee IN(0,runtime_role.oid))
          OR EXISTS(SELECT 1 FROM pg_catalog.pg_namespace namespace
            WHERE namespace.nspname NOT IN('pg_catalog','information_schema')
              AND namespace.nspname !~ '^pg_(toast|temp_)'
              AND pg_catalog.has_schema_privilege(runtime_role.oid,namespace.oid,'CREATE'))
          OR EXISTS(SELECT 1 FROM pg_catalog.pg_class relation
            JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace
            WHERE namespace.nspname NOT IN('pg_catalog','information_schema')
              AND namespace.nspname !~ '^pg_(toast|temp_)'
              AND CASE WHEN relation.relkind IN('r','p','v','m','f') THEN
                pg_catalog.has_table_privilege(runtime_role.oid,relation.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN')
                OR pg_catalog.has_any_column_privilege(runtime_role.oid,relation.oid,'SELECT,INSERT,UPDATE,REFERENCES')
              WHEN relation.relkind='S' THEN
                pg_catalog.has_sequence_privilege(runtime_role.oid,relation.oid,'USAGE,SELECT,UPDATE')
              ELSE false END)
          END);
    -- END delivery runtime relation privileges

    ok := ok
      AND (status_runtime IS NULL OR (
        NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc function_row WHERE function_row.proowner IN(status_runtime,delivery_runtime))
        AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc function_row
          CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(function_row.proacl,
            pg_catalog.acldefault('f',function_row.proowner))) acl
          WHERE acl.grantee=status_runtime AND (acl.privilege_type<>'EXECUTE' OR acl.is_grantable OR function_row.oid NOT IN(
              'enrollment_execution.read_grant_status_receipt(uuid,uuid)'::regprocedure,
              'enrollment_execution.append_grant_status_observation(uuid,uuid,uuid,text,text,timestamptz,timestamptz,uuid,uuid,uuid,timestamptz,timestamptz,timestamptz,smallint,timestamptz,bytea,bytea)'::regprocedure,
              'enrollment_execution.audit_delivery_privileges(uuid)'::regprocedure)))
        AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc function_row
          CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(function_row.proacl,
            pg_catalog.acldefault('f',function_row.proowner))) acl
          WHERE acl.grantee=delivery_runtime AND (acl.privilege_type<>'EXECUTE' OR acl.is_grantable OR function_row.oid NOT IN(
              'enrollment_execution.read_grant_delivery(uuid,uuid,uuid,text)'::regprocedure,
              'enrollment_execution.acknowledge_grant_delivery(uuid,uuid,uuid,text,bytea,bytea)'::regprocedure,
              'enrollment_execution.audit_delivery_privileges(uuid)'::regprocedure)))
        AND (SELECT count(*)=3 FROM pg_catalog.pg_proc function_row CROSS JOIN LATERAL
          pg_catalog.aclexplode(function_row.proacl) acl WHERE acl.grantee=status_runtime
            AND acl.privilege_type='EXECUTE' AND NOT acl.is_grantable)
        AND (SELECT count(*)=3 FROM pg_catalog.pg_proc function_row CROSS JOIN LATERAL
          pg_catalog.aclexplode(function_row.proacl) acl WHERE acl.grantee=delivery_runtime
            AND acl.privilege_type='EXECUTE' AND NOT acl.is_grantable)))
      AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class relation
        CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(relation.relacl,pg_catalog.acldefault('r',relation.relowner))) acl
        WHERE acl.grantee=delivery_definer AND acl.is_grantable)
      AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_attribute attribute
        CROSS JOIN LATERAL pg_catalog.aclexplode(attribute.attacl) acl
        WHERE acl.grantee=delivery_definer AND acl.is_grantable);

    ok := ok AND (SELECT count(*)=1 AND bool_and(p.proowner=table_owner AND l.lanname='plpgsql'
        AND NOT p.prosecdef AND p.provolatile='v' AND p.proparallel='u' AND NOT p.proisstrict AND NOT p.proleakproof
        AND p.prokind='f' AND NOT p.proretset AND p.prorettype='trigger'::regtype AND p.pronargs=0
        AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']
        AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
            pg_catalog.btrim(pg_catalog.regexp_replace(p.prosrc,'[[:space:]]+',' ','g')),'UTF8')),'hex')
            ='dd8064d70027f2b4ae9070970e54aa183e1f70bb4c8798b64f751673de59ee27'
        AND NOT EXISTS(SELECT 1 FROM pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) acl
            WHERE acl.grantee<>table_owner OR acl.privilege_type<>'EXECUTE' OR acl.is_grantable))
      FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_language l ON l.oid=p.prolang
      WHERE p.oid=pg_catalog.to_regprocedure('public.validate_enrollment_grant_queue_anchor()'));

    RETURN QUERY SELECT COALESCE(ok,false),CASE WHEN COALESCE(ok,false) THEN 'None' ELSE 'ProfileDrift' END,4::smallint;
END
$function$;
REVOKE ALL ON FUNCTION enrollment_execution.audit_execution_privileges(uuid) FROM PUBLIC;
ALTER FUNCTION enrollment_execution.audit_execution_privileges(uuid) OWNER TO :"expected_table_owner_role";
