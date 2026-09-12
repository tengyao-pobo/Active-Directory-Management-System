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

CREATE FUNCTION enrollment_execution.audit_execution_privileges(p_environment uuid)
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
          ('CHECK (((capability = ''EnrollmentGrantExecution''::text) AND (role_kind = ANY (ARRAY[''Runtime''::text, ''Definer''::text, ''QueueDefiner''::text]))) OR ((capability = ''EnrollmentGrantDelivery''::text) AND (role_kind = ANY (ARRAY[''DeliveryDefiner''::text, ''StatusRuntime''::text, ''DeliveryRuntime''::text]))))'),
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
          ('enrollment_execution.read_execution_record(uuid,uuid)',definer,true,false,'plpgsql','v','u',true,'cd7c0975c4cb6f31725fe1151b1513e5df6d7fb51b822f1a862e54df47c9f0f6'),
          ('enrollment_execution.read_and_lock_plan_context(uuid,uuid)',definer,true,false,'plpgsql','v','u',true,'0add6825c35e78b11019b42477581f9c893536005fde7c66e726e51e80bc14f1'),
          ('enrollment_execution.authorize_and_store_candidate(uuid,uuid,text,bytea,bytea,bytea)',definer,true,false,'plpgsql','v','u',true,'69f37bda1a514534520cadfb8431bd4efa17c487ed5e19930f5b1b7d80f8d7d6'),
          ('enrollment_execution.record_execution_result(uuid,uuid,bytea,text,text,uuid,uuid,uuid,uuid,timestamptz,timestamptz,timestamptz,smallint,timestamptz,bytea,bytea)',definer,true,false,'plpgsql','v','u',true,'ca2fa2d60055e2956f59346b02450e692e63e103d180c4fa7b2444e3668bd6c2'),
          ('enrollment_execution.quarantine_execution(uuid,uuid,bytea,text)',definer,true,false,'plpgsql','v','u',true,'a7cd12830602f399b12593e59fc4a3d221875c8efb0da666e7e0131669d99524')),
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

    ok := ok AND (SELECT count(*)=2 AND bool_and(p.proowner=table_owner AND l.lanname='sql'
        AND p.prosecdef AND p.provolatile='s' AND p.proparallel='u' AND NOT p.proretset
        AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp','row_security=off']
        AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
          pg_catalog.btrim(pg_catalog.regexp_replace(p.prosrc,'[[:space:]]+',' ','g')),'UTF8')),'hex')
          =CASE p.proname WHEN 'has_environment_membership' THEN 'c9529f8fad835c8125509e539be576a576a94e7d03660e67023392b7e951ae4c'
                          ELSE '9822d3a40ee96593c8aad915ac6ca454868274347f5a6e30fab61eeca60752a4' END)
      FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_language l ON l.oid=p.prolang
      WHERE p.oid IN('public.has_environment_membership(uuid,uuid)'::regprocedure,
                     'public.directory_database_access(uuid,uuid)'::regprocedure));

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
        WHERE definer=ANY(p.polroles) AND p.polname NOT LIKE 'enrollment_execution_worker_%')
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
          ('enrollment_execution.claim_next(uuid,uuid)',queue_definer,true,true,'v','82e5af6d26d860170794d29f404254525c267a36ccae4d0cf1ed030e4dd6aa93'),
          ('enrollment_execution.defer_claim(uuid,uuid,uuid,text)',queue_definer,true,true,'v','496e54664b5efa4a3656e570d0254d84ace518cac3843a24aca42614223f3379'),
          ('enrollment_execution.complete_claim(uuid,uuid,uuid)',queue_definer,true,true,'v','9ed1b979fda3916936ad235f4466522a3b90cb871dcb6eea961d1bdf9ec18e82')),
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
      AND NOT EXISTS(
        WITH expected(signature,owner_oid,security_definer,with_rls,volatility,body_hash) AS (VALUES
          ('enrollment_execution.guard_status_observation()',table_owner,false,false,'v','205fb0e014963548e6ed954ef2680df39de239c5a94893e79079009986c63c17'),
          ('enrollment_execution.record_status_observation(uuid,uuid,uuid,text,text,timestamptz,timestamptz,uuid,uuid,uuid,timestamptz,timestamptz,timestamptz,smallint,timestamptz,bytea,bytea)',table_owner,false,false,'v','16e7ce5bada9c6ad5cd54a083fc2f5064300bfa0f1b1591ec5d7a1f328b83e10'),
          ('enrollment_execution.read_status_refresh_receipt(uuid,uuid)',table_owner,false,false,'v','b140b5dbe814117c4a1214fe4f86d2b595069b35f81a74f94afb061108d9e26f'),
          ('enrollment_execution.lock_delivery_context(uuid,uuid,uuid,text)',table_owner,false,false,'v','2773f0caa2d5ccdb20d5192bcefc5ef4d848004424b52bd43c746ef2abdd806b'),
          ('enrollment_execution.get_sealed_delivery(uuid,uuid,uuid,text)',table_owner,false,false,'v','49ac0d54d67374f2e26c4bb1ad57c7ccdd15096da5b013ee1175002b04fefa53'),
          ('enrollment_execution.ack_sealed_delivery(uuid,uuid,uuid,text,bytea,bytea)',table_owner,false,false,'v','85a3d6f503a90f067a7d94cffaf3fc03f6f3b1adb84db92a40110c721454ab24'),
          ('enrollment_execution.delivery_worker_scope(uuid,text)',table_owner,true,true,'s','a2abaa5afe86cdf2b548c52e54467b96a16af011f2780bdb8b49e4e1dd7efb8c'),
          ('enrollment_execution.read_grant_status_receipt(uuid,uuid)',delivery_definer,true,true,'v','63cc9a1b50e70f66d59ed1a754a54c05aee02259341b8f7b6ed9ecf10256ed78'),
          ('enrollment_execution.append_grant_status_observation(uuid,uuid,uuid,text,text,timestamptz,timestamptz,uuid,uuid,uuid,timestamptz,timestamptz,timestamptz,smallint,timestamptz,bytea,bytea)',delivery_definer,true,true,'v','545ce0efbc1807b4104a1d5386d328326f1bfc03db98dbcec9ab531f021b03cf'),
          ('enrollment_execution.read_grant_delivery(uuid,uuid,uuid,text)',delivery_definer,true,true,'v','f80126238164f65f17e8fb933b13799aa2fd6b45a1f3eb58a8f673014fcf5e3b'),
          ('enrollment_execution.acknowledge_grant_delivery(uuid,uuid,uuid,text,bytea,bytea)',delivery_definer,true,true,'v','99f68247c9d723dfa7755481005aa7104f93646f6095315ea8439db444668323'),
          ('enrollment_execution.reject_delivery_update()',table_owner,true,true,'v','279e969ccd38a161d13a2dad55009fd9e759ee9fd9e9b615dbb834ba4abfeb76'),
          ('enrollment_execution.audit_delivery_privileges(uuid)',table_owner,true,true,'s','3bf777d8dc0d6b4643c7893912af7d6768acca388c8ded40b47a7350d088467a')),
        actual AS (SELECT expected.*,function_row.oid,function_row.proowner,function_row.prosecdef,function_row.proisstrict,
            language_row.lanname,function_row.provolatile,function_row.proparallel,function_row.proconfig,
            pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(pg_catalog.btrim(
              pg_catalog.regexp_replace(function_row.prosrc,'[[:space:]]+',' ','g')),'UTF8')),'hex') actual_hash
          FROM expected LEFT JOIN pg_catalog.pg_proc function_row
            ON function_row.oid=pg_catalog.to_regprocedure(expected.signature)
          LEFT JOIN pg_catalog.pg_language language_row ON language_row.oid=function_row.prolang)
        SELECT 1 FROM actual WHERE oid IS NULL OR proowner<>owner_oid OR prosecdef<>security_definer
          OR proisstrict OR lanname<>'plpgsql' OR provolatile::text<>volatility OR proparallel<>'u'
          OR proconfig<>CASE WHEN with_rls THEN ARRAY['search_path=pg_catalog, pg_temp','row_security=on']
                            ELSE ARRAY['search_path=pg_catalog, pg_temp'] END OR actual_hash<>body_hash)
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

    ok := ok
      AND (status_runtime IS NULL OR (
        NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc function_row WHERE function_row.proowner IN(status_runtime,delivery_runtime))
        AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class relation
          WHERE pg_catalog.has_table_privilege(status_runtime,relation.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
             OR pg_catalog.has_table_privilege(delivery_runtime,relation.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'))
        AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class relation
          WHERE pg_catalog.has_any_column_privilege(status_runtime,relation.oid,'SELECT,INSERT,UPDATE,REFERENCES')
             OR pg_catalog.has_any_column_privilege(delivery_runtime,relation.oid,'SELECT,INSERT,UPDATE,REFERENCES'))
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
