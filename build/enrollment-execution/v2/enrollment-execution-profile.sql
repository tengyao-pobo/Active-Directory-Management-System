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

CREATE FUNCTION enrollment_execution.audit_execution_privileges(p_environment uuid)
RETURNS TABLE(is_valid boolean,diagnostic_code text,profile_version smallint)
LANGUAGE plpgsql STABLE PARALLEL UNSAFE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET row_security=on AS $function$
DECLARE
    table_owner oid;
    definer oid;
    runtime oid;
    ok boolean;
    private_registry oid;
    private_marker oid;
BEGIN
    SELECT c.relowner INTO table_owner FROM pg_catalog.pg_class c
        WHERE c.oid='enrollment_execution.role_reservations'::regclass;
    SELECT r.role_oid INTO definer FROM enrollment_execution.role_reservations r
        WHERE r.capability='EnrollmentGrantExecution' AND r.role_kind='Definer';
    SELECT role.oid INTO runtime
    FROM public."DirectoryDatabaseBindings" b JOIN pg_catalog.pg_roles role ON role.rolname=b."LoginRole"
    JOIN enrollment_execution.role_reservations reservation
      ON reservation.role_name=b."LoginRole" AND reservation.role_oid=role.oid
      AND reservation.capability='EnrollmentGrantExecution' AND reservation.role_kind='Runtime'
    WHERE b."Purpose"='EnrollmentGrantExecution' AND b."ContractVersion"=2
      AND b."EnvironmentId"=p_environment AND b."PrincipalId" IS NULL;

    ok := p_environment IS NOT NULL AND p_environment<>'00000000-0000-0000-0000-000000000000'::uuid
      AND table_owner IS NOT NULL AND definer IS NOT NULL AND runtime IS NOT NULL
      AND (SELECT count(*)=1 FROM enrollment_execution.role_reservations
           WHERE capability='EnrollmentGrantExecution' AND role_kind='Definer')
      AND (SELECT count(*)=1 FROM public."DirectoryDatabaseBindings"
           WHERE "Purpose"='EnrollmentGrantExecution' AND "ContractVersion"=2
             AND "EnvironmentId"=p_environment AND "PrincipalId" IS NULL)
      AND NOT EXISTS (
          SELECT 1 FROM enrollment_execution.role_reservations reservation
          LEFT JOIN pg_catalog.pg_roles role ON role.oid=reservation.role_oid AND role.rolname=reservation.role_name
          WHERE role.oid IS NULL OR reservation.capability<>'EnrollmentGrantExecution'
             OR reservation.reservation_schema_version<>1
             OR (reservation.role_kind='Runtime') IS DISTINCT FROM role.rolcanlogin
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
      AND EXISTS(SELECT 1 FROM pg_catalog.pg_index index_row JOIN pg_catalog.pg_class index_class ON index_class.oid=index_row.indexrelid
          WHERE index_class.relname='enrollment_execution_environment_login'
            AND index_row.indrelid='public."DirectoryDatabaseBindings"'::regclass AND index_row.indisunique
            AND index_row.indisvalid AND index_row.indisready AND index_row.indpred IS NOT NULL
            AND pg_catalog.pg_get_expr(index_row.indpred,index_row.indrelid)='("Purpose" = ''EnrollmentGrantExecution''::text)')
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
          ('CHECK (capability = ''EnrollmentGrantExecution''::text)'),('CHECK (reservation_schema_version = 1)'),
          ('CHECK (role_kind = ANY (ARRAY[''Runtime''::text, ''Definer''::text]))'),
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
            AND pg_catalog.btrim(p.prosrc,E' \t\r\n')='SELECT 2::smallint')
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
          ('enrollment_execution.read_execution_record(uuid,uuid)',definer,true,false,'plpgsql','v','u',true,'9b1c550cf510584afd81a063b5cf8e3c2d41ff06cb1956e86547e6377f2d6b89'),
          ('enrollment_execution.read_and_lock_plan_context(uuid,uuid)',definer,true,false,'plpgsql','v','u',true,'f259bd9b6c9a2590831ee03646e2c7ffca3e4c521973ba016a1577fed4e42209'),
          ('enrollment_execution.authorize_and_store_candidate(uuid,uuid,text,bytea,bytea,bytea)',definer,true,false,'plpgsql','v','u',true,'d46b11292ae7bfc673b781b3424bda8b33cff7bb03d1a4dc0a775216cf0ee1d8'),
          ('enrollment_execution.record_execution_result(uuid,uuid,bytea,text,text,uuid,uuid,uuid,uuid,timestamptz,timestamptz,timestamptz,smallint,timestamptz,bytea,bytea)',definer,true,false,'plpgsql','v','u',true,'f553b9909588423969729dd985c154a8ee590be3e228429908d24a69bc5bb2c0'),
          ('enrollment_execution.quarantine_execution(uuid,uuid,bytea,text)',definer,true,false,'plpgsql','v','u',true,'f420d2d7913085ac6fa46710ee76c26310a4d8000ac65256900e59c92243c483')),
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
      AND (SELECT count(*)=6 FROM pg_catalog.pg_proc p
          CROSS JOIN LATERAL pg_catalog.aclexplode(p.proacl) acl
          WHERE acl.grantee=runtime AND acl.privilege_type='EXECUTE' AND NOT acl.is_grantable
            AND p.oid IN ('enrollment_execution.read_execution_record(uuid,uuid)'::regprocedure,
              'enrollment_execution.read_and_lock_plan_context(uuid,uuid)'::regprocedure,
              'enrollment_execution.authorize_and_store_candidate(uuid,uuid,text,bytea,bytea,bytea)'::regprocedure,
              'enrollment_execution.record_execution_result(uuid,uuid,bytea,text,text,uuid,uuid,uuid,uuid,timestamptz,timestamptz,timestamptz,smallint,timestamptz,bytea,bytea)'::regprocedure,
              'enrollment_execution.quarantine_execution(uuid,uuid,bytea,text)'::regprocedure,
              'enrollment_execution.audit_execution_privileges(uuid)'::regprocedure))
      AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p
          CROSS JOIN LATERAL pg_catalog.aclexplode(p.proacl) acl
          WHERE acl.grantee=runtime AND (acl.privilege_type<>'EXECUTE' OR acl.is_grantable OR p.oid NOT IN (
              'enrollment_execution.read_execution_record(uuid,uuid)'::regprocedure,
              'enrollment_execution.read_and_lock_plan_context(uuid,uuid)'::regprocedure,
              'enrollment_execution.authorize_and_store_candidate(uuid,uuid,text,bytea,bytea,bytea)'::regprocedure,
              'enrollment_execution.record_execution_result(uuid,uuid,bytea,text,text,uuid,uuid,uuid,uuid,timestamptz,timestamptz,timestamptz,smallint,timestamptz,bytea,bytea)'::regprocedure,
              'enrollment_execution.quarantine_execution(uuid,uuid,bytea,text)'::regprocedure,
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

    RETURN QUERY SELECT COALESCE(ok,false),CASE WHEN COALESCE(ok,false) THEN 'None' ELSE 'ProfileDrift' END,2::smallint;
END
$function$;
REVOKE ALL ON FUNCTION enrollment_execution.audit_execution_privileges(uuid) FROM PUBLIC;
ALTER FUNCTION enrollment_execution.audit_execution_privileges(uuid) OWNER TO :"expected_table_owner_role";
