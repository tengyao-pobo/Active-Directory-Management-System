-- Included only by the profile4 upgrade/provision transaction while holding the exclusive deployment lock.

CREATE FUNCTION enrollment_execution.delivery_worker_scope(p_environment uuid,p_purpose text)
RETURNS boolean LANGUAGE plpgsql STABLE PARALLEL UNSAFE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET row_security=on AS $function$
DECLARE runtime_oid oid; definer_oid oid; runtime_rows integer; definer_rows integer; binding_rows integer;
BEGIN
    IF p_environment IS NULL OR p_environment='00000000-0000-0000-0000-000000000000'::uuid
       OR p_purpose IS NULL OR p_purpose NOT IN ('EnrollmentGrantStatusRefresh','EnrollmentGrantDelivery') THEN
        RETURN false;
    END IF;
    SELECT count(*),min(role.oid) INTO runtime_rows,runtime_oid
    FROM pg_catalog.pg_roles role
    WHERE role.rolname=SESSION_USER AND role.rolcanlogin
      AND NOT(role.rolsuper OR role.rolbypassrls OR role.rolcreatedb OR role.rolcreaterole
        OR role.rolinherit OR role.rolreplication)
      AND role.oid<>CURRENT_USER::regrole::oid
      AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members membership
        WHERE membership.member=role.oid OR membership.roleid=role.oid);
    SELECT count(*),min(role.oid) INTO definer_rows,definer_oid
    FROM enrollment_execution.role_reservations reservation
    JOIN pg_catalog.pg_roles role ON role.oid=reservation.role_oid AND role.rolname=reservation.role_name
    WHERE reservation.capability='EnrollmentGrantDelivery' AND reservation.role_kind='DeliveryDefiner'
      AND reservation.reservation_schema_version=1
      AND NOT(role.rolcanlogin OR role.rolsuper OR role.rolbypassrls OR role.rolcreatedb OR role.rolcreaterole
        OR role.rolinherit OR role.rolreplication)
      AND role.oid<>CURRENT_USER::regrole::oid
      AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members membership
        WHERE membership.member=role.oid OR membership.roleid=role.oid);
    IF runtime_rows<>1 OR definer_rows<>1 OR runtime_oid=definer_oid
       OR (SELECT count(*) FROM enrollment_execution.role_reservations
         WHERE capability='EnrollmentGrantDelivery' AND role_kind='DeliveryDefiner')<>1 THEN
        RETURN false;
    END IF;
    SELECT count(*) INTO binding_rows
    FROM (
       SELECT 1 FROM public."DirectoryDatabaseBindings" binding
       JOIN enrollment_execution.role_reservations runtime_reservation
         ON runtime_reservation.role_name=binding."LoginRole"
        AND runtime_reservation.role_oid=runtime_oid
        AND runtime_reservation.capability='EnrollmentGrantDelivery'
        AND runtime_reservation.reservation_schema_version=1
        AND runtime_reservation.role_kind=CASE p_purpose
              WHEN 'EnrollmentGrantStatusRefresh' THEN 'StatusRuntime' ELSE 'DeliveryRuntime' END
       WHERE binding."EnvironmentId"=p_environment AND binding."Purpose"=p_purpose
         AND binding."ContractVersion"=1 AND binding."PrincipalId" IS NULL
         AND binding."LoginRole"=SESSION_USER) matched;
    RETURN binding_rows=1;
END
$function$;
REVOKE ALL ON FUNCTION enrollment_execution.delivery_worker_scope(uuid,text) FROM PUBLIC;
ALTER FUNCTION enrollment_execution.delivery_worker_scope(uuid,text) OWNER TO :"expected_table_owner_role";
GRANT EXECUTE ON FUNCTION enrollment_execution.delivery_worker_scope(uuid,text) TO :"delivery_definer_role";

CREATE FUNCTION enrollment_execution.read_grant_status_receipt(p_environment uuid,p_operation uuid)
RETURNS TABLE(contract_version smallint,outcome text,environment_id uuid,operation_id uuid,
    grant_id uuid,directory_object_id uuid,device_id uuid,mapping_created_at timestamptz,
    grant_created_at timestamptz,grant_expires_at timestamptz,issue_contract_version smallint,
    mint_permit_not_after timestamptz,token_sha256 bytea,authorization_digest bytea)
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET row_security=on AS $function$
DECLARE audit_rows integer; valid_rows integer;
BEGIN
    IF current_setting('transaction_isolation')<>'serializable' THEN
        RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='Grant delivery requires a serializable transaction.';
    END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock_shared(1162235478,1);
    SELECT count(*),count(*) FILTER(WHERE audit.is_valid AND audit.diagnostic_code='None' AND audit.profile_version=4)
      INTO audit_rows,valid_rows FROM enrollment_execution.audit_delivery_privileges(p_environment) audit;
    IF audit_rows<>1 OR valid_rows<>1 OR enrollment_execution.delivery_worker_scope(
        p_environment,'EnrollmentGrantStatusRefresh') IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='Enrollment delivery privilege audit failed.';
    END IF;
    PERFORM pg_catalog.set_config('app.delivery_environment_id',COALESCE(p_environment::text,''),true);
    PERFORM pg_catalog.set_config('app.delivery_operation_id',COALESCE(p_operation::text,''),true);
    PERFORM pg_catalog.set_config('app.delivery_requester_id','',true);
    RETURN QUERY SELECT * FROM enrollment_execution.read_status_refresh_receipt(p_environment,p_operation);
END
$function$;
REVOKE ALL ON FUNCTION enrollment_execution.read_grant_status_receipt(uuid,uuid) FROM PUBLIC;

CREATE FUNCTION enrollment_execution.append_grant_status_observation(
    p_environment uuid,p_operation uuid,p_observation uuid,p_state text,p_diagnostic text,
    p_private_observed_at timestamptz,p_private_state_changed_at timestamptz,
    p_grant uuid,p_directory_object uuid,p_device uuid,p_mapping_created_at timestamptz,
    p_grant_created_at timestamptz,p_grant_expires_at timestamptz,p_issue_contract smallint,
    p_mint_permit_not_after timestamptz,p_token_sha256 bytea,p_authorization_digest bytea)
RETURNS TABLE(contract_version smallint,outcome text,observation_id uuid,environment_id uuid,operation_id uuid,
    sequence bigint,state text,diagnostic text,private_observed_at timestamptz,private_state_changed_at timestamptz,
    recorded_at timestamptz,available_until timestamptz)
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET row_security=on AS $function$
DECLARE audit_rows integer; valid_rows integer;
BEGIN
    IF current_setting('transaction_isolation')<>'serializable' THEN
        RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='Grant delivery requires a serializable transaction.';
    END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock_shared(1162235478,1);
    SELECT count(*),count(*) FILTER(WHERE audit.is_valid AND audit.diagnostic_code='None' AND audit.profile_version=4)
      INTO audit_rows,valid_rows FROM enrollment_execution.audit_delivery_privileges(p_environment) audit;
    IF audit_rows<>1 OR valid_rows<>1 OR enrollment_execution.delivery_worker_scope(
        p_environment,'EnrollmentGrantStatusRefresh') IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='Enrollment delivery privilege audit failed.';
    END IF;
    PERFORM pg_catalog.set_config('app.delivery_environment_id',COALESCE(p_environment::text,''),true);
    PERFORM pg_catalog.set_config('app.delivery_operation_id',COALESCE(p_operation::text,''),true);
    PERFORM pg_catalog.set_config('app.delivery_requester_id','',true);
    RETURN QUERY SELECT * FROM enrollment_execution.record_status_observation(
        p_environment,p_operation,p_observation,p_state,p_diagnostic,p_private_observed_at,p_private_state_changed_at,
        p_grant,p_directory_object,p_device,p_mapping_created_at,p_grant_created_at,p_grant_expires_at,
        p_issue_contract,p_mint_permit_not_after,p_token_sha256,p_authorization_digest);
END
$function$;
REVOKE ALL ON FUNCTION enrollment_execution.append_grant_status_observation(uuid,uuid,uuid,text,text,timestamptz,timestamptz,uuid,uuid,uuid,timestamptz,timestamptz,timestamptz,smallint,timestamptz,bytea,bytea) FROM PUBLIC;

CREATE FUNCTION enrollment_execution.read_grant_delivery(
    p_environment uuid,p_operation uuid,p_requester uuid,p_session_hash text)
RETURNS TABLE(contract_version smallint,outcome text,environment_id uuid,operation_id uuid,
    format_version smallint,recipient_fingerprint bytea,ciphertext bytea,ciphertext_sha256 bytea,
    delivery_not_after timestamptz,queried_at timestamptz)
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET row_security=on AS $function$
DECLARE audit_rows integer; valid_rows integer;
BEGIN
    IF current_setting('transaction_isolation')<>'serializable' THEN
        RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='Grant delivery requires a serializable transaction.';
    END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock_shared(1162235478,1);
    SELECT count(*),count(*) FILTER(WHERE audit.is_valid AND audit.diagnostic_code='None' AND audit.profile_version=4)
      INTO audit_rows,valid_rows FROM enrollment_execution.audit_delivery_privileges(p_environment) audit;
    IF audit_rows<>1 OR valid_rows<>1 OR enrollment_execution.delivery_worker_scope(
        p_environment,'EnrollmentGrantDelivery') IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='Enrollment delivery privilege audit failed.';
    END IF;
    PERFORM pg_catalog.set_config('app.delivery_environment_id',COALESCE(p_environment::text,''),true);
    PERFORM pg_catalog.set_config('app.delivery_operation_id',COALESCE(p_operation::text,''),true);
    PERFORM pg_catalog.set_config('app.delivery_requester_id',COALESCE(p_requester::text,''),true);
    RETURN QUERY SELECT * FROM enrollment_execution.get_sealed_delivery(p_environment,p_operation,p_requester,p_session_hash);
END
$function$;
REVOKE ALL ON FUNCTION enrollment_execution.read_grant_delivery(uuid,uuid,uuid,text) FROM PUBLIC;

CREATE FUNCTION enrollment_execution.acknowledge_grant_delivery(
    p_environment uuid,p_operation uuid,p_requester uuid,p_session_hash text,
    p_recipient_fingerprint bytea,p_ciphertext_sha256 bytea)
RETURNS TABLE(contract_version smallint,outcome text)
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET row_security=on AS $function$
DECLARE audit_rows integer; valid_rows integer;
BEGIN
    IF current_setting('transaction_isolation')<>'serializable' THEN
        RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='Grant delivery requires a serializable transaction.';
    END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock_shared(1162235478,1);
    SELECT count(*),count(*) FILTER(WHERE audit.is_valid AND audit.diagnostic_code='None' AND audit.profile_version=4)
      INTO audit_rows,valid_rows FROM enrollment_execution.audit_delivery_privileges(p_environment) audit;
    IF audit_rows<>1 OR valid_rows<>1 OR enrollment_execution.delivery_worker_scope(
        p_environment,'EnrollmentGrantDelivery') IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='Enrollment delivery privilege audit failed.';
    END IF;
    PERFORM pg_catalog.set_config('app.delivery_environment_id',COALESCE(p_environment::text,''),true);
    PERFORM pg_catalog.set_config('app.delivery_operation_id',COALESCE(p_operation::text,''),true);
    PERFORM pg_catalog.set_config('app.delivery_requester_id',COALESCE(p_requester::text,''),true);
    RETURN QUERY SELECT * FROM enrollment_execution.ack_sealed_delivery(
        p_environment,p_operation,p_requester,p_session_hash,p_recipient_fingerprint,p_ciphertext_sha256);
END
$function$;
REVOKE ALL ON FUNCTION enrollment_execution.acknowledge_grant_delivery(uuid,uuid,uuid,text,bytea,bytea) FROM PUBLIC;

CREATE FUNCTION enrollment_execution.reject_delivery_update() RETURNS trigger
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET row_security=on AS $function$
BEGIN
    IF EXISTS(SELECT 1 FROM public."DirectoryDatabaseBindings" binding
        WHERE binding."LoginRole"=SESSION_USER
          AND binding."Purpose" IN ('EnrollmentGrantStatusRefresh','EnrollmentGrantDelivery')
          AND binding."ContractVersion"=1) THEN
        RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='Enrollment delivery runtime cannot mutate authoritative state.';
    END IF;
    RETURN NEW;
END
$function$;
REVOKE ALL ON FUNCTION enrollment_execution.reject_delivery_update() FROM PUBLIC;
ALTER FUNCTION enrollment_execution.reject_delivery_update() OWNER TO :"expected_table_owner_role";

CREATE TRIGGER enrollment_delivery_environment_guard BEFORE UPDATE ON public."Environments"
    FOR EACH ROW EXECUTE FUNCTION enrollment_execution.reject_delivery_update();
CREATE TRIGGER enrollment_delivery_sync_guard BEFORE UPDATE ON public."DirectorySync"
    FOR EACH ROW EXECUTE FUNCTION enrollment_execution.reject_delivery_update();
CREATE TRIGGER enrollment_delivery_directory_guard BEFORE UPDATE ON public."DirectoryObjects"
    FOR EACH ROW EXECUTE FUNCTION enrollment_execution.reject_delivery_update();
CREATE TRIGGER enrollment_delivery_principal_guard BEFORE UPDATE ON public."Principals"
    FOR EACH ROW EXECUTE FUNCTION enrollment_execution.reject_delivery_update();
CREATE TRIGGER enrollment_delivery_membership_guard BEFORE UPDATE ON public."Memberships"
    FOR EACH ROW EXECUTE FUNCTION enrollment_execution.reject_delivery_update();
CREATE TRIGGER enrollment_delivery_operation_guard BEFORE UPDATE ON public."EnrollmentGrantOperations"
    FOR EACH ROW EXECUTE FUNCTION enrollment_execution.reject_delivery_update();

-- The shared delivery definer is narrowed to one immutable operation and, for browser delivery,
-- one requester. Paired restrictive policies prevent unrelated permissive policies widening it.
CREATE POLICY enrollment_delivery_operations_allow ON public."EnrollmentGrantOperations" AS PERMISSIVE FOR ALL TO :"delivery_definer_role"
    USING ("EnvironmentId"=nullif(current_setting('app.delivery_environment_id',true),'')::uuid
       AND "Id"=nullif(current_setting('app.delivery_operation_id',true),'')::uuid)
    WITH CHECK ("EnvironmentId"=nullif(current_setting('app.delivery_environment_id',true),'')::uuid
       AND "Id"=nullif(current_setting('app.delivery_operation_id',true),'')::uuid);
CREATE POLICY enrollment_delivery_operations_limit ON public."EnrollmentGrantOperations" AS RESTRICTIVE FOR ALL TO :"delivery_definer_role"
    USING ("EnvironmentId"=nullif(current_setting('app.delivery_environment_id',true),'')::uuid
       AND "Id"=nullif(current_setting('app.delivery_operation_id',true),'')::uuid)
    WITH CHECK ("EnvironmentId"=nullif(current_setting('app.delivery_environment_id',true),'')::uuid
       AND "Id"=nullif(current_setting('app.delivery_operation_id',true),'')::uuid);

CREATE POLICY enrollment_delivery_environment_allow ON public."Environments" AS PERMISSIVE FOR ALL TO :"delivery_definer_role"
    USING ("Id"=nullif(current_setting('app.delivery_environment_id',true),'')::uuid)
    WITH CHECK ("Id"=nullif(current_setting('app.delivery_environment_id',true),'')::uuid);
CREATE POLICY enrollment_delivery_environment_limit ON public."Environments" AS RESTRICTIVE FOR ALL TO :"delivery_definer_role"
    USING ("Id"=nullif(current_setting('app.delivery_environment_id',true),'')::uuid)
    WITH CHECK ("Id"=nullif(current_setting('app.delivery_environment_id',true),'')::uuid);
CREATE POLICY enrollment_delivery_sync_allow ON public."DirectorySync" AS PERMISSIVE FOR ALL TO :"delivery_definer_role"
    USING ("EnvironmentId"=nullif(current_setting('app.delivery_environment_id',true),'')::uuid)
    WITH CHECK ("EnvironmentId"=nullif(current_setting('app.delivery_environment_id',true),'')::uuid);
CREATE POLICY enrollment_delivery_sync_limit ON public."DirectorySync" AS RESTRICTIVE FOR ALL TO :"delivery_definer_role"
    USING ("EnvironmentId"=nullif(current_setting('app.delivery_environment_id',true),'')::uuid)
    WITH CHECK ("EnvironmentId"=nullif(current_setting('app.delivery_environment_id',true),'')::uuid);
CREATE POLICY enrollment_delivery_directory_allow ON public."DirectoryObjects" AS PERMISSIVE FOR ALL TO :"delivery_definer_role"
    USING ("EnvironmentId"=nullif(current_setting('app.delivery_environment_id',true),'')::uuid)
    WITH CHECK ("EnvironmentId"=nullif(current_setting('app.delivery_environment_id',true),'')::uuid);
CREATE POLICY enrollment_delivery_directory_limit ON public."DirectoryObjects" AS RESTRICTIVE FOR ALL TO :"delivery_definer_role"
    USING ("EnvironmentId"=nullif(current_setting('app.delivery_environment_id',true),'')::uuid)
    WITH CHECK ("EnvironmentId"=nullif(current_setting('app.delivery_environment_id',true),'')::uuid);
CREATE POLICY enrollment_delivery_principals_allow ON public."Principals" AS PERMISSIVE FOR ALL TO :"delivery_definer_role"
    USING ("Id"=nullif(current_setting('app.delivery_requester_id',true),'')::uuid)
    WITH CHECK ("Id"=nullif(current_setting('app.delivery_requester_id',true),'')::uuid);
CREATE POLICY enrollment_delivery_principals_limit ON public."Principals" AS RESTRICTIVE FOR ALL TO :"delivery_definer_role"
    USING ("Id"=nullif(current_setting('app.delivery_requester_id',true),'')::uuid)
    WITH CHECK ("Id"=nullif(current_setting('app.delivery_requester_id',true),'')::uuid);
CREATE POLICY enrollment_delivery_memberships_allow ON public."Memberships" AS PERMISSIVE FOR ALL TO :"delivery_definer_role"
    USING ("EnvironmentId"=nullif(current_setting('app.delivery_environment_id',true),'')::uuid
       AND "PrincipalId"=nullif(current_setting('app.delivery_requester_id',true),'')::uuid)
    WITH CHECK ("EnvironmentId"=nullif(current_setting('app.delivery_environment_id',true),'')::uuid
       AND "PrincipalId"=nullif(current_setting('app.delivery_requester_id',true),'')::uuid);
CREATE POLICY enrollment_delivery_memberships_limit ON public."Memberships" AS RESTRICTIVE FOR ALL TO :"delivery_definer_role"
    USING ("EnvironmentId"=nullif(current_setting('app.delivery_environment_id',true),'')::uuid
       AND "PrincipalId"=nullif(current_setting('app.delivery_requester_id',true),'')::uuid)
    WITH CHECK ("EnvironmentId"=nullif(current_setting('app.delivery_environment_id',true),'')::uuid
       AND "PrincipalId"=nullif(current_setting('app.delivery_requester_id',true),'')::uuid);
CREATE POLICY enrollment_delivery_sessions_allow ON public."Sessions" AS PERMISSIVE FOR SELECT TO :"delivery_definer_role"
    USING ("PrincipalId"=nullif(current_setting('app.delivery_requester_id',true),'')::uuid);
CREATE POLICY enrollment_delivery_sessions_limit ON public."Sessions" AS RESTRICTIVE FOR SELECT TO :"delivery_definer_role"
    USING ("PrincipalId"=nullif(current_setting('app.delivery_requester_id',true),'')::uuid);
CREATE POLICY enrollment_delivery_roles_allow ON public."Roles" AS PERMISSIVE FOR SELECT TO :"delivery_definer_role"
    USING ("EnvironmentId"=nullif(current_setting('app.delivery_environment_id',true),'')::uuid);
CREATE POLICY enrollment_delivery_roles_limit ON public."Roles" AS RESTRICTIVE FOR SELECT TO :"delivery_definer_role"
    USING ("EnvironmentId"=nullif(current_setting('app.delivery_environment_id',true),'')::uuid);
CREATE POLICY enrollment_delivery_role_permissions_allow ON public."RolePermissions" AS PERMISSIVE FOR SELECT TO :"delivery_definer_role"
    USING ("EnvironmentId"=nullif(current_setting('app.delivery_environment_id',true),'')::uuid);
CREATE POLICY enrollment_delivery_role_permissions_limit ON public."RolePermissions" AS RESTRICTIVE FOR SELECT TO :"delivery_definer_role"
    USING ("EnvironmentId"=nullif(current_setting('app.delivery_environment_id',true),'')::uuid);
CREATE POLICY enrollment_delivery_assignments_allow ON public."Assignments" AS PERMISSIVE FOR SELECT TO :"delivery_definer_role"
    USING ("EnvironmentId"=nullif(current_setting('app.delivery_environment_id',true),'')::uuid);
CREATE POLICY enrollment_delivery_assignments_limit ON public."Assignments" AS RESTRICTIVE FOR SELECT TO :"delivery_definer_role"
    USING ("EnvironmentId"=nullif(current_setting('app.delivery_environment_id',true),'')::uuid);
CREATE POLICY enrollment_delivery_scopes_allow ON public."Scopes" AS PERMISSIVE FOR SELECT TO :"delivery_definer_role"
    USING ("EnvironmentId"=nullif(current_setting('app.delivery_environment_id',true),'')::uuid);
CREATE POLICY enrollment_delivery_scopes_limit ON public."Scopes" AS RESTRICTIVE FOR SELECT TO :"delivery_definer_role"
    USING ("EnvironmentId"=nullif(current_setting('app.delivery_environment_id',true),'')::uuid);
CREATE POLICY enrollment_delivery_tag_assignments_allow ON public."DeviceTagAssignments" AS PERMISSIVE FOR SELECT TO :"delivery_definer_role"
    USING ("EnvironmentId"=nullif(current_setting('app.delivery_environment_id',true),'')::uuid);
CREATE POLICY enrollment_delivery_tag_assignments_limit ON public."DeviceTagAssignments" AS RESTRICTIVE FOR SELECT TO :"delivery_definer_role"
    USING ("EnvironmentId"=nullif(current_setting('app.delivery_environment_id',true),'')::uuid);

CREATE POLICY enrollment_delivery_results_allow ON enrollment_execution.issue_results AS PERMISSIVE FOR SELECT TO :"delivery_definer_role"
    USING (environment_id=nullif(current_setting('app.delivery_environment_id',true),'')::uuid
       AND operation_id=nullif(current_setting('app.delivery_operation_id',true),'')::uuid);
CREATE POLICY enrollment_delivery_results_limit ON enrollment_execution.issue_results AS RESTRICTIVE FOR SELECT TO :"delivery_definer_role"
    USING (environment_id=nullif(current_setting('app.delivery_environment_id',true),'')::uuid
       AND operation_id=nullif(current_setting('app.delivery_operation_id',true),'')::uuid);
CREATE POLICY enrollment_delivery_permits_allow ON enrollment_execution.mint_permits AS PERMISSIVE FOR SELECT TO :"delivery_definer_role"
    USING (operation_id=nullif(current_setting('app.delivery_operation_id',true),'')::uuid);
CREATE POLICY enrollment_delivery_permits_limit ON enrollment_execution.mint_permits AS RESTRICTIVE FOR SELECT TO :"delivery_definer_role"
    USING (operation_id=nullif(current_setting('app.delivery_operation_id',true),'')::uuid);
CREATE POLICY enrollment_delivery_envelopes_allow ON enrollment_execution.sealed_envelopes AS PERMISSIVE FOR ALL TO :"delivery_definer_role"
    USING (operation_id=nullif(current_setting('app.delivery_operation_id',true),'')::uuid);
CREATE POLICY enrollment_delivery_envelopes_limit ON enrollment_execution.sealed_envelopes AS RESTRICTIVE FOR ALL TO :"delivery_definer_role"
    USING (operation_id=nullif(current_setting('app.delivery_operation_id',true),'')::uuid);
CREATE POLICY enrollment_delivery_acks_allow ON enrollment_execution.delivery_acks AS PERMISSIVE FOR ALL TO :"delivery_definer_role"
    USING (operation_id=nullif(current_setting('app.delivery_operation_id',true),'')::uuid)
    WITH CHECK (operation_id=nullif(current_setting('app.delivery_operation_id',true),'')::uuid
       AND requester_id=nullif(current_setting('app.delivery_requester_id',true),'')::uuid);
CREATE POLICY enrollment_delivery_acks_limit ON enrollment_execution.delivery_acks AS RESTRICTIVE FOR ALL TO :"delivery_definer_role"
    USING (operation_id=nullif(current_setting('app.delivery_operation_id',true),'')::uuid)
    WITH CHECK (operation_id=nullif(current_setting('app.delivery_operation_id',true),'')::uuid
       AND requester_id=nullif(current_setting('app.delivery_requester_id',true),'')::uuid);
CREATE POLICY enrollment_delivery_status_allow ON enrollment_execution.status_observations AS PERMISSIVE FOR ALL TO :"delivery_definer_role"
    USING (environment_id=nullif(current_setting('app.delivery_environment_id',true),'')::uuid
       AND operation_id=nullif(current_setting('app.delivery_operation_id',true),'')::uuid)
    WITH CHECK (environment_id=nullif(current_setting('app.delivery_environment_id',true),'')::uuid
       AND operation_id=nullif(current_setting('app.delivery_operation_id',true),'')::uuid);
CREATE POLICY enrollment_delivery_status_limit ON enrollment_execution.status_observations AS RESTRICTIVE FOR ALL TO :"delivery_definer_role"
    USING (environment_id=nullif(current_setting('app.delivery_environment_id',true),'')::uuid
       AND operation_id=nullif(current_setting('app.delivery_operation_id',true),'')::uuid)
    WITH CHECK (environment_id=nullif(current_setting('app.delivery_environment_id',true),'')::uuid
       AND operation_id=nullif(current_setting('app.delivery_operation_id',true),'')::uuid);

CREATE FUNCTION enrollment_execution.audit_delivery_privileges(p_environment uuid)
RETURNS TABLE(is_valid boolean,diagnostic_code text,profile_version smallint)
LANGUAGE plpgsql STABLE PARALLEL UNSAFE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET row_security=on AS $function$
DECLARE base_rows integer; base_valid integer; slice_valid boolean;
BEGIN
    SELECT count(*),count(*) FILTER(WHERE audit.is_valid AND audit.diagnostic_code='None' AND audit.profile_version=4)
      INTO base_rows,base_valid FROM enrollment_execution.audit_execution_privileges(p_environment) audit;
    -- The complete delivery slice is catalog-pinned by audit_execution_privileges profile4.
    slice_valid:=base_rows=1 AND base_valid=1;
    -- Direct owner maintenance may inspect the profile. All runtime calls, including
    -- calls through delivery-definer wrappers, retain the bound LOGIN as SESSION_USER.
    IF slice_valid AND SESSION_USER<>CURRENT_USER THEN
        slice_valid:=enrollment_execution.delivery_worker_scope(p_environment,'EnrollmentGrantStatusRefresh') IS TRUE
            OR enrollment_execution.delivery_worker_scope(p_environment,'EnrollmentGrantDelivery') IS TRUE;
    END IF;
    RETURN QUERY SELECT COALESCE(slice_valid,false),
        CASE WHEN COALESCE(slice_valid,false) THEN 'None' ELSE 'ProfileDrift' END,4::smallint;
END
$function$;
REVOKE ALL ON FUNCTION enrollment_execution.audit_delivery_privileges(uuid) FROM PUBLIC;
ALTER FUNCTION enrollment_execution.audit_delivery_privileges(uuid) OWNER TO :"expected_table_owner_role";
