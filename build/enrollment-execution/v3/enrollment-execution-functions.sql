-- Install only inside the reviewed execution provisioning transaction.
-- The installer assigns restricted owners, exact policies/grants and creates the profile marker last.
-- These entrypoints require the complete audit; there is no permissive fallback.

CREATE OR REPLACE FUNCTION enrollment_execution.worker_scope(p_environment uuid)
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY INVOKER
    SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    RETURN p_environment IS NOT NULL AND p_environment<>'00000000-0000-0000-0000-000000000000'::uuid
        AND EXISTS(SELECT 1 FROM pg_catalog.pg_proc marker
            WHERE marker.oid=pg_catalog.to_regprocedure('enrollment_execution.execution_store_profile()')
            AND marker.proowner=(SELECT c.relowner FROM pg_catalog.pg_class c
                WHERE c.oid='enrollment_execution.role_reservations'::regclass))
        AND (SELECT count(*)=6 AND bool_and(p.proowner=CURRENT_USER::regrole::oid)
            FROM pg_catalog.pg_proc p WHERE p.oid IN(
              'enrollment_execution.worker_scope(uuid)'::regprocedure,
              'enrollment_execution.read_execution_record(uuid,uuid)'::regprocedure,
              'enrollment_execution.read_and_lock_plan_context(uuid,uuid)'::regprocedure,
              'enrollment_execution.authorize_and_store_candidate(uuid,uuid,text,bytea,bytea,bytea)'::regprocedure,
              'enrollment_execution.record_execution_result(uuid,uuid,bytea,text,text,uuid,uuid,uuid,uuid,timestamptz,timestamptz,timestamptz,smallint,timestamptz,bytea,bytea)'::regprocedure,
              'enrollment_execution.quarantine_execution(uuid,uuid,bytea,text)'::regprocedure))
        AND (SELECT count(*)=2 AND bool_and(NOT role.rolsuper AND NOT role.rolbypassrls
            AND NOT role.rolcreatedb AND NOT role.rolcreaterole AND NOT role.rolinherit AND NOT role.rolreplication
            AND role.rolcanlogin=(role.rolname=SESSION_USER)
            AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members membership
                WHERE membership.roleid=role.oid OR membership.member=role.oid))
            FROM pg_catalog.pg_roles role WHERE role.rolname IN (SESSION_USER,CURRENT_USER))
        AND EXISTS(SELECT 1 FROM public."DirectoryDatabaseBindings" binding
            WHERE binding."LoginRole"=SESSION_USER AND binding."Purpose"='EnrollmentGrantExecution'
            AND binding."ContractVersion"=2 AND binding."EnvironmentId"=p_environment AND binding."PrincipalId" IS NULL);
END
$function$;
REVOKE ALL ON FUNCTION enrollment_execution.worker_scope(uuid) FROM PUBLIC;

CREATE OR REPLACE FUNCTION enrollment_execution.read_execution_record(p_environment uuid,p_operation uuid)
RETURNS TABLE (
    contract_version smallint,
    outcome text,
    execution_state text,
    op_environment_id uuid,
    op_id uuid,
    op_plan_id uuid,
    op_request_id uuid,
    op_approval_id uuid,
    op_requester_id uuid,
    op_approver_id uuid,
    op_requester_operator_id uuid,
    op_approver_operator_id uuid,
    op_plan_hash text,
    op_directory_object_id uuid,
    op_server_device_id uuid,
    op_mapping_created_at timestamptz,
    op_directory_generation uuid,
    op_environment_version bigint,
    op_recipient_spki bytea,
    op_recipient_fingerprint bytea,
    op_queued_at timestamptz,
    op_authorization_not_after timestamptz,
    permit_version smallint,
    permit_issued_at timestamptz,
    permit_not_after timestamptz,
    permit_token_sha256 bytea,
    permit_recipient_fingerprint bytea,
    permit_ciphertext_sha256 bytea,
    permit_authorization_digest bytea,
    ciphertext bytea,
    result_outcome text,
    result_diagnostic text,
    result_recorded_at timestamptz,
    receipt_grant_id uuid,
    receipt_environment_id uuid,
    receipt_directory_object_id uuid,
    receipt_device_id uuid,
    receipt_mapping_created_at timestamptz,
    receipt_created_at timestamptz,
    receipt_expires_at timestamptz,
    receipt_contract_version smallint,
    receipt_permit_not_after timestamptz,
    receipt_token_sha256 bytea,
    receipt_authorization_digest bytea,
    ack_requester_id uuid,
    ack_token_sha256 bytea,
    ack_ciphertext_sha256 bytea,
    ack_at timestamptz,
    stop_reason text,
    stop_recorded_at timestamptz
)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
    SET search_path=pg_catalog,pg_temp SET row_security=on AS $function$
DECLARE audit_rows bigint; valid_rows bigint; operation public."EnrollmentGrantOperations"%ROWTYPE;
BEGIN
    PERFORM pg_catalog.pg_advisory_xact_lock_shared(1162235478,1);
    SELECT count(*),count(*) FILTER (WHERE audit.is_valid AND audit.profile_version=3)
        INTO audit_rows,valid_rows FROM enrollment_execution.audit_execution_privileges(p_environment) audit;
    IF audit_rows<>1 OR valid_rows<>1 OR enrollment_execution.worker_scope(p_environment) IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='Execution capability is unavailable.';
    END IF;
    PERFORM pg_catalog.set_config('app.execution_plan_id','',true);
    PERFORM pg_catalog.set_config('app.execution_directory_id','',true);
    PERFORM pg_catalog.set_config('app.execution_requester_id','',true);
    PERFORM pg_catalog.set_config('app.execution_approver_id','',true);
    PERFORM pg_catalog.set_config('app.execution_approval_id','',true);
    PERFORM pg_catalog.set_config('app.execution_environment_id',p_environment::text,true);
    PERFORM pg_catalog.set_config('app.execution_operation_id',p_operation::text,true);
    SELECT * INTO operation FROM public."EnrollmentGrantOperations"
        WHERE "EnvironmentId"=p_environment AND "Id"=p_operation;
    IF FOUND THEN
        PERFORM pg_catalog.set_config('app.execution_plan_id',operation."PlanId"::text,true);
        PERFORM pg_catalog.set_config('app.execution_directory_id',operation."DirectoryObjectId"::text,true);
        PERFORM pg_catalog.set_config('app.execution_requester_id',operation."RequesterId"::text,true);
        PERFORM pg_catalog.set_config('app.execution_approver_id',operation."ApproverId"::text,true);
        PERFORM pg_catalog.set_config('app.execution_approval_id',operation."ApprovalId"::text,true);
    END IF;
    RETURN QUERY SELECT * FROM enrollment_execution.read_record(p_environment,p_operation);
END
$function$;
REVOKE ALL ON FUNCTION enrollment_execution.read_execution_record(uuid,uuid) FROM PUBLIC;

CREATE OR REPLACE FUNCTION enrollment_execution.read_and_lock_plan_context(p_environment uuid,p_operation uuid)
RETURNS TABLE (
    contract_version smallint,
    outcome text,
    plan_environment_id uuid,
    plan_id uuid,
    plan_requester_id uuid,
    plan_action text,
    plan_immutable_json text,
    plan_hash text,
    plan_policy_version bigint,
    plan_expires_at timestamptz,
    plan_state integer,
    plan_reason text,
    item_environment_id uuid,
    item_plan_id uuid,
    item_id uuid,
    item_target_id text,
    item_expected_version bigint,
    approval_environment_id uuid,
    approval_id uuid,
    approval_plan_id uuid,
    approval_plan_hash text,
    approval_approver_id uuid,
    approval_approved_at timestamptz,
    approval_expires_at timestamptz,
    reservation_fingerprint bytea,
    reservation_environment_id uuid,
    reservation_plan_id uuid,
    reservation_requester_id uuid,
    reservation_request_id uuid,
    reservation_request_digest bytea,
    reservation_created_at timestamptz,
    database_checked_at timestamptz,
    operation_binding_sha256 bytea
)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
    SET search_path=pg_catalog,pg_temp SET row_security=on AS $function$
DECLARE audit_rows bigint; valid_rows bigint; operation public."EnrollmentGrantOperations"%ROWTYPE;
BEGIN
    PERFORM pg_catalog.pg_advisory_xact_lock_shared(1162235478,1);
    SELECT count(*),count(*) FILTER (WHERE audit.is_valid AND audit.profile_version=3)
        INTO audit_rows,valid_rows FROM enrollment_execution.audit_execution_privileges(p_environment) audit;
    IF audit_rows<>1 OR valid_rows<>1 OR enrollment_execution.worker_scope(p_environment) IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='Execution capability is unavailable.';
    END IF;
    PERFORM pg_catalog.set_config('app.execution_plan_id','',true);
    PERFORM pg_catalog.set_config('app.execution_directory_id','',true);
    PERFORM pg_catalog.set_config('app.execution_requester_id','',true);
    PERFORM pg_catalog.set_config('app.execution_approver_id','',true);
    PERFORM pg_catalog.set_config('app.execution_approval_id','',true);
    PERFORM pg_catalog.set_config('app.execution_environment_id',p_environment::text,true);
    PERFORM pg_catalog.set_config('app.execution_operation_id',p_operation::text,true);
    SELECT * INTO operation FROM public."EnrollmentGrantOperations"
        WHERE "EnvironmentId"=p_environment AND "Id"=p_operation;
    IF FOUND THEN
        PERFORM pg_catalog.set_config('app.execution_plan_id',operation."PlanId"::text,true);
        PERFORM pg_catalog.set_config('app.execution_directory_id',operation."DirectoryObjectId"::text,true);
        PERFORM pg_catalog.set_config('app.execution_requester_id',operation."RequesterId"::text,true);
        PERFORM pg_catalog.set_config('app.execution_approver_id',operation."ApproverId"::text,true);
        PERFORM pg_catalog.set_config('app.execution_approval_id',operation."ApprovalId"::text,true);
    END IF;
    RETURN QUERY SELECT * FROM enrollment_execution.lock_plan_context(p_environment,p_operation);
END
$function$;
REVOKE ALL ON FUNCTION enrollment_execution.read_and_lock_plan_context(uuid,uuid) FROM PUBLIC;

CREATE OR REPLACE FUNCTION enrollment_execution.authorize_and_store_candidate(
    p_environment uuid,p_operation uuid,p_verified_plan_hash text,p_token_sha256 bytea,
    p_fingerprint bytea,p_ciphertext bytea)
RETURNS TABLE(contract_version smallint,outcome text,stop_reason text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
    SET search_path=pg_catalog,pg_temp SET row_security=on AS $function$
DECLARE audit_rows bigint; valid_rows bigint; operation public."EnrollmentGrantOperations"%ROWTYPE;
BEGIN
    PERFORM pg_catalog.pg_advisory_xact_lock_shared(1162235478,1);
    SELECT count(*),count(*) FILTER (WHERE audit.is_valid AND audit.profile_version=3)
        INTO audit_rows,valid_rows FROM enrollment_execution.audit_execution_privileges(p_environment) audit;
    IF audit_rows<>1 OR valid_rows<>1 OR enrollment_execution.worker_scope(p_environment) IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='Execution capability is unavailable.';
    END IF;
    PERFORM pg_catalog.set_config('app.execution_plan_id','',true);
    PERFORM pg_catalog.set_config('app.execution_directory_id','',true);
    PERFORM pg_catalog.set_config('app.execution_requester_id','',true);
    PERFORM pg_catalog.set_config('app.execution_approver_id','',true);
    PERFORM pg_catalog.set_config('app.execution_approval_id','',true);
    PERFORM pg_catalog.set_config('app.execution_environment_id',p_environment::text,true);
    PERFORM pg_catalog.set_config('app.execution_operation_id',p_operation::text,true);
    SELECT * INTO operation FROM public."EnrollmentGrantOperations"
        WHERE "EnvironmentId"=p_environment AND "Id"=p_operation;
    IF FOUND THEN
        PERFORM pg_catalog.set_config('app.execution_plan_id',operation."PlanId"::text,true);
        PERFORM pg_catalog.set_config('app.execution_directory_id',operation."DirectoryObjectId"::text,true);
        PERFORM pg_catalog.set_config('app.execution_requester_id',operation."RequesterId"::text,true);
        PERFORM pg_catalog.set_config('app.execution_approver_id',operation."ApproverId"::text,true);
        PERFORM pg_catalog.set_config('app.execution_approval_id',operation."ApprovalId"::text,true);
    END IF;
    RETURN QUERY SELECT * FROM enrollment_execution.store_candidate(p_environment,p_operation,
        p_verified_plan_hash,p_token_sha256,p_fingerprint,p_ciphertext);
END
$function$;
REVOKE ALL ON FUNCTION enrollment_execution.authorize_and_store_candidate(uuid,uuid,text,bytea,bytea,bytea) FROM PUBLIC;

CREATE OR REPLACE FUNCTION enrollment_execution.record_execution_result(
    p_environment uuid,p_operation uuid,p_permit_digest bytea,p_outcome text,p_diagnostic text,
    p_grant uuid,p_receipt_environment uuid,p_directory uuid,p_device uuid,p_mapping_at timestamptz,
    p_created_at timestamptz,p_expires_at timestamptz,p_issue_version smallint,p_permit_not_after timestamptz,
    p_token_sha256 bytea,p_receipt_digest bytea)
RETURNS TABLE(contract_version smallint,outcome text,stop_reason text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
    SET search_path=pg_catalog,pg_temp SET row_security=on AS $function$
DECLARE audit_rows bigint; valid_rows bigint; operation public."EnrollmentGrantOperations"%ROWTYPE;
BEGIN
    PERFORM pg_catalog.pg_advisory_xact_lock_shared(1162235478,1);
    SELECT count(*),count(*) FILTER (WHERE audit.is_valid AND audit.profile_version=3)
        INTO audit_rows,valid_rows FROM enrollment_execution.audit_execution_privileges(p_environment) audit;
    IF audit_rows<>1 OR valid_rows<>1 OR enrollment_execution.worker_scope(p_environment) IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='Execution capability is unavailable.';
    END IF;
    PERFORM pg_catalog.set_config('app.execution_plan_id','',true);
    PERFORM pg_catalog.set_config('app.execution_directory_id','',true);
    PERFORM pg_catalog.set_config('app.execution_requester_id','',true);
    PERFORM pg_catalog.set_config('app.execution_approver_id','',true);
    PERFORM pg_catalog.set_config('app.execution_approval_id','',true);
    PERFORM pg_catalog.set_config('app.execution_environment_id',p_environment::text,true);
    PERFORM pg_catalog.set_config('app.execution_operation_id',p_operation::text,true);
    SELECT * INTO operation FROM public."EnrollmentGrantOperations"
        WHERE "EnvironmentId"=p_environment AND "Id"=p_operation;
    IF FOUND THEN
        PERFORM pg_catalog.set_config('app.execution_plan_id',operation."PlanId"::text,true);
        PERFORM pg_catalog.set_config('app.execution_directory_id',operation."DirectoryObjectId"::text,true);
        PERFORM pg_catalog.set_config('app.execution_requester_id',operation."RequesterId"::text,true);
        PERFORM pg_catalog.set_config('app.execution_approver_id',operation."ApproverId"::text,true);
        PERFORM pg_catalog.set_config('app.execution_approval_id',operation."ApprovalId"::text,true);
    END IF;
    RETURN QUERY SELECT * FROM enrollment_execution.store_result(p_environment,p_operation,p_permit_digest,
        p_outcome,p_diagnostic,p_grant,p_receipt_environment,p_directory,p_device,p_mapping_at,p_created_at,
        p_expires_at,p_issue_version,p_permit_not_after,p_token_sha256,p_receipt_digest);
END
$function$;
REVOKE ALL ON FUNCTION enrollment_execution.record_execution_result(uuid,uuid,bytea,text,text,uuid,uuid,uuid,uuid,timestamptz,timestamptz,timestamptz,smallint,timestamptz,bytea,bytea) FROM PUBLIC;

CREATE OR REPLACE FUNCTION enrollment_execution.quarantine_execution(
    p_environment uuid,p_operation uuid,p_permit_digest bytea,p_reason text)
RETURNS TABLE(contract_version smallint,outcome text,stop_reason text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
    SET search_path=pg_catalog,pg_temp SET row_security=on AS $function$
DECLARE audit_rows bigint; valid_rows bigint; operation public."EnrollmentGrantOperations"%ROWTYPE;
BEGIN
    PERFORM pg_catalog.pg_advisory_xact_lock_shared(1162235478,1);
    SELECT count(*),count(*) FILTER (WHERE audit.is_valid AND audit.profile_version=3)
        INTO audit_rows,valid_rows FROM enrollment_execution.audit_execution_privileges(p_environment) audit;
    IF audit_rows<>1 OR valid_rows<>1 OR enrollment_execution.worker_scope(p_environment) IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='Execution capability is unavailable.';
    END IF;
    PERFORM pg_catalog.set_config('app.execution_plan_id','',true);
    PERFORM pg_catalog.set_config('app.execution_directory_id','',true);
    PERFORM pg_catalog.set_config('app.execution_requester_id','',true);
    PERFORM pg_catalog.set_config('app.execution_approver_id','',true);
    PERFORM pg_catalog.set_config('app.execution_approval_id','',true);
    PERFORM pg_catalog.set_config('app.execution_environment_id',p_environment::text,true);
    PERFORM pg_catalog.set_config('app.execution_operation_id',p_operation::text,true);
    SELECT * INTO operation FROM public."EnrollmentGrantOperations"
        WHERE "EnvironmentId"=p_environment AND "Id"=p_operation;
    IF FOUND THEN
        PERFORM pg_catalog.set_config('app.execution_plan_id',operation."PlanId"::text,true);
        PERFORM pg_catalog.set_config('app.execution_directory_id',operation."DirectoryObjectId"::text,true);
        PERFORM pg_catalog.set_config('app.execution_requester_id',operation."RequesterId"::text,true);
        PERFORM pg_catalog.set_config('app.execution_approver_id',operation."ApproverId"::text,true);
        PERFORM pg_catalog.set_config('app.execution_approval_id',operation."ApprovalId"::text,true);
    END IF;
    RETURN QUERY SELECT * FROM enrollment_execution.store_quarantine(
        p_environment,p_operation,p_permit_digest,p_reason);
END
$function$;
REVOKE ALL ON FUNCTION enrollment_execution.quarantine_execution(uuid,uuid,bytea,text) FROM PUBLIC;
