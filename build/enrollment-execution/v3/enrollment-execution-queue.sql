CREATE OR REPLACE FUNCTION public.validate_enrollment_grant_queue_anchor() RETURNS trigger
    LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SET search_path=pg_catalog,pg_temp AS $function$
DECLARE
    environment_uuid uuid;
    plan_uuid uuid;
    operation_row public."EnrollmentGrantOperations"%ROWTYPE;
    plan_state integer;
    plan_action text;
    operation_count integer;
    outbox_count integer;
BEGIN
    IF TG_TABLE_NAME='Outbox' AND TG_OP='UPDATE' THEN
        IF (OLD."EnvironmentId",OLD."Id",OLD."EventType",OLD."Version",OLD."Payload",OLD."CreatedAt")
            IS NOT DISTINCT FROM
           (NEW."EnvironmentId",NEW."Id",NEW."EventType",NEW."Version",NEW."Payload",NEW."CreatedAt") THEN
            RETURN NULL;
        END IF;
    END IF;
    IF TG_TABLE_NAME='Plans' THEN
        environment_uuid:=coalesce(NEW."EnvironmentId",OLD."EnvironmentId");
        plan_uuid:=coalesce(NEW."Id",OLD."Id");
    ELSIF TG_TABLE_NAME='EnrollmentGrantOperations' THEN
        environment_uuid:=coalesce(NEW."EnvironmentId",OLD."EnvironmentId");
        plan_uuid:=coalesce(NEW."PlanId",OLD."PlanId");
    ELSE
        IF coalesce(NEW."EventType",OLD."EventType")<>'EnrollmentGrantExecutionRequested' THEN RETURN NULL; END IF;
        environment_uuid:=coalesce(NEW."EnvironmentId",OLD."EnvironmentId");
        SELECT * INTO operation_row FROM public."EnrollmentGrantOperations"
        WHERE "EnvironmentId"=environment_uuid AND "Id"=coalesce(NEW."Id",OLD."Id");
        IF NOT FOUND THEN
            RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='Enrollment grant outbox requires its operation.';
        END IF;
        plan_uuid:=operation_row."PlanId";
    END IF;

    SELECT "State","Action" INTO plan_state,plan_action FROM public."Plans"
    WHERE "EnvironmentId"=environment_uuid AND "Id"=plan_uuid;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='Enrollment grant anchor plan is unavailable.';
    END IF;
    SELECT count(*)::integer INTO operation_count FROM public."EnrollmentGrantOperations"
    WHERE "EnvironmentId"=environment_uuid AND "PlanId"=plan_uuid;
    IF plan_action='agent-enrollment.initial-grant.v1' AND plan_state=5 THEN
        IF operation_count<>1 THEN
            RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='Queued enrollment grant plan requires one operation.';
        END IF;
        SELECT * INTO STRICT operation_row FROM public."EnrollmentGrantOperations"
        WHERE "EnvironmentId"=environment_uuid AND "PlanId"=plan_uuid;
        SELECT count(*)::integer INTO outbox_count FROM public."Outbox"
        WHERE "EnvironmentId"=environment_uuid AND "Id"=operation_row."Id"
          AND "EventType"='EnrollmentGrantExecutionRequested' AND "Version"=1
          AND "CreatedAt"=operation_row."QueuedAt"
          AND "Payload"=jsonb_build_object('version',1,'environmentId',environment_uuid,'operationId',operation_row."Id");
        IF outbox_count<>1 THEN
            RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='Queued enrollment grant plan requires its exact outbox.';
        END IF;
    ELSIF operation_count<>0 THEN
        RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='Enrollment grant operation requires a queued plan.';
    END IF;
    RETURN NULL;
END
$function$;

-- Installed only by the reviewed v2-to-v3 execution profile upgrade.

CREATE FUNCTION enrollment_execution.queue_worker_scope(p_environment uuid)
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    RETURN p_environment IS NOT NULL
       AND p_environment<>'00000000-0000-0000-0000-000000000000'::uuid
       AND (SELECT count(*)=4 AND bool_and(p.proowner=CURRENT_USER::regrole::oid)
            FROM pg_catalog.pg_proc AS p
            WHERE p.oid IN (
                'enrollment_execution.queue_worker_scope(uuid)'::regprocedure,
                'enrollment_execution.claim_next(uuid,uuid)'::regprocedure,
                'enrollment_execution.defer_claim(uuid,uuid,uuid,text)'::regprocedure,
                'enrollment_execution.complete_claim(uuid,uuid,uuid)'::regprocedure))
       AND (SELECT count(*)=2 AND bool_and(NOT role.rolsuper AND NOT role.rolbypassrls
            AND NOT role.rolcreatedb AND NOT role.rolcreaterole AND NOT role.rolinherit
            AND NOT role.rolreplication AND role.rolcanlogin=(role.rolname=SESSION_USER)
            AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members AS membership
                WHERE membership.roleid=role.oid OR membership.member=role.oid))
            FROM pg_catalog.pg_roles AS role WHERE role.rolname IN (SESSION_USER,CURRENT_USER))
       AND EXISTS (SELECT 1 FROM public."DirectoryDatabaseBindings" AS binding
            WHERE binding."LoginRole"=SESSION_USER
              AND binding."Purpose"='EnrollmentGrantExecution'
              AND binding."ContractVersion"=2
              AND binding."EnvironmentId"=p_environment
              AND binding."PrincipalId" IS NULL);
END
$function$;
REVOKE ALL ON FUNCTION enrollment_execution.queue_worker_scope(uuid) FROM PUBLIC;

CREATE FUNCTION enrollment_execution.claim_next(p_environment uuid,p_token uuid)
RETURNS TABLE(contract_version smallint,outcome text,queried_at timestamptz,environment_id uuid,
    operation_id uuid,claim_token uuid,attempt integer,claimed_at timestamptz,lease_until timestamptz)
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET row_security=on AS $function$
DECLARE audit_rows bigint; valid_rows bigint;
BEGIN
    PERFORM pg_catalog.pg_advisory_xact_lock_shared(1162235478,1);
    SELECT count(*),count(*) FILTER (WHERE audit.is_valid AND audit.diagnostic_code='None' AND audit.profile_version=3)
      INTO audit_rows,valid_rows FROM enrollment_execution.audit_execution_privileges(p_environment) AS audit;
    IF audit_rows<>1 OR valid_rows<>1 OR enrollment_execution.queue_worker_scope(p_environment) IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='Execution queue capability is unavailable.';
    END IF;
    PERFORM pg_catalog.set_config('app.execution_environment_id',p_environment::text,true);
    PERFORM pg_catalog.set_config('app.execution_operation_id','',true);
    PERFORM pg_catalog.set_config('app.execution_claim_token',p_token::text,true);
    RETURN QUERY SELECT * FROM enrollment_execution.claim_next_work(p_environment,p_token);
END
$function$;
REVOKE ALL ON FUNCTION enrollment_execution.claim_next(uuid,uuid) FROM PUBLIC;

CREATE FUNCTION enrollment_execution.defer_claim(p_environment uuid,p_operation uuid,p_token uuid,p_reason text)
RETURNS TABLE(contract_version smallint,outcome text,queried_at timestamptz,next_attempt_at timestamptz)
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET row_security=on AS $function$
DECLARE audit_rows bigint; valid_rows bigint;
BEGIN
    PERFORM pg_catalog.pg_advisory_xact_lock_shared(1162235478,1);
    SELECT count(*),count(*) FILTER (WHERE audit.is_valid AND audit.diagnostic_code='None' AND audit.profile_version=3)
      INTO audit_rows,valid_rows FROM enrollment_execution.audit_execution_privileges(p_environment) AS audit;
    IF audit_rows<>1 OR valid_rows<>1 OR enrollment_execution.queue_worker_scope(p_environment) IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='Execution queue capability is unavailable.';
    END IF;
    PERFORM pg_catalog.set_config('app.execution_environment_id',p_environment::text,true);
    PERFORM pg_catalog.set_config('app.execution_operation_id',p_operation::text,true);
    PERFORM pg_catalog.set_config('app.execution_claim_token',p_token::text,true);
    RETURN QUERY SELECT * FROM enrollment_execution.defer_work_claim(p_environment,p_operation,p_token,p_reason);
END
$function$;
REVOKE ALL ON FUNCTION enrollment_execution.defer_claim(uuid,uuid,uuid,text) FROM PUBLIC;

CREATE FUNCTION enrollment_execution.complete_claim(p_environment uuid,p_operation uuid,p_token uuid)
RETURNS TABLE(contract_version smallint,outcome text,queried_at timestamptz,next_attempt_at timestamptz)
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET row_security=on AS $function$
DECLARE audit_rows bigint; valid_rows bigint;
BEGIN
    PERFORM pg_catalog.pg_advisory_xact_lock_shared(1162235478,1);
    SELECT count(*),count(*) FILTER (WHERE audit.is_valid AND audit.diagnostic_code='None' AND audit.profile_version=3)
      INTO audit_rows,valid_rows FROM enrollment_execution.audit_execution_privileges(p_environment) AS audit;
    IF audit_rows<>1 OR valid_rows<>1 OR enrollment_execution.queue_worker_scope(p_environment) IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='Execution queue capability is unavailable.';
    END IF;
    PERFORM pg_catalog.set_config('app.execution_environment_id',p_environment::text,true);
    PERFORM pg_catalog.set_config('app.execution_operation_id',p_operation::text,true);
    PERFORM pg_catalog.set_config('app.execution_claim_token',p_token::text,true);
    RETURN QUERY SELECT * FROM enrollment_execution.complete_work_claim(p_environment,p_operation,p_token);
END
$function$;
REVOKE ALL ON FUNCTION enrollment_execution.complete_claim(uuid,uuid,uuid) FROM PUBLIC;
