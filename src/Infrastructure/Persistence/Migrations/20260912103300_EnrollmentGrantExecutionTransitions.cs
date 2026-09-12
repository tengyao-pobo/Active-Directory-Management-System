using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace ItManagement.Persistence.Migrations;

/// <summary>Owner-only atomic journal transitions. Public worker entrypoints require separate reviewed provisioning.</summary>
[DbContext(typeof(ConsoleDbContext))]
[Migration("20260912103300_EnrollmentGrantExecutionTransitions")]
public sealed class EnrollmentGrantExecutionTransitions : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder) => migrationBuilder.Sql("""
        CREATE FUNCTION enrollment_execution.store_candidate(
            p_environment uuid,p_operation uuid,p_verified_plan_hash text,
            p_token_sha256 bytea,p_fingerprint bytea,p_ciphertext bytea)
        RETURNS TABLE(contract_version smallint,outcome text,stop_reason text)
        LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $function$
        DECLARE
            operation public."EnrollmentGrantOperations"%ROWTYPE;
            context record;
            checked_at timestamptz;
            permit_deadline timestamptz;
            cipher_hash bytea;
            digest bytea;
            reason text;
        BEGIN
            IF current_setting('transaction_isolation')<>'serializable' THEN
                RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='Execution requires a serializable transaction.';
            END IF;
            -- Read one context for anchor comparisons; the explicit child counts below
            -- reject ambiguity durably instead of throwing before a stop can be saved.
            SELECT * INTO context FROM enrollment_execution.lock_plan_context(p_environment,p_operation);
            SELECT * INTO operation FROM public."EnrollmentGrantOperations"
                WHERE "EnvironmentId"=p_environment AND "Id"=p_operation;
            IF NOT FOUND THEN RETURN QUERY SELECT 1::smallint,'NotFound'::text,NULL::text; RETURN; END IF;
            -- A committed disposition is never replaced by a newly generated candidate.
            SELECT reason_stop.reason INTO reason FROM enrollment_execution.execution_stops reason_stop
                WHERE reason_stop.operation_id=p_operation;
            IF FOUND THEN
                RETURN QUERY SELECT 1::smallint,
                    CASE WHEN reason IN ('AuthorizationChanged','AuthorizationExpired') THEN 'AuthorizationRejected' ELSE 'Conflict' END,reason;
                RETURN;
            END IF;
            IF EXISTS(SELECT 1 FROM enrollment_execution.mint_permits WHERE operation_id=p_operation) THEN
                RETURN QUERY SELECT 1::smallint,'Existing'::text,NULL::text; RETURN;
            END IF;
            IF (p_verified_plan_hash=operation."PlanHash"
                AND octet_length(p_token_sha256)=32 AND p_fingerprint=operation."RecipientKeyFingerprint"
                AND octet_length(p_ciphertext)=384) IS DISTINCT FROM TRUE THEN
                RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='Invalid execution candidate.';
            END IF;

            -- The C# caller has independently reconstructed the canonical plan hash.
            -- SQL rechecks every immutable relational anchor; a supplied digest is not authority.
            IF context.outcome IS DISTINCT FROM 'Found'
                OR (context.plan_environment_id=operation."EnvironmentId" AND context.plan_id=operation."PlanId"
                    AND context.plan_requester_id=operation."RequesterId" AND context.plan_hash=operation."PlanHash"
                    AND context.plan_action='agent-enrollment.initial-grant.v1' AND context.plan_state=5
                    AND context.plan_policy_version=operation."EnvironmentVersion"
                    AND context.plan_expires_at>=operation."AuthorizationNotAfter"
                    AND context.item_environment_id=operation."EnvironmentId" AND context.item_plan_id=operation."PlanId"
                    AND context.item_target_id=operation."EnvironmentId"::text AND context.item_expected_version=operation."EnvironmentVersion"
                    AND context.approval_environment_id=operation."EnvironmentId" AND context.approval_plan_id=operation."PlanId"
                    AND context.approval_id=operation."ApprovalId" AND context.approval_plan_hash=operation."PlanHash"
                    AND context.approval_approver_id=operation."ApproverId" AND context.approval_approved_at<=operation."QueuedAt"
                    AND context.approval_expires_at>=operation."AuthorizationNotAfter"
                    AND context.reservation_environment_id=operation."EnvironmentId" AND context.reservation_plan_id=operation."PlanId"
                    AND context.reservation_requester_id=operation."RequesterId" AND context.reservation_request_id=operation."RequestId"
                    AND context.reservation_fingerprint=operation."RecipientKeyFingerprint"
                    AND context.reservation_created_at<=context.approval_approved_at
                    AND context.plan_expires_at=context.reservation_created_at+interval '600 seconds') IS DISTINCT FROM TRUE
                OR (SELECT count(*) FROM public."PlanItems" WHERE "EnvironmentId"=p_environment AND "PlanId"=operation."PlanId")<>1
                OR (SELECT count(*) FROM public."Approvals" WHERE "EnvironmentId"=p_environment AND "PlanId"=operation."PlanId")<>1
                OR NOT EXISTS(SELECT 1 FROM public."Outbox" WHERE "EnvironmentId"=p_environment AND "Id"=p_operation
                    AND "EventType"='EnrollmentGrantExecutionRequested' AND "Version"=1 AND "CreatedAt"=operation."QueuedAt"
                    AND "Payload"=jsonb_build_object('version',1,'environmentId',p_environment,'operationId',p_operation)) THEN
                reason:='StoredDataInvalid';
            END IF;
            -- Last clock after all row-lock waits. Environment/person locks stabilize the authority query.
            checked_at:=clock_timestamp();
            IF checked_at<operation."QueuedAt" THEN
                RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='Invalid execution time.';
            END IF;
            IF reason IS NULL THEN
                IF checked_at>=operation."AuthorizationNotAfter" THEN reason:='AuthorizationExpired';
                ELSIF enrollment_execution.current_authority_matches(operation,checked_at) IS DISTINCT FROM TRUE THEN
                    reason:='AuthorizationChanged';
                END IF;
            END IF;
            IF reason IS NOT NULL THEN
                INSERT INTO enrollment_execution.execution_stops(operation_id,reason,recorded_at)
                    VALUES(p_operation,reason,checked_at);
                RETURN QUERY SELECT 1::smallint,
                    CASE WHEN reason='StoredDataInvalid' THEN 'Conflict' ELSE 'AuthorizationRejected' END,reason;
                RETURN;
            END IF;
            permit_deadline:=least(operation."AuthorizationNotAfter",checked_at+interval '60 seconds');
            cipher_hash:=sha256(p_ciphertext);
            digest:=enrollment_execution.authorization_digest(operation,1::smallint,checked_at,permit_deadline,
                p_token_sha256,p_fingerprint,cipher_hash);
            INSERT INTO enrollment_execution.mint_permits
                (operation_id,format_version,issued_at,not_after,token_sha256,recipient_fingerprint,ciphertext_sha256,authorization_digest)
                VALUES(p_operation,1,checked_at,permit_deadline,p_token_sha256,p_fingerprint,cipher_hash,digest);
            INSERT INTO enrollment_execution.sealed_envelopes(operation_id,ciphertext) VALUES(p_operation,p_ciphertext);
            RETURN QUERY SELECT 1::smallint,'Stored'::text,NULL::text;
        END
        $function$;
        REVOKE ALL ON FUNCTION enrollment_execution.store_candidate(uuid,uuid,text,bytea,bytea,bytea) FROM PUBLIC;

        CREATE FUNCTION enrollment_execution.store_result(
            p_environment uuid,p_operation uuid,p_permit_digest bytea,p_outcome text,p_diagnostic text,
            p_grant uuid,p_receipt_environment uuid,p_directory uuid,p_device uuid,
            p_mapping_at timestamptz,p_created_at timestamptz,p_expires_at timestamptz,
            p_issue_version smallint,p_permit_not_after timestamptz,p_token_sha256 bytea,p_receipt_digest bytea)
        RETURNS TABLE(contract_version smallint,outcome text,stop_reason text)
        LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $function$
        DECLARE
            operation public."EnrollmentGrantOperations"%ROWTYPE;
            permit enrollment_execution.mint_permits%ROWTYPE;
            existing enrollment_execution.issue_results%ROWTYPE;
            checked_at timestamptz;
        BEGIN
            IF current_setting('transaction_isolation')<>'serializable' THEN
                RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='Execution requires a serializable transaction.';
            END IF;
            PERFORM pg_advisory_xact_lock_shared(1162235478,1);
            SELECT * INTO operation FROM public."EnrollmentGrantOperations"
                WHERE "EnvironmentId"=p_environment AND "Id"=p_operation FOR NO KEY UPDATE;
            IF NOT FOUND THEN RETURN QUERY SELECT 1::smallint,'NotFound'::text,NULL::text; RETURN; END IF;
            SELECT * INTO permit FROM enrollment_execution.mint_permits WHERE operation_id=p_operation;
            IF NOT FOUND OR p_permit_digest IS DISTINCT FROM permit.authorization_digest
                OR EXISTS(SELECT 1 FROM enrollment_execution.execution_stops WHERE operation_id=p_operation) THEN
                RETURN QUERY SELECT 1::smallint,'Conflict'::text,NULL::text; RETURN;
            END IF;
            SELECT * INTO existing FROM enrollment_execution.issue_results WHERE operation_id=p_operation;
            IF FOUND THEN
                IF ROW(existing.outcome,existing.diagnostic,existing.grant_id,existing.environment_id,existing.directory_object_id,
                    existing.device_id,existing.mapping_created_at,existing.grant_created_at,existing.grant_expires_at,
                    existing.issue_contract_version,existing.mint_permit_not_after,existing.token_sha256,existing.authorization_digest)
                    IS NOT DISTINCT FROM ROW(p_outcome,p_diagnostic,p_grant,p_receipt_environment,p_directory,p_device,
                        p_mapping_at,p_created_at,p_expires_at,p_issue_version,p_permit_not_after,p_token_sha256,p_receipt_digest) THEN
                    RETURN QUERY SELECT 1::smallint,'AlreadyRecorded'::text,NULL::text;
                ELSE RETURN QUERY SELECT 1::smallint,'Conflict'::text,NULL::text;
                END IF;
                RETURN;
            END IF;
            checked_at:=clock_timestamp();
            -- Journal constraints validate the complete receipt and fixed rejection vocabulary.
            -- The stored permit is selected by trusted environment/operation, never by receipt IDs.
            IF checked_at<permit.issued_at THEN
                RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='Invalid execution time.';
            END IF;
            INSERT INTO enrollment_execution.issue_results
                (operation_id,outcome,diagnostic,recorded_at,grant_id,environment_id,directory_object_id,device_id,
                    mapping_created_at,grant_created_at,grant_expires_at,issue_contract_version,mint_permit_not_after,token_sha256,authorization_digest)
                VALUES(p_operation,p_outcome,p_diagnostic,checked_at,p_grant,p_receipt_environment,p_directory,p_device,
                    p_mapping_at,p_created_at,p_expires_at,p_issue_version,p_permit_not_after,p_token_sha256,p_receipt_digest);
            IF p_outcome='Rejected' THEN DELETE FROM enrollment_execution.sealed_envelopes WHERE operation_id=p_operation; END IF;
            RETURN QUERY SELECT 1::smallint,'Recorded'::text,NULL::text;
        END
        $function$;
        REVOKE ALL ON FUNCTION enrollment_execution.store_result(
            uuid,uuid,bytea,text,text,uuid,uuid,uuid,uuid,timestamptz,timestamptz,timestamptz,smallint,timestamptz,bytea,bytea) FROM PUBLIC;

        CREATE FUNCTION enrollment_execution.store_quarantine(
            p_environment uuid,p_operation uuid,p_permit_digest bytea,p_reason text)
        RETURNS TABLE(contract_version smallint,outcome text,stop_reason text)
        LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $function$
        DECLARE
            operation public."EnrollmentGrantOperations"%ROWTYPE;
            permit enrollment_execution.mint_permits%ROWTYPE;
            existing enrollment_execution.execution_stops%ROWTYPE;
            checked_at timestamptz;
        BEGIN
            IF current_setting('transaction_isolation')<>'serializable' THEN
                RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='Execution requires a serializable transaction.';
            END IF;
            PERFORM pg_advisory_xact_lock_shared(1162235478,1);
            IF p_reason IS NULL OR p_reason NOT IN ('StoredDataInvalid','OperationConflict','ReceiptMismatch') THEN
                RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='Invalid execution disposition.';
            END IF;
            SELECT * INTO operation FROM public."EnrollmentGrantOperations"
                WHERE "EnvironmentId"=p_environment AND "Id"=p_operation FOR NO KEY UPDATE;
            IF NOT FOUND THEN RETURN QUERY SELECT 1::smallint,'NotFound'::text,NULL::text; RETURN; END IF;
            SELECT * INTO existing FROM enrollment_execution.execution_stops WHERE operation_id=p_operation;
            IF FOUND THEN
                RETURN QUERY SELECT 1::smallint,CASE WHEN existing.reason=p_reason THEN 'AlreadyRecorded' ELSE 'Conflict' END,existing.reason;
                RETURN;
            END IF;
            IF EXISTS(SELECT 1 FROM enrollment_execution.issue_results WHERE operation_id=p_operation)
                OR EXISTS(SELECT 1 FROM enrollment_execution.delivery_acks WHERE operation_id=p_operation) THEN
                RETURN QUERY SELECT 1::smallint,'Conflict'::text,NULL::text; RETURN;
            END IF;
            SELECT * INTO permit FROM enrollment_execution.mint_permits WHERE operation_id=p_operation;
            IF p_reason<>'StoredDataInvalid' AND
                (permit.operation_id IS NULL OR p_permit_digest IS DISTINCT FROM permit.authorization_digest) THEN
                RETURN QUERY SELECT 1::smallint,'Conflict'::text,NULL::text; RETURN;
            END IF;
            checked_at:=clock_timestamp();
            IF checked_at<operation."QueuedAt" OR (permit.operation_id IS NOT NULL AND checked_at<permit.issued_at) THEN
                RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='Invalid execution time.';
            END IF;
            INSERT INTO enrollment_execution.execution_stops(operation_id,reason,recorded_at) VALUES(p_operation,p_reason,checked_at);
            RETURN QUERY SELECT 1::smallint,'Recorded'::text,p_reason;
        END
        $function$;
        REVOKE ALL ON FUNCTION enrollment_execution.store_quarantine(uuid,uuid,bytea,text) FROM PUBLIC;
        """);

    protected override void Down(MigrationBuilder migrationBuilder) =>
        throw new NotSupportedException("Execution transitions require a reviewed forward migration.");
}
