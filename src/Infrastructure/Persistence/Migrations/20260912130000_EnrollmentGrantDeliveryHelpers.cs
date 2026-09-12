using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace ItManagement.Persistence.Migrations;

/// <summary>Purpose-specific delivery operations; runtime grants are installed by the audited profile.</summary>
[DbContext(typeof(ConsoleDbContext))]
[Migration("20260912130000_EnrollmentGrantDeliveryHelpers")]
public sealed class EnrollmentGrantDeliveryHelpers : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder) => migrationBuilder.Sql("""
        CREATE FUNCTION enrollment_execution.read_status_refresh_receipt(p_environment uuid,p_operation uuid)
        RETURNS TABLE(contract_version smallint,outcome text,environment_id uuid,operation_id uuid,
            grant_id uuid,directory_object_id uuid,device_id uuid,mapping_created_at timestamptz,
            grant_created_at timestamptz,grant_expires_at timestamptz,issue_contract_version smallint,
            mint_permit_not_after timestamptz,token_sha256 bytea,authorization_digest bytea)
        LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $function$
        DECLARE issued enrollment_execution.issue_results%ROWTYPE;
        BEGIN
            IF current_setting('transaction_isolation')<>'serializable' THEN
                RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='Grant status reads require a serializable transaction.';
            END IF;
            IF p_environment IS NULL OR p_environment='00000000-0000-0000-0000-000000000000'::uuid
                OR p_operation IS NULL OR p_operation='00000000-0000-0000-0000-000000000000'::uuid THEN
                RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='Invalid grant status receipt request.';
            END IF;
            PERFORM 1 FROM public."EnrollmentGrantOperations" AS operation
                WHERE operation."Id"=p_operation AND operation."EnvironmentId"=p_environment;
            IF FOUND THEN
                SELECT result.* INTO issued FROM enrollment_execution.issue_results AS result
                    WHERE result.operation_id=p_operation AND result.environment_id=p_environment AND result.outcome='Issued';
            END IF;
            IF issued.operation_id IS NULL THEN
                RETURN QUERY SELECT 1::smallint,'NotFound'::text,NULL::uuid,NULL::uuid,NULL::uuid,NULL::uuid,NULL::uuid,
                    NULL::timestamptz,NULL::timestamptz,NULL::timestamptz,NULL::smallint,NULL::timestamptz,NULL::bytea,NULL::bytea;
                RETURN;
            END IF;
            RETURN QUERY SELECT 1::smallint,'Found'::text,issued.environment_id,issued.operation_id,issued.grant_id,
                issued.directory_object_id,issued.device_id,issued.mapping_created_at,issued.grant_created_at,
                issued.grant_expires_at,issued.issue_contract_version,issued.mint_permit_not_after,
                issued.token_sha256,issued.authorization_digest;
        END
        $function$;
        REVOKE ALL ON FUNCTION enrollment_execution.read_status_refresh_receipt(uuid,uuid) FROM PUBLIC;

        CREATE FUNCTION enrollment_execution.lock_delivery_context(
            p_environment uuid,p_operation uuid,p_requester uuid,p_session_hash text)
        RETURNS TABLE(authorized boolean,checked_at timestamptz)
        LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $function$
        DECLARE
            initial_operation public."EnrollmentGrantOperations"%ROWTYPE;
            locked_operation public."EnrollmentGrantOperations"%ROWTYPE;
            current_generation uuid;
            sync_status text;
            sync_completed timestamptz;
            target_exists boolean;
            environment_exists boolean;
            principal_enabled boolean;
            membership_active boolean;
            session_principal uuid;
            session_created timestamptz;
            session_seen timestamptz;
            session_expires timestamptz;
            session_step_up timestamptz;
            session_revoked timestamptz;
            now_at timestamptz;
            allowed boolean;
        BEGIN
            IF current_setting('transaction_isolation')<>'serializable' THEN
                RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='Grant delivery requires a serializable transaction.';
            END IF;
            IF (p_environment IS NOT NULL AND p_environment<>'00000000-0000-0000-0000-000000000000'::uuid
                AND p_operation IS NOT NULL AND p_operation<>'00000000-0000-0000-0000-000000000000'::uuid
                AND p_requester IS NOT NULL AND p_requester<>'00000000-0000-0000-0000-000000000000'::uuid
                AND p_session_hash ~ '^[0-9A-F]{64}$'
                AND current_setting('app.delivery_environment_id',true)=p_environment::text
                AND current_setting('app.delivery_operation_id',true)=p_operation::text
                AND current_setting('app.delivery_requester_id',true)=p_requester::text) IS NOT TRUE THEN
                RETURN QUERY SELECT false,NULL::timestamptz; RETURN;
            END IF;
            SELECT operation.* INTO initial_operation FROM public."EnrollmentGrantOperations" AS operation
                WHERE operation."EnvironmentId"=p_environment AND operation."Id"=p_operation
                    AND operation."RequesterId"=p_requester;
            IF initial_operation."Id" IS NULL THEN
                RETURN QUERY SELECT false,NULL::timestamptz; RETURN;
            END IF;
            -- Match the public authority lock order. The initial read supplies only the immutable target.
            SELECT true INTO environment_exists FROM public."Environments" WHERE "Id"=p_environment FOR SHARE;
            SELECT "Generation","Status","CompletedAt" INTO current_generation,sync_status,sync_completed
                FROM public."DirectorySync" WHERE "EnvironmentId"=p_environment FOR SHARE;
            SELECT true INTO target_exists FROM public."DirectoryObjects"
                WHERE "EnvironmentId"=p_environment AND "Id"=initial_operation."DirectoryObjectId"
                    AND "Generation"=current_generation AND "Kind"='Computer' FOR SHARE;
            SELECT "Enabled" INTO principal_enabled FROM public."Principals" WHERE "Id"=p_requester FOR SHARE;
            SELECT "Active" INTO membership_active FROM public."Memberships"
                WHERE "EnvironmentId"=p_environment AND "PrincipalId"=p_requester FOR SHARE;
            SELECT "PrincipalId","CreatedAt","LastSeenAt","ExpiresAt","StepUpAt","RevokedAt"
                INTO session_principal,session_created,session_seen,session_expires,session_step_up,session_revoked
                FROM public."Sessions" WHERE "IdHash"=p_session_hash AND "PrincipalId"=p_requester FOR SHARE;
            SELECT operation.* INTO locked_operation FROM public."EnrollmentGrantOperations" AS operation
                WHERE operation."EnvironmentId"=p_environment AND operation."Id"=p_operation FOR NO KEY UPDATE;
            now_at:=clock_timestamp();
            allowed:=(locked_operation."Id" IS NOT NULL
                AND (locked_operation."EnvironmentId",locked_operation."Id",locked_operation."RequesterId",locked_operation."DirectoryObjectId")
                    IS NOT DISTINCT FROM (p_environment,p_operation,p_requester,initial_operation."DirectoryObjectId")
                AND environment_exists AND target_exists AND principal_enabled AND membership_active
                AND sync_status='Ready' AND isfinite(sync_completed)
                AND sync_completed BETWEEN now_at-interval '15 minutes' AND now_at
                AND session_principal=p_requester AND session_revoked IS NULL
                AND isfinite(session_created) AND isfinite(session_seen) AND isfinite(session_expires) AND isfinite(session_step_up)
                AND session_expires>now_at AND session_created<=session_step_up AND session_step_up<=now_at
                AND session_step_up>now_at-interval '1 minute'
                AND session_created<=session_seen AND session_seen<=now_at AND session_seen>now_at-interval '1 minute'
                AND enrollment_execution.has_computer_permission(p_environment,p_requester,
                    locked_operation."DirectoryObjectId",current_generation,'Computer.View')
                AND enrollment_execution.has_computer_permission(p_environment,p_requester,
                    locked_operation."DirectoryObjectId",current_generation,'AgentEnrollmentGrant.Manage')) IS TRUE;
            RETURN QUERY SELECT allowed,CASE WHEN allowed THEN now_at ELSE NULL::timestamptz END;
        END
        $function$;
        REVOKE ALL ON FUNCTION enrollment_execution.lock_delivery_context(uuid,uuid,uuid,text) FROM PUBLIC;

        CREATE FUNCTION enrollment_execution.get_sealed_delivery(
            p_environment uuid,p_operation uuid,p_requester uuid,p_session_hash text)
        RETURNS TABLE(contract_version smallint,outcome text,environment_id uuid,operation_id uuid,
            format_version smallint,recipient_fingerprint bytea,ciphertext bytea,ciphertext_sha256 bytea,
            delivery_not_after timestamptz,queried_at timestamptz)
        LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $function$
        DECLARE
            context record;
            issued enrollment_execution.issue_results%ROWTYPE;
            permit enrollment_execution.mint_permits%ROWTYPE;
            latest enrollment_execution.status_observations%ROWTYPE;
            sealed bytea;
            result_outcome text;
        BEGIN
            SELECT * INTO context FROM enrollment_execution.lock_delivery_context(p_environment,p_operation,p_requester,p_session_hash);
            IF context.authorized IS NOT TRUE THEN result_outcome:='NotFound';
            ELSE
                SELECT result.* INTO issued FROM enrollment_execution.issue_results AS result WHERE result.operation_id=p_operation;
                IF issued.operation_id IS NULL THEN result_outcome:='Pending';
                ELSIF issued.outcome<>'Issued' OR issued.environment_id<>p_environment THEN result_outcome:='Unavailable';
                ELSIF EXISTS(SELECT 1 FROM enrollment_execution.delivery_acks AS ack WHERE ack.operation_id=p_operation) THEN
                    result_outcome:='Acknowledged';
                ELSE
                    SELECT observation.* INTO latest FROM enrollment_execution.status_observations AS observation
                        WHERE observation.operation_id=p_operation ORDER BY observation.sequence DESC LIMIT 1;
                    IF latest.observation_id IS NULL THEN result_outcome:='Pending';
                    ELSIF latest.state='Unknown' THEN result_outcome:='OutcomeUnknown';
                    ELSIF (latest.state='Available' AND latest.environment_id=p_environment
                        AND latest.recorded_at<=context.checked_at AND latest.private_observed_at<=context.checked_at
                        AND latest.available_until>context.checked_at AND issued.grant_created_at<=context.checked_at
                        AND issued.grant_expires_at>context.checked_at) IS NOT TRUE THEN result_outcome:='Unavailable';
                    ELSE
                        SELECT value.* INTO permit FROM enrollment_execution.mint_permits AS value WHERE value.operation_id=p_operation;
                        SELECT envelope.ciphertext INTO sealed FROM enrollment_execution.sealed_envelopes AS envelope WHERE envelope.operation_id=p_operation;
                        IF (permit.format_version=1 AND octet_length(permit.recipient_fingerprint)=32
                            AND octet_length(sealed)=384 AND octet_length(permit.ciphertext_sha256)=32
                            AND sha256(sealed)=permit.ciphertext_sha256 AND permit.token_sha256=issued.token_sha256
                            AND permit.authorization_digest=issued.authorization_digest) IS NOT TRUE THEN result_outcome:='OutcomeUnknown';
                        ELSE
                            RETURN QUERY SELECT 1::smallint,'Available'::text,p_environment,p_operation,
                                permit.format_version,permit.recipient_fingerprint,sealed,permit.ciphertext_sha256,
                                least(latest.available_until,issued.grant_expires_at,context.checked_at+interval '15 seconds'),context.checked_at;
                            RETURN;
                        END IF;
                    END IF;
                END IF;
            END IF;
            RETURN QUERY SELECT 1::smallint,result_outcome,NULL::uuid,NULL::uuid,NULL::smallint,
                NULL::bytea,NULL::bytea,NULL::bytea,NULL::timestamptz,NULL::timestamptz;
        END
        $function$;
        REVOKE ALL ON FUNCTION enrollment_execution.get_sealed_delivery(uuid,uuid,uuid,text) FROM PUBLIC;

        CREATE FUNCTION enrollment_execution.ack_sealed_delivery(
            p_environment uuid,p_operation uuid,p_requester uuid,p_session_hash text,
            p_recipient_fingerprint bytea,p_ciphertext_sha256 bytea)
        RETURNS TABLE(contract_version smallint,outcome text)
        LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $function$
        DECLARE
            context record;
            issued enrollment_execution.issue_results%ROWTYPE;
            permit enrollment_execution.mint_permits%ROWTYPE;
            prior enrollment_execution.delivery_acks%ROWTYPE;
            sealed bytea;
        BEGIN
            IF (octet_length(p_recipient_fingerprint)=32 AND octet_length(p_ciphertext_sha256)=32) IS NOT TRUE THEN
                RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='Invalid sealed grant acknowledgement.';
            END IF;
            SELECT * INTO context FROM enrollment_execution.lock_delivery_context(p_environment,p_operation,p_requester,p_session_hash);
            IF context.authorized IS NOT TRUE THEN
                RETURN QUERY SELECT 1::smallint,'NotFound'::text; RETURN;
            END IF;
            SELECT result.* INTO issued FROM enrollment_execution.issue_results AS result
                WHERE result.operation_id=p_operation AND result.environment_id=p_environment AND result.outcome='Issued';
            SELECT value.* INTO permit FROM enrollment_execution.mint_permits AS value WHERE value.operation_id=p_operation;
            IF (issued.operation_id IS NOT NULL AND permit.operation_id IS NOT NULL
                AND permit.recipient_fingerprint=p_recipient_fingerprint AND permit.ciphertext_sha256=p_ciphertext_sha256
                AND permit.token_sha256=issued.token_sha256 AND permit.authorization_digest=issued.authorization_digest) IS NOT TRUE THEN
                RETURN QUERY SELECT 1::smallint,'Conflict'::text; RETURN;
            END IF;
            SELECT ack.* INTO prior FROM enrollment_execution.delivery_acks AS ack WHERE ack.operation_id=p_operation;
            IF prior.operation_id IS NOT NULL THEN
                IF (prior.requester_id,prior.ciphertext_sha256,prior.token_sha256)
                    IS NOT DISTINCT FROM (p_requester,p_ciphertext_sha256,permit.token_sha256) THEN
                    RETURN QUERY SELECT 1::smallint,'AlreadyAcknowledged'::text;
                ELSE RETURN QUERY SELECT 1::smallint,'Conflict'::text;
                END IF;
                RETURN;
            END IF;
            SELECT envelope.ciphertext INTO sealed FROM enrollment_execution.sealed_envelopes AS envelope WHERE envelope.operation_id=p_operation;
            IF (octet_length(sealed)=384 AND sha256(sealed)=p_ciphertext_sha256
                AND context.checked_at>=issued.grant_created_at) IS NOT TRUE THEN
                RETURN QUERY SELECT 1::smallint,'Conflict'::text; RETURN;
            END IF;
            -- Token proof is derived from immutable rows, never supplied by the browser.
            INSERT INTO enrollment_execution.delivery_acks
                (operation_id,requester_id,ciphertext_sha256,token_sha256,acknowledged_at)
            VALUES(p_operation,p_requester,p_ciphertext_sha256,permit.token_sha256,context.checked_at);
            DELETE FROM enrollment_execution.sealed_envelopes AS envelope WHERE envelope.operation_id=p_operation;
            IF NOT FOUND THEN
                RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='Sealed grant acknowledgement did not remove its envelope.';
            END IF;
            RETURN QUERY SELECT 1::smallint,'Acknowledged'::text;
        END
        $function$;
        REVOKE ALL ON FUNCTION enrollment_execution.ack_sealed_delivery(uuid,uuid,uuid,text,bytea,bytea) FROM PUBLIC;
        """);

    protected override void Down(MigrationBuilder migrationBuilder) =>
        throw new NotSupportedException("Grant delivery contracts require a reviewed forward migration.");
}
