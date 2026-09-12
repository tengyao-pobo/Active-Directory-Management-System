using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace ItManagement.Persistence.Migrations;

/// <summary>Append-only delivery status evidence. Runtime capabilities are installed separately.</summary>
[DbContext(typeof(ConsoleDbContext))]
[Migration("20260912120000_EnrollmentGrantStatusObservations")]
public sealed class EnrollmentGrantStatusObservations : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder) => migrationBuilder.Sql("""
        CREATE TABLE enrollment_execution.status_observations (
            observation_id uuid PRIMARY KEY CHECK (observation_id<>'00000000-0000-0000-0000-000000000000'::uuid),
            environment_id uuid NOT NULL CHECK (environment_id<>'00000000-0000-0000-0000-000000000000'::uuid),
            operation_id uuid NOT NULL REFERENCES enrollment_execution.issue_results(operation_id) ON DELETE RESTRICT,
            sequence bigint NOT NULL CHECK (sequence>0),
            state text NOT NULL CHECK (state IN ('Available','Unknown','Consumed','Revoked','Expired')),
            diagnostic text NOT NULL,
            private_observed_at timestamptz,
            private_state_changed_at timestamptz,
            recorded_at timestamptz NOT NULL CHECK (isfinite(recorded_at)),
            available_until timestamptz,
            UNIQUE(operation_id,sequence),
            CONSTRAINT status_observation_diagnostic CHECK (
                (state='Unknown' AND diagnostic IN ('ResponseUnavailable','ConnectionUnavailable',
                    'ReceiptUnavailable','OperationConflict','PrivilegeAuditFailed'))
                OR (state<>'Unknown' AND diagnostic='None')),
            CONSTRAINT status_observation_shape CHECK (
                (state='Unknown' AND private_observed_at IS NULL AND private_state_changed_at IS NULL AND available_until IS NULL)
                OR (state<>'Unknown' AND private_observed_at IS NOT NULL AND isfinite(private_observed_at)
                    AND private_observed_at<=recorded_at AND (
                        (state='Available' AND private_state_changed_at IS NULL AND available_until IS NOT NULL
                            AND isfinite(available_until) AND available_until>recorded_at
                            AND available_until-private_observed_at<=interval '15 seconds')
                        OR (state='Expired' AND private_state_changed_at IS NULL AND available_until IS NULL)
                        OR (state IN ('Consumed','Revoked') AND private_state_changed_at IS NOT NULL
                            AND isfinite(private_state_changed_at) AND private_state_changed_at<=private_observed_at
                            AND available_until IS NULL))))
        );

        CREATE FUNCTION enrollment_execution.guard_status_observation() RETURNS trigger
        LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $function$
        DECLARE
            issued enrollment_execution.issue_results%ROWTYPE;
            latest_sequence bigint;
            unknown_barrier timestamptz;
        BEGIN
            IF current_setting('transaction_isolation')<>'serializable' THEN
                RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='Status observations require a serializable transaction.';
            END IF;
            PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(NEW.observation_id::text,1162235479));
            PERFORM 1 FROM public."EnrollmentGrantOperations" AS operation
                WHERE operation."Id"=NEW.operation_id AND operation."EnvironmentId"=NEW.environment_id FOR UPDATE;
            IF NOT FOUND THEN
                RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='Status observation operation is unavailable.';
            END IF;
            SELECT result.* INTO issued FROM enrollment_execution.issue_results AS result
                WHERE result.operation_id=NEW.operation_id AND result.environment_id=NEW.environment_id AND result.outcome='Issued';
            IF NOT FOUND THEN
                RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='Status observation receipt is unavailable.';
            END IF;
            IF EXISTS(SELECT 1 FROM enrollment_execution.status_observations AS observation
                WHERE observation.operation_id=NEW.operation_id AND observation.state IN ('Consumed','Revoked','Expired')) THEN
                RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='A terminal status observation cannot be superseded.';
            END IF;
            SELECT max(observation.sequence) INTO latest_sequence FROM enrollment_execution.status_observations AS observation
                WHERE observation.operation_id=NEW.operation_id;
            IF latest_sequence=9223372036854775807 THEN
                RAISE EXCEPTION USING ERRCODE='22003',MESSAGE='Status observation sequence is exhausted.';
            END IF;
            -- Assign public metadata only after the operation lock; callers cannot choose or extend it.
            NEW.sequence:=coalesce(latest_sequence,0)+1;
            NEW.recorded_at:=clock_timestamp();
            NEW.available_until:=NULL;
            IF NEW.state='Unknown' THEN
                IF NEW.private_observed_at IS NOT NULL OR NEW.private_state_changed_at IS NOT NULL THEN
                    RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='Unknown status has no private timestamp.';
                END IF;
            ELSE
                IF (NEW.private_observed_at IS NOT NULL AND isfinite(NEW.private_observed_at)
                    AND NEW.private_observed_at>=issued.grant_created_at AND NEW.private_observed_at<=NEW.recorded_at) IS NOT TRUE THEN
                    RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='Invalid private status observation time.';
                END IF;
                IF NEW.state='Available' THEN
                    -- Retain the strongest Unknown barrier even if the public wall clock moves backward.
                    SELECT max(observation.recorded_at) INTO unknown_barrier
                        FROM enrollment_execution.status_observations AS observation
                        WHERE observation.operation_id=NEW.operation_id AND observation.state='Unknown';
                    IF (NEW.private_state_changed_at IS NULL AND NEW.private_observed_at<issued.grant_expires_at
                        AND NEW.private_observed_at>NEW.recorded_at-interval '15 seconds'
                        AND (unknown_barrier IS NULL OR NEW.private_observed_at>=unknown_barrier)) IS NOT TRUE THEN
                        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='Available status observation is not current.';
                    END IF;
                    NEW.available_until:=least(NEW.private_observed_at+interval '15 seconds',
                        NEW.recorded_at+interval '15 seconds',issued.grant_expires_at);
                    IF NEW.available_until<=NEW.recorded_at THEN
                        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='Available status observation has expired.';
                    END IF;
                ELSIF NEW.state='Expired' THEN
                    IF NEW.private_observed_at<issued.grant_expires_at OR NEW.private_state_changed_at IS NOT NULL THEN
                        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='Invalid expired status observation.';
                    END IF;
                ELSIF NEW.state IN ('Consumed','Revoked') THEN
                    IF (NEW.private_state_changed_at IS NOT NULL AND isfinite(NEW.private_state_changed_at)
                        AND NEW.private_state_changed_at>=issued.grant_created_at
                        AND NEW.private_state_changed_at<=NEW.private_observed_at
                        AND (NEW.state<>'Consumed' OR NEW.private_state_changed_at<issued.grant_expires_at)) IS NOT TRUE THEN
                        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='Invalid terminal status change time.';
                    END IF;
                END IF;
            END IF;
            RETURN NEW;
        END
        $function$;

        CREATE TRIGGER status_observations_guard BEFORE INSERT ON enrollment_execution.status_observations
            FOR EACH ROW EXECUTE FUNCTION enrollment_execution.guard_status_observation();
        CREATE TRIGGER status_observations_immutable BEFORE UPDATE OR DELETE ON enrollment_execution.status_observations
            FOR EACH ROW EXECUTE FUNCTION enrollment_execution.reject_history_mutation();

        CREATE FUNCTION enrollment_execution.record_status_observation(
            p_environment uuid,p_operation uuid,p_observation uuid,p_state text,p_diagnostic text,
            p_private_observed_at timestamptz,p_private_state_changed_at timestamptz,
            p_grant uuid,p_directory_object uuid,p_device uuid,p_mapping_created_at timestamptz,
            p_grant_created_at timestamptz,p_grant_expires_at timestamptz,p_issue_contract smallint,
            p_mint_permit_not_after timestamptz,p_token_sha256 bytea,p_authorization_digest bytea)
        RETURNS TABLE(contract_version smallint,outcome text,observation_id uuid,environment_id uuid,operation_id uuid,
            sequence bigint,state text,diagnostic text,private_observed_at timestamptz,private_state_changed_at timestamptz,
            recorded_at timestamptz,available_until timestamptz)
        LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $function$
        DECLARE
            issued enrollment_execution.issue_results%ROWTYPE;
            prior enrollment_execution.status_observations%ROWTYPE;
            saved enrollment_execution.status_observations%ROWTYPE;
            result_outcome text;
        BEGIN
            IF current_setting('transaction_isolation')<>'serializable' THEN
                RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='Status observations require a serializable transaction.';
            END IF;
            IF p_environment IS NULL OR p_environment='00000000-0000-0000-0000-000000000000'::uuid
                OR p_operation IS NULL OR p_operation='00000000-0000-0000-0000-000000000000'::uuid
                OR p_observation IS NULL OR p_observation='00000000-0000-0000-0000-000000000000'::uuid
                OR p_state IS NULL OR p_state NOT IN ('Available','Unknown','Consumed','Revoked','Expired')
                OR p_diagnostic IS NULL OR
                    ((p_state='Unknown' AND p_diagnostic IN ('ResponseUnavailable','ConnectionUnavailable','ReceiptUnavailable',
                        'OperationConflict','PrivilegeAuditFailed') AND p_private_observed_at IS NULL AND p_private_state_changed_at IS NULL)
                    OR (p_state<>'Unknown' AND p_diagnostic='None' AND p_private_observed_at IS NOT NULL AND isfinite(p_private_observed_at)
                        AND ((p_state IN ('Available','Expired') AND p_private_state_changed_at IS NULL)
                            OR (p_state IN ('Consumed','Revoked') AND p_private_state_changed_at IS NOT NULL
                                AND isfinite(p_private_state_changed_at))))) IS NOT TRUE THEN
                RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='Invalid status observation request.';
            END IF;
            PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(p_observation::text,1162235479));
            SELECT observation.* INTO prior FROM enrollment_execution.status_observations AS observation
                WHERE observation.observation_id=p_observation;
            IF prior.observation_id IS NOT NULL AND
                (prior.environment_id,prior.operation_id,prior.state,prior.diagnostic,prior.private_observed_at,prior.private_state_changed_at)
                IS DISTINCT FROM (p_environment,p_operation,p_state,p_diagnostic,p_private_observed_at,p_private_state_changed_at) THEN
                RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='Status observation replay conflicts.';
            END IF;
            PERFORM 1 FROM public."EnrollmentGrantOperations" AS operation
                WHERE operation."Id"=p_operation AND operation."EnvironmentId"=p_environment FOR UPDATE;
            IF NOT FOUND THEN
                RETURN QUERY SELECT 1::smallint,'NotFound'::text,NULL::uuid,NULL::uuid,NULL::uuid,NULL::bigint,
                    NULL::text,NULL::text,NULL::timestamptz,NULL::timestamptz,NULL::timestamptz,NULL::timestamptz; RETURN;
            END IF;
            SELECT result.* INTO issued FROM enrollment_execution.issue_results AS result
                WHERE result.operation_id=p_operation AND result.environment_id=p_environment AND result.outcome='Issued';
            IF NOT FOUND THEN
                RETURN QUERY SELECT 1::smallint,'NotFound'::text,NULL::uuid,NULL::uuid,NULL::uuid,NULL::bigint,
                    NULL::text,NULL::text,NULL::timestamptz,NULL::timestamptz,NULL::timestamptz,NULL::timestamptz; RETURN;
            END IF;
            IF (issued.grant_id,issued.directory_object_id,issued.device_id,issued.mapping_created_at,
                issued.grant_created_at,issued.grant_expires_at,issued.issue_contract_version,issued.mint_permit_not_after,
                issued.token_sha256,issued.authorization_digest) IS DISTINCT FROM
                (p_grant,p_directory_object,p_device,p_mapping_created_at,p_grant_created_at,p_grant_expires_at,
                p_issue_contract,p_mint_permit_not_after,p_token_sha256,p_authorization_digest) THEN
                RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='Status observation receipt conflicts.';
            END IF;
            IF prior.observation_id IS NOT NULL THEN
                saved:=prior; result_outcome:='AlreadyRecorded';
            ELSE
                SELECT observation.* INTO saved FROM enrollment_execution.status_observations AS observation
                    WHERE observation.operation_id=p_operation AND observation.state IN ('Consumed','Revoked','Expired')
                    ORDER BY observation.sequence DESC LIMIT 1;
                IF saved.observation_id IS NOT NULL THEN
                    result_outcome:='Terminal';
                ELSE
                    INSERT INTO enrollment_execution.status_observations AS observation
                        (observation_id,environment_id,operation_id,state,diagnostic,private_observed_at,private_state_changed_at)
                    VALUES(p_observation,p_environment,p_operation,p_state,p_diagnostic,p_private_observed_at,p_private_state_changed_at)
                    RETURNING observation.* INTO saved;
                    result_outcome:='Recorded';
                END IF;
            END IF;
            RETURN QUERY SELECT 1::smallint,result_outcome,saved.observation_id,saved.environment_id,saved.operation_id,
                saved.sequence,saved.state,saved.diagnostic,saved.private_observed_at,saved.private_state_changed_at,
                saved.recorded_at,saved.available_until;
        END
        $function$;

        ALTER TABLE enrollment_execution.status_observations ENABLE ROW LEVEL SECURITY;
        ALTER TABLE enrollment_execution.status_observations FORCE ROW LEVEL SECURITY;
        REVOKE ALL ON enrollment_execution.status_observations FROM PUBLIC;
        REVOKE ALL ON FUNCTION enrollment_execution.guard_status_observation(),
            enrollment_execution.record_status_observation(uuid,uuid,uuid,text,text,timestamptz,timestamptz,
                uuid,uuid,uuid,timestamptz,timestamptz,timestamptz,smallint,timestamptz,bytea,bytea) FROM PUBLIC;
        """);

    protected override void Down(MigrationBuilder migrationBuilder) =>
        throw new NotSupportedException("Enrollment status history requires a reviewed forward migration.");
}
