using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace ItManagement.Persistence.Migrations;

/// <summary>
/// Closed journal foundation. No application role receives table access or an execution function.
/// Purpose-bound execution functions and their deployment audit must be installed separately.
/// </summary>
[DbContext(typeof(ConsoleDbContext))]
[Migration("20260912090000_EnrollmentGrantExecutionJournal")]
public sealed class EnrollmentGrantExecutionJournal : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder) => migrationBuilder.Sql("""
        CREATE SCHEMA enrollment_execution;
        REVOKE ALL ON SCHEMA enrollment_execution FROM PUBLIC;

        CREATE TABLE enrollment_execution.mint_permits (
            operation_id uuid PRIMARY KEY REFERENCES public."EnrollmentGrantOperations"("Id") ON DELETE RESTRICT,
            format_version smallint NOT NULL CHECK (format_version=1),
            issued_at timestamptz NOT NULL,
            not_after timestamptz NOT NULL,
            token_sha256 bytea NOT NULL UNIQUE CHECK (octet_length(token_sha256)=32),
            recipient_fingerprint bytea NOT NULL CHECK (octet_length(recipient_fingerprint)=32),
            ciphertext_sha256 bytea NOT NULL CHECK (octet_length(ciphertext_sha256)=32),
            authorization_digest bytea NOT NULL CHECK (octet_length(authorization_digest)=32),
            CONSTRAINT mint_permit_time CHECK (isfinite(issued_at) AND isfinite(not_after)
                AND issued_at<not_after AND not_after<=issued_at+interval '60 seconds')
        );
        CREATE TABLE enrollment_execution.sealed_envelopes (
            operation_id uuid PRIMARY KEY REFERENCES enrollment_execution.mint_permits(operation_id) ON DELETE RESTRICT,
            ciphertext bytea NOT NULL CHECK (octet_length(ciphertext)=384)
        );
        CREATE TABLE enrollment_execution.issue_results (
            operation_id uuid PRIMARY KEY REFERENCES enrollment_execution.mint_permits(operation_id) ON DELETE RESTRICT,
            outcome text NOT NULL CHECK (outcome IN ('Issued','Rejected')),
            diagnostic text NOT NULL,
            recorded_at timestamptz NOT NULL CHECK (isfinite(recorded_at)),
            grant_id uuid,
            environment_id uuid,
            directory_object_id uuid,
            device_id uuid,
            mapping_created_at timestamptz,
            grant_created_at timestamptz,
            grant_expires_at timestamptz,
            issue_contract_version smallint,
            mint_permit_not_after timestamptz,
            token_sha256 bytea,
            authorization_digest bytea,
            CONSTRAINT issue_result_closed_shape CHECK (
                (outcome='Issued' AND diagnostic='None'
                    AND grant_id IS NOT NULL AND grant_id<>'00000000-0000-0000-0000-000000000000'::uuid
                    AND environment_id IS NOT NULL AND environment_id<>'00000000-0000-0000-0000-000000000000'::uuid
                    AND directory_object_id IS NOT NULL AND directory_object_id<>'00000000-0000-0000-0000-000000000000'::uuid
                    AND device_id IS NOT NULL AND device_id<>'00000000-0000-0000-0000-000000000000'::uuid
                    AND mapping_created_at IS NOT NULL AND isfinite(mapping_created_at)
                    AND grant_created_at IS NOT NULL AND isfinite(grant_created_at)
                    AND grant_expires_at IS NOT NULL AND isfinite(grant_expires_at)
                    AND mapping_created_at<=grant_created_at AND grant_expires_at=grant_created_at+interval '600 seconds'
                    AND recorded_at>=grant_created_at
                    AND issue_contract_version IS NOT NULL AND issue_contract_version=2
                    AND mint_permit_not_after IS NOT NULL AND isfinite(mint_permit_not_after)
                    AND grant_created_at<mint_permit_not_after
                    AND token_sha256 IS NOT NULL AND octet_length(token_sha256)=32
                    AND authorization_digest IS NOT NULL AND octet_length(authorization_digest)=32)
                OR (outcome='Rejected' AND diagnostic IN ('MappingUnavailable','DeviceUnavailable',
                    'EnrollmentAlreadyExists','EnrollmentInProgress','GrantAlreadyAvailable','MintPermitExpired')
                    AND grant_id IS NULL AND environment_id IS NULL AND directory_object_id IS NULL AND device_id IS NULL
                    AND mapping_created_at IS NULL AND grant_created_at IS NULL AND grant_expires_at IS NULL
                    AND issue_contract_version IS NULL AND mint_permit_not_after IS NULL
                    AND token_sha256 IS NULL AND authorization_digest IS NULL))
        );
        CREATE UNIQUE INDEX issue_results_private_grant ON enrollment_execution.issue_results(environment_id,grant_id)
            WHERE outcome='Issued';
        CREATE TABLE enrollment_execution.delivery_acks (
            operation_id uuid PRIMARY KEY REFERENCES enrollment_execution.issue_results(operation_id) ON DELETE RESTRICT,
            requester_id uuid NOT NULL CHECK (requester_id<>'00000000-0000-0000-0000-000000000000'::uuid),
            ciphertext_sha256 bytea NOT NULL CHECK (octet_length(ciphertext_sha256)=32),
            token_sha256 bytea NOT NULL CHECK (octet_length(token_sha256)=32),
            acknowledged_at timestamptz NOT NULL CHECK (isfinite(acknowledged_at))
        );

        CREATE FUNCTION enrollment_execution.reject_history_mutation() RETURNS trigger
            LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
        BEGIN
            RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='Enrollment execution history is immutable.';
        END
        $function$;

        CREATE FUNCTION enrollment_execution.validate_journal() RETURNS trigger
            LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
        DECLARE
            operation_uuid uuid := coalesce(NEW.operation_id,OLD.operation_id);
            permit enrollment_execution.mint_permits%ROWTYPE;
            operation public."EnrollmentGrantOperations"%ROWTYPE;
            result enrollment_execution.issue_results%ROWTYPE;
            ack enrollment_execution.delivery_acks%ROWTYPE;
            envelope enrollment_execution.sealed_envelopes%ROWTYPE;
        BEGIN
            SELECT * INTO STRICT permit FROM enrollment_execution.mint_permits WHERE operation_id=operation_uuid;
            SELECT * INTO STRICT operation FROM public."EnrollmentGrantOperations" WHERE "Id"=operation_uuid;
            SELECT * INTO result FROM enrollment_execution.issue_results WHERE operation_id=operation_uuid;
            SELECT * INTO ack FROM enrollment_execution.delivery_acks WHERE operation_id=operation_uuid;
            SELECT * INTO envelope FROM enrollment_execution.sealed_envelopes WHERE operation_id=operation_uuid;
            IF permit.issued_at<operation."QueuedAt" OR permit.not_after>operation."AuthorizationNotAfter"
                OR permit.recipient_fingerprint<>operation."RecipientKeyFingerprint" THEN
                RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='Invalid enrollment permit binding.';
            END IF;
            IF envelope.operation_id IS NOT NULL AND pg_catalog.sha256(envelope.ciphertext)<>permit.ciphertext_sha256 THEN
                RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='Invalid enrollment envelope binding.';
            END IF;
            IF result.operation_id IS NOT NULL AND (result.recorded_at<permit.issued_at
                OR (result.diagnostic='MintPermitExpired' AND result.recorded_at<permit.not_after)) THEN
                RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='Invalid enrollment result time.';
            END IF;
            IF result.outcome='Issued' AND (result.environment_id<>operation."EnvironmentId"
                OR result.directory_object_id<>operation."DirectoryObjectId" OR result.device_id<>operation."ServerDeviceId"
                OR result.mapping_created_at<>operation."MappingCreatedAt" OR result.mint_permit_not_after<>permit.not_after
                OR result.grant_created_at<permit.issued_at OR result.token_sha256<>permit.token_sha256
                OR result.authorization_digest<>permit.authorization_digest) THEN
                RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='Invalid enrollment receipt binding.';
            END IF;
            IF ack.operation_id IS NOT NULL AND (result.outcome IS DISTINCT FROM 'Issued'
                OR ack.requester_id<>operation."RequesterId" OR ack.ciphertext_sha256<>permit.ciphertext_sha256
                OR ack.token_sha256<>permit.token_sha256 OR ack.acknowledged_at<result.recorded_at) THEN
                RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='Invalid enrollment acknowledgement binding.';
            END IF;
            IF (ack.operation_id IS NOT NULL OR result.outcome='Rejected') THEN
                IF envelope.operation_id IS NOT NULL THEN
                    RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='Final enrollment disposition must erase its envelope.';
                END IF;
            ELSIF envelope.operation_id IS NULL THEN
                RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='Enrollment permit requires its durable envelope.';
            END IF;
            RETURN NULL;
        END
        $function$;

        CREATE TRIGGER mint_permits_immutable BEFORE UPDATE OR DELETE ON enrollment_execution.mint_permits
            FOR EACH ROW EXECUTE FUNCTION enrollment_execution.reject_history_mutation();
        CREATE TRIGGER issue_results_immutable BEFORE UPDATE OR DELETE ON enrollment_execution.issue_results
            FOR EACH ROW EXECUTE FUNCTION enrollment_execution.reject_history_mutation();
        CREATE TRIGGER delivery_acks_immutable BEFORE UPDATE OR DELETE ON enrollment_execution.delivery_acks
            FOR EACH ROW EXECUTE FUNCTION enrollment_execution.reject_history_mutation();
        CREATE TRIGGER sealed_envelopes_immutable BEFORE UPDATE ON enrollment_execution.sealed_envelopes
            FOR EACH ROW EXECUTE FUNCTION enrollment_execution.reject_history_mutation();
        CREATE CONSTRAINT TRIGGER mint_permits_consistent AFTER INSERT ON enrollment_execution.mint_permits
            DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION enrollment_execution.validate_journal();
        CREATE CONSTRAINT TRIGGER sealed_envelopes_consistent AFTER INSERT OR DELETE ON enrollment_execution.sealed_envelopes
            DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION enrollment_execution.validate_journal();
        CREATE CONSTRAINT TRIGGER issue_results_consistent AFTER INSERT ON enrollment_execution.issue_results
            DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION enrollment_execution.validate_journal();
        CREATE CONSTRAINT TRIGGER delivery_acks_consistent AFTER INSERT ON enrollment_execution.delivery_acks
            DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION enrollment_execution.validate_journal();

        ALTER TABLE enrollment_execution.mint_permits ENABLE ROW LEVEL SECURITY;
        ALTER TABLE enrollment_execution.mint_permits FORCE ROW LEVEL SECURITY;
        ALTER TABLE enrollment_execution.sealed_envelopes ENABLE ROW LEVEL SECURITY;
        ALTER TABLE enrollment_execution.sealed_envelopes FORCE ROW LEVEL SECURITY;
        ALTER TABLE enrollment_execution.issue_results ENABLE ROW LEVEL SECURITY;
        ALTER TABLE enrollment_execution.issue_results FORCE ROW LEVEL SECURITY;
        ALTER TABLE enrollment_execution.delivery_acks ENABLE ROW LEVEL SECURITY;
        ALTER TABLE enrollment_execution.delivery_acks FORCE ROW LEVEL SECURITY;
        REVOKE ALL ON ALL TABLES IN SCHEMA enrollment_execution FROM PUBLIC;
        REVOKE ALL ON ALL FUNCTIONS IN SCHEMA enrollment_execution FROM PUBLIC;
        """);

    protected override void Down(MigrationBuilder migrationBuilder) =>
        throw new NotSupportedException("Enrollment execution history requires a reviewed forward migration.");
}
