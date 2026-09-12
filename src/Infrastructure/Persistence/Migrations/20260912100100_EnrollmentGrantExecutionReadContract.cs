using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace ItManagement.Persistence.Migrations;

/// <summary>Owner-only codecs. Deployment must separately install and audit the purpose-bound execution capabilities.</summary>
[DbContext(typeof(ConsoleDbContext))]
[Migration("20260912100100_EnrollmentGrantExecutionReadContract")]
public sealed class EnrollmentGrantExecutionReadContract : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder) => migrationBuilder.Sql("""
        CREATE FUNCTION enrollment_execution.read_record(p_environment uuid,p_operation uuid)
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
        LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $function$
            SELECT
                1::smallint,
                CASE WHEN o."Id" IS NULL THEN 'NotFound' ELSE 'Found' END,
                CASE WHEN o."Id" IS NULL THEN NULL WHEN s.reason IN ('AuthorizationChanged','AuthorizationExpired') THEN 'PermanentRejected' WHEN s.reason IS NOT NULL THEN 'Quarantined' WHEN a.operation_id IS NOT NULL THEN 'Acknowledged' WHEN r.outcome='Issued' THEN 'Completed' WHEN r.outcome='Rejected' THEN 'PermanentRejected' WHEN p.operation_id IS NOT NULL THEN 'PermitStored' ELSE 'Queued' END,
                o."EnvironmentId",
                o."Id",
                o."PlanId",
                o."RequestId",
                o."ApprovalId",
                o."RequesterId",
                o."ApproverId",
                o."RequesterOperatorId",
                o."ApproverOperatorId",
                o."PlanHash"::text,
                o."DirectoryObjectId",
                o."ServerDeviceId",
                o."MappingCreatedAt",
                o."DirectoryGeneration",
                o."EnvironmentVersion",
                o."RecipientSpki",
                o."RecipientKeyFingerprint",
                o."QueuedAt",
                o."AuthorizationNotAfter",
                p.format_version,
                p.issued_at,
                p.not_after,
                p.token_sha256,
                p.recipient_fingerprint,
                p.ciphertext_sha256,
                p.authorization_digest,
                e.ciphertext,
                r.outcome,
                r.diagnostic,
                r.recorded_at,
                r.grant_id,
                r.environment_id,
                r.directory_object_id,
                r.device_id,
                r.mapping_created_at,
                r.grant_created_at,
                r.grant_expires_at,
                r.issue_contract_version,
                r.mint_permit_not_after,
                r.token_sha256,
                r.authorization_digest,
                a.requester_id,
                a.token_sha256,
                a.ciphertext_sha256,
                a.acknowledged_at,
                s.reason,
                s.recorded_at
            FROM (VALUES (1)) seed(value)
            LEFT JOIN public."EnrollmentGrantOperations" o ON o."EnvironmentId"=p_environment AND o."Id"=p_operation
            LEFT JOIN enrollment_execution.mint_permits p ON p.operation_id=o."Id"
            LEFT JOIN enrollment_execution.sealed_envelopes e ON e.operation_id=o."Id"
            LEFT JOIN enrollment_execution.issue_results r ON r.operation_id=o."Id"
            LEFT JOIN enrollment_execution.delivery_acks a ON a.operation_id=o."Id"
            LEFT JOIN enrollment_execution.execution_stops s ON s.operation_id=o."Id"
        $function$;
        REVOKE ALL ON FUNCTION enrollment_execution.read_record(uuid,uuid) FROM PUBLIC;

        -- Pure binary serialization; this digest is never proof of current authorization.
        -- RSA key validation and authorization remain the caller's responsibility.
        CREATE FUNCTION enrollment_execution.authorization_digest(
            o public."EnrollmentGrantOperations",p_version smallint,p_issued timestamptz,p_deadline timestamptz,
            p_token bytea,p_fingerprint bytea,p_ciphertext bytea)
        RETURNS bytea LANGUAGE plpgsql IMMUTABLE STRICT SECURITY INVOKER
            SET search_path=pg_catalog,pg_temp AS $function$
        BEGIN
            IF o IS NULL OR
                o."EnvironmentId" IS NULL OR o."EnvironmentId"='00000000-0000-0000-0000-000000000000'::uuid OR
                o."Id" IS NULL OR o."Id"='00000000-0000-0000-0000-000000000000'::uuid OR
                o."PlanId" IS NULL OR o."PlanId"='00000000-0000-0000-0000-000000000000'::uuid OR
                o."RequestId" IS NULL OR o."RequestId"='00000000-0000-0000-0000-000000000000'::uuid OR
                o."ApprovalId" IS NULL OR o."ApprovalId"='00000000-0000-0000-0000-000000000000'::uuid OR
                o."RequesterId" IS NULL OR o."RequesterId"='00000000-0000-0000-0000-000000000000'::uuid OR
                o."ApproverId" IS NULL OR o."ApproverId"='00000000-0000-0000-0000-000000000000'::uuid OR
                o."RequesterOperatorId" IS NULL OR o."RequesterOperatorId"='00000000-0000-0000-0000-000000000000'::uuid OR
                o."ApproverOperatorId" IS NULL OR o."ApproverOperatorId"='00000000-0000-0000-0000-000000000000'::uuid OR
                o."DirectoryObjectId" IS NULL OR o."DirectoryObjectId"='00000000-0000-0000-0000-000000000000'::uuid OR
                o."ServerDeviceId" IS NULL OR o."ServerDeviceId"='00000000-0000-0000-0000-000000000000'::uuid OR
                o."DirectoryGeneration" IS NULL OR o."DirectoryGeneration"='00000000-0000-0000-0000-000000000000'::uuid OR
                o."RequesterId"=o."ApproverId" OR o."RequesterOperatorId"=o."ApproverOperatorId" OR
                o."PlanHash" IS NULL OR o."PlanHash"!~'^[0-9a-f]{64}$' OR
                o."EnvironmentVersion" IS NULL OR o."EnvironmentVersion"<=0 OR
                o."RecipientSpki" IS NULL OR octet_length(o."RecipientSpki") NOT BETWEEN 1 AND 512 OR
                o."RecipientKeyFingerprint" IS NULL OR octet_length(o."RecipientKeyFingerprint")<>32 OR
                sha256(o."RecipientSpki")<>o."RecipientKeyFingerprint" OR
                o."MappingCreatedAt" IS NULL OR o."QueuedAt" IS NULL OR o."AuthorizationNotAfter" IS NULL OR
                NOT isfinite(o."MappingCreatedAt") OR NOT isfinite(o."QueuedAt") OR NOT isfinite(o."AuthorizationNotAfter") OR
                o."MappingCreatedAt">o."QueuedAt" OR o."AuthorizationNotAfter"<=o."QueuedAt" OR
                o."AuthorizationNotAfter">o."QueuedAt"+interval '600 seconds' OR
                p_version<>1 OR NOT isfinite(p_issued) OR NOT isfinite(p_deadline) OR
                p_issued<o."QueuedAt" OR p_deadline<=p_issued OR p_deadline>p_issued+interval '60 seconds' OR
                p_deadline>o."AuthorizationNotAfter" OR octet_length(p_token)<>32 OR
                octet_length(p_fingerprint)<>32 OR p_fingerprint<>o."RecipientKeyFingerprint" OR octet_length(p_ciphertext)<>32 THEN
                RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='Invalid enrollment authorization digest input.';
            END IF;
            RETURN sha256(
                convert_to('ADGRAUTH','UTF8') || int2send(1::smallint) ||
                convert_to(o."EnvironmentId"::text,'UTF8') ||
                convert_to(o."Id"::text,'UTF8') ||
                convert_to(o."PlanId"::text,'UTF8') ||
                convert_to(o."RequestId"::text,'UTF8') ||
                convert_to(o."ApprovalId"::text,'UTF8') ||
                convert_to(o."RequesterId"::text,'UTF8') ||
                convert_to(o."ApproverId"::text,'UTF8') ||
                convert_to(o."RequesterOperatorId"::text,'UTF8') ||
                convert_to(o."ApproverOperatorId"::text,'UTF8') ||
                int2send(octet_length(convert_to(o."PlanHash",'UTF8'))::smallint) || convert_to(o."PlanHash",'UTF8') ||
                convert_to(o."DirectoryObjectId"::text,'UTF8') || convert_to(o."ServerDeviceId"::text,'UTF8') ||
                int8send((extract(epoch FROM o."MappingCreatedAt")*1000000)::bigint) || convert_to(o."DirectoryGeneration"::text,'UTF8') ||
                int8send(o."EnvironmentVersion") ||
                int2send(octet_length(o."RecipientSpki")::smallint) || o."RecipientSpki" || o."RecipientKeyFingerprint" ||
                int8send((extract(epoch FROM o."QueuedAt")*1000000)::bigint) || int8send((extract(epoch FROM o."AuthorizationNotAfter")*1000000)::bigint) ||
                int2send(p_version) || int8send((extract(epoch FROM p_issued)*1000000)::bigint) || int8send((extract(epoch FROM p_deadline)*1000000)::bigint) ||
                p_token || p_fingerprint || p_ciphertext);
        END
        $function$;
        REVOKE ALL ON FUNCTION enrollment_execution.authorization_digest(
            public."EnrollmentGrantOperations",smallint,timestamptz,timestamptz,bytea,bytea,bytea) FROM PUBLIC;
        """);

    protected override void Down(MigrationBuilder migrationBuilder) =>
        throw new NotSupportedException("Execution contracts require a reviewed forward migration.");
}
