using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace ItManagement.Persistence.Migrations;

/// <summary>Owner-only context lock/read contract; it does not authorize or issue a permit.</summary>
[DbContext(typeof(ConsoleDbContext))]
[Migration("20260912103100_EnrollmentGrantExecutionContext")]
public sealed class EnrollmentGrantExecutionContext : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder) => migrationBuilder.Sql("""
        CREATE FUNCTION enrollment_execution.lock_plan_context(p_environment uuid,p_operation uuid)
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
        LANGUAGE plpgsql VOLATILE SECURITY INVOKER
            SET search_path=pg_catalog,pg_temp AS $function$
        DECLARE
            operation public."EnrollmentGrantOperations"%ROWTYPE;
            checked_at timestamptz;
            current_generation uuid;
        BEGIN
            PERFORM pg_catalog.pg_advisory_xact_lock_shared(1162235478,1);
            -- The immutable operation selects all identities; callers cannot supply a target or principal.
            SELECT * INTO operation FROM public."EnrollmentGrantOperations"
                WHERE "EnvironmentId"=p_environment AND "Id"=p_operation;
            IF NOT FOUND THEN
                RETURN QUERY SELECT 1::smallint,'NotFound'::text,
                    NULL::uuid,
                    NULL::uuid,
                    NULL::uuid,
                    NULL::text,
                    NULL::text,
                    NULL::text,
                    NULL::bigint,
                    NULL::timestamptz,
                    NULL::integer,
                    NULL::text,
                    NULL::uuid,
                    NULL::uuid,
                    NULL::uuid,
                    NULL::text,
                    NULL::bigint,
                    NULL::uuid,
                    NULL::uuid,
                    NULL::uuid,
                    NULL::text,
                    NULL::uuid,
                    NULL::timestamptz,
                    NULL::timestamptz,
                    NULL::bytea,
                    NULL::uuid,
                    NULL::uuid,
                    NULL::uuid,
                    NULL::uuid,
                    NULL::bytea,
                    NULL::timestamptz,
                    NULL::timestamptz,
                    NULL::bytea;
                RETURN;
            END IF;
            PERFORM pg_catalog.set_config('app.environment_id',p_environment::text,true);
            PERFORM pg_catalog.set_config('app.principal_id',operation."RequesterId"::text,true);

            -- Global lock order shared with API and the final authorizer. No remote call is made while held.
            PERFORM "Id" FROM public."Environments" WHERE "Id"=p_environment FOR NO KEY UPDATE;
            SELECT "Generation" INTO current_generation FROM public."DirectorySync"
                WHERE "EnvironmentId"=p_environment FOR NO KEY UPDATE;
            PERFORM "Id" FROM public."DirectoryObjects"
                WHERE "EnvironmentId"=p_environment AND "Id"=operation."DirectoryObjectId"
                    AND "Generation"=current_generation AND "Kind"='Computer' FOR NO KEY UPDATE;
            PERFORM "Id" FROM public."Principals" WHERE "Id" IN (operation."RequesterId",operation."ApproverId")
                ORDER BY "Id" FOR SHARE;
            PERFORM "PrincipalId" FROM public."Memberships"
                WHERE "EnvironmentId"=p_environment AND "PrincipalId" IN (operation."RequesterId",operation."ApproverId")
                ORDER BY "PrincipalId" FOR SHARE;
            PERFORM "Id" FROM public."Plans" WHERE "EnvironmentId"=p_environment AND "Id"=operation."PlanId" FOR NO KEY UPDATE;
            -- The parent lock blocks child anchor triggers. Reservations are already immutable.
            -- Child row locks would add UPDATE privileges without preventing phantom inserts.
            PERFORM "Id" FROM public."EnrollmentGrantOperations" WHERE "EnvironmentId"=p_environment AND "Id"=p_operation FOR NO KEY UPDATE;
            PERFORM "Id" FROM public."Outbox" WHERE "EnvironmentId"=p_environment AND "Id"=p_operation FOR NO KEY UPDATE;

            checked_at:=clock_timestamp();
            RETURN QUERY SELECT
                1::smallint,
                CASE WHEN plan."Id" IS NULL THEN 'NotFound' ELSE 'Found' END,
                plan."EnvironmentId",
                plan."Id",
                plan."RequesterId",
                plan."Action"::text,
                plan."ImmutablePlanJson"::text,
                plan."PlanHash"::text,
                plan."PolicyVersion",
                plan."ExpiresAt",
                plan."State",
                plan."Reason"::text,
                item."EnvironmentId",
                item."PlanId",
                item."Id",
                item."TargetId"::text,
                item."ExpectedVersion",
                approval."EnvironmentId",
                approval."Id",
                approval."PlanId",
                approval."PlanHash"::text,
                approval."ApproverId",
                approval."ApprovedAt",
                approval."ExpiresAt",
                reservation."Fingerprint",
                reservation."EnvironmentId",
                reservation."PlanId",
                reservation."RequesterId",
                reservation."RequestId",
                reservation."RequestDigest",
                reservation."CreatedAt",
                CASE WHEN plan."Id" IS NULL THEN NULL ELSE checked_at END,
                CASE WHEN plan."Id" IS NULL THEN NULL ELSE
                    sha256(convert_to('ITM-ENROLLMENT-CONTEXT-V1','UTF8') ||
                        enrollment_execution.authorization_digest(operation,1::smallint,operation."QueuedAt",
                        least(operation."AuthorizationNotAfter",operation."QueuedAt"+interval '60 seconds'),
                        decode(repeat('00',32),'hex'),operation."RecipientKeyFingerprint",decode(repeat('00',32),'hex'))) END
            FROM (VALUES(1)) seed(value)
            LEFT JOIN public."Plans" plan ON plan."EnvironmentId"=p_environment AND plan."Id"=operation."PlanId"
            LEFT JOIN public."PlanItems" item ON item."EnvironmentId"=plan."EnvironmentId" AND item."PlanId"=plan."Id"
            LEFT JOIN public."Approvals" approval ON approval."EnvironmentId"=plan."EnvironmentId"
                AND approval."PlanId"=plan."Id" AND approval."Id"=operation."ApprovalId"
            LEFT JOIN public."EnrollmentGrantRecipientReservations" reservation ON reservation."EnvironmentId"=plan."EnvironmentId"
                AND reservation."PlanId"=plan."Id" AND reservation."Fingerprint"=operation."RecipientKeyFingerprint";
        END
        $function$;
        REVOKE ALL ON FUNCTION enrollment_execution.lock_plan_context(uuid,uuid) FROM PUBLIC;
        """);

    protected override void Down(MigrationBuilder migrationBuilder) =>
        throw new NotSupportedException("Execution context contracts require a reviewed forward migration.");
}
