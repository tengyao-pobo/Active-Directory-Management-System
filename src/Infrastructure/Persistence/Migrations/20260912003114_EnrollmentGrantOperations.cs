using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Persistence.Migrations
{
    /// <inheritdoc />
    public partial class EnrollmentGrantOperations : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddUniqueConstraint(
                name: "AK_Plans_EnvironmentId_Id_RequesterId_PlanHash",
                table: "Plans",
                columns: new[] { "EnvironmentId", "Id", "RequesterId", "PlanHash" });

            migrationBuilder.AddUniqueConstraint(
                name: "AK_EnrollmentGrantRecipientReservations_Fingerprint_Environmen~",
                table: "EnrollmentGrantRecipientReservations",
                columns: new[] { "Fingerprint", "EnvironmentId", "PlanId", "RequesterId", "RequestId" });

            migrationBuilder.AddUniqueConstraint(
                name: "AK_Approvals_EnvironmentId_Id_PlanId_PlanHash_ApproverId",
                table: "Approvals",
                columns: new[] { "EnvironmentId", "Id", "PlanId", "PlanHash", "ApproverId" });

            migrationBuilder.CreateTable(
                name: "EnrollmentGrantOperations",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    EnvironmentId = table.Column<Guid>(type: "uuid", nullable: false),
                    PlanId = table.Column<Guid>(type: "uuid", nullable: false),
                    RequestId = table.Column<Guid>(type: "uuid", nullable: false),
                    ApprovalId = table.Column<Guid>(type: "uuid", nullable: false),
                    RequesterId = table.Column<Guid>(type: "uuid", nullable: false),
                    ApproverId = table.Column<Guid>(type: "uuid", nullable: false),
                    RequesterOperatorId = table.Column<Guid>(type: "uuid", nullable: false),
                    ApproverOperatorId = table.Column<Guid>(type: "uuid", nullable: false),
                    PlanHash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    DirectoryObjectId = table.Column<Guid>(type: "uuid", nullable: false),
                    ServerDeviceId = table.Column<Guid>(type: "uuid", nullable: false),
                    MappingCreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    DirectoryGeneration = table.Column<Guid>(type: "uuid", nullable: false),
                    EnvironmentVersion = table.Column<long>(type: "bigint", nullable: false),
                    RecipientSpki = table.Column<byte[]>(type: "bytea", nullable: false),
                    RecipientKeyFingerprint = table.Column<byte[]>(type: "bytea", nullable: false),
                    QueuedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    AuthorizationNotAfter = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_EnrollmentGrantOperations", x => x.Id);
                    table.ForeignKey(
                        name: "FK_EnrollmentGrantOperations_Approvals_EnvironmentId_ApprovalI~",
                        columns: x => new { x.EnvironmentId, x.ApprovalId, x.PlanId, x.PlanHash, x.ApproverId },
                        principalTable: "Approvals",
                        principalColumns: new[] { "EnvironmentId", "Id", "PlanId", "PlanHash", "ApproverId" },
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_EnrollmentGrantOperations_EnrollmentGrantRecipientReservati~",
                        columns: x => new { x.RecipientKeyFingerprint, x.EnvironmentId, x.PlanId, x.RequesterId, x.RequestId },
                        principalTable: "EnrollmentGrantRecipientReservations",
                        principalColumns: new[] { "Fingerprint", "EnvironmentId", "PlanId", "RequesterId", "RequestId" },
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_EnrollmentGrantOperations_Environments_EnvironmentId",
                        column: x => x.EnvironmentId,
                        principalTable: "Environments",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_EnrollmentGrantOperations_Plans_EnvironmentId_PlanId_Reques~",
                        columns: x => new { x.EnvironmentId, x.PlanId, x.RequesterId, x.PlanHash },
                        principalTable: "Plans",
                        principalColumns: new[] { "EnvironmentId", "Id", "RequesterId", "PlanHash" },
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "IX_EnrollmentGrantOperations_EnvironmentId_ApprovalId",
                table: "EnrollmentGrantOperations",
                columns: new[] { "EnvironmentId", "ApprovalId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_EnrollmentGrantOperations_EnvironmentId_ApprovalId_PlanId_P~",
                table: "EnrollmentGrantOperations",
                columns: new[] { "EnvironmentId", "ApprovalId", "PlanId", "PlanHash", "ApproverId" });

            migrationBuilder.CreateIndex(
                name: "IX_EnrollmentGrantOperations_EnvironmentId_PlanId",
                table: "EnrollmentGrantOperations",
                columns: new[] { "EnvironmentId", "PlanId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_EnrollmentGrantOperations_EnvironmentId_PlanId_RequesterId_~",
                table: "EnrollmentGrantOperations",
                columns: new[] { "EnvironmentId", "PlanId", "RequesterId", "PlanHash" });

            migrationBuilder.CreateIndex(
                name: "IX_EnrollmentGrantOperations_RecipientKeyFingerprint",
                table: "EnrollmentGrantOperations",
                column: "RecipientKeyFingerprint",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_EnrollmentGrantOperations_RecipientKeyFingerprint_Environme~",
                table: "EnrollmentGrantOperations",
                columns: new[] { "RecipientKeyFingerprint", "EnvironmentId", "PlanId", "RequesterId", "RequestId" });
            migrationBuilder.Sql("""
                ALTER TABLE public."Plans" ADD CONSTRAINT enrollment_grant_only_dedicated_queue CHECK (
                    "State"<>5 OR "Action"='agent-enrollment.initial-grant.v1');
                ALTER TABLE public."EnrollmentGrantOperations"
                    ADD CONSTRAINT enrollment_grant_operation_ids_nonempty CHECK (
                        "EnvironmentId"<>'00000000-0000-0000-0000-000000000000'::uuid AND
                        "Id"<>'00000000-0000-0000-0000-000000000000'::uuid AND
                        "RequestId"<>'00000000-0000-0000-0000-000000000000'::uuid AND
                        "PlanId"<>'00000000-0000-0000-0000-000000000000'::uuid AND
                        "ApprovalId"<>'00000000-0000-0000-0000-000000000000'::uuid AND
                        "RequesterId"<>'00000000-0000-0000-0000-000000000000'::uuid AND
                        "ApproverId"<>'00000000-0000-0000-0000-000000000000'::uuid AND
                        "RequesterOperatorId"<>'00000000-0000-0000-0000-000000000000'::uuid AND
                        "ApproverOperatorId"<>'00000000-0000-0000-0000-000000000000'::uuid AND
                        "DirectoryObjectId"<>'00000000-0000-0000-0000-000000000000'::uuid AND
                        "ServerDeviceId"<>'00000000-0000-0000-0000-000000000000'::uuid AND
                        "DirectoryGeneration"<>'00000000-0000-0000-0000-000000000000'::uuid),
                    ADD CONSTRAINT enrollment_grant_operation_independent_approval CHECK (
                        "RequesterId"<>"ApproverId" AND "RequesterOperatorId"<>"ApproverOperatorId"),
                    ADD CONSTRAINT enrollment_grant_operation_version CHECK ("EnvironmentVersion">0),
                    ADD CONSTRAINT enrollment_grant_operation_recipient CHECK (
                        octet_length("RecipientKeyFingerprint")=32 AND octet_length("RecipientSpki") BETWEEN 1 AND 512),
                    ADD CONSTRAINT enrollment_grant_operation_plan_hash CHECK ("PlanHash" ~ '^[0-9a-f]{64}$'),
                    ADD CONSTRAINT enrollment_grant_operation_time CHECK (
                        isfinite("MappingCreatedAt") AND isfinite("QueuedAt") AND isfinite("AuthorizationNotAfter") AND
                        "MappingCreatedAt"<="QueuedAt" AND "QueuedAt"<"AuthorizationNotAfter" AND
                        "AuthorizationNotAfter"<="QueuedAt"+interval '600 seconds');
                ALTER TABLE public."EnrollmentGrantOperations" ENABLE ROW LEVEL SECURITY;
                ALTER TABLE public."EnrollmentGrantOperations" FORCE ROW LEVEL SECURITY;
                CREATE POLICY environment_enrollment_grant_operations ON public."EnrollmentGrantOperations"
                    USING ("EnvironmentId"::text=current_setting('app.environment_id',true)
                        AND "RequesterId"=nullif(current_setting('app.principal_id',true),'')::uuid
                        AND public.has_environment_membership("EnvironmentId",nullif(current_setting('app.principal_id',true),'')::uuid))
                    WITH CHECK ("EnvironmentId"::text=current_setting('app.environment_id',true)
                        AND "RequesterId"=nullif(current_setting('app.principal_id',true),'')::uuid
                        AND public.has_environment_membership("EnvironmentId",nullif(current_setting('app.principal_id',true),'')::uuid));
                CREATE FUNCTION public.reject_enrollment_grant_operation_mutation() RETURNS trigger
                    LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $function$
                BEGIN
                    RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='Enrollment grant operations are immutable.';
                END
                $function$;
                REVOKE ALL ON FUNCTION public.reject_enrollment_grant_operation_mutation() FROM PUBLIC;
                CREATE TRIGGER enrollment_grant_operations_immutable
                    BEFORE UPDATE OR DELETE ON public."EnrollmentGrantOperations"
                    FOR EACH ROW EXECUTE FUNCTION public.reject_enrollment_grant_operation_mutation();
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("""
                DO $guard$
                BEGIN
                    IF EXISTS(SELECT 1 FROM public."EnrollmentGrantOperations") OR
                        EXISTS(SELECT 1 FROM public."Plans" WHERE "State"=5) OR
                        EXISTS(SELECT 1 FROM public."Outbox" WHERE "EventType"='EnrollmentGrantExecutionRequested') THEN
                        RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='Enrollment grant execution history prevents downgrade.';
                    END IF;
                END
                $guard$;
                """);
            migrationBuilder.DropTable(
                name: "EnrollmentGrantOperations");
            migrationBuilder.Sql("DROP FUNCTION public.reject_enrollment_grant_operation_mutation();");
            migrationBuilder.Sql("ALTER TABLE public.\"Plans\" DROP CONSTRAINT enrollment_grant_only_dedicated_queue;");

            migrationBuilder.DropUniqueConstraint(
                name: "AK_Plans_EnvironmentId_Id_RequesterId_PlanHash",
                table: "Plans");

            migrationBuilder.DropUniqueConstraint(
                name: "AK_EnrollmentGrantRecipientReservations_Fingerprint_Environmen~",
                table: "EnrollmentGrantRecipientReservations");

            migrationBuilder.DropUniqueConstraint(
                name: "AK_Approvals_EnvironmentId_Id_PlanId_PlanHash_ApproverId",
                table: "Approvals");
        }
    }
}
