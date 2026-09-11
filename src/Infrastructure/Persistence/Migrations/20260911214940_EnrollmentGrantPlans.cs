using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Persistence.Migrations
{
    /// <inheritdoc />
    public partial class EnrollmentGrantPlans : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "EnrollmentGrantRecipientReservations",
                columns: table => new
                {
                    Fingerprint = table.Column<byte[]>(type: "bytea", nullable: false),
                    EnvironmentId = table.Column<Guid>(type: "uuid", nullable: false),
                    PlanId = table.Column<Guid>(type: "uuid", nullable: false),
                    RequesterId = table.Column<Guid>(type: "uuid", nullable: false),
                    RequestId = table.Column<Guid>(type: "uuid", nullable: false),
                    RequestDigest = table.Column<byte[]>(type: "bytea", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_EnrollmentGrantRecipientReservations", x => x.Fingerprint);
                    table.ForeignKey(
                        name: "FK_EnrollmentGrantRecipientReservations_Plans_EnvironmentId_Pl~",
                        columns: x => new { x.EnvironmentId, x.PlanId },
                        principalTable: "Plans",
                        principalColumns: new[] { "EnvironmentId", "Id" },
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "IX_EnrollmentGrantRecipientReservations_EnvironmentId_PlanId",
                table: "EnrollmentGrantRecipientReservations",
                columns: new[] { "EnvironmentId", "PlanId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_EnrollmentGrantRecipientReservations_EnvironmentId_Requeste~",
                table: "EnrollmentGrantRecipientReservations",
                columns: new[] { "EnvironmentId", "RequesterId", "RequestId" },
                unique: true);

            migrationBuilder.Sql("""
                ALTER TABLE public."EnrollmentGrantRecipientReservations"
                    ADD CONSTRAINT enrollment_grant_recipient_fingerprint_length CHECK (octet_length("Fingerprint")=32),
                    ADD CONSTRAINT enrollment_grant_request_digest_length CHECK (octet_length("RequestDigest")=32),
                    ADD CONSTRAINT enrollment_grant_reservation_ids_nonempty CHECK (
                        "EnvironmentId"<>'00000000-0000-0000-0000-000000000000'::uuid AND
                        "PlanId"<>'00000000-0000-0000-0000-000000000000'::uuid AND
                        "RequesterId"<>'00000000-0000-0000-0000-000000000000'::uuid AND
                        "RequestId"<>'00000000-0000-0000-0000-000000000000'::uuid);
                ALTER TABLE public."Plans" ADD CONSTRAINT enrollment_grant_plan_never_executed CHECK (
                    "Action"<>'agent-enrollment.initial-grant.v1' OR "State"<>2);

                ALTER TABLE public."EnrollmentGrantRecipientReservations" ENABLE ROW LEVEL SECURITY;
                ALTER TABLE public."EnrollmentGrantRecipientReservations" FORCE ROW LEVEL SECURITY;
                CREATE POLICY environment_enrollment_grant_recipient_reservations
                    ON public."EnrollmentGrantRecipientReservations"
                    USING ("EnvironmentId"::text=current_setting('app.environment_id',true)
                        AND public.has_environment_membership("EnvironmentId",nullif(current_setting('app.principal_id',true),'')::uuid))
                    WITH CHECK ("EnvironmentId"::text=current_setting('app.environment_id',true)
                        AND public.has_environment_membership("EnvironmentId",nullif(current_setting('app.principal_id',true),'')::uuid));

                CREATE FUNCTION public.reject_enrollment_grant_reservation_mutation() RETURNS trigger
                    LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $function$
                BEGIN
                    RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='Enrollment grant recipient reservations are immutable.';
                END
                $function$;
                REVOKE ALL ON FUNCTION public.reject_enrollment_grant_reservation_mutation() FROM PUBLIC;
                CREATE TRIGGER enrollment_grant_recipient_reservations_immutable
                    BEFORE UPDATE OR DELETE ON public."EnrollmentGrantRecipientReservations"
                    FOR EACH ROW EXECUTE FUNCTION public.reject_enrollment_grant_reservation_mutation();

                CREATE FUNCTION public.lock_enrollment_grant_plan_context(
                    p_environment_id uuid,
                    p_directory_object_id uuid,
                    p_principal_ids uuid[])
                RETURNS void LANGUAGE plpgsql SECURITY DEFINER
                VOLATILE PARALLEL UNSAFE
                SET search_path=pg_catalog,pg_temp AS $function$
                DECLARE
                    v_session_principal uuid;
                    v_generation uuid;
                    v_count integer;
                BEGIN
                    BEGIN
                        v_session_principal := nullif(pg_catalog.current_setting('app.principal_id',true),'')::uuid;
                    EXCEPTION WHEN invalid_text_representation THEN
                        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='Enrollment grant plan lock context rejected.';
                    END;
                    IF v_session_principal IS NULL THEN
                        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='Enrollment grant plan lock context rejected.';
                    END IF;
                    IF p_environment_id IS NULL OR p_environment_id='00000000-0000-0000-0000-000000000000'::uuid OR
                        p_directory_object_id IS NULL OR p_directory_object_id='00000000-0000-0000-0000-000000000000'::uuid OR
                        p_environment_id::text IS DISTINCT FROM pg_catalog.current_setting('app.environment_id',true) OR
                        p_principal_ids IS NULL OR pg_catalog.cardinality(p_principal_ids) NOT BETWEEN 1 AND 2 OR
                        EXISTS (SELECT 1 FROM pg_catalog.unnest(p_principal_ids) id WHERE id IS NULL OR id='00000000-0000-0000-0000-000000000000'::uuid) OR
                        (SELECT pg_catalog.count(DISTINCT id) FROM pg_catalog.unnest(p_principal_ids) id)<>pg_catalog.cardinality(p_principal_ids) OR
                        NOT (v_session_principal=ANY(p_principal_ids)) THEN
                        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='Enrollment grant plan lock context rejected.';
                    END IF;
                    IF NOT EXISTS (
                        SELECT 1 FROM public."DirectoryDatabaseBindings"
                        WHERE "LoginRole"=SESSION_USER AND "Purpose"='Api' AND "EnvironmentId" IS NULL AND "PrincipalId" IS NULL) THEN
                        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='Enrollment grant plan lock context rejected.';
                    END IF;
                    PERFORM 1 FROM public."Environments" WHERE "Id"=p_environment_id FOR SHARE;
                    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='Enrollment grant plan lock context rejected.'; END IF;
                    SELECT "Generation" INTO v_generation FROM public."DirectorySync" WHERE "EnvironmentId"=p_environment_id FOR SHARE;
                    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='Enrollment grant plan lock context rejected.'; END IF;
                    PERFORM 1 FROM public."DirectoryObjects" WHERE "EnvironmentId"=p_environment_id AND "Id"=p_directory_object_id
                        AND "Generation"=v_generation AND "Kind"='Computer' FOR SHARE;
                    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='Enrollment grant plan lock context rejected.'; END IF;
                    PERFORM 1 FROM public."Principals" WHERE "Id"=ANY(p_principal_ids) ORDER BY "Id" FOR SHARE;
                    GET DIAGNOSTICS v_count=ROW_COUNT;
                    IF v_count<>pg_catalog.cardinality(p_principal_ids) THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='Enrollment grant plan lock context rejected.'; END IF;
                    PERFORM 1 FROM public."Memberships" WHERE "EnvironmentId"=p_environment_id AND "PrincipalId"=ANY(p_principal_ids)
                        ORDER BY "EnvironmentId","PrincipalId" FOR SHARE;
                    GET DIAGNOSTICS v_count=ROW_COUNT;
                    IF v_count<>pg_catalog.cardinality(p_principal_ids) OR NOT EXISTS (
                        SELECT 1 FROM public."Memberships" WHERE "EnvironmentId"=p_environment_id AND "PrincipalId"=v_session_principal AND "Active") THEN
                        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='Enrollment grant plan lock context rejected.';
                    END IF;
                END
                $function$;
                REVOKE ALL ON FUNCTION public.lock_enrollment_grant_plan_context(uuid,uuid,uuid[]) FROM PUBLIC;
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("""
                DO $block$
                BEGIN
                    IF EXISTS (SELECT 1 FROM public."EnrollmentGrantRecipientReservations") THEN
                        RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='Enrollment grant recipient reservations prevent rollback.';
                    END IF;
                END
                $block$;
                DROP TRIGGER IF EXISTS enrollment_grant_recipient_reservations_immutable ON public."EnrollmentGrantRecipientReservations";
                DROP FUNCTION IF EXISTS public.reject_enrollment_grant_reservation_mutation();
                DROP FUNCTION IF EXISTS public.lock_enrollment_grant_plan_context(uuid,uuid,uuid[]);
                ALTER TABLE public."Plans" DROP CONSTRAINT IF EXISTS enrollment_grant_plan_never_executed;
                """);
            migrationBuilder.DropTable(
                name: "EnrollmentGrantRecipientReservations");
        }
    }
}
