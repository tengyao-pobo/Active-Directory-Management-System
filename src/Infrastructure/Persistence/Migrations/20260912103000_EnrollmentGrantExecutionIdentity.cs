using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace ItManagement.Persistence.Migrations;

/// <summary>Identity metadata only; no execution role, policy or runtime capability is installed here.</summary>
[DbContext(typeof(ConsoleDbContext))]
[Migration("20260912103000_EnrollmentGrantExecutionIdentity")]
public sealed class EnrollmentGrantExecutionIdentity : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder) => migrationBuilder.Sql("""
        ALTER TABLE public."DirectoryDatabaseBindings"
            ADD COLUMN "ContractVersion" smallint NOT NULL DEFAULT 1;
        ALTER TABLE public."DirectoryDatabaseBindings"
            DROP CONSTRAINT "DirectoryDatabaseBindings_Purpose_check",
            DROP CONSTRAINT "DirectoryDatabaseBindings_check";
        ALTER TABLE public."DirectoryDatabaseBindings"
            ADD CONSTRAINT directory_database_binding_purpose
                CHECK ("Purpose" IN ('Api','Connector','EnrollmentGrantExecution')),
            ADD CONSTRAINT directory_database_binding_shape
                CHECK (("Purpose"='Api' AND "ContractVersion"=1 AND "EnvironmentId" IS NULL AND "PrincipalId" IS NULL)
                    OR ("Purpose"='Connector' AND "ContractVersion"=1 AND "EnvironmentId" IS NOT NULL AND "PrincipalId" IS NOT NULL)
                    OR ("Purpose"='EnrollmentGrantExecution' AND "ContractVersion"=2
                        AND "EnvironmentId" IS NOT NULL AND "PrincipalId" IS NULL
                        AND "EnvironmentId"<>'00000000-0000-0000-0000-000000000000'::uuid));
        CREATE UNIQUE INDEX enrollment_execution_environment_login
            ON public."DirectoryDatabaseBindings"("EnvironmentId") WHERE "Purpose"='EnrollmentGrantExecution';

        CREATE TABLE enrollment_execution.role_reservations (
            role_name name PRIMARY KEY CHECK (btrim(role_name::text)<>''),
            role_oid oid NOT NULL UNIQUE CHECK (role_oid<>0),
            capability text NOT NULL CHECK (capability='EnrollmentGrantExecution'),
            role_kind text NOT NULL CHECK (role_kind IN ('Runtime','Definer')),
            reservation_schema_version smallint NOT NULL CHECK (reservation_schema_version=1)
        );
        ALTER TABLE enrollment_execution.role_reservations ENABLE ROW LEVEL SECURITY;
        ALTER TABLE enrollment_execution.role_reservations FORCE ROW LEVEL SECURITY;
        REVOKE ALL ON enrollment_execution.role_reservations FROM PUBLIC;
        DO $policy$
        BEGIN
            EXECUTE format('CREATE POLICY enrollment_execution_reservation_owner ON enrollment_execution.role_reservations TO %I USING (true) WITH CHECK (true)',current_user);
        END
        $policy$;
        CREATE TRIGGER enrollment_execution_role_reservations_immutable
            BEFORE UPDATE OR DELETE ON enrollment_execution.role_reservations
            FOR EACH ROW EXECUTE FUNCTION enrollment_execution.reject_history_mutation();
        """);

    protected override void Down(MigrationBuilder migrationBuilder) =>
        throw new NotSupportedException("Execution identities require a reviewed forward migration.");
}
