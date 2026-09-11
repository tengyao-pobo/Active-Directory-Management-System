using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace ItManagement.Persistence.Migrations;

[DbContext(typeof(ConsoleDbContext))]
[Migration("20260911205500_EnrollmentGrantPermission")]
public sealed class EnrollmentGrantPermission : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder) => migrationBuilder.Sql("""
        INSERT INTO public."RolePermissions" ("EnvironmentId","RoleId","Permission")
        SELECT "EnvironmentId","Id",'AgentEnrollmentGrant.Manage'
        FROM public."Roles" WHERE "BuiltInKind"='Owner'
        ON CONFLICT DO NOTHING;
        """);

    protected override void Down(MigrationBuilder migrationBuilder) => migrationBuilder.Sql("""
        DELETE FROM public."RolePermissions"
        WHERE "Permission"='AgentEnrollmentGrant.Manage';
        """);
}
