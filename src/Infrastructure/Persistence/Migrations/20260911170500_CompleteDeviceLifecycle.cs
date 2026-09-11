using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using ItManagement.Persistence;

namespace Persistence.Migrations;

[DbContext(typeof(ConsoleDbContext))]
[Migration("20260911170500_CompleteDeviceLifecycle")]
public sealed class CompleteDeviceLifecycle : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder) => migrationBuilder.Sql("""
        ALTER TABLE "DeviceAssets" DROP CONSTRAINT asset_lifecycle;
        ALTER TABLE "DeviceAssets" ADD CONSTRAINT asset_lifecycle CHECK
            ("Lifecycle" IN ('Unknown','Active','Spare','Repair','ReplacementPlanned','Retired','Disposed','Lost'));
        """);

    // Existing new-state records must be reconciled explicitly; never silently relabel them on rollback.
    protected override void Down(MigrationBuilder migrationBuilder) =>
        throw new NotSupportedException("Use a reviewed forward migration for lifecycle data.");
}
