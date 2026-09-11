using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Persistence.Migrations
{
    /// <inheritdoc />
    public partial class DeviceAssets : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "DeviceAssets",
                columns: table => new
                {
                    EnvironmentId = table.Column<Guid>(type: "uuid", nullable: false),
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Lifecycle = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    Notes = table.Column<string>(type: "character varying(4000)", maxLength: 4000, nullable: false),
                    Version = table.Column<long>(type: "bigint", nullable: false),
                    UpdatedBy = table.Column<Guid>(type: "uuid", nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DeviceAssets", x => new { x.EnvironmentId, x.Id });
                    table.ForeignKey(
                        name: "FK_DeviceAssets_Environments_EnvironmentId",
                        column: x => x.EnvironmentId,
                        principalTable: "Environments",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });
            migrationBuilder.Sql("""
                ALTER TABLE "DeviceAssets" ENABLE ROW LEVEL SECURITY;
                ALTER TABLE "DeviceAssets" FORCE ROW LEVEL SECURITY;
                CREATE POLICY environment_isolation ON "DeviceAssets"
                USING ("EnvironmentId"::text=current_setting('app.environment_id',true) AND public.has_environment_membership("EnvironmentId",NULLIF(current_setting('app.principal_id',true),'')::uuid))
                WITH CHECK ("EnvironmentId"::text=current_setting('app.environment_id',true) AND public.has_environment_membership("EnvironmentId",NULLIF(current_setting('app.principal_id',true),'')::uuid));
                ALTER TABLE "DeviceAssets" ADD CONSTRAINT asset_lifecycle CHECK ("Lifecycle" IN ('Unknown','Active','Spare','Repair','Retired'));
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "DeviceAssets");
        }
    }
}
