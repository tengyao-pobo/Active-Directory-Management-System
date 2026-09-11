using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Persistence.Migrations
{
    /// <inheritdoc />
    public partial class DeviceUserLinks : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "DeviceUserLinks",
                columns: table => new
                {
                    EnvironmentId = table.Column<Guid>(type: "uuid", nullable: false),
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    UserId = table.Column<Guid>(type: "uuid", nullable: true),
                    Version = table.Column<long>(type: "bigint", nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DeviceUserLinks", x => new { x.EnvironmentId, x.Id });
                    table.ForeignKey(
                        name: "FK_DeviceUserLinks_Environments_EnvironmentId",
                        column: x => x.EnvironmentId,
                        principalTable: "Environments",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "IX_DeviceUserLinks_EnvironmentId_UserId_Id",
                table: "DeviceUserLinks",
                columns: new[] { "EnvironmentId", "UserId", "Id" });
            migrationBuilder.Sql("""
                ALTER TABLE "DeviceUserLinks" ENABLE ROW LEVEL SECURITY;
                ALTER TABLE "DeviceUserLinks" FORCE ROW LEVEL SECURITY;
                CREATE POLICY environment_isolation ON "DeviceUserLinks"
                USING ("EnvironmentId"::text=current_setting('app.environment_id',true) AND public.has_environment_membership("EnvironmentId",NULLIF(current_setting('app.principal_id',true),'')::uuid))
                WITH CHECK ("EnvironmentId"::text=current_setting('app.environment_id',true) AND public.has_environment_membership("EnvironmentId",NULLIF(current_setting('app.principal_id',true),'')::uuid));
                ALTER TABLE "DeviceUserLinks" ADD CONSTRAINT link_positive_version CHECK ("Version">0);
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "DeviceUserLinks");
        }
    }
}
