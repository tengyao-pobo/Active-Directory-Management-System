using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Persistence.Migrations
{
    /// <inheritdoc />
    public partial class DeviceTags : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "DeviceTags",
                columns: table => new
                {
                    EnvironmentId = table.Column<Guid>(type: "uuid", nullable: false),
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Key = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    Version = table.Column<long>(type: "bigint", nullable: false),
                    ArchivedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    CreatedBy = table.Column<Guid>(type: "uuid", nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    UpdatedBy = table.Column<Guid>(type: "uuid", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DeviceTags", x => new { x.EnvironmentId, x.Id });
                    table.ForeignKey(
                        name: "FK_DeviceTags_Environments_EnvironmentId",
                        column: x => x.EnvironmentId,
                        principalTable: "Environments",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "DeviceTagAssignments",
                columns: table => new
                {
                    EnvironmentId = table.Column<Guid>(type: "uuid", nullable: false),
                    TagId = table.Column<Guid>(type: "uuid", nullable: false),
                    ObjectId = table.Column<Guid>(type: "uuid", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    CreatedBy = table.Column<Guid>(type: "uuid", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DeviceTagAssignments", x => new { x.EnvironmentId, x.TagId, x.ObjectId });
                    table.ForeignKey(
                        name: "FK_DeviceTagAssignments_DeviceTags_EnvironmentId_TagId",
                        columns: x => new { x.EnvironmentId, x.TagId },
                        principalTable: "DeviceTags",
                        principalColumns: new[] { "EnvironmentId", "Id" },
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "IX_DeviceTagAssignments_EnvironmentId_ObjectId_TagId",
                table: "DeviceTagAssignments",
                columns: new[] { "EnvironmentId", "ObjectId", "TagId" });

            migrationBuilder.CreateIndex(
                name: "IX_DeviceTags_EnvironmentId_Key",
                table: "DeviceTags",
                columns: new[] { "EnvironmentId", "Key" },
                unique: true);
            migrationBuilder.Sql("""
                ALTER TABLE public."DeviceTags" ADD CONSTRAINT device_tag_key
                    CHECK ("Key" IN ('VIP','Finance','Shared','MeetingRoom','ServerRoom','Critical','Test','Replacement'));
                ALTER TABLE public."DeviceTags" ADD CONSTRAINT device_tag_version CHECK ("Version">0);
                ALTER TABLE public."DeviceTags" ENABLE ROW LEVEL SECURITY;
                ALTER TABLE public."DeviceTags" FORCE ROW LEVEL SECURITY;
                CREATE POLICY environment_device_tags ON public."DeviceTags"
                USING ("EnvironmentId"::text=current_setting('app.environment_id',true)
                    AND public.has_environment_membership("EnvironmentId",nullif(current_setting('app.principal_id',true),'')::uuid))
                WITH CHECK ("EnvironmentId"::text=current_setting('app.environment_id',true)
                    AND public.has_environment_membership("EnvironmentId",nullif(current_setting('app.principal_id',true),'')::uuid));
                ALTER TABLE public."DeviceTagAssignments" ENABLE ROW LEVEL SECURITY;
                ALTER TABLE public."DeviceTagAssignments" FORCE ROW LEVEL SECURITY;
                CREATE POLICY environment_device_tag_assignments ON public."DeviceTagAssignments"
                USING ("EnvironmentId"::text=current_setting('app.environment_id',true)
                    AND public.has_environment_membership("EnvironmentId",nullif(current_setting('app.principal_id',true),'')::uuid))
                WITH CHECK ("EnvironmentId"::text=current_setting('app.environment_id',true)
                    AND public.has_environment_membership("EnvironmentId",nullif(current_setting('app.principal_id',true),'')::uuid));
                INSERT INTO public."RolePermissions" ("EnvironmentId","RoleId","Permission")
                    SELECT "EnvironmentId","Id",'DeviceTag.Manage' FROM public."Roles" WHERE "BuiltInKind"='Owner'
                    ON CONFLICT DO NOTHING;
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("""
                DELETE FROM public."RolePermissions" p USING public."Roles" r
                WHERE p."EnvironmentId"=r."EnvironmentId" AND p."RoleId"=r."Id"
                    AND r."BuiltInKind"='Owner' AND p."Permission"='DeviceTag.Manage';
                """);
            migrationBuilder.DropTable(
                name: "DeviceTagAssignments");

            migrationBuilder.DropTable(
                name: "DeviceTags");
        }
    }
}
