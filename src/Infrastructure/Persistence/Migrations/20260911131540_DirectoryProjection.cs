using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Persistence.Migrations
{
    /// <inheritdoc />
    public partial class DirectoryProjection : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "DirectoryObjects",
                columns: table => new
                {
                    EnvironmentId = table.Column<Guid>(type: "uuid", nullable: false),
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Generation = table.Column<Guid>(type: "uuid", nullable: false),
                    Kind = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    DistinguishedName = table.Column<string>(type: "character varying(4096)", maxLength: 4096, nullable: false),
                    Name = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    SamAccountName = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    Department = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    ObjectSid = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    UsnChanged = table.Column<long>(type: "bigint", nullable: false),
                    IsProtected = table.Column<bool>(type: "boolean", nullable: false),
                    ProtectionKnown = table.Column<bool>(type: "boolean", nullable: false),
                    ParentOuId = table.Column<Guid>(type: "uuid", nullable: true),
                    OuAncestry = table.Column<Guid[]>(type: "uuid[]", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DirectoryObjects", x => new { x.EnvironmentId, x.Id });
                    table.ForeignKey(
                        name: "FK_DirectoryObjects_Environments_EnvironmentId",
                        column: x => x.EnvironmentId,
                        principalTable: "Environments",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "DirectorySync",
                columns: table => new
                {
                    EnvironmentId = table.Column<Guid>(type: "uuid", nullable: false),
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Generation = table.Column<Guid>(type: "uuid", nullable: false),
                    CompletedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    AttemptedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    Status = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    ErrorCode = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    SourceServer = table.Column<string>(type: "text", nullable: false),
                    NamingContext = table.Column<string>(type: "text", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DirectorySync", x => new { x.EnvironmentId, x.Id });
                    table.ForeignKey(
                        name: "FK_DirectorySync_Environments_EnvironmentId",
                        column: x => x.EnvironmentId,
                        principalTable: "Environments",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "IX_DirectoryObjects_EnvironmentId_Generation_Kind_Id",
                table: "DirectoryObjects",
                columns: new[] { "EnvironmentId", "Generation", "Kind", "Id" });

            migrationBuilder.CreateIndex(
                name: "IX_DirectorySync_EnvironmentId",
                table: "DirectorySync",
                column: "EnvironmentId",
                unique: true);
            foreach (var table in new[] { "DirectoryObjects", "DirectorySync" })
                migrationBuilder.Sql($"""
                    ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY;
                    ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY;
                    CREATE POLICY environment_isolation ON "{table}"
                    USING ("EnvironmentId"::text=current_setting('app.environment_id',true)
                        AND public.has_environment_membership("EnvironmentId",NULLIF(current_setting('app.principal_id',true),'')::uuid))
                    WITH CHECK ("EnvironmentId"::text=current_setting('app.environment_id',true)
                        AND public.has_environment_membership("EnvironmentId",NULLIF(current_setting('app.principal_id',true),'')::uuid));
                    """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "DirectoryObjects");

            migrationBuilder.DropTable(
                name: "DirectorySync");
        }
    }
}
