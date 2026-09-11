using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Persistence.Migrations
{
    /// <inheritdoc />
    public partial class PrincipalLanguagePreference : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "Preferences",
                columns: table => new
                {
                    PrincipalId = table.Column<Guid>(type: "uuid", nullable: false),
                    Locale = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Preferences", x => x.PrincipalId);
                    table.ForeignKey(
                        name: "FK_Preferences_Principals_PrincipalId",
                        column: x => x.PrincipalId,
                        principalTable: "Principals",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });
            migrationBuilder.Sql("""
                ALTER TABLE "Preferences" ADD CONSTRAINT "CK_Preferences_Locale" CHECK ("Locale" IN ('zh-TW', 'en-US'));
                ALTER TABLE "Preferences" ENABLE ROW LEVEL SECURITY;
                ALTER TABLE "Preferences" FORCE ROW LEVEL SECURITY;
                CREATE POLICY self_preferences ON "Preferences"
                    USING ("PrincipalId"::text = current_setting('app.principal_id', true))
                    WITH CHECK ("PrincipalId"::text = current_setting('app.principal_id', true));
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "Preferences");
        }
    }
}
