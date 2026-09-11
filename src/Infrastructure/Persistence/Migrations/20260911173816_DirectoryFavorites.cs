using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Persistence.Migrations
{
    /// <inheritdoc />
    public partial class DirectoryFavorites : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "Favorites",
                columns: table => new
                {
                    EnvironmentId = table.Column<Guid>(type: "uuid", nullable: false),
                    PrincipalId = table.Column<Guid>(type: "uuid", nullable: false),
                    ObjectId = table.Column<Guid>(type: "uuid", nullable: false),
                    Kind = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "clock_timestamp()")
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Favorites", x => new { x.EnvironmentId, x.PrincipalId, x.ObjectId });
                    table.ForeignKey(
                        name: "FK_Favorites_Memberships_EnvironmentId_PrincipalId",
                        columns: x => new { x.EnvironmentId, x.PrincipalId },
                        principalTable: "Memberships",
                        principalColumns: new[] { "EnvironmentId", "PrincipalId" },
                        onDelete: ReferentialAction.Restrict);
                });
            migrationBuilder.Sql("""
                ALTER TABLE public."Favorites" ENABLE ROW LEVEL SECURITY;
                ALTER TABLE public."Favorites" FORCE ROW LEVEL SECURITY;
                CREATE POLICY personal_favorites ON public."Favorites"
                USING ("EnvironmentId"::text=current_setting('app.environment_id',true)
                    AND "PrincipalId"::text=current_setting('app.principal_id',true)
                    AND public.has_environment_membership("EnvironmentId","PrincipalId"))
                WITH CHECK ("EnvironmentId"::text=current_setting('app.environment_id',true)
                    AND "PrincipalId"::text=current_setting('app.principal_id',true)
                    AND public.has_environment_membership("EnvironmentId","PrincipalId"));
                ALTER TABLE public."Favorites" ADD CONSTRAINT favorite_kind
                    CHECK ("Kind" IN ('Computer','User','Group','OrganizationalUnit'));
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "Favorites");
        }
    }
}
