using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Persistence.Migrations
{
    /// <inheritdoc />
    public partial class SavedFilters : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "SavedFilters",
                columns: table => new
                {
                    EnvironmentId = table.Column<Guid>(type: "uuid", nullable: false),
                    PrincipalId = table.Column<Guid>(type: "uuid", nullable: false),
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    SchemaVersion = table.Column<int>(type: "integer", nullable: false),
                    Name = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    Kind = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    Search = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    TagId = table.Column<Guid>(type: "uuid", nullable: true),
                    Version = table.Column<long>(type: "bigint", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SavedFilters", x => new { x.EnvironmentId, x.PrincipalId, x.Id });
                    table.ForeignKey(
                        name: "FK_SavedFilters_DeviceTags_EnvironmentId_TagId",
                        columns: x => new { x.EnvironmentId, x.TagId },
                        principalTable: "DeviceTags",
                        principalColumns: new[] { "EnvironmentId", "Id" },
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_SavedFilters_Memberships_EnvironmentId_PrincipalId",
                        columns: x => new { x.EnvironmentId, x.PrincipalId },
                        principalTable: "Memberships",
                        principalColumns: new[] { "EnvironmentId", "PrincipalId" },
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "IX_SavedFilters_EnvironmentId_TagId",
                table: "SavedFilters",
                columns: new[] { "EnvironmentId", "TagId" });
            migrationBuilder.Sql("""
                ALTER TABLE public."SavedFilters" ADD CONSTRAINT saved_filter_schema CHECK ("SchemaVersion"=1);
                ALTER TABLE public."SavedFilters" ADD CONSTRAINT saved_filter_name CHECK
                    (length("Name") BETWEEN 1 AND 128 AND "Name"=btrim("Name") AND "Name"<>'' AND "Name"!~'[[:cntrl:]]');
                ALTER TABLE public."SavedFilters" ADD CONSTRAINT saved_filter_kind CHECK
                    ("Kind" IN ('User','Group','Computer','OrganizationalUnit'));
                ALTER TABLE public."SavedFilters" ADD CONSTRAINT saved_filter_search CHECK
                    (length("Search")<=128 AND "Search"=btrim("Search") AND "Search"!~'[[:cntrl:]]');
                ALTER TABLE public."SavedFilters" ADD CONSTRAINT saved_filter_tag_kind CHECK
                    ("TagId" IS NULL OR "Kind"='Computer');
                ALTER TABLE public."SavedFilters" ADD CONSTRAINT saved_filter_version CHECK ("Version">0);
                ALTER TABLE public."SavedFilters" ADD CONSTRAINT saved_filter_times CHECK ("UpdatedAt">="CreatedAt");
                ALTER TABLE public."SavedFilters" ENABLE ROW LEVEL SECURITY;
                ALTER TABLE public."SavedFilters" FORCE ROW LEVEL SECURITY;
                CREATE POLICY personal_saved_filters ON public."SavedFilters"
                USING ("EnvironmentId"::text=current_setting('app.environment_id',true)
                    AND "PrincipalId"::text=current_setting('app.principal_id',true)
                    AND public.has_environment_membership("EnvironmentId","PrincipalId"))
                WITH CHECK ("EnvironmentId"::text=current_setting('app.environment_id',true)
                    AND "PrincipalId"::text=current_setting('app.principal_id',true)
                    AND public.has_environment_membership("EnvironmentId","PrincipalId"));
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "SavedFilters");
        }
    }
}
