using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Persistence.Migrations
{
    /// <inheritdoc />
    public partial class EnforceEnvironmentIsolation : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            foreach (var table in new[] { "Roles", "RolePermissions", "Scopes", "Assignments", "GroupMappings", "Audit", "Outbox", "Plans", "PlanItems", "Approvals" })
                migrationBuilder.Sql($"""
                    ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY;
                    ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY;
                    CREATE POLICY environment_isolation ON "{table}"
                    USING ("EnvironmentId"::text = current_setting('app.environment_id', true))
                    WITH CHECK ("EnvironmentId"::text = current_setting('app.environment_id', true));
                    """);
            migrationBuilder.Sql("""
                ALTER TABLE "Memberships" ENABLE ROW LEVEL SECURITY;
                ALTER TABLE "Memberships" FORCE ROW LEVEL SECURITY;
                CREATE POLICY member_read ON "Memberships" FOR SELECT USING (
                    "EnvironmentId"::text = current_setting('app.environment_id', true)
                    OR "PrincipalId"::text = current_setting('app.principal_id', true));
                CREATE POLICY member_write ON "Memberships" FOR ALL USING (
                    "EnvironmentId"::text = current_setting('app.environment_id', true))
                    WITH CHECK ("EnvironmentId"::text = current_setting('app.environment_id', true));
                ALTER TABLE "Environments" ENABLE ROW LEVEL SECURITY;
                ALTER TABLE "Environments" FORCE ROW LEVEL SECURITY;
                CREATE POLICY environment_read ON "Environments" FOR SELECT USING (
                    "Id"::text = current_setting('app.environment_id', true)
                    OR EXISTS (SELECT 1 FROM "Memberships" m WHERE m."EnvironmentId"="Environments"."Id"
                        AND m."PrincipalId"::text=current_setting('app.principal_id', true) AND m."Active"));
                CREATE POLICY environment_write ON "Environments" FOR ALL USING (
                    "Id"::text = current_setting('app.environment_id', true))
                    WITH CHECK ("Id"::text = current_setting('app.environment_id', true));

                CREATE FUNCTION guard_role_identity() RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN
                    IF TG_OP = 'UPDATE' AND NEW."BuiltInKind" IS DISTINCT FROM OLD."BuiltInKind" THEN
                        RAISE EXCEPTION 'Built-in role identity is immutable' USING ERRCODE='23514';
                    END IF;
                    RETURN NEW;
                END $$;
                CREATE TRIGGER role_identity_immutable BEFORE UPDATE ON "Roles"
                    FOR EACH ROW EXECUTE FUNCTION guard_role_identity();

                CREATE FUNCTION guard_owner_mapping() RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN
                    IF EXISTS (SELECT 1 FROM "Roles" WHERE "EnvironmentId"=NEW."EnvironmentId" AND "Id"=NEW."RoleId" AND "BuiltInKind"='Owner') THEN
                        RAISE EXCEPTION 'Owner cannot be granted through directory groups' USING ERRCODE='23514';
                    END IF;
                    RETURN NEW;
                END $$;
                CREATE TRIGGER no_owner_mapping BEFORE INSERT OR UPDATE ON "GroupMappings"
                    FOR EACH ROW EXECUTE FUNCTION guard_owner_mapping();

                CREATE FUNCTION forbid_audit_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN
                    RAISE EXCEPTION 'Audit is append-only' USING ERRCODE='23514';
                END $$;
                CREATE TRIGGER audit_append_only BEFORE UPDATE OR DELETE ON "Audit"
                    FOR EACH ROW EXECUTE FUNCTION forbid_audit_mutation();
                CREATE TRIGGER security_events_append_only BEFORE UPDATE OR DELETE ON "SecurityEvents"
                    FOR EACH ROW EXECUTE FUNCTION forbid_audit_mutation();
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            throw new System.NotSupportedException("Security isolation migrations cannot be rolled back automatically; use a reviewed forward migration.");
        }
    }
}
