using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Persistence.Migrations
{
    /// <inheritdoc />
    public partial class BindIsolationToMembership : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("""
                CREATE FUNCTION public.has_environment_membership(p_environment_id uuid, p_principal_id uuid)
                RETURNS boolean LANGUAGE sql STABLE STRICT SECURITY DEFINER
                SET search_path = pg_catalog, pg_temp SET row_security = off AS $$
                    SELECT EXISTS (SELECT 1 FROM public."Memberships" m
                        JOIN public."Principals" p ON p."Id"=m."PrincipalId"
                        WHERE m."EnvironmentId"=p_environment_id AND m."PrincipalId"=p_principal_id AND m."Active" AND p."Enabled")
                $$;
                REVOKE ALL ON FUNCTION public.has_environment_membership(uuid, uuid) FROM PUBLIC;
                ALTER TABLE "Principals" ADD CONSTRAINT operator_required CHECK ("OperatorId" <> '00000000-0000-0000-0000-000000000000'::uuid);
                CREATE FUNCTION public.guard_operator_identity() RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN
                    IF NEW."OperatorId" IS DISTINCT FROM OLD."OperatorId" THEN
                        RAISE EXCEPTION 'Operator identity is immutable' USING ERRCODE='23514';
                    END IF;
                    RETURN NEW;
                END $$;
                CREATE TRIGGER operator_identity_immutable BEFORE UPDATE ON "Principals"
                    FOR EACH ROW EXECUTE FUNCTION public.guard_operator_identity();
                """);
            foreach (var table in new[] { "Roles", "RolePermissions", "Scopes", "Assignments", "GroupMappings", "Audit", "Outbox", "Plans", "PlanItems", "Approvals" })
                migrationBuilder.Sql($"""
                    DROP POLICY environment_isolation ON "{table}";
                    CREATE POLICY environment_isolation ON "{table}"
                    USING ("EnvironmentId"::text=current_setting('app.environment_id',true)
                        AND public.has_environment_membership("EnvironmentId",NULLIF(current_setting('app.principal_id',true),'')::uuid))
                    WITH CHECK ("EnvironmentId"::text=current_setting('app.environment_id',true)
                        AND public.has_environment_membership("EnvironmentId",NULLIF(current_setting('app.principal_id',true),'')::uuid));
                    """);
            migrationBuilder.Sql("""
                DROP POLICY member_read ON "Memberships";
                DROP POLICY member_write ON "Memberships";
                CREATE POLICY member_read ON "Memberships" FOR SELECT USING (
                    public.has_environment_membership("EnvironmentId",NULLIF(current_setting('app.principal_id',true),'')::uuid)
                    AND ("PrincipalId"::text=current_setting('app.principal_id',true)
                        OR "EnvironmentId"::text=current_setting('app.environment_id',true)));
                CREATE POLICY member_insert ON "Memberships" FOR INSERT WITH CHECK (
                    "EnvironmentId"::text=current_setting('app.environment_id',true)
                    AND public.has_environment_membership("EnvironmentId",NULLIF(current_setting('app.principal_id',true),'')::uuid));
                CREATE POLICY member_update ON "Memberships" FOR UPDATE USING (
                    "EnvironmentId"::text=current_setting('app.environment_id',true)
                    AND public.has_environment_membership("EnvironmentId",NULLIF(current_setting('app.principal_id',true),'')::uuid))
                    WITH CHECK ("EnvironmentId"::text=current_setting('app.environment_id',true)
                    AND public.has_environment_membership("EnvironmentId",NULLIF(current_setting('app.principal_id',true),'')::uuid));
                CREATE POLICY member_delete ON "Memberships" FOR DELETE USING (
                    "EnvironmentId"::text=current_setting('app.environment_id',true)
                    AND public.has_environment_membership("EnvironmentId",NULLIF(current_setting('app.principal_id',true),'')::uuid));
                DROP POLICY environment_read ON "Environments";
                DROP POLICY environment_write ON "Environments";
                CREATE POLICY environment_read ON "Environments" FOR SELECT USING (
                    public.has_environment_membership("Id",NULLIF(current_setting('app.principal_id',true),'')::uuid));
                CREATE POLICY environment_update ON "Environments" FOR UPDATE USING (
                    "Id"::text=current_setting('app.environment_id',true)
                    AND public.has_environment_membership("Id",NULLIF(current_setting('app.principal_id',true),'')::uuid))
                    WITH CHECK ("Id"::text=current_setting('app.environment_id',true)
                    AND public.has_environment_membership("Id",NULLIF(current_setting('app.principal_id',true),'')::uuid));
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            throw new System.NotSupportedException("Use a reviewed forward migration; cannot remove membership isolation automatically.");
        }
    }
}
