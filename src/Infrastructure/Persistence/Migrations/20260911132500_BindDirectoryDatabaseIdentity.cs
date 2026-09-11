using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using ItManagement.Persistence;

namespace Persistence.Migrations;

[DbContext(typeof(ConsoleDbContext))]
[Migration("20260911132500_BindDirectoryDatabaseIdentity")]
public sealed class BindDirectoryDatabaseIdentity : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder) => migrationBuilder.Sql("""
        CREATE TABLE "DirectoryDatabaseBindings" (
            "LoginRole" name NOT NULL, "Purpose" text NOT NULL CHECK ("Purpose" IN ('Api','Connector')),
            "EnvironmentId" uuid REFERENCES "Environments"("Id"), "PrincipalId" uuid REFERENCES "Principals"("Id"),
            PRIMARY KEY("LoginRole"),
            CHECK (("Purpose"='Api' AND "EnvironmentId" IS NULL AND "PrincipalId" IS NULL)
                OR ("Purpose"='Connector' AND "EnvironmentId" IS NOT NULL AND "PrincipalId" IS NOT NULL))
        );
        REVOKE ALL ON "DirectoryDatabaseBindings" FROM PUBLIC;
        CREATE FUNCTION public.directory_database_access(p_environment uuid,p_principal uuid)
        RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=off AS $$
            SELECT EXISTS(SELECT 1 FROM public."DirectoryDatabaseBindings" b WHERE b."LoginRole"=session_user
                AND (b."Purpose"='Api' OR (b."EnvironmentId"=p_environment AND b."PrincipalId"=p_principal)))
                AND public.has_environment_membership(p_environment,p_principal)
        $$;
        CREATE FUNCTION public.directory_connector_scope(p_environment uuid,p_principal uuid)
        RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=off AS $$
            SELECT NOT EXISTS(SELECT 1 FROM public."DirectoryDatabaseBindings" b WHERE b."LoginRole"=session_user AND b."Purpose"='Connector')
                OR public.directory_database_access(p_environment,p_principal)
        $$;
        REVOKE ALL ON FUNCTION public.directory_database_access(uuid,uuid), public.directory_connector_scope(uuid,uuid) FROM PUBLIC;
        DROP POLICY environment_isolation ON "DirectoryObjects";
        DROP POLICY environment_isolation ON "DirectorySync";
        CREATE POLICY environment_isolation ON "DirectoryObjects"
            USING ("EnvironmentId"::text=current_setting('app.environment_id',true) AND public.directory_database_access("EnvironmentId",NULLIF(current_setting('app.principal_id',true),'')::uuid))
            WITH CHECK ("EnvironmentId"::text=current_setting('app.environment_id',true) AND public.directory_database_access("EnvironmentId",NULLIF(current_setting('app.principal_id',true),'')::uuid));
        CREATE POLICY environment_isolation ON "DirectorySync"
            USING ("EnvironmentId"::text=current_setting('app.environment_id',true) AND public.directory_database_access("EnvironmentId",NULLIF(current_setting('app.principal_id',true),'')::uuid))
            WITH CHECK ("EnvironmentId"::text=current_setting('app.environment_id',true) AND public.directory_database_access("EnvironmentId",NULLIF(current_setting('app.principal_id',true),'')::uuid));
        CREATE POLICY connector_identity ON "Audit" AS RESTRICTIVE
            USING (public.directory_connector_scope("EnvironmentId",NULLIF(current_setting('app.principal_id',true),'')::uuid))
            WITH CHECK (public.directory_connector_scope("EnvironmentId",NULLIF(current_setting('app.principal_id',true),'')::uuid));
        """);
    protected override void Down(MigrationBuilder migrationBuilder) => throw new NotSupportedException("Use a reviewed forward migration.");
}
