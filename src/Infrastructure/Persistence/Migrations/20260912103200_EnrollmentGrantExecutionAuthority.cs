using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace ItManagement.Persistence.Migrations;

/// <summary>Owner-only current-authority predicates. They neither mint a permit nor grant runtime access.</summary>
[DbContext(typeof(ConsoleDbContext))]
[Migration("20260912103200_EnrollmentGrantExecutionAuthority")]
public sealed class EnrollmentGrantExecutionAuthority : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder) => migrationBuilder.Sql("""
        CREATE FUNCTION enrollment_execution.scope_uuid(p_value text)
        RETURNS uuid LANGUAGE plpgsql IMMUTABLE SECURITY INVOKER
            SET search_path=pg_catalog,pg_temp AS $function$
        DECLARE value text:=btrim(p_value,E' \t\r\n');
        BEGIN
            -- Accept the D/N/B/P Guid representations used by the API. Unsupported X and
            -- other whitespace forms conservatively deny; PostgreSQL's looser UUID parser
            -- must not introduce scope grants that Guid.TryParse would reject.
            IF value IS NULL THEN RETURN NULL; END IF;
            IF (left(value,1)='{' AND right(value,1)='}')
                OR (left(value,1)='(' AND right(value,1)=')') THEN
                value:=substr(value,2,length(value)-2);
                IF value !~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$' THEN RETURN NULL; END IF;
            END IF;
            IF value ~ '^[0-9a-fA-F]{32}$'
                OR value ~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$' THEN
                RETURN value::uuid;
            END IF;
            RETURN NULL;
        END
        $function$;
        REVOKE ALL ON FUNCTION enrollment_execution.scope_uuid(text) FROM PUBLIC;

        CREATE FUNCTION enrollment_execution.has_computer_permission(
            p_environment uuid,p_principal uuid,p_directory uuid,p_generation uuid,p_permission text)
        RETURNS boolean LANGUAGE sql STABLE SECURITY INVOKER
            SET search_path=pg_catalog,pg_temp AS $function$
            SELECT p_permission IN ('Computer.View','AgentEnrollmentGrant.Manage','Change.Approve') AND EXISTS (
                SELECT 1 FROM public."DirectoryObjects" object
                JOIN public."Assignments" assignment ON assignment."EnvironmentId"=object."EnvironmentId"
                    AND assignment."PrincipalId"=p_principal
                JOIN public."Roles" role ON role."EnvironmentId"=assignment."EnvironmentId" AND role."Id"=assignment."RoleId"
                JOIN public."RolePermissions" permission ON permission."EnvironmentId"=role."EnvironmentId"
                    AND permission."RoleId"=role."Id" AND permission."Permission"=p_permission
                JOIN public."Scopes" scope ON scope."EnvironmentId"=assignment."EnvironmentId" AND scope."Id"=assignment."ScopeId"
                WHERE object."EnvironmentId"=p_environment AND object."Id"=p_directory
                    AND object."Generation"=p_generation AND object."Kind"='Computer'
                    AND (p_permission<>'AgentEnrollmentGrant.Manage' OR role."BuiltInKind"='Owner')
                    AND ((scope."Kind"=0 AND scope."Value" IS NULL)
                        OR (scope."Kind"=1 AND scope."Value"<>'' AND scope."Value"=object."Department")
                        OR (scope."Kind"=4 AND ((NOT scope."IncludeDescendants"
                            AND enrollment_execution.scope_uuid(scope."Value")=object."ParentOuId")
                            OR (scope."IncludeDescendants"
                                AND enrollment_execution.scope_uuid(scope."Value")=ANY(object."OuAncestry"))))
                        OR (scope."Kind"=3 AND NOT scope."IncludeDescendants"
                            AND scope."Value" ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
                            AND scope."Value"<>'00000000-0000-0000-0000-000000000000'
                            AND EXISTS(SELECT 1 FROM public."DeviceTagAssignments" tag
                                WHERE tag."EnvironmentId"=object."EnvironmentId" AND tag."ObjectId"=object."Id"
                                    AND tag."TagId"=enrollment_execution.scope_uuid(scope."Value"))))
            )
        $function$;
        REVOKE ALL ON FUNCTION enrollment_execution.has_computer_permission(uuid,uuid,uuid,uuid,text) FROM PUBLIC;

        CREATE FUNCTION enrollment_execution.current_authority_matches(
            operation public."EnrollmentGrantOperations",p_checked_at timestamptz)
        RETURNS boolean LANGUAGE sql STABLE SECURITY INVOKER
            SET search_path=pg_catalog,pg_temp AS $function$
            -- Caller must hold lock_plan_context's locks in the same SERIALIZABLE transaction.
            -- This is a predicate, not an authorization token or a runtime entrypoint.
            SELECT isfinite(p_checked_at) AND p_checked_at>=operation."QueuedAt"
                AND p_checked_at<operation."AuthorizationNotAfter"
                AND EXISTS(SELECT 1 FROM public."Environments" environment
                    WHERE environment."Id"=operation."EnvironmentId" AND environment."Version"=operation."EnvironmentVersion")
                AND EXISTS(SELECT 1 FROM public."DirectorySync" sync
                    WHERE sync."EnvironmentId"=operation."EnvironmentId" AND sync."Status"='Ready'
                        AND sync."Generation"=operation."DirectoryGeneration"
                        AND sync."CompletedAt" BETWEEN p_checked_at-interval '15 minutes' AND p_checked_at)
                AND (SELECT count(*)=2 FROM public."Principals" principal
                    JOIN public."Memberships" membership ON membership."PrincipalId"=principal."Id"
                        AND membership."EnvironmentId"=operation."EnvironmentId" AND membership."Active"
                    WHERE principal."Enabled" AND ((principal."Id"=operation."RequesterId"
                        AND principal."OperatorId"=operation."RequesterOperatorId")
                        OR (principal."Id"=operation."ApproverId" AND principal."OperatorId"=operation."ApproverOperatorId")))
                AND operation."RequesterId"<>operation."ApproverId"
                AND operation."RequesterOperatorId"<>operation."ApproverOperatorId"
                AND enrollment_execution.has_computer_permission(operation."EnvironmentId",operation."RequesterId",
                    operation."DirectoryObjectId",operation."DirectoryGeneration",'Computer.View')
                AND enrollment_execution.has_computer_permission(operation."EnvironmentId",operation."RequesterId",
                    operation."DirectoryObjectId",operation."DirectoryGeneration",'AgentEnrollmentGrant.Manage')
                AND enrollment_execution.has_computer_permission(operation."EnvironmentId",operation."ApproverId",
                    operation."DirectoryObjectId",operation."DirectoryGeneration",'Computer.View')
                AND enrollment_execution.has_computer_permission(operation."EnvironmentId",operation."ApproverId",
                    operation."DirectoryObjectId",operation."DirectoryGeneration",'Change.Approve')
        $function$;
        REVOKE ALL ON FUNCTION enrollment_execution.current_authority_matches(public."EnrollmentGrantOperations",timestamptz) FROM PUBLIC;
        """);

    protected override void Down(MigrationBuilder migrationBuilder) =>
        throw new NotSupportedException("Execution authority contracts require a reviewed forward migration.");
}
