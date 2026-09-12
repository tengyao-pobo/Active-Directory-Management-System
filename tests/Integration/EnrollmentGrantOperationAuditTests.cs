using System.Net;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantPlanTests
{
    [Theory]
    [InlineData("table-acl")]
    [InlineData("column-acl")]
    [InlineData("public-acl")]
    [InlineData("policy")]
    [InlineData("trigger")]
    [InlineData("anchor-plan")]
    [InlineData("anchor-child")]
    [InlineData("anchor-approval")]
    [InlineData("anchor-operation")]
    [InlineData("anchor-outbox")]
    [InlineData("anchor-plan-deferred")]
    [InlineData("anchor-operation-deferred")]
    [InlineData("anchor-outbox-deferred")]
    [InlineData("anchor-function-acl")]
    [InlineData("anchor-function-profile")]
    [InlineData("anchor-extra-plan")]
    [InlineData("anchor-extra-child")]
    [InlineData("anchor-extra-approval")]
    [InlineData("anchor-extra-outbox")]
    [InlineData("anchor-truncate")]
    [InlineData("anchor-trigger-privilege")]
    [InlineData("constraint")]
    [InlineData("foreign-key")]
    [InlineData("unique-index")]
    public async Task ExecutionCatalogDriftClosesBothRoutesAndProvisioningRollsBack(string drift)
    {
        var seeded = await Seed(); using var factory = ExecutionFactory(seeded, new Clock(seeded.Now));
        var plan = await ApprovedExecutionPlan(seeded, factory);
        using var requester = Client(factory, seeded.Data.RequesterToken);
        var queued = await Post(requester, ExecutionPath(seeded, plan.Id), new { planHash = plan.Hash });
        Assert.Equal(HttpStatusCode.Accepted, queued.Status);
        var operation = queued.Json.GetProperty("id").GetGuid();
        var runtime = QuoteIdentifier(new NpgsqlConnectionStringBuilder(Environment.GetEnvironmentVariable("CONSOLE_TEST_RUNTIME_DB")).Username!);
        var (apply, restore) = drift switch
        {
            "anchor-plan" => TriggerDrift("Plans", "enrollment_grant_queued_plan_immutable"),
            "anchor-extra-plan" => ExtraTriggerDrift("Plans"),
            "anchor-extra-child" => ExtraTriggerDrift("PlanItems"),
            "anchor-extra-approval" => ExtraTriggerDrift("Approvals"),
            "anchor-extra-outbox" => ExtraTriggerDrift("Outbox"),
            "anchor-truncate" => ($"GRANT TRUNCATE ON public.\"PlanItems\" TO {runtime}",
                $"REVOKE TRUNCATE ON public.\"PlanItems\" FROM {runtime}"),
            "anchor-trigger-privilege" => ($"GRANT TRIGGER ON public.\"Outbox\" TO {runtime}",
                $"REVOKE TRIGGER ON public.\"Outbox\" FROM {runtime}"),
            "anchor-child" => TriggerDrift("PlanItems", "enrollment_grant_plan_items_anchor"),
            "anchor-approval" => TriggerDrift("Approvals", "enrollment_grant_approvals_anchor"),
            "anchor-operation" => TriggerDrift("EnrollmentGrantOperations", "enrollment_grant_operation_parent"),
            "anchor-outbox" => TriggerDrift("Outbox", "enrollment_grant_outbox_anchor"),
            "anchor-plan-deferred" => TriggerDrift("Plans", "enrollment_grant_plan_anchor_consistent"),
            "anchor-operation-deferred" => TriggerDrift("EnrollmentGrantOperations", "enrollment_grant_operation_anchor_consistent"),
            "anchor-outbox-deferred" => TriggerDrift("Outbox", "enrollment_grant_outbox_anchor_consistent"),
            "anchor-function-acl" => ("GRANT EXECUTE ON FUNCTION public.guard_enrollment_grant_operation_parent() TO PUBLIC",
                "REVOKE EXECUTE ON FUNCTION public.guard_enrollment_grant_operation_parent() FROM PUBLIC"),
            "anchor-function-profile" => ("ALTER FUNCTION public.guard_enrollment_grant_operation_parent() IMMUTABLE",
                "ALTER FUNCTION public.guard_enrollment_grant_operation_parent() VOLATILE"),
            "table-acl" => ($"GRANT UPDATE ON public.\"EnrollmentGrantOperations\" TO {runtime}", $"REVOKE UPDATE ON public.\"EnrollmentGrantOperations\" FROM {runtime}"),
            "column-acl" => ($"GRANT UPDATE(\"QueuedAt\") ON public.\"EnrollmentGrantOperations\" TO {runtime}", $"REVOKE UPDATE(\"QueuedAt\") ON public.\"EnrollmentGrantOperations\" FROM {runtime}"),
            "public-acl" => ("GRANT SELECT ON public.\"EnrollmentGrantOperations\" TO PUBLIC", "REVOKE SELECT ON public.\"EnrollmentGrantOperations\" FROM PUBLIC"),
            "policy" => ("CREATE POLICY unexpected_execution_read ON public.\"EnrollmentGrantOperations\" FOR SELECT TO PUBLIC USING(true)", "DROP POLICY unexpected_execution_read ON public.\"EnrollmentGrantOperations\""),
            "trigger" => ("ALTER TABLE public.\"EnrollmentGrantOperations\" DISABLE TRIGGER enrollment_grant_operations_immutable", "ALTER TABLE public.\"EnrollmentGrantOperations\" ENABLE TRIGGER enrollment_grant_operations_immutable"),
            "constraint" => ("ALTER TABLE public.\"EnrollmentGrantOperations\" DROP CONSTRAINT enrollment_grant_operation_version", "ALTER TABLE public.\"EnrollmentGrantOperations\" ADD CONSTRAINT enrollment_grant_operation_version CHECK (\"EnvironmentVersion\">0)"),
            "foreign-key" => ("ALTER TABLE public.\"EnrollmentGrantOperations\" DROP CONSTRAINT \"FK_EnrollmentGrantOperations_Plans_EnvironmentId_PlanId_Reques~\"", "ALTER TABLE public.\"EnrollmentGrantOperations\" ADD CONSTRAINT \"FK_EnrollmentGrantOperations_Plans_EnvironmentId_PlanId_Reques~\" FOREIGN KEY (\"EnvironmentId\",\"PlanId\",\"RequesterId\",\"PlanHash\") REFERENCES public.\"Plans\"(\"EnvironmentId\",\"Id\",\"RequesterId\",\"PlanHash\") ON DELETE RESTRICT"),
            "unique-index" => ("CREATE UNIQUE INDEX unexpected_execution_unique ON public.\"EnrollmentGrantOperations\"(\"ApprovalId\")", "DROP INDEX public.unexpected_execution_unique"),
            _ => throw new ArgumentOutOfRangeException(nameof(drift))
        };
        await using var owner = Db();
        await owner.Database.OpenConnectionAsync();
        await owner.Database.ExecuteSqlRawAsync(apply);
        try
        {
            Assert.Equal(HttpStatusCode.ServiceUnavailable,
                (await Post(requester, ExecutionPath(seeded, plan.Id), new { planHash = plan.Hash })).Status);
            using var unavailable = await requester.GetAsync(OperationPath(seeded, operation));
            Assert.Equal(HttpStatusCode.ServiceUnavailable, unavailable.StatusCode);
            var before = await ExecutionCatalogFingerprint();
            await Assert.ThrowsAsync<PostgresException>(() => _fixture.ProvisionRuntimeAsync(owner));
            await owner.Database.ExecuteSqlRawAsync("ROLLBACK");
            Assert.Equal(before, await ExecutionCatalogFingerprint());
        }
        finally
        {
            // Explicit SQL BEGIN in a failed provisioning script must be closed before restoring the test drift.
            await owner.Database.ExecuteSqlRawAsync("ROLLBACK");
            await owner.Database.ExecuteSqlRawAsync(restore);
        }
        using var restored = await requester.GetAsync(OperationPath(seeded, operation));
        Assert.Equal(HttpStatusCode.OK, restored.StatusCode);
    }

    private static async Task<string> ExecutionCatalogFingerprint()
    {
        await using var db = Db();
        return await db.Database.SqlQueryRaw<string>("""
            SELECT pg_catalog.md5(pg_catalog.concat_ws('|',
                (SELECT pg_catalog.string_agg(c.oid::text||c.relowner::text||COALESCE(c.relacl::text,''),E'\n' ORDER BY c.oid)
                    FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public'),
                (SELECT pg_catalog.string_agg(p.oid::text||p.proowner::text||p.prosrc||COALESCE(p.proacl::text,''),E'\n' ORDER BY p.oid)
                    FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public'),
                (SELECT pg_catalog.string_agg(p.oid::text||p.polrelid::text||COALESCE(p.polqual::text,''),E'\n' ORDER BY p.oid)
                    FROM pg_catalog.pg_policy p),
                (SELECT pg_catalog.string_agg(t.oid::text||t.tgenabled::text||pg_catalog.pg_get_triggerdef(t.oid),E'\n' ORDER BY t.oid)
                    FROM pg_catalog.pg_trigger t WHERE NOT t.tgisinternal),
                (SELECT pg_catalog.string_agg(c.oid::text||pg_catalog.pg_get_constraintdef(c.oid),E'\n' ORDER BY c.oid)
                    FROM pg_catalog.pg_constraint c JOIN pg_catalog.pg_namespace n ON n.oid=c.connamespace WHERE n.nspname='public'))) AS "Value"
            """).SingleAsync();
    }

    private static (string Apply, string Restore) TriggerDrift(string table, string trigger) =>
        ($"ALTER TABLE public.{QuoteIdentifier(table)} DISABLE TRIGGER {QuoteIdentifier(trigger)}",
         $"ALTER TABLE public.{QuoteIdentifier(table)} ENABLE TRIGGER {QuoteIdentifier(trigger)}");

    private static (string Apply, string Restore) ExtraTriggerDrift(string table) =>
        ($"CREATE TRIGGER z_unexpected_anchor BEFORE UPDATE ON public.{QuoteIdentifier(table)} FOR EACH ROW EXECUTE FUNCTION public.reject_enrollment_grant_operation_mutation()",
         $"DROP TRIGGER z_unexpected_anchor ON public.{QuoteIdentifier(table)}");
}
