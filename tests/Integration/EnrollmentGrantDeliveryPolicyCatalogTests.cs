using System.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Npgsql;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantPlanTests
{
    [Fact]
    public async Task DeliveryPermitPolicyRequiresExactOperationContext()
    {
        var operation = await QueuedJournalOperation();
        await using var db = Db();
        await using var tx = await db.Database.BeginTransactionAsync(IsolationLevel.Serializable);
        await SeedStatusReceipt(db, operation);
        var connection = (NpgsqlConnection)db.Database.GetDbConnection();
        var transaction = (NpgsqlTransaction)tx.GetDbTransaction();
        var definer = $"permit_probe_{Guid.NewGuid():N}";
        async Task Execute(string sql)
        {
            await using var command = new NpgsqlCommand(sql, connection, transaction);
            await command.ExecuteNonQueryAsync();
        }
        var source = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "enrollment-delivery-profile.sql"));
        var start = source.IndexOf("CREATE POLICY enrollment_delivery_permits_allow", StringComparison.Ordinal);
        var end = source.IndexOf("CREATE POLICY enrollment_delivery_envelopes_allow", StringComparison.Ordinal);
        Assert.True(start >= 0 && end > start);
        await Execute($"CREATE ROLE {QuoteIdentifier(definer)} NOLOGIN NOINHERIT");
        await Execute(source[start..end].Replace(":\"delivery_definer_role\"", QuoteIdentifier(definer), StringComparison.Ordinal));
        await Execute($"""
            GRANT USAGE ON SCHEMA enrollment_execution TO {QuoteIdentifier(definer)};
            GRANT SELECT ON enrollment_execution.mint_permits TO {QuoteIdentifier(definer)};
            SET LOCAL ROLE {QuoteIdentifier(definer)};
            """);
        // SET ROLE isolates policy behavior only; runtime SESSION_USER tests live in the scope suite.
        async Task<long> Visible(string context)
        {
            await using var setting = new NpgsqlCommand("SELECT set_config('app.delivery_operation_id',@context,true)", connection, transaction);
            setting.Parameters.AddWithValue("context", context);
            await setting.ExecuteNonQueryAsync();
            await using var command = new NpgsqlCommand("SELECT count(*) FROM enrollment_execution.mint_permits", connection, transaction);
            return (long)(await command.ExecuteScalarAsync())!;
        }
        Assert.Equal(0, await Visible(""));
        Assert.Equal(0, await Visible(Guid.NewGuid().ToString()));
        Assert.Equal(1, await Visible(operation.Id.ToString()));
        Assert.Equal(0, await Visible(""));
        await tx.RollbackAsync();
    }

    [Theory]
    [InlineData("none")]
    [InlineData("using")]
    [InlineData("check")]
    [InlineData("role")]
    [InlineData("permissive")]
    [InlineData("moved-policy")]
    [InlineData("extra-policy")]
    [InlineData("missing-stop-policy")]
    [InlineData("widened-stop-policy")]
    [InlineData("rls")]
    [InlineData("force-rls")]
    [InlineData("disabled-trigger")]
    [InlineData("moved-trigger")]
    [InlineData("conditional-trigger")]
    [InlineData("column-trigger")]
    [InlineData("extra-trigger")]
    [InlineData("unprefixed-trigger")]
    public async Task DeliveryPolicyCatalogRejectsStructuralDrift(string drift)
    {
        // Exercise the exact installation and audit slices on PostgreSQL. This does not
        // claim that the unfinished complete profile4 installer or external gate passes.
        await using var connection = new NpgsqlConnection(Environment.GetEnvironmentVariable("CONSOLE_TEST_DB")!);
        await connection.OpenAsync();
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable);
        var definer = $"policy_probe_{Guid.NewGuid():N}";
        async Task Execute(string sql)
        {
            await using var command = new NpgsqlCommand(sql, connection, transaction);
            await command.ExecuteNonQueryAsync();
        }
        await using var ownerCommand = new NpgsqlCommand("SELECT CURRENT_USER::text", connection, transaction);
        var owner = (string)(await ownerCommand.ExecuteScalarAsync())!;
        await Execute($"CREATE ROLE {QuoteIdentifier(definer)} NOLOGIN NOINHERIT");
        var source = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "enrollment-delivery-profile.sql"));
        var start = source.IndexOf("CREATE FUNCTION enrollment_execution.reject_delivery_update()", StringComparison.Ordinal);
        var end = source.IndexOf("CREATE FUNCTION enrollment_execution.audit_delivery_privileges(", StringComparison.Ordinal);
        Assert.True(start >= 0 && end > start);
        await Execute(source[start..end]
            .Replace(":\"expected_table_owner_role\"", QuoteIdentifier(owner), StringComparison.Ordinal)
            .Replace(":\"delivery_definer_role\"", QuoteIdentifier(definer), StringComparison.Ordinal));

        // These two global identity tables do not yet have production RLS policies.
        // Supply the required flags only in this rollback fixture so we can prove both
        // the desired catalog and rejection when either prerequisite is absent.
        await Execute("""
            ALTER TABLE public."Principals" ENABLE ROW LEVEL SECURITY;
            ALTER TABLE public."Principals" FORCE ROW LEVEL SECURITY;
            ALTER TABLE public."Sessions" ENABLE ROW LEVEL SECURITY;
            ALTER TABLE public."Sessions" FORCE ROW LEVEL SECURITY;
            """);

        var audit = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "enrollment-execution-profile.sql"));
        start = audit.IndexOf("-- BEGIN exact delivery structure", StringComparison.Ordinal);
        end = audit.IndexOf("-- END exact delivery structure", StringComparison.Ordinal);
        Assert.True(start >= 0 && end > start);
        await Execute($"""
            CREATE FUNCTION pg_temp.test_delivery_structure() RETURNS boolean LANGUAGE plpgsql AS $test$
            DECLARE delivery_definer oid := '{definer}'::regrole; table_owner oid := CURRENT_USER::regrole; ok boolean := true;
            BEGIN
            {audit[start..end]}
            RETURN COALESCE(ok,false);
            END $test$;
            """);
        async Task<bool> Valid()
        {
            await using var command = new NpgsqlCommand("SELECT pg_temp.test_delivery_structure()", connection, transaction);
            return (bool)(await command.ExecuteScalarAsync())!;
        }
        Assert.True(await Valid());
        var sql = drift switch
        {
            "none" => "SELECT 1",
            "using" => "ALTER POLICY enrollment_delivery_operations_limit ON public.\"EnrollmentGrantOperations\" USING(true)",
            "check" => "ALTER POLICY enrollment_delivery_operations_limit ON public.\"EnrollmentGrantOperations\" WITH CHECK(true)",
            "role" => "ALTER POLICY enrollment_delivery_operations_limit ON public.\"EnrollmentGrantOperations\" TO PUBLIC",
            "permissive" => $"DROP POLICY enrollment_delivery_operations_limit ON public.\"EnrollmentGrantOperations\"; CREATE POLICY enrollment_delivery_operations_limit ON public.\"EnrollmentGrantOperations\" AS PERMISSIVE TO {QuoteIdentifier(definer)} USING(true)",
            "moved-policy" => $"DROP POLICY enrollment_delivery_operations_limit ON public.\"EnrollmentGrantOperations\"; CREATE POLICY enrollment_delivery_operations_limit ON public.\"Outbox\" AS RESTRICTIVE TO {QuoteIdentifier(definer)} USING(true)",
            "extra-policy" => $"CREATE POLICY enrollment_delivery_extra ON public.\"Outbox\" TO {QuoteIdentifier(definer)} USING(true)",
            "missing-stop-policy" => "DROP POLICY enrollment_delivery_stops_allow ON enrollment_execution.execution_stops",
            "widened-stop-policy" => "ALTER POLICY enrollment_delivery_stops_limit ON enrollment_execution.execution_stops USING(true)",
            "rls" => "ALTER TABLE public.\"Principals\" DISABLE ROW LEVEL SECURITY",
            "force-rls" => "ALTER TABLE public.\"Principals\" NO FORCE ROW LEVEL SECURITY",
            "disabled-trigger" => "ALTER TABLE public.\"Environments\" DISABLE TRIGGER enrollment_delivery_environment_guard",
            "moved-trigger" => "DROP TRIGGER enrollment_delivery_environment_guard ON public.\"Environments\"; CREATE TRIGGER enrollment_delivery_environment_guard BEFORE UPDATE ON public.\"Outbox\" FOR EACH ROW EXECUTE FUNCTION enrollment_execution.reject_delivery_update()",
            "conditional-trigger" => "DROP TRIGGER enrollment_delivery_environment_guard ON public.\"Environments\"; CREATE TRIGGER enrollment_delivery_environment_guard BEFORE UPDATE ON public.\"Environments\" FOR EACH ROW WHEN(false) EXECUTE FUNCTION enrollment_execution.reject_delivery_update()",
            "column-trigger" => "DROP TRIGGER enrollment_delivery_environment_guard ON public.\"Environments\"; CREATE TRIGGER enrollment_delivery_environment_guard BEFORE UPDATE OF \"Name\" ON public.\"Environments\" FOR EACH ROW EXECUTE FUNCTION enrollment_execution.reject_delivery_update()",
            "extra-trigger" => "CREATE TRIGGER enrollment_delivery_extra BEFORE UPDATE ON public.\"Outbox\" FOR EACH ROW EXECUTE FUNCTION enrollment_execution.reject_delivery_update()",
            "unprefixed-trigger" => "CREATE TRIGGER unexpected_guard BEFORE UPDATE ON public.\"Outbox\" FOR EACH ROW EXECUTE FUNCTION enrollment_execution.reject_delivery_update()",
            _ => throw new ArgumentOutOfRangeException(nameof(drift))
        };
        await Execute(sql);
        Assert.Equal(drift == "none", await Valid());
        await transaction.RollbackAsync();
    }
}
