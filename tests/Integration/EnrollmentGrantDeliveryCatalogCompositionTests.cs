using System.Data;
using Npgsql;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantPlanTests
{
    private const string DeliveryCatalogBegin = "    -- BEGIN generated delivery catalog slices";
    private const string DeliveryCatalogEnd = "    -- END generated delivery catalog slices";

    [Fact]
    public void DeliveryFixtureSnapshotsDefaultAndConfiguredPlanLockOwners()
    {
        const string key = "CONSOLE_TEST_PLAN_LOCK_OWNER";
        var previous = Environment.GetEnvironmentVariable(key);
        try
        {
            Environment.SetEnvironmentVariable(key, null);
            // Construction only snapshots settings; no database or host is initialized.
            var defaults = new PostgresApiFixture();
            Assert.Equal("console_enrollment_plan_locker", defaults.PlanLockOwner);
            Environment.SetEnvironmentVariable(key, "configured_plan_locker_probe");
            Assert.Equal("console_enrollment_plan_locker", defaults.PlanLockOwner);
            Assert.Equal("configured_plan_locker_probe", new PostgresApiFixture().PlanLockOwner);
        }
        finally { Environment.SetEnvironmentVariable(key, previous); }
    }

    [Fact]
    public async Task DeliveryGeneratedCatalogSlicesMatchSources()
    {
        var parts = new List<string>();
        foreach (var file in new[] { "audit-enrollment-delivery-bindings.sql", "audit-enrollment-delivery-identity.sql" })
        {
            var source = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, file));
            var query = source[source.IndexOf("WITH ", StringComparison.Ordinal)..].Trim().TrimEnd(';')
                .Replace(":'expected_table_owner_role'", "pg_catalog.pg_get_userbyid(table_owner)", StringComparison.Ordinal)
                .Replace(":'execution_definer_role'", "pg_catalog.pg_get_userbyid(definer)", StringComparison.Ordinal)
                .Replace(":'delivery_definer_role'", "pg_catalog.pg_get_userbyid(delivery_definer)", StringComparison.Ordinal)
                .Replace(":'enrollment_plan_lock_owner_role'", "(SELECT pg_catalog.pg_get_userbyid(plan_helper.proowner) FROM pg_catalog.pg_proc plan_helper WHERE plan_helper.oid=pg_catalog.to_regprocedure('public.lock_enrollment_grant_plan_context(uuid,uuid,uuid[])'))", StringComparison.Ordinal);
            parts.Add($"    -- Source: {file}\n    ok := ok AND (\n{query}\n    );");
        }
        var expected = DeliveryCatalogBegin + "\n" + string.Join("\n", parts) + "\n" + DeliveryCatalogEnd;
        var profile = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "enrollment-execution-profile.sql"));
        var start = profile.IndexOf(DeliveryCatalogBegin, StringComparison.Ordinal);
        var end = profile.IndexOf(DeliveryCatalogEnd, StringComparison.Ordinal);
        Assert.True(start >= 0 && end > start);
        Assert.Equal(expected.Replace("\r\n", "\n"), profile[start..(end + DeliveryCatalogEnd.Length)].Replace("\r\n", "\n"));
    }

    [Theory]
    [InlineData("none")]
    [InlineData("bindings")]
    [InlineData("identity")]
    [InlineData("plan-owner")]
    [InlineData("missing-plan-helper")]
    [InlineData("duplicate-api")]
    [InlineData("missing-api")]
    [InlineData("wrong-api-grantee")]
    [InlineData("bound-plan")]
    public async Task DeliveryCatalogCompositionRequiresBothStructures(string fault)
    {
        var boundEnvironment = fault == "bound-plan" ? (await _fixture.SeedAsync()).Environment.Id : Guid.Empty;
        await using var connection = new NpgsqlConnection(Environment.GetEnvironmentVariable("CONSOLE_TEST_DB")!);
        await connection.OpenAsync();
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable);
        var owner = new NpgsqlConnectionStringBuilder(connection.ConnectionString).Username!;
        var plan = _fixture.PlanLockOwner;
        var execution = "composed_execution_" + Guid.NewGuid().ToString("N");
        var delivery = "composed_delivery_" + Guid.NewGuid().ToString("N");
        async Task Execute(string sql)
        {
            await using var command = new NpgsqlCommand(sql, connection, transaction);
            await command.ExecuteNonQueryAsync();
        }
        string Configure(string source) => source
            .Replace(":\"expected_table_owner_role\"", QuoteIdentifier(owner), StringComparison.Ordinal)
            .Replace(":\"enrollment_plan_lock_owner_role\"", QuoteIdentifier(plan), StringComparison.Ordinal)
            .Replace(":\"execution_definer_role\"", QuoteIdentifier(execution), StringComparison.Ordinal)
            .Replace(":\"delivery_definer_role\"", QuoteIdentifier(delivery), StringComparison.Ordinal);
        await Execute($"CREATE ROLE {QuoteIdentifier(execution)} NOLOGIN NOINHERIT; CREATE ROLE {QuoteIdentifier(delivery)} NOLOGIN NOINHERIT; SET LOCAL search_path=pg_catalog,pg_temp;");
        var upgrade = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "upgrade-enrollment-execution-v3-to-v4.sql"));
        var start = upgrade.IndexOf("ALTER TABLE public.\"DirectoryDatabaseBindings\" DROP CONSTRAINT", StringComparison.Ordinal);
        var end = upgrade.IndexOf("ALTER TABLE enrollment_execution.role_reservations DROP CONSTRAINT", start, StringComparison.Ordinal);
        Assert.True(start >= 0 && end > start);
        await Execute(upgrade[start..end]);
        var source = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "enrollment-delivery-profile.sql"));
        start = source.IndexOf("CREATE FUNCTION enrollment_execution.reject_delivery_update()", StringComparison.Ordinal);
        end = source.IndexOf("CREATE FUNCTION enrollment_execution.audit_delivery_privileges(", StringComparison.Ordinal);
        Assert.True(start >= 0 && end > start);
        await Execute(Configure(source[start..end]));
        await Execute(Configure(await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "enrollment-delivery-identity.sql"))));
        var profile = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "enrollment-execution-profile.sql"));
        start = profile.IndexOf(DeliveryCatalogBegin, StringComparison.Ordinal);
        end = profile.IndexOf("    -- END delivery API binding identity", StringComparison.Ordinal);
        Assert.True(start >= 0 && end > start);
        // Exact generated PL/pgSQL expressions, not a substitute implementation.
        // The complete profile still must pin the plan helper and all remaining authority.
        await Execute($"""
            CREATE FUNCTION pg_temp.test_delivery_catalog_composition() RETURNS boolean LANGUAGE plpgsql AS $test$
            DECLARE table_owner oid := CURRENT_USER::regrole; definer oid := '{execution}'::regrole;
              delivery_definer oid := '{delivery}'::regrole; ok boolean := true;
            BEGIN
            {profile[start..end]}
            RETURN COALESCE(ok,false);
            END $test$;
            """);
        async Task<bool> Valid()
        {
            await using var command = new NpgsqlCommand("SELECT pg_temp.test_delivery_catalog_composition()", connection, transaction);
            return (bool)(await command.ExecuteScalarAsync())!;
        }
        Assert.True(await Valid());
        await Execute(fault switch
        {
            "none" => "SELECT 1",
            "bindings" => "ALTER TABLE public.\"DirectoryDatabaseBindings\" DROP CONSTRAINT \"DirectoryDatabaseBindings_pkey\"",
            "identity" => "ALTER TABLE public.\"Sessions\" NO FORCE ROW LEVEL SECURITY",
            "plan-owner" => $"ALTER FUNCTION public.lock_enrollment_grant_plan_context(uuid,uuid,uuid[]) OWNER TO {QuoteIdentifier(execution)}",
            "missing-plan-helper" => "DROP FUNCTION public.lock_enrollment_grant_plan_context(uuid,uuid,uuid[]) CASCADE",
            "duplicate-api" => $"INSERT INTO public.\"DirectoryDatabaseBindings\"(\"LoginRole\",\"Purpose\") VALUES('{execution}','Api')",
            "missing-api" => "DELETE FROM public.\"DirectoryDatabaseBindings\" WHERE \"Purpose\"='Api'",
            "wrong-api-grantee" => $"UPDATE public.\"DirectoryDatabaseBindings\" SET \"LoginRole\"='{execution}' WHERE \"Purpose\"='Api'",
            "bound-plan" => $"INSERT INTO public.\"DirectoryDatabaseBindings\"(\"LoginRole\",\"Purpose\",\"ContractVersion\",\"EnvironmentId\") VALUES('{plan}','EnrollmentGrantExecution',2,'{boundEnvironment}')",
            _ => throw new ArgumentOutOfRangeException(nameof(fault))
        });
        Assert.Equal(fault == "none", await Valid());
        await transaction.RollbackAsync();
    }
}
