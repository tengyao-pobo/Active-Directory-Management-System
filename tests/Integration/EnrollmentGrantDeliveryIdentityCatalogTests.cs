using System.Data;
using Npgsql;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantPlanTests
{
    [Theory]
    [InlineData("none")]
    [InlineData("missing-helper")]
    [InlineData("helper-body")]
    [InlineData("helper-owner")]
    [InlineData("helper-config")]
    [InlineData("helper-support")]
    [InlineData("helper-grant")]
    [InlineData("helper-public-revoked")]
    [InlineData("api-crossover")]
    [InlineData("plan-update")]
    [InlineData("extra-policy")]
    [InlineData("policy-role")]
    [InlineData("rls")]
    [InlineData("force-rls")]
    [InlineData("definer-login")]
    [InlineData("definer-membership")]
    [InlineData("search-path")]
    public async Task DeliveryIdentityCatalogRejectsPolicyAndHelperDrift(string fault)
    {
        await using var connection = new NpgsqlConnection(Environment.GetEnvironmentVariable("CONSOLE_TEST_DB")!);
        await connection.OpenAsync();
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable);
        var owner = new NpgsqlConnectionStringBuilder(connection.ConnectionString).Username!;
        var suffix = Guid.NewGuid().ToString("N");
        var plan = "id_plan_" + suffix;
        var execution = "id_exec_" + suffix;
        var delivery = "id_delivery_" + suffix;
        var extra = "id_extra_" + suffix;
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
        await Execute($"""
            CREATE ROLE "{plan}" NOLOGIN NOINHERIT;
            CREATE ROLE "{execution}" NOLOGIN NOINHERIT;
            CREATE ROLE "{delivery}" NOLOGIN NOINHERIT;
            CREATE ROLE "{extra}" NOLOGIN NOINHERIT;
            SET LOCAL search_path=pg_catalog,pg_temp;
            """);
        var profile = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "enrollment-delivery-profile.sql"));
        var start = profile.IndexOf("CREATE FUNCTION enrollment_execution.reject_delivery_update()", StringComparison.Ordinal);
        var end = profile.IndexOf("CREATE FUNCTION enrollment_execution.audit_delivery_privileges(", StringComparison.Ordinal);
        Assert.True(start >= 0 && end > start);
        await Execute(Configure(profile[start..end]));
        await Execute(Configure(await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "enrollment-delivery-identity.sql"))));
        var audit = (await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "audit-enrollment-delivery-identity.sql")))
            .Replace(":'expected_table_owner_role'", "@owner", StringComparison.Ordinal)
            .Replace(":'enrollment_plan_lock_owner_role'", "@plan", StringComparison.Ordinal)
            .Replace(":'execution_definer_role'", "@execution", StringComparison.Ordinal)
            .Replace(":'delivery_definer_role'", "@delivery", StringComparison.Ordinal);
        async Task<bool> Valid()
        {
            await using var command = new NpgsqlCommand(audit, connection, transaction);
            command.Parameters.AddWithValue("owner", owner);
            command.Parameters.AddWithValue("plan", plan);
            command.Parameters.AddWithValue("execution", execution);
            command.Parameters.AddWithValue("delivery", delivery);
            await using var reader = await command.ExecuteReaderAsync();
            Assert.Equal(1, reader.FieldCount);
            Assert.Equal("is_valid", reader.GetName(0));
            Assert.True(await reader.ReadAsync());
            var result = reader.GetBoolean(0);
            Assert.False(await reader.ReadAsync());
            Assert.False(await reader.NextResultAsync());
            return result;
        }
        Assert.True(await Valid());
        await Execute(fault switch
        {
            "none" => "SELECT 1",
            "missing-helper" => "DROP FUNCTION public.api_database_session() CASCADE",
            "helper-body" => "CREATE OR REPLACE FUNCTION public.api_database_session() RETURNS boolean LANGUAGE sql STABLE PARALLEL UNSAFE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS 'SELECT true'",
            "helper-owner" => $"ALTER FUNCTION public.api_database_session() OWNER TO \"{extra}\"",
            "helper-config" => "ALTER FUNCTION public.api_database_session() SET row_security=off",
            "helper-support" => "ALTER FUNCTION public.api_database_session() SUPPORT pg_catalog.textlike_support",
            "helper-grant" => $"GRANT EXECUTE ON FUNCTION public.api_database_session() TO \"{extra}\"",
            "helper-public-revoked" => "REVOKE EXECUTE ON FUNCTION public.api_database_session() FROM PUBLIC",
            "api-crossover" => "ALTER POLICY enrollment_identity_principals_api_read ON public.\"Principals\" USING(public.api_database_session())",
            "plan-update" => "ALTER POLICY enrollment_identity_principals_plan_lock ON public.\"Principals\" WITH CHECK(true)",
            "extra-policy" => "CREATE POLICY unrelated_visibility ON public.\"Principals\" TO PUBLIC USING(true)",
            "policy-role" => "ALTER POLICY enrollment_identity_principals_plan_read ON public.\"Principals\" TO PUBLIC",
            "rls" => "ALTER TABLE public.\"Sessions\" DISABLE ROW LEVEL SECURITY",
            "force-rls" => "ALTER TABLE public.\"Sessions\" NO FORCE ROW LEVEL SECURITY",
            "definer-login" => $"ALTER ROLE \"{execution}\" LOGIN",
            "definer-membership" => $"GRANT \"{extra}\" TO \"{execution}\"",
            "search-path" => "SET LOCAL search_path=public,pg_catalog",
            _ => throw new ArgumentOutOfRangeException(nameof(fault))
        });
        Assert.Equal(fault == "none", await Valid());
        await transaction.RollbackAsync();
    }
}
