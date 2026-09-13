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
    [InlineData("plan-helper-body")]
    [InlineData("plan-helper-config")]
    [InlineData("plan-helper-support")]
    [InlineData("plan-extra-function")]
    [InlineData("plan-public-execute")]
    [InlineData("plan-extra-execute")]
    [InlineData("plan-grant-option")]
    [InlineData("plan-extra-table")]
    [InlineData("plan-column")]
    [InlineData("plan-public-table")]
    [InlineData("plan-missing-function")]
    [InlineData("plan-missing-schema")]
    [InlineData("api-directory-update")]
    [InlineData("api-directory-column")]
    [InlineData("api-extra-schema")]
    public async Task DeliveryIdentityCatalogRejectsPolicyAndHelperDrift(string fault)
    {
        await using var connection = new NpgsqlConnection(Environment.GetEnvironmentVariable("CONSOLE_TEST_DB")!);
        await connection.OpenAsync();
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable);
        var owner = new NpgsqlConnectionStringBuilder(connection.ConnectionString).Username!;
        var suffix = Guid.NewGuid().ToString("N");
        var plan = _fixture.PlanLockOwner;
        var execution = "id_exec_" + suffix;
        var delivery = "id_delivery_" + suffix;
        var extra = "id_extra_" + suffix;
        var api = new NpgsqlConnectionStringBuilder(Environment.GetEnvironmentVariable("CONSOLE_TEST_RUNTIME_DB")!).Username!;
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
            CREATE ROLE "{execution}" NOLOGIN NOINHERIT;
            CREATE ROLE "{delivery}" NOLOGIN NOINHERIT;
            CREATE ROLE "{extra}" NOLOGIN NOINHERIT;
            SET LOCAL search_path=pg_catalog,pg_temp;
            ALTER FUNCTION public.lock_enrollment_grant_plan_context(uuid,uuid,uuid[]) OWNER TO "{plan}";
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
            "plan-helper-body" => "CREATE OR REPLACE FUNCTION public.lock_enrollment_grant_plan_context(p_environment_id uuid,p_directory_object_id uuid,p_principal_ids uuid[]) RETURNS void LANGUAGE plpgsql SECURITY DEFINER VOLATILE PARALLEL UNSAFE SET search_path=pg_catalog,pg_temp AS 'BEGIN RETURN; END'",
            "plan-helper-config" => "ALTER FUNCTION public.lock_enrollment_grant_plan_context(uuid,uuid,uuid[]) SET row_security=off",
            "plan-helper-support" => "ALTER FUNCTION public.lock_enrollment_grant_plan_context(uuid,uuid,uuid[]) SUPPORT pg_catalog.textlike_support",
            "plan-extra-function" => $"CREATE FUNCTION public.unexpected_plan_function() RETURNS boolean LANGUAGE sql SECURITY DEFINER AS 'SELECT true'; ALTER FUNCTION public.unexpected_plan_function() OWNER TO \"{plan}\"",
            "plan-public-execute" => "GRANT EXECUTE ON FUNCTION public.lock_enrollment_grant_plan_context(uuid,uuid,uuid[]) TO PUBLIC",
            "plan-extra-execute" => $"GRANT EXECUTE ON FUNCTION public.lock_enrollment_grant_plan_context(uuid,uuid,uuid[]) TO \"{extra}\"",
            "plan-grant-option" => $"GRANT EXECUTE ON FUNCTION public.lock_enrollment_grant_plan_context(uuid,uuid,uuid[]) TO {QuoteIdentifier(api)} WITH GRANT OPTION",
            "plan-extra-table" => $"GRANT SELECT ON public.\"Sessions\" TO \"{plan}\"",
            "plan-column" => $"GRANT SELECT(\"Id\") ON public.\"Principals\" TO \"{plan}\"",
            "plan-public-table" => "GRANT SELECT ON public.\"Sessions\" TO PUBLIC",
            "plan-missing-function" => $"REVOKE EXECUTE ON FUNCTION public.has_environment_membership(uuid,uuid) FROM \"{plan}\"",
            "plan-missing-schema" => $"REVOKE USAGE ON SCHEMA public FROM \"{plan}\"",
            "api-directory-update" => $"GRANT UPDATE ON public.\"DirectoryObjects\" TO {QuoteIdentifier(api)}",
            "api-directory-column" => $"GRANT UPDATE(\"Status\") ON public.\"DirectorySync\" TO {QuoteIdentifier(api)}",
            "api-extra-schema" => $"GRANT USAGE ON SCHEMA enrollment_execution TO {QuoteIdentifier(api)}",
            _ => throw new ArgumentOutOfRangeException(nameof(fault))
        });
        Assert.Equal(fault == "none", await Valid());
        await transaction.RollbackAsync();
    }
}
