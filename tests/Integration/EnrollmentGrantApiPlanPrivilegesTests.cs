using Npgsql;
using System.Text.RegularExpressions;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantExecutionQueueUpgradeTests
{
    [Fact]
    public async Task Profile4ApiPlanPrivilegeTablesMatchProvisioningSource()
    {
        var source = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "provision-runtime.sql"));
        var catalog = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "audit-enrollment-profile4-api-plan-privileges.sql"));
        var actual = new List<string>();
        foreach (Match grant in Regex.Matches(source, "GRANT (?<privileges>SELECT(?:, UPDATE)?) ON (?<tables>[^;]+) TO :\"enrollment_plan_lock_owner_role\";"))
        foreach (Match table in Regex.Matches(grant.Groups["tables"].Value, "\"(?<table>\\w+)\""))
        foreach (var privilege in grant.Groups["privileges"].Value.Split(',', StringSplitOptions.TrimEntries))
            actual.Add(table.Groups["table"].Value + "|" + privilege);
        var block = catalog[catalog.IndexOf("expected_tables(table_name,privilege_type)", StringComparison.Ordinal)..catalog.IndexOf("), expected_table_acl", StringComparison.Ordinal)];
        var expected = Regex.Matches(block, @"\('([^']+)','([^']+)'\)").Select(x => x.Groups[1].Value + "|" + x.Groups[2].Value).ToArray();
        Assert.Equal(11, expected.Length);
        Assert.Equal(expected.Order(), actual.Order());
    }

    private static async Task VerifyProfile4ApiPlanPrivilegesAsync(NpgsqlConnection owner, NpgsqlConnection admin, NpgsqlConnection api, CancellationToken cancellationToken)
    {
        var catalog = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "audit-enrollment-profile4-api-plan-privileges.sql"), cancellationToken);
        var prefix = catalog[..catalog.LastIndexOf("\nSELECT COALESCE", StringComparison.Ordinal)];
        async Task Check(bool expected)
        {
            await using var transaction = await api.BeginTransactionAsync(cancellationToken);
            await using (var path = new NpgsqlCommand("SET LOCAL search_path=pg_catalog,pg_temp", api))
                await path.ExecuteNonQueryAsync(cancellationToken);
            await using var command = new NpgsqlCommand(catalog, api);
            var valid = (bool)(await command.ExecuteScalarAsync(cancellationToken))!;
            if (expected && !valid)
            {
                await using var diagnostic = new NpgsqlCommand(prefix + """

                    SELECT n.nspname||'.'||p.proname FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace CROSS JOIN identities i
                    WHERE n.nspname NOT IN('pg_catalog','information_schema') AND pg_catalog.has_function_privilege(i.plan_oid,p.oid,'EXECUTE')
                    """, api);
                var details = new List<string>();
                await using var reader = await diagnostic.ExecuteReaderAsync(cancellationToken);
                while (await reader.ReadAsync(cancellationToken)) details.Add(reader.GetString(0));
                Assert.Fail("Canonical plan privileges rejected; effective routines: " + string.Join(",", details));
            }
            Assert.Equal(expected, valid);
            await transaction.RollbackAsync(cancellationToken);
        }
        await Check(true);
        await using var identity = new NpgsqlCommand(prefix + "\nSELECT pg_catalog.quote_ident(pg_catalog.pg_get_userbyid(plan_oid)) FROM identities", owner);
        var planRole = (string)(await identity.ExecuteScalarAsync(cancellationToken))!;
        async Task Drift(string mutation, string restoreSql, NpgsqlConnection? writer = null)
        {
            try
            {
                await using var change = new NpgsqlCommand(mutation, writer ?? owner);
                await change.ExecuteNonQueryAsync(cancellationToken);
                await Check(false);
            }
            finally
            {
                await using var restore = new NpgsqlCommand(restoreSql, writer ?? owner) { CommandTimeout = 10 };
                await restore.ExecuteNonQueryAsync(CancellationToken.None);
            }
            await Check(true);
        }
        var grants = new List<(string Table, string Privilege)>();
        await using (var command = new NpgsqlCommand(prefix + "\nSELECT pg_catalog.quote_ident(table_name),privilege_type FROM expected_tables", owner))
        {
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken)) grants.Add((reader.GetString(0), reader.GetString(1)));
        }
        Assert.Equal(11, grants.Count);
        foreach (var grant in grants)
        {
            await Drift($"REVOKE {grant.Privilege} ON public.{grant.Table} FROM {planRole}",
                $"GRANT {grant.Privilege} ON public.{grant.Table} TO {planRole}");
            await Drift($"GRANT {grant.Privilege} ON public.{grant.Table} TO {planRole} WITH GRANT OPTION",
                $"REVOKE GRANT OPTION FOR {grant.Privilege} ON public.{grant.Table} FROM {planRole}");
        }
        foreach (var function in new[] { "public.has_environment_membership(uuid,uuid)", "public.directory_database_access(uuid,uuid)" })
        {
            await Drift($"REVOKE EXECUTE ON FUNCTION {function} FROM {planRole}", $"GRANT EXECUTE ON FUNCTION {function} TO {planRole}");
            await Drift($"GRANT EXECUTE ON FUNCTION {function} TO {planRole} WITH GRANT OPTION", $"REVOKE GRANT OPTION FOR EXECUTE ON FUNCTION {function} FROM {planRole}");
        }
        foreach (var grantee in new[] { planRole, "PUBLIC" })
        {
            await Drift($"GRANT DELETE ON public.\"Environments\" TO {grantee}", $"REVOKE DELETE ON public.\"Environments\" FROM {grantee}");
            await Drift($"GRANT SELECT ON public.\"Outbox\" TO {grantee}", $"REVOKE SELECT ON public.\"Outbox\" FROM {grantee}");
            await Drift($"GRANT INSERT (\"Id\") ON public.\"Principals\" TO {grantee}", $"REVOKE INSERT (\"Id\") ON public.\"Principals\" FROM {grantee}");
            await Drift($"GRANT EXECUTE ON FUNCTION public.guard_operator_identity() TO {grantee}", $"REVOKE EXECUTE ON FUNCTION public.guard_operator_identity() FROM {grantee}");
        }
        await Drift($"GRANT SELECT (\"Id\") ON public.\"Principals\" TO {planRole}", $"REVOKE SELECT (\"Id\") ON public.\"Principals\" FROM {planRole}");
        await Drift($"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO {planRole}",
            $"ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE SELECT ON TABLES FROM {planRole}");
        await Drift($"CREATE SEQUENCE public.api_plan_sequence; GRANT USAGE ON SEQUENCE public.api_plan_sequence TO PUBLIC",
            "DROP SEQUENCE IF EXISTS public.api_plan_sequence");
        await Drift("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO PUBLIC",
            "ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE SELECT ON TABLES FROM PUBLIC");
        await Drift("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE ON SEQUENCES TO PUBLIC",
            "ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE USAGE ON SEQUENCES FROM PUBLIC");
        await Drift($"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO {planRole}",
            $"ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE EXECUTE ON FUNCTIONS FROM {planRole}");
        await Drift($"GRANT USAGE ON SCHEMA enrollment_execution TO {planRole}", $"REVOKE USAGE ON SCHEMA enrollment_execution FROM {planRole}");
        await Drift($"REVOKE USAGE ON SCHEMA public FROM {planRole}", $"GRANT USAGE ON SCHEMA public TO {planRole}");
        await Drift($"GRANT USAGE ON SCHEMA public TO {planRole} WITH GRANT OPTION", $"REVOKE GRANT OPTION FOR USAGE ON SCHEMA public FROM {planRole}");
        await using var database = new NpgsqlCommand("SELECT pg_catalog.quote_ident(pg_catalog.current_database())", owner);
        var databaseName = (string)(await database.ExecuteScalarAsync(cancellationToken))!;
        foreach (var grantee in new[] { planRole, "PUBLIC" })
        {
            await Drift($"GRANT CREATE ON SCHEMA public TO {grantee}", $"REVOKE CREATE ON SCHEMA public FROM {grantee}");
            await Drift($"GRANT CREATE ON DATABASE {databaseName} TO {grantee}", $"REVOKE CREATE ON DATABASE {databaseName} FROM {grantee}");
            await Drift($"GRANT SET ON PARAMETER session_replication_role TO {grantee}", $"REVOKE SET ON PARAMETER session_replication_role FROM {grantee}", admin);
        }
        await using var apiIdentity = new NpgsqlCommand("SELECT pg_catalog.quote_ident(SESSION_USER)", api);
        var apiRole = (string)(await apiIdentity.ExecuteScalarAsync(cancellationToken))!;
        try
        {
            await using var grantOption = new NpgsqlCommand($"GRANT SELECT ON public.\"Environments\" TO {apiRole} WITH GRANT OPTION", owner);
            await grantOption.ExecuteNonQueryAsync(cancellationToken);
            // The same expected privilege from a second grantor must not pass exact ACL equality.
            await Drift($"GRANT SELECT ON public.\"Environments\" TO {planRole}",
                $"REVOKE SELECT ON public.\"Environments\" FROM {planRole}", api);
        }
        finally
        {
            await using var restore = new NpgsqlCommand($"REVOKE GRANT OPTION FOR SELECT ON public.\"Environments\" FROM {apiRole}", owner) { CommandTimeout = 10 };
            await restore.ExecuteNonQueryAsync(CancellationToken.None);
        }
        await Check(true);
    }
}
