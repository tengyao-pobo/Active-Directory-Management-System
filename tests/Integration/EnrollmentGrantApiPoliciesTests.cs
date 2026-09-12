using Npgsql;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantExecutionQueueUpgradeTests
{
    private static async Task VerifyProfile4ApiPoliciesAsync(NpgsqlConnection owner, NpgsqlConnection api, CancellationToken cancellationToken)
    {
        var catalog = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "audit-enrollment-profile4-api-policies.sql"), cancellationToken);
        async Task Check(bool expected)
        {
            await using var transaction = await api.BeginTransactionAsync(cancellationToken);
            await using (var path = new NpgsqlCommand("SET LOCAL search_path=pg_catalog,pg_temp", api))
                await path.ExecuteNonQueryAsync(cancellationToken);
            await using var command = new NpgsqlCommand(catalog, api);
            Assert.Equal(expected, await command.ExecuteScalarAsync(cancellationToken));
            await transaction.RollbackAsync(cancellationToken);
        }
        async Task Drift(string mutation, string restoreSql)
        {
            try
            {
                await using var change = new NpgsqlCommand(mutation, owner);
                await change.ExecuteNonQueryAsync(cancellationToken);
                await Check(false);
            }
            finally
            {
                await using var restore = new NpgsqlCommand(restoreSql, owner) { CommandTimeout = 10 };
                await restore.ExecuteNonQueryAsync(CancellationToken.None);
            }
            await Check(true);
        }
        await Check(true);
        await using var identity = new NpgsqlCommand("SELECT pg_catalog.quote_ident(SESSION_USER)", api);
        var apiRole = (string)(await identity.ExecuteScalarAsync(cancellationToken))!;
        await using var ownerIdentity = new NpgsqlCommand("SELECT pg_catalog.quote_ident(SESSION_USER)", owner);
        var ownerRole = (string)(await ownerIdentity.ExecuteScalarAsync(cancellationToken))!;
        var policies = new List<(string Target, string Create, string Command, bool Permissive)>();
        await using (var transaction = await owner.BeginTransactionAsync(cancellationToken))
        {
            await using (var path = new NpgsqlCommand("SET LOCAL search_path=pg_catalog,pg_temp", owner))
                await path.ExecuteNonQueryAsync(cancellationToken);
            await using var command = new NpgsqlCommand("""
                SELECT pg_catalog.format('%I ON public.%I',p.polname,c.relname),
                  pg_catalog.format('CREATE POLICY %I ON public.%I AS %s FOR %s TO %s%s%s',p.polname,c.relname,
                    CASE WHEN p.polpermissive THEN 'PERMISSIVE' ELSE 'RESTRICTIVE' END,
                    CASE p.polcmd WHEN '*' THEN 'ALL' WHEN 'r' THEN 'SELECT' WHEN 'a' THEN 'INSERT' WHEN 'w' THEN 'UPDATE' WHEN 'd' THEN 'DELETE' END,
                    CASE WHEN p.polroles=ARRAY[0::oid] THEN 'PUBLIC' ELSE pg_catalog.quote_ident(pg_catalog.pg_get_userbyid(p.polroles[1])) END,
                    CASE WHEN p.polqual IS NULL THEN '' ELSE ' USING ('||pg_catalog.pg_get_expr(p.polqual,p.polrelid)||')' END,
                    CASE WHEN p.polwithcheck IS NULL THEN '' ELSE ' WITH CHECK ('||pg_catalog.pg_get_expr(p.polwithcheck,p.polrelid)||')' END),
                  p.polcmd::text,p.polpermissive
                FROM pg_catalog.pg_policy p JOIN pg_catalog.pg_class c ON c.oid=p.polrelid
                JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
                WHERE n.nspname='public' AND c.relname IN('EnrollmentGrantOperations','Memberships','EnrollmentGrantRecipientReservations')
                ORDER BY c.relname,p.polname
                """, owner);
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
                policies.Add((reader.GetString(0), reader.GetString(1), reader.GetString(2), reader.GetBoolean(3)));
            await reader.DisposeAsync();
            await transaction.RollbackAsync(cancellationToken);
        }
        Assert.Equal(19, policies.Count);
        foreach (var policy in policies)
        {
            var drop = $"DROP POLICY IF EXISTS {policy.Target};";
            var restore = drop + policy.Create;
            await Drift($"ALTER POLICY {policy.Target} {(policy.Command == "a" ? "WITH CHECK" : "USING")} (false)", restore);
            await Drift($"ALTER POLICY {policy.Target} TO {apiRole}", restore);
            // PostgreSQL collapses PUBLIC plus named roles to PUBLIC. Use two real OIDs.
            await Drift($"ALTER POLICY {policy.Target} TO {ownerRole},{apiRole}", restore);
            await Drift(drop, restore);
            await Drift(drop + policy.Create.Replace(policy.Permissive ? " AS PERMISSIVE " : " AS RESTRICTIVE ",
                policy.Permissive ? " AS RESTRICTIVE " : " AS PERMISSIVE ", StringComparison.Ordinal), restore);
            var command = policy.Command switch { "*" => "ALL", "r" => "SELECT", "a" => "INSERT", "w" => "UPDATE", "d" => "DELETE", _ => throw new InvalidOperationException() };
            await Drift(drop + policy.Create.Replace($" FOR {command} TO ",
                $" FOR {(policy.Command == "w" ? "ALL" : "UPDATE")} TO ", StringComparison.Ordinal), restore);
            // ALL can have a NULL check (queue) or an explicit one; both must be exact.
            if (policy.Command is "*" or "w")
                await Drift($"ALTER POLICY {policy.Target} WITH CHECK (true)", restore);
            if (policy.Target.StartsWith("enrollment_execution_worker_operations_allow ", StringComparison.Ordinal))
                await Drift(drop + policy.Create[..policy.Create.IndexOf(" WITH CHECK (", StringComparison.Ordinal)], restore);
            if (policy.Target.StartsWith("enrollment_execution_queue_operations_allow ", StringComparison.Ordinal))
            {
                var usingClause = policy.Create[(policy.Create.IndexOf(" USING (", StringComparison.Ordinal) + " USING ".Length)..];
                await Drift($"ALTER POLICY {policy.Target} WITH CHECK {usingClause}", restore);
            }
        }
        foreach (var table in new[] { "EnrollmentGrantOperations", "Memberships", "EnrollmentGrantRecipientReservations" })
        {
            foreach (var mode in new[] { "PERMISSIVE", "RESTRICTIVE" })
                await Drift($"CREATE POLICY api_catalog_extra ON public.\"{table}\" AS {mode} USING (true)",
                    $"DROP POLICY IF EXISTS api_catalog_extra ON public.\"{table}\"");
            await Drift($"ALTER TABLE public.\"{table}\" DISABLE ROW LEVEL SECURITY",
                $"ALTER TABLE public.\"{table}\" ENABLE ROW LEVEL SECURITY");
            await Drift($"ALTER TABLE public.\"{table}\" NO FORCE ROW LEVEL SECURITY",
                $"ALTER TABLE public.\"{table}\" FORCE ROW LEVEL SECURITY");
        }
    }
}
