using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore.Migrations.Operations;
using Npgsql;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantExecutionQueueUpgradeTests
{
    [Fact]
    public async Task Profile4ApiCapabilityPinsMatchCanonicalSourcesAndCompiledPlanMigration()
    {
        var catalog = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "audit-enrollment-profile4-api-capabilities.sql"));
        var contracts = Regex.Matches(catalog, @"(?m)^ \('(?<signature>(?:public|enrollment_execution)\.[^']+)','(?<group>plan|execution|queue|delivery)'.*?'(?<hash>[0-9a-f]{64})','(?:api|owner|runtime)'\),?\r?$");
        Assert.Equal(15, contracts.Count);
        foreach (Match contract in contracts)
        {
            var group = contract.Groups["group"].Value;
            var name = contract.Groups["signature"].Value.Split('(')[0];
            var source = group == "plan"
                ? new global::Persistence.Migrations.EnrollmentGrantPlans().UpOperations.OfType<SqlOperation>().Single(x => x.Sql.Contains("CREATE FUNCTION " + name, StringComparison.Ordinal)).Sql
                : await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, group switch
                {
                    "execution" => "enrollment-execution-functions.sql", "queue" => "enrollment-execution-queue.sql", _ => "enrollment-delivery-profile.sql"
                }));
            var bodies = Regex.Matches(source.Replace("\r\n", "\n", StringComparison.Ordinal),
                @"CREATE (?:OR REPLACE )?FUNCTION " + Regex.Escape(name) + @"\(.*?AS \$function\$(?<body>.*?)\$function\$;", RegexOptions.Singleline);
            var body = Assert.Single(bodies.Cast<Match>()).Groups["body"].Value;
            Assert.Equal(Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(body))).ToLowerInvariant(), contract.Groups["hash"].Value);
        }
    }

    private static async Task VerifyProfile4ApiCapabilitiesAsync(NpgsqlConnection owner, NpgsqlConnection admin, NpgsqlConnection api,
        Guid environment, CancellationToken cancellationToken)
    {
        var catalog = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "audit-enrollment-profile4-api-capabilities.sql"), cancellationToken);
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
                await using var change = new NpgsqlCommand(mutation, admin);
                await change.ExecuteNonQueryAsync(cancellationToken);
                await Check(false);
            }
            finally
            {
                await using var restore = new NpgsqlCommand(restoreSql, admin) { CommandTimeout = 10 };
                await restore.ExecuteNonQueryAsync(CancellationToken.None);
            }
            await Check(true);
        }
        await Check(true);
        await using var identity = new NpgsqlCommand("SELECT pg_catalog.quote_ident(SESSION_USER)", api);
        var apiRole = (string)(await identity.ExecuteScalarAsync(cancellationToken))!;
        var signatures = Regex.Matches(catalog, @"(?m)^ \('((?:public|enrollment_execution)\.[^']+)',").Cast<Match>().Select(m => m.Groups[1].Value).ToArray();
        Assert.Equal(15, signatures.Length);
        var definers = new HashSet<string>(StringComparer.Ordinal);
        foreach (var signature in signatures)
        {
            await using var metadata = new NpgsqlCommand("""
                SELECT pg_catalog.pg_get_functiondef(p.oid),pg_catalog.quote_ident(pg_catalog.pg_get_userbyid(p.proowner)),
                  p.prosecdef,p.provolatile::text
                FROM pg_catalog.pg_proc p WHERE p.oid=pg_catalog.to_regprocedure(@signature)
                """, admin);
            metadata.Parameters.AddWithValue("signature", signature);
            string original, functionOwner, volatility; bool definer;
            await using (var reader = await metadata.ExecuteReaderAsync(cancellationToken))
            {
                Assert.True(await reader.ReadAsync(cancellationToken));
                original = reader.GetString(0); functionOwner = reader.GetString(1); definer = reader.GetBoolean(2); volatility = reader.GetString(3);
                Assert.False(await reader.ReadAsync(cancellationToken));
            }
            definers.Add(functionOwner);
            Assert.Equal(2, Regex.Matches(original, Regex.Escape("$function$")).Count);
            foreach (var mutation in new[]
            {
                original.Insert(original.LastIndexOf("$function$", StringComparison.Ordinal), "\n-- API capability body drift\n"),
                $"ALTER FUNCTION {signature} RESET ALL", $"ALTER FUNCTION {signature} PARALLEL SAFE",
                $"ALTER FUNCTION {signature} RETURNS NULL ON NULL INPUT",
                $"ALTER FUNCTION {signature} SECURITY {(definer ? "INVOKER" : "DEFINER")}",
                $"ALTER FUNCTION {signature} {(volatility == "v" ? "STABLE" : "VOLATILE")}",
            }) await Drift(mutation, original);
            await Drift($"GRANT EXECUTE ON FUNCTION {signature} TO {apiRole} WITH GRANT OPTION",
                $"REVOKE {(signature.StartsWith("public.", StringComparison.Ordinal) ? "GRANT OPTION FOR " : "")}EXECUTE ON FUNCTION {signature} FROM {apiRole}");
            await Drift($"GRANT EXECUTE ON FUNCTION {signature} TO PUBLIC", $"REVOKE EXECUTE ON FUNCTION {signature} FROM PUBLIC");
            var name = signature.Split('(')[0];
            await Drift($"CREATE FUNCTION {name}(text) RETURNS boolean LANGUAGE sql AS 'SELECT false'",
                $"DROP FUNCTION IF EXISTS {name}(text)");
            if (!signature.StartsWith("public.", StringComparison.Ordinal))
                await Drift($"REVOKE EXECUTE ON FUNCTION {signature} FROM {functionOwner}",
                    $"GRANT EXECUTE ON FUNCTION {signature} TO {functionOwner}");
        }
        Assert.Equal(4, definers.Count);
        foreach (var definer in definers)
        {
            foreach (var attribute in new[] { "LOGIN", "SUPERUSER", "BYPASSRLS", "CREATEDB", "CREATEROLE", "INHERIT", "REPLICATION" })
                await Drift($"ALTER ROLE {definer} {attribute}", $"ALTER ROLE {definer} NO{attribute}");
            await Drift($"GRANT {definer} TO {apiRole}", $"REVOKE {definer} FROM {apiRole}");
            var name = "api_catalog_owned_" + Guid.NewGuid().ToString("N");
            await Drift($"CREATE TYPE public.{name} AS ENUM ('probe'); ALTER TYPE public.{name} OWNER TO {definer}",
                $"DROP TYPE IF EXISTS public.{name}");
            await Drift($"CREATE FUNCTION public.{name}() RETURNS boolean LANGUAGE sql AS 'SELECT false'; ALTER FUNCTION public.{name}() OWNER TO {definer}",
                $"DROP FUNCTION IF EXISTS public.{name}()");
        }
        var otherDatabase = "console_api_owned_" + Guid.NewGuid().ToString("N");
        try
        {
            await using (var create = new NpgsqlCommand($"CREATE DATABASE {otherDatabase} TEMPLATE template0", admin))
                await create.ExecuteNonQueryAsync(cancellationToken);
            // An open NpgsqlConnection redacts its password; reuse the fixture's original settings.
            var settings = new NpgsqlConnectionStringBuilder(Environment.GetEnvironmentVariable("CONSOLE_TEST_DB")!);
            var currentSettings = new NpgsqlConnectionStringBuilder(admin.ConnectionString);
            Assert.Equal(currentSettings.Host, settings.Host);
            Assert.Equal(currentSettings.Port, settings.Port);
            Assert.Equal(currentSettings.Username, settings.Username);
            var otherConnectionString = new NpgsqlConnectionStringBuilder(settings.ConnectionString) { Database = otherDatabase, Pooling = false }.ConnectionString;
            await using var other = new NpgsqlConnection(otherConnectionString);
            await other.OpenAsync(cancellationToken);
            await Check(true);
            try
            {
                await using var createType = new NpgsqlCommand($"CREATE TYPE public.api_owned_probe AS ENUM ('probe'); ALTER TYPE public.api_owned_probe OWNER TO {definers.First()}", other);
                await createType.ExecuteNonQueryAsync(cancellationToken);
                await Check(false);
            }
            finally
            {
                await using var dropType = new NpgsqlCommand("DROP TYPE IF EXISTS public.api_owned_probe", other) { CommandTimeout = 10 };
                await dropType.ExecuteNonQueryAsync(CancellationToken.None);
            }
            await Check(true);
        }
        finally
        {
            await using var dropDatabase = new NpgsqlCommand($"DROP DATABASE IF EXISTS {otherDatabase}", admin) { CommandTimeout = 10 };
            await dropDatabase.ExecuteNonQueryAsync(CancellationToken.None);
        }
        await using (var cleanup = new NpgsqlCommand("SELECT count(*) FROM pg_catalog.pg_database WHERE datname=@name", admin))
        {
            cleanup.Parameters.AddWithValue("name", otherDatabase);
            Assert.Equal(0L, await cleanup.ExecuteScalarAsync(cancellationToken));
        }
        async Task RuntimeAudit(bool expected)
        {
            await using var audit = new NpgsqlCommand("SELECT is_valid FROM enrollment_execution.audit_execution_privileges(@environment)", owner);
            audit.Parameters.AddWithValue("environment", environment);
            Assert.Equal(expected, await audit.ExecuteScalarAsync(cancellationToken));
        }
        await RuntimeAudit(true);
        await using var statusIdentity = new NpgsqlCommand("""
            SELECT pg_catalog.quote_ident(r.rolname) FROM pg_catalog.pg_proc p
            CROSS JOIN LATERAL pg_catalog.aclexplode(p.proacl) a JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
            WHERE p.oid=pg_catalog.to_regprocedure('enrollment_execution.read_grant_status_receipt(uuid,uuid)')
              AND r.rolcanlogin AND a.grantee<>p.proowner
            """, owner);
        var extraLogin = (string)(await statusIdentity.ExecuteScalarAsync(cancellationToken))!;
        try
        {
            await using var grant = new NpgsqlCommand($"GRANT EXECUTE ON FUNCTION enrollment_execution.read_execution_record(uuid,uuid) TO {extraLogin}", admin);
            await grant.ExecuteNonQueryAsync(cancellationToken);
            // Catalog-only qualification intentionally cannot validate private purpose bindings.
            await Check(true);
            await RuntimeAudit(false);
            await using var insert = new NpgsqlCommand("""
                INSERT INTO public."EnrollmentGrantOperations"("EnvironmentId","Id") VALUES(@environment,@operation)
                """, api);
            insert.Parameters.AddWithValue("environment", environment);
            insert.Parameters.AddWithValue("operation", Guid.NewGuid());
            var rejected = await Assert.ThrowsAsync<PostgresException>(async () => { await insert.ExecuteNonQueryAsync(cancellationToken); });
            Assert.Equal("55000", rejected.SqlState);
            Assert.Equal("Enrollment grant publication is unavailable.", rejected.MessageText);
        }
        finally
        {
            await using var revoke = new NpgsqlCommand($"REVOKE EXECUTE ON FUNCTION enrollment_execution.read_execution_record(uuid,uuid) FROM {extraLogin}", admin) { CommandTimeout = 10 };
            await revoke.ExecuteNonQueryAsync(CancellationToken.None);
        }
        await Check(true);
        await RuntimeAudit(true);
    }
}
