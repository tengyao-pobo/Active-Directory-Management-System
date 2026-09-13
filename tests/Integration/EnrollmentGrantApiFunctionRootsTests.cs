using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore.Migrations.Operations;
using Npgsql;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantExecutionQueueUpgradeTests
{
    private static readonly (string Name, string Signature, string Source)[] ApiFunctionRoots =
    [
        ("enrollment_execution.execution_store_profile", "enrollment_execution.execution_store_profile()", "upgrade-enrollment-execution-v3-to-v4.sql"),
        ("enrollment_execution.audit_execution_privileges", "enrollment_execution.audit_execution_privileges(uuid)", "enrollment-profile4-runtime-audit.sql"),
        ("enrollment_execution.audit_delivery_privileges", "enrollment_execution.audit_delivery_privileges(uuid)", "enrollment-delivery-profile.sql"),
        ("enrollment_execution.guard_profile4_publication", "enrollment_execution.guard_profile4_publication()", "enrollment-profile4-publication.sql"),
        ("public.api_database_session", "public.api_database_session()", "enrollment-delivery-identity.sql"),
        ("public.has_environment_membership", "public.has_environment_membership(uuid,uuid)", "enrollment-profile4-membership.sql"),
        ("public.directory_database_access", "public.directory_database_access(uuid,uuid)", "")
    ];

    [Fact]
    public async Task Profile4ApiFunctionPinsMatchIndependentSqlAndCompiledMigration()
    {
        var catalog = (await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "audit-enrollment-profile4-api-functions.sql"))).Replace("\r\n", "\n", StringComparison.Ordinal);
        foreach (var root in ApiFunctionRoots)
        {
            var source = root.Source.Length == 0
                ? Assert.Single(new global::Persistence.Migrations.BindDirectoryDatabaseIdentity().UpOperations.OfType<SqlOperation>()).Sql
                : await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, root.Source));
            source = source.Replace("\r\n", "\n", StringComparison.Ordinal);
            var tail = root.Name.EndsWith("execution_store_profile", StringComparison.Ordinal)
                ? "AS '(?<body>[^']*)';"
                : root.Source.Length == 0 ? @"AS \$\$(?<body>.*?)\$\$;" : @"AS \$function\$(?<body>.*?)\$function\$;";
            var functions = Regex.Matches(source, @"CREATE (?:OR REPLACE )?FUNCTION " + Regex.Escape(root.Name) + @"\(.*?\).*?" + tail, RegexOptions.Singleline);
            var body = Assert.Single(functions.Cast<Match>()).Groups["body"].Value;
            var pins = Regex.Matches(catalog, @"(?m)^ \('" + Regex.Escape(root.Signature) + @"',.*?'([0-9a-f]{64})','[^']+'\),?$");
            Assert.Equal(Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(body))).ToLowerInvariant(),
                Assert.Single(pins.Cast<Match>()).Groups[1].Value);
        }
    }

    private static async Task VerifyProfile4ApiFunctionRootsAsync(NpgsqlConnection owner, NpgsqlConnection api, CancellationToken cancellationToken)
    {
        var catalog = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "audit-enrollment-profile4-api-functions.sql"), cancellationToken);
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
                // Commit catalog drift so the separate physical API LOGIN sees it.
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
        // Object OIDs permit catalog inspection without private namespace resolution.
        await using (var capabilities = new NpgsqlCommand("""
            SELECT pg_catalog.has_schema_privilege(n.oid,'USAGE'),
              pg_catalog.has_table_privilege(c.oid,'SELECT'),pg_catalog.has_any_column_privilege(c.oid,'SELECT'),
              pg_catalog.has_function_privilege(p.oid,'EXECUTE')
            FROM pg_catalog.pg_namespace n JOIN pg_catalog.pg_class c ON c.relnamespace=n.oid
            JOIN pg_catalog.pg_proc p ON p.pronamespace=n.oid
            WHERE n.nspname='enrollment_execution' AND c.relname='role_reservations'
              AND p.proname='audit_execution_privileges' AND p.proargtypes::text='2950'
            """, api))
        {
            await using var reader = await capabilities.ExecuteReaderAsync(cancellationToken);
            Assert.True(await reader.ReadAsync(cancellationToken));
            for (var field = 0; field < 4; field++) Assert.False(reader.GetBoolean(field));
            Assert.False(await reader.ReadAsync(cancellationToken));
        }
        await using var apiIdentity = new NpgsqlCommand("SELECT pg_catalog.quote_ident(SESSION_USER)", api);
        var apiRole = (string)(await apiIdentity.ExecuteScalarAsync(cancellationToken))!;
        foreach (var grantee in new[] { apiRole, "PUBLIC" })
        foreach (var privilege in new[] { "USAGE", "CREATE" })
            await Drift($"GRANT {privilege} ON SCHEMA enrollment_execution TO {grantee}",
                $"REVOKE {privilege} ON SCHEMA enrollment_execution FROM {grantee}");
        foreach (var root in ApiFunctionRoots)
        {
            await using var definition = new NpgsqlCommand("SELECT pg_catalog.pg_get_functiondef(pg_catalog.to_regprocedure(@signature))", owner);
            definition.Parameters.AddWithValue("signature", root.Signature);
            var original = (string)(await definition.ExecuteScalarAsync(cancellationToken))!;
            Assert.Equal(2, Regex.Matches(original, Regex.Escape("$function$")).Count);
            var changedBody = original.Insert(original.LastIndexOf("$function$", StringComparison.Ordinal), "\n-- API catalog body drift\n");
            var isMarker = root.Name.EndsWith("execution_store_profile", StringComparison.Ordinal);
            var isMembership = root.Name.EndsWith("has_environment_membership", StringComparison.Ordinal);
            foreach (var mutation in new[]
            {
                changedBody,
                $"ALTER FUNCTION {root.Signature} RESET ALL",
                $"ALTER FUNCTION {root.Signature} SECURITY {(isMarker ? "DEFINER" : "INVOKER")}",
                $"ALTER FUNCTION {root.Signature} {(isMarker ? "VOLATILE" : "IMMUTABLE")}",
                $"ALTER FUNCTION {root.Signature} PARALLEL {(isMarker ? "UNSAFE" : "SAFE")}",
                $"ALTER FUNCTION {root.Signature} {(isMembership ? "CALLED ON NULL INPUT" : "RETURNS NULL ON NULL INPUT")}"
            }) await Drift(mutation, original);

            var isPublic = root.Name == "public.api_database_session";
            await Drift(
                $"{(isPublic ? "REVOKE" : "GRANT")} EXECUTE ON FUNCTION {root.Signature} {(isPublic ? "FROM" : "TO")} PUBLIC",
                $"{(isPublic ? "GRANT" : "REVOKE")} EXECUTE ON FUNCTION {root.Signature} {(isPublic ? "TO" : "FROM")} PUBLIC");
            var hasDirectApiGrant = isMembership || root.Name == "public.directory_database_access";
            await Drift(
                $"GRANT EXECUTE ON FUNCTION {root.Signature} TO {apiRole} WITH GRANT OPTION",
                $"REVOKE {(hasDirectApiGrant ? "GRANT OPTION FOR " : "")}EXECUTE ON FUNCTION {root.Signature} FROM {apiRole}");
            await Drift(
                $"CREATE FUNCTION {root.Name}(text) RETURNS boolean LANGUAGE sql AS 'SELECT false'",
                $"DROP FUNCTION IF EXISTS {root.Name}(text)");
        }
    }
}
