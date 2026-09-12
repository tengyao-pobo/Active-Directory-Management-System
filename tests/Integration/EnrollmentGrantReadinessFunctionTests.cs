using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Npgsql;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantExecutionQueueUpgradeTests
{
    [Fact]
    public async Task Profile4FunctionContractsMatchIndependentSources()
    {
        var rows = new List<string>();
        foreach (var (name, file, volatility, definer, type) in new[] {
            ("guard_profile4_readiness", "enrollment-profile4-readiness.sql", "v", "false", 2279),
            ("profile4_ready", "enrollment-profile4-ready.sql", "s", "true", 16) })
        {
            var source = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, file));
            var matches = Regex.Matches(source, @"CREATE FUNCTION enrollment_execution\." + Regex.Escape(name) + @"\(\).*?AS \$function\$(?<body>.*?)\$function\$;", RegexOptions.Singleline);
            Assert.Single(matches);
            var body = matches[0].Groups["body"].Value.Replace("\r\n", "\n", StringComparison.Ordinal);
            var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(body))).ToLowerInvariant();
            rows.Add($" ('enrollment_execution.{name}()','{volatility}',{definer},{type}::oid,'{hash}')");
        }
        var catalog = (await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "audit-enrollment-profile4-readiness-functions.sql"))).Replace("\r\n", "\n", StringComparison.Ordinal);
        var blocks = Regex.Matches(catalog, "-- BEGIN generated readiness function contracts\n(?<rows>.*?)\n-- END generated readiness function contracts", RegexOptions.Singleline);
        Assert.Single(blocks);
        Assert.Equal(string.Join(",\n", rows), blocks[0].Groups["rows"].Value);
    }

    private static async Task VerifyReadinessFunctionsAsync(NpgsqlConnection owner, CancellationToken cancellationToken)
    {
        var source = (await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "audit-enrollment-profile4-readiness-functions.sql"), cancellationToken))
            .Replace(":'expected_table_owner_role'", "@owner", StringComparison.Ordinal);
        async Task Audit(bool expected, string context = "baseline")
        {
            await using var command = new NpgsqlCommand(source, owner);
            command.Parameters.AddWithValue("owner", new NpgsqlConnectionStringBuilder(owner.ConnectionString).Username!);
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            Assert.True(await reader.ReadAsync(cancellationToken));
            Assert.True(expected == reader.GetBoolean(0), context);
            Assert.False(await reader.ReadAsync(cancellationToken));
        }
        await Audit(true);
        var mutations = new List<string>();
        foreach (var name in new[] { "guard_profile4_readiness", "profile4_ready" })
        {
            var signature = "enrollment_execution." + name + "()";
            mutations.AddRange(new[] {
                $"ALTER FUNCTION {signature} RENAME TO missing_{name}",
                $"ALTER FUNCTION {signature} SET search_path=public,pg_temp",
                $"ALTER FUNCTION {signature} SET row_security=off",
                $"ALTER FUNCTION {signature} SET statement_timeout='5s'",
                $"ALTER FUNCTION {signature} PARALLEL SAFE",
                $"ALTER FUNCTION {signature} STRICT",
                $"ALTER FUNCTION {signature} " + (name == "profile4_ready" ? "VOLATILE" : "STABLE"),
                $"ALTER FUNCTION {signature} " + (name == "profile4_ready" ? "SECURITY INVOKER" : "SECURITY DEFINER"),
                $"GRANT EXECUTE ON FUNCTION {signature} TO PUBLIC",
                $"CREATE FUNCTION enrollment_execution.{name}(integer) RETURNS boolean LANGUAGE sql AS 'SELECT true'"
            });
        }
        mutations.Add("CREATE OR REPLACE FUNCTION enrollment_execution.profile4_ready() RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $f$ BEGIN RETURN true; END $f$");
        mutations.Add("CREATE OR REPLACE FUNCTION enrollment_execution.guard_profile4_readiness() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,pg_temp SET row_security=on AS $f$ BEGIN RETURN NEW; END $f$");
        mutations.Add("DROP FUNCTION enrollment_execution.profile4_ready(); CREATE FUNCTION enrollment_execution.profile4_ready() RETURNS SETOF boolean LANGUAGE sql AS 'SELECT true'");
        mutations.Add("DROP FUNCTION enrollment_execution.guard_profile4_readiness() CASCADE; CREATE FUNCTION enrollment_execution.guard_profile4_readiness() RETURNS boolean LANGUAGE sql AS 'SELECT true'");
        foreach (var mutation in mutations)
        {
            await using var transaction = await owner.BeginTransactionAsync(cancellationToken);
            await using var command = new NpgsqlCommand(mutation, owner);
            await command.ExecuteNonQueryAsync(cancellationToken);
            await Audit(false, mutation);
            await transaction.RollbackAsync(cancellationToken);
            await Audit(true);
        }
    }
}
