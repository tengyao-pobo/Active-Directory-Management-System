using System.Diagnostics;
using Npgsql;

namespace ItManagement.AgentPlatformGrants.Tests;

[Collection(PlatformGrantCollection.Name)]
public sealed class EnrollmentExecutionSplitDatabaseTests(AgentPlatformGrantFixture fixture)
{
    [Fact]
    public async Task CanonicalPrivateCapabilityProfileRejectsExecutionProvisionBeforeMutation()
    {
        var source = Environment.GetEnvironmentVariable("AGENT_PLATFORM_GRANT_TEST_DB")
            ?? Environment.GetEnvironmentVariable("CONSOLE_TEST_DB")
            ?? throw new InvalidOperationException("A synthetic PostgreSQL test database is required.");
        var builder = new NpgsqlConnectionStringBuilder(source);
        var suffix = Guid.NewGuid().ToString("N");
        var runtime = $"exe_split_r_{suffix}";
        var definer = $"exe_split_d_{suffix}";
        var password = Convert.ToHexString(Guid.NewGuid().ToByteArray());

        await fixture.Execute($"""
            CREATE ROLE "{runtime}" LOGIN PASSWORD '{password}' NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION;
            CREATE ROLE "{definer}" NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION;
            """);
        try
        {
            Assert.Equal((short)2, await fixture.Scalar<short>("SELECT agent_private.agent_capability_isolation_profile()"));
            var before = await ExecutionCatalogFingerprint();
            var result = await RunProvision(builder, runtime, definer, fixture.EnvironmentId);
            Assert.NotEqual(0, result.ExitCode);
            Assert.Contains("55000", result.StandardError, StringComparison.Ordinal);
            Assert.Equal(before, await ExecutionCatalogFingerprint());
        }
        finally
        {
            await fixture.Execute($"DROP ROLE IF EXISTS \"{runtime}\"; DROP ROLE IF EXISTS \"{definer}\";");
        }
    }

    private Task<string> ExecutionCatalogFingerprint() => fixture.Scalar<string>("""
        SELECT pg_catalog.md5(pg_catalog.concat_ws('|',
          (SELECT pg_catalog.string_agg(object.relname||object.relowner::text||COALESCE(object.relacl::text,'')||
                    object.relrowsecurity::text||object.relforcerowsecurity::text,E'\n' ORDER BY object.relname)
             FROM pg_catalog.pg_class object JOIN pg_catalog.pg_namespace namespace ON namespace.oid=object.relnamespace
            WHERE namespace.nspname='enrollment_execution'),
          (SELECT pg_catalog.string_agg(pg_catalog.pg_get_functiondef(function.oid)||COALESCE(function.proacl::text,''),E'\n' ORDER BY function.oid)
             FROM pg_catalog.pg_proc function JOIN pg_catalog.pg_namespace namespace ON namespace.oid=function.pronamespace
            WHERE namespace.nspname='enrollment_execution'),
          (SELECT pg_catalog.string_agg(policy.polname::text||policy.polcmd::text||policy.polroles::text||
                    COALESCE(pg_catalog.pg_get_expr(policy.polqual,policy.polrelid),'')||
                    COALESCE(pg_catalog.pg_get_expr(policy.polwithcheck,policy.polrelid),''),E'\n' ORDER BY policy.polrelid,policy.polname)
             FROM pg_catalog.pg_policy policy JOIN pg_catalog.pg_class object ON object.oid=policy.polrelid
             JOIN pg_catalog.pg_namespace namespace ON namespace.oid=object.relnamespace
            WHERE policy.polname LIKE 'enrollment_execution_%'),
          (SELECT pg_catalog.string_agg(trigger.tgname::text||trigger.tgtype::text||trigger.tgenabled::text,E'\n' ORDER BY trigger.tgrelid,trigger.tgname)
             FROM pg_catalog.pg_trigger trigger WHERE NOT trigger.tgisinternal AND trigger.tgname LIKE 'enrollment_execution_%')))
        """);

    private static async Task<(int ExitCode, string StandardError)> RunProvision(
        NpgsqlConnectionStringBuilder connection, string runtime, string definer, Guid environment)
    {
        var psql = Environment.GetEnvironmentVariable("CONSOLE_TEST_PSQL");
        if (string.IsNullOrWhiteSpace(psql)) psql = "psql";
        var process = new ProcessStartInfo(psql)
        {
            WorkingDirectory = AppContext.BaseDirectory,
            RedirectStandardError = true,
            RedirectStandardOutput = true,
            UseShellExecute = false
        };
        process.Environment["PGPASSWORD"] = connection.Password;
        foreach (var argument in new[]
        {
            "-X", "-h", connection.Host!, "-p", connection.Port.ToString(), "-U", connection.Username!,
            "-d", connection.Database!, "-v", "ON_ERROR_STOP=1", "-v", "VERBOSITY=verbose", "-v", $"execution_runtime_role={runtime}",
            "-v", $"execution_definer_role={definer}", "-v", $"expected_table_owner_role={connection.Username}",
            "-v", $"expected_environment_id={environment}", "-v", $"DBNAME={connection.Database}",
            "-f", "provision-enrollment-execution.sql"
        }) process.ArgumentList.Add(argument);

        using var child = Process.Start(process) ?? throw new InvalidOperationException("Unable to start psql.");
        var output = child.StandardOutput.ReadToEndAsync();
        var error = child.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        try { await child.WaitForExitAsync(timeout.Token); }
        catch (OperationCanceledException)
        {
            child.Kill(entireProcessTree: true);
            await child.WaitForExitAsync();
            throw new TimeoutException("Enrollment execution provisioning timed out.");
        }
        _ = await output;
        return (child.ExitCode, await error);
    }
}
