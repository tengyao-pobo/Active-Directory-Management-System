using Npgsql;
using System.Text.RegularExpressions;

namespace ItManagement.AgentPlatformGrants.Tests;

[Collection(PlatformGrantCollection.Name)]
public sealed class PlatformGrantIsolationUpgradeTests(AgentPlatformGrantFixture fixture)
{
    [Fact]
    public async Task StandaloneUpgradeInstallsTheCurrentAuditDefinitions()
    {
        var upgrade = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "upgrade-agent-platform-grant-isolation-v1.sql"));
        foreach (var (file, name) in new[]
        {
            ("agent-store.sql", "platform_grant_role_is_unbound"),
            ("agent-store.sql", "audit_ingest_privileges"),
            ("agent-enrollment-store.sql", "audit_enrollment_privileges"),
            ("agent-projection-store.sql", "audit_projection_privileges")
        })
        {
            var source = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, file));
            var pattern = @"CREATE OR REPLACE FUNCTION agent_private\." + Regex.Escape(name) + @"\(.*?\$function\$;";
            var expected = Assert.Single(Regex.Matches(source, pattern, RegexOptions.Singleline).Cast<Match>());
            var actual = Assert.Single(Regex.Matches(upgrade, pattern, RegexOptions.Singleline).Cast<Match>());
            Assert.Equal(expected.Value.ReplaceLineEndings("\n"), actual.Value.ReplaceLineEndings("\n"));
        }
    }

    [Fact]
    public async Task CompletedUpgradeIsIdempotentAndKeepsRuntimeAcl()
    {
        var before = await Fingerprint();
        await fixture.Script("upgrade-agent-platform-grant-isolation-v1.sql", fixture.IsolationUpgrade());
        Assert.Equal(before, await Fingerprint());
        Assert.Equal((short)1, await fixture.Scalar<short>("SELECT agent_private.platform_grant_isolation_profile()"));
    }

    [Fact]
    public async Task UnsafeOwnerFailsBeforeAnyAuditReplacement()
    {
        var before = await Fingerprint();
        await fixture.Execute($"ALTER ROLE \"{fixture.ProjectionDefinerRole}\" INHERIT");
        try
        {
            await AssertRejected(() => fixture.Script("upgrade-agent-platform-grant-isolation-v1.sql", fixture.IsolationUpgrade()));
            Assert.Equal(before, await Fingerprint());
        }
        finally { await fixture.Execute($"ALTER ROLE \"{fixture.ProjectionDefinerRole}\" NOINHERIT"); }
    }

    [Fact]
    public async Task UnexpectedHelperGranteeFailsPostflightAndRollsBackAuditChanges()
    {
        // This grant is confined to the isolated synthetic database and always restored.
        await fixture.Execute($"GRANT EXECUTE ON FUNCTION agent_private.platform_grant_role_is_unbound(name) TO \"{fixture.PlatformRole}\"");
        var before = await Fingerprint();
        try
        {
            await AssertRejected(() => fixture.Script("upgrade-agent-platform-grant-isolation-v1.sql", fixture.IsolationUpgrade()));
            Assert.Equal(before, await Fingerprint());
        }
        finally { await fixture.Execute($"REVOKE EXECUTE ON FUNCTION agent_private.platform_grant_role_is_unbound(name) FROM \"{fixture.PlatformRole}\""); }
    }

    [Fact]
    public async Task ProjectionDowngradeRejectsInstalledExtensionWithoutChangingState()
    {
        var before = await Fingerprint();
        var bindings = await fixture.Scalar<long>("SELECT count(*) FROM agent_private.platform_grant_database_bindings");
        await AssertRejected(() => fixture.Script("downgrade-v2-to-v1.sql", fixture.ProjectionDowngrade()));
        Assert.Equal(before, await Fingerprint());
        Assert.Equal(bindings, await fixture.Scalar<long>("SELECT count(*) FROM agent_private.platform_grant_database_bindings"));
        Assert.Equal("TABLE(is_valid boolean, diagnostic_code text, profile_version smallint)",
            await fixture.Scalar<string>("SELECT pg_get_function_result('agent_private.audit_projection_privileges(uuid,name,name)'::regprocedure)"));
    }

    private static async Task AssertRejected(Func<Task> action)
    {
        var error = await Assert.ThrowsAnyAsync<Exception>(action);
        while (error is not PostgresException && error.InnerException is not null) error = error.InnerException;
        Assert.Equal(PostgresErrorCodes.DivisionByZero, Assert.IsType<PostgresException>(error).SqlState);
    }

    private Task<string> Fingerprint() => fixture.Scalar<string>("""
        SELECT md5(string_agg(pg_get_functiondef(p.oid)||p.proowner::text||coalesce(p.proacl::text,''), E'\n' ORDER BY p.oid))
        FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
        WHERE n.nspname='agent_private'
        """);
}
