using Npgsql;

namespace ItManagement.AgentEnrollmentTargets.Tests;

[Collection(EnrollmentTargetCollection.Name)]
public sealed class CapabilityIsolationUpgradeTests(AgentEnrollmentTargetFixture fixture)
{
    [Fact]
    public async Task CompletedUpgradePreservesNewCapabilityReservationsAndIsIdempotent()
    {
        var before = await Fingerprint();
        await fixture.Script("upgrade-agent-capability-isolation-v2.sql", fixture.CapabilityUpgrade());
        Assert.Equal(before, await Fingerprint());
        Assert.Equal((short)2, await fixture.Scalar<short>("SELECT agent_private.agent_capability_isolation_profile()"));
        Assert.Equal(2, await fixture.Scalar<long>("SELECT count(*) FROM agent_private.agent_capability_roles WHERE capability='EnrollmentTargetRead' AND role_name IN(@runtime::name,@definer::name)",
            new NpgsqlParameter("runtime", fixture.TargetRole), new NpgsqlParameter("definer", fixture.TargetDefinerRole)));
    }

    [Fact]
    public async Task FailureAfterAuditReplacementRollsBackTheWholeUpgrade()
    {
        var sql = await File.ReadAllTextAsync(System.IO.Path.Combine(AppContext.BaseDirectory, "upgrade-agent-capability-isolation-v2.sql"));
        const string postflight = "SELECT 1/pg_catalog.count(*) AS capability_registry_postflight";
        Assert.Equal(1, sql.Split(postflight, StringSplitOptions.None).Length - 1);
        sql = sql.Replace(postflight,
            $"GRANT EXECUTE ON FUNCTION agent_private.agent_role_has_capability(name,text,text) TO {Id(fixture.TargetRole)};\n{postflight}", StringComparison.Ordinal);
        sql = string.Join('\n', sql.Split('\n').Where(line => !line.StartsWith('\\')));
        foreach (var replacement in fixture.CapabilityUpgrade().OrderByDescending(x => x.Key.Length))
            sql = sql.Replace(replacement.Key, replacement.Value, StringComparison.Ordinal);
        var before = await Fingerprint();
        await Rejected(() => fixture.Execute(sql));
        Assert.Equal(before, await Fingerprint());
    }

    [Theory]
    [InlineData("downgrade-v2-to-v1.sql")]
    [InlineData("upgrade-v1-to-v2.sql")]
    [InlineData("upgrade-agent-platform-grant-isolation-v1.sql")]
    public async Task LegacyAuditReplacementCannotInvalidateCompletedCapabilityIsolation(string file)
    {
        var before = await Fingerprint();
        await Rejected(() => fixture.Script(file, file == "upgrade-agent-platform-grant-isolation-v1.sql" ? fixture.IsolationUpgrade() : fixture.ProjectionDowngrade()));
        Assert.Equal(before, await Fingerprint());
    }

    [Theory]
    [InlineData("ingest", false)] [InlineData("ingest", true)]
    [InlineData("enrollment", false)] [InlineData("enrollment", true)]
    [InlineData("issue", false)] [InlineData("issue", true)]
    [InlineData("projection", false)] [InlineData("projection", true)]
    [InlineData("platform", false)] [InlineData("platform", true)]
    [InlineData("platform-revoker", false)] [InlineData("platform-revoker", true)]
    public async Task ExistingProvisionersCannotReuseTargetRuntimeOrDefiner(string capability, bool definer)
    {
        var role = definer ? fixture.TargetDefinerRole : fixture.TargetRole;
        var (file, replacements) = ExistingProvision(capability, role);
        var before = await Fingerprint();
        await Rejected(() => fixture.Script(file, replacements));
        Assert.Equal(before, await Fingerprint());
    }

    [Theory]
    [InlineData("ingest")] [InlineData("enroll")] [InlineData("issue")]
    [InlineData("projection")] [InlineData("platform")] [InlineData("revoker")]
    public async Task TargetProvisionerCannotReuseExistingRuntime(string capability)
    {
        var role = capability switch
        {
            "ingest" => fixture.IngestRole, "enroll" => fixture.EnrollRole,
            "issue" => fixture.IssueRole, "projection" => fixture.ProjectionRole, "revoker" => fixture.RevokerRole, _ => fixture.PlatformRole
        };
        var replacements = fixture.TargetProvision(Database);
        SetRole(replacements, "agent_enrollment_target_role", role);
        var before = await Fingerprint();
        await Rejected(() => fixture.Script("provision-agent-enrollment-target.sql", replacements));
        Assert.Equal(before, await Fingerprint());
    }

    private (string File, Dictionary<string, string> Replacements) ExistingProvision(string capability, string role)
    {
        var replacements = new Dictionary<string, string>
        {
            [":'environment_id'"] = Lit(fixture.EnvironmentId.ToString()), [":DBNAME"] = Id(Database)
        };
        SetRole(replacements, "agent_table_owner_role", fixture.TableOwnerRole);
        switch (capability)
        {
            case "ingest":
                SetRole(replacements, "agent_definer_role", fixture.TableOwnerRole);
                SetRole(replacements, "agent_ingest_role", role);
                return ("provision-agent-store.sql", replacements);
            case "enrollment":
            case "issue":
                SetRole(replacements, "agent_enrollment_definer_role", fixture.EnrollmentDefinerRole);
                SetRole(replacements, "agent_enroll_role", capability == "enrollment" ? role : fixture.EnrollRole);
                SetRole(replacements, "agent_issue_role", capability == "issue" ? role : fixture.IssueRole);
                return ("provision-agent-enrollment.sql", replacements);
            case "projection":
                SetRole(replacements, "agent_projection_definer_role", fixture.ProjectionDefinerRole);
                SetRole(replacements, "agent_projection_role", role);
                return ("provision-agent-projection.sql", replacements);
            default:
                SetRole(replacements, "agent_platform_grant_definer_role", fixture.PlatformDefinerRole);
                SetRole(replacements, "agent_platform_grant_role", capability == "platform-revoker" ? fixture.PlatformRole : role);
                SetRole(replacements, "agent_platform_grant_revoker_role", capability == "platform-revoker" ? role : fixture.RevokerRole);
                return ("provision-agent-platform-grants.sql", replacements);
        }
    }

    private string Database => new NpgsqlConnectionStringBuilder(fixture.Owner.ConnectionString).Database!;
    private static string Id(string value) => '"' + value.Replace("\"", "\"\"", StringComparison.Ordinal) + '"';
    private static string Lit(string value) => "'" + value.Replace("'", "''", StringComparison.Ordinal) + "'";
    private static void SetRole(Dictionary<string, string> replacements, string variable, string role)
    {
        replacements[$":\"{variable}\""] = Id(role);
        replacements[$":'{variable}'"] = Lit(role);
    }

    private static async Task Rejected(Func<Task> action)
    {
        var error = await Assert.ThrowsAnyAsync<Exception>(action);
        while (error is not PostgresException && error.InnerException is not null) error = error.InnerException;
        Assert.Equal(PostgresErrorCodes.DivisionByZero, Assert.IsType<PostgresException>(error).SqlState);
    }

    private Task<string> Fingerprint() => fixture.Scalar<string>("""
        SELECT md5(concat_ws('|',
          (SELECT string_agg(pg_get_functiondef(p.oid)||p.proowner::text||coalesce(p.proacl::text,''), E'\n' ORDER BY p.oid)
           FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='agent_private'),
          (SELECT string_agg(row(role_name,capability,role_kind)::text,E'\n' ORDER BY role_name) FROM agent_private.agent_capability_roles),
          (SELECT string_agg(row(rolname,rolcanlogin,rolsuper,rolbypassrls,rolcreatedb,rolcreaterole,rolinherit,rolreplication)::text,E'\n' ORDER BY rolname)
           FROM pg_roles WHERE rolname::text=ANY(@roles)),
          (SELECT string_agg(to_jsonb(binding)::text,E'\n' ORDER BY login_role) FROM agent_private.agent_database_bindings binding),
          (SELECT string_agg(to_jsonb(binding)::text,E'\n' ORDER BY login_role) FROM agent_private.enrollment_database_bindings binding),
          (SELECT string_agg(to_jsonb(binding)::text,E'\n' ORDER BY login_role) FROM agent_private.agent_projection_database_bindings binding),
          (SELECT string_agg(to_jsonb(binding)::text,E'\n' ORDER BY login_role) FROM agent_private.platform_grant_database_bindings binding),
          (SELECT string_agg(to_jsonb(binding)::text,E'\n' ORDER BY login_role) FROM agent_private.enrollment_target_read_database_bindings binding),
          (SELECT string_agg(c.relname||coalesce(c.relacl::text,'')||c.relowner::text||c.relrowsecurity::text||c.relforcerowsecurity::text,E'\n' ORDER BY c.relname)
           FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='agent_private' AND c.relkind='r')))
        """, new NpgsqlParameter("roles", new[] { fixture.TableOwnerRole, fixture.IngestRole, fixture.EnrollmentDefinerRole,
            fixture.EnrollRole, fixture.IssueRole, fixture.ProjectionDefinerRole, fixture.ProjectionRole,
            fixture.PlatformDefinerRole, fixture.PlatformRole, fixture.RevokerRole, fixture.TargetDefinerRole, fixture.TargetRole }));
}
