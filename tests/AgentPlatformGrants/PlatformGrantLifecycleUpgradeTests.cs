using System.Security.Cryptography;
using Npgsql;

namespace ItManagement.AgentPlatformGrants.Tests;

[Collection(PlatformGrantCollection.Name)]
public sealed class PlatformGrantLifecycleUpgradeTests(AgentPlatformGrantFixture fixture)
{
    [Fact]
    public async Task PurposeSpecificExecuteAndStoreDriftAreAuditedExactly()
    {
        await fixture.Reset();
        await AssertAudited();
        Assert.False(await HasExecute(fixture.PlatformRole, ReadSignature));
        Assert.False(await HasExecute(fixture.PlatformRole, RevokeSignature));
        Assert.False(await HasExecute(fixture.RevokerRole, IssueSignature));

        await AssertDriftRejected(
            $"GRANT EXECUTE ON FUNCTION {ReadSignature} TO \"{fixture.PlatformRole}\"",
            $"REVOKE EXECUTE ON FUNCTION {ReadSignature} FROM \"{fixture.PlatformRole}\"");
        await AssertDriftRejected(
            $"REVOKE EXECUTE ON FUNCTION {RevokeSignature} FROM \"{fixture.RevokerRole}\"",
            $"GRANT EXECUTE ON FUNCTION {RevokeSignature} TO \"{fixture.RevokerRole}\"");
        await AssertDriftRejected(
            $"GRANT SELECT(grant_id) ON agent_private.platform_grant_revocation_receipts TO \"{fixture.PlatformRole}\"",
            $"REVOKE SELECT(grant_id) ON agent_private.platform_grant_revocation_receipts FROM \"{fixture.PlatformRole}\"");
        await AssertDriftRejected(
            $"REVOKE SELECT(consumed_at) ON agent_private.enrollment_grants FROM \"{fixture.PlatformDefinerRole}\"",
            $"GRANT SELECT(consumed_at) ON agent_private.enrollment_grants TO \"{fixture.PlatformDefinerRole}\"");
        await AssertDriftRejected(
            "DROP POLICY platform_grant_definer_update ON agent_private.enrollment_grants",
            $"CREATE POLICY platform_grant_definer_update ON agent_private.enrollment_grants FOR UPDATE TO \"{fixture.PlatformDefinerRole}\" USING(state='Available') WITH CHECK(state='Revoked')");
        await AssertDriftRejected(
            $"CREATE POLICY unexpected_platform_grant_policy ON agent_private.platform_grant_revocation_receipts FOR SELECT TO \"{fixture.PlatformDefinerRole}\" USING(true)",
            "DROP POLICY unexpected_platform_grant_policy ON agent_private.platform_grant_revocation_receipts");
        await AssertDriftRejected(
            $"CREATE POLICY arbitrary_role_policy ON agent_private.enrollment_grants FOR SELECT TO \"{fixture.PlatformDefinerRole}\" USING(true)",
            "DROP POLICY arbitrary_role_policy ON agent_private.enrollment_grants");
        await AssertDriftRejected(
            "CREATE POLICY arbitrary_public_policy ON agent_private.enrollment_grants FOR UPDATE TO PUBLIC USING(true) WITH CHECK(true)",
            "DROP POLICY arbitrary_public_policy ON agent_private.enrollment_grants");

        await AssertAudited();
    }

    [Fact]
    public async Task NonemptyRevocationHistoryMakesDowngradeFailWithoutChangingProfile()
    {
        await fixture.Reset();
        var mapping = await fixture.SeedMapping();
        var issuer = await IssueRepository();
        var issued = await issuer.IssueAsync(Guid.NewGuid(),
            ValidatedGrantAuthorization.FromValidatedPlan(mapping.DirectoryObjectId, mapping.DeviceId, mapping.MappingCreatedAt, RandomNumberGenerator.GetBytes(32)),
            ValidatedPersistedPlatformGrant.FromValidatedOutboxRecord(RandomNumberGenerator.GetBytes(32)), CancellationToken.None);
        Assert.NotNull(issued.Receipt);
        var revoker = await RevokeRepository();
        var authorization = ValidatedGrantRevocationAuthorization.FromValidatedPlan(issued.Receipt!, RandomNumberGenerator.GetBytes(32));
        Assert.Equal(PlatformGrantRevocationOutcome.Completed,
            (await revoker.RevokeAsync(Guid.NewGuid(), authorization, CancellationToken.None)).Outcome);

        var before = await Fingerprint();
        await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.Script("downgrade-agent-platform-grants-v2-to-v1.sql", fixture.PlatformDowngrade()));
        Assert.Equal(before, await Fingerprint());
        await AssertAudited();
    }

    [Fact]
    public async Task V2PolicyDriftRejectsDowngradeBeforeAnyLifecycleMutation()
    {
        await fixture.Reset();
        await fixture.Execute("CREATE POLICY downgrade_public_drift ON agent_private.enrollment_grants FOR UPDATE TO PUBLIC USING(true) WITH CHECK(true)");
        var before = await Fingerprint();
        try
        {
            await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.Script("downgrade-agent-platform-grants-v2-to-v1.sql", fixture.PlatformDowngrade()));
            Assert.Equal(before, await Fingerprint());
            Assert.Equal(1, await fixture.Scalar<long>("SELECT count(*) FROM pg_catalog.pg_class WHERE oid=pg_catalog.to_regclass('agent_private.platform_grant_revocation_receipts')"));
            Assert.Equal((false, (short)2), await ReadAuditProfile(fixture.Platform));
        }
        finally
        {
            await fixture.Execute("DROP POLICY downgrade_public_drift ON agent_private.enrollment_grants");
        }
        await AssertAudited();
    }

    [Fact]
    public async Task EmptyV2DowngradesToExactV1AndUpgradesBackToV2()
    {
        await fixture.Reset();
        try
        {
            await fixture.Script("downgrade-agent-platform-grants-v2-to-v1.sql", fixture.PlatformDowngrade());
            Assert.Equal(0, await fixture.Scalar<long>("SELECT count(*) FROM pg_catalog.pg_class WHERE oid=pg_catalog.to_regclass('agent_private.platform_grant_revocation_receipts')"));
            Assert.Equal(0, await fixture.Scalar<long>("SELECT count(*) FROM pg_catalog.pg_proc WHERE oid IN(pg_catalog.to_regprocedure('agent_private.read_initial_enrollment_grant(uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz)'),pg_catalog.to_regprocedure('agent_private.revoke_initial_enrollment_grant(uuid,uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz,bytea)'))"));
            Assert.Equal((true, (short)1), await ReadAuditProfile(fixture.Platform));
            Assert.Equal(0, await fixture.Scalar<long>("SELECT count(*) FROM agent_private.platform_grant_database_bindings WHERE purpose='RevokeInitialGrant'"));
            Assert.Equal(0, await fixture.Scalar<long>("SELECT count(*) FROM agent_private.agent_capability_roles WHERE role_name=@role", new NpgsqlParameter("role", fixture.RevokerRole)));
            Assert.False(await fixture.Scalar<bool>("SELECT rolcanlogin FROM pg_catalog.pg_roles WHERE rolname=@role", new NpgsqlParameter("role", fixture.RevokerRole)));
            Assert.False(await fixture.Scalar<bool>("SELECT pg_catalog.has_schema_privilege(@role,'agent_private','USAGE')", new NpgsqlParameter("role", fixture.RevokerRole)));

            await fixture.Script("upgrade-agent-platform-grants-v1-to-v2.sql", fixture.PlatformStore());
            var database = new NpgsqlConnectionStringBuilder(fixture.Owner.ConnectionString).Database!;
            await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.Script("provision-agent-platform-grants.sql", fixture.PlatformProvision(database)));
            Assert.Equal(0, await fixture.Scalar<long>("SELECT count(*) FROM agent_private.platform_grant_database_bindings WHERE purpose='RevokeInitialGrant'"));
            Assert.Equal(0, await fixture.Scalar<long>("SELECT count(*) FROM agent_private.agent_capability_roles WHERE role_name=@role", new NpgsqlParameter("role", fixture.RevokerRole)));
            Assert.False(await HasExecute(fixture.RevokerRole, RevokeSignature));

            await fixture.Execute($"ALTER ROLE \"{fixture.RevokerRole}\" LOGIN");
            await fixture.Script("provision-agent-platform-grants.sql", fixture.PlatformProvision(database));
        }
        finally
        {
            await RestoreV2();
        }
        await AssertAudited();
    }

    [Fact]
    public async Task V1PolicyDriftRejectsUpgradeBeforeAnyLifecycleMutation()
    {
        await fixture.Reset();
        await fixture.Script("downgrade-agent-platform-grants-v2-to-v1.sql", fixture.PlatformDowngrade());
        await fixture.Execute("DROP POLICY platform_grant_definer_insert ON agent_private.platform_grant_receipts");
        try
        {
            await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.Script("upgrade-agent-platform-grants-v1-to-v2.sql", fixture.PlatformStore()));
            Assert.Equal(0, await fixture.Scalar<long>("SELECT count(*) FROM pg_catalog.pg_class WHERE oid=pg_catalog.to_regclass('agent_private.platform_grant_revocation_receipts')"));
            Assert.Equal(0, await fixture.Scalar<long>("SELECT count(*) FROM pg_catalog.pg_proc WHERE oid=pg_catalog.to_regprocedure('agent_private.read_initial_enrollment_grant(uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz)')"));
            Assert.Equal((false, (short)1), await ReadAuditProfile(fixture.Platform));
        }
        finally
        {
            await fixture.Execute($"CREATE POLICY platform_grant_definer_insert ON agent_private.platform_grant_receipts FOR INSERT TO \"{fixture.PlatformDefinerRole}\" WITH CHECK(true)");
            Assert.Equal((true, (short)1), await ReadAuditProfile(fixture.Platform));
            await RestoreV2();
        }
        await AssertAudited();
    }

    [Fact]
    public async Task LateUpgradePostflightFailureRollsBackEveryLifecycleMutation()
    {
        await fixture.Reset();
        await fixture.Script("downgrade-agent-platform-grants-v2-to-v1.sql", fixture.PlatformDowngrade());
        try
        {
            const string postflight = "SELECT 1/pg_catalog.count(*) AS target_profile_is_v2";
            var error = await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.Script(
                "upgrade-agent-platform-grants-v1-to-v2.sql",
                fixture.PlatformStore(),
                sql =>
                {
                    Assert.Equal(1, Count(sql, postflight));
                    return sql.Replace(postflight, "SELECT 1/0 AS target_profile_is_v2", StringComparison.Ordinal);
                }));
            Assert.Equal(PostgresErrorCodes.DivisionByZero, Assert.IsType<PostgresException>(error.InnerException).SqlState);
            Assert.Equal(0, await fixture.Scalar<long>("SELECT count(*) FROM pg_catalog.pg_class WHERE oid=pg_catalog.to_regclass('agent_private.platform_grant_revocation_receipts')"));
            Assert.Equal(0, await fixture.Scalar<long>("SELECT count(*) FROM pg_catalog.pg_proc WHERE oid IN(pg_catalog.to_regprocedure('agent_private.read_initial_enrollment_grant(uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz)'),pg_catalog.to_regprocedure('agent_private.revoke_initial_enrollment_grant(uuid,uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz,bytea)'))"));
            Assert.Equal((true, (short)1), await ReadAuditProfile(fixture.Platform));
            Assert.Equal(1, await fixture.Scalar<long>(
                "SELECT count(*) FROM pg_catalog.pg_constraint WHERE conrelid='agent_private.platform_grant_database_bindings'::pg_catalog.regclass AND contype='c' AND pg_catalog.pg_get_constraintdef(oid) LIKE '%IssueInitialGrant%' AND pg_catalog.pg_get_constraintdef(oid) NOT LIKE '%RevokeInitialGrant%'"));
        }
        finally
        {
            await RestoreV2();
        }
        await AssertAudited();
    }

    [Fact]
    public async Task CapabilityIsolationRerunPreservesLifecycleV2AuditAndRuntimeAccess()
    {
        await fixture.Reset();
        var before = await LifecycleFingerprint();

        await fixture.Script("upgrade-agent-capability-isolation-v2.sql", fixture.CapabilityUpgrade());

        Assert.Equal(before, await LifecycleFingerprint());
        Assert.Equal((true, (short)2), await ReadAuditProfile(fixture.Platform));
        Assert.Equal((true, (short)2), await ReadAuditProfile(fixture.Revoker));
        await AssertAudited();
    }

    private async Task AssertDriftRejected(string apply, string restore)
    {
        await fixture.Execute(apply);
        try
        {
            await Assert.ThrowsAsync<InvalidOperationException>(IssueRepository);
            await Assert.ThrowsAsync<InvalidOperationException>(RevokeRepository);
        }
        finally
        {
            await fixture.Execute(restore);
        }
    }

    private async Task AssertAudited()
    {
        _ = await IssueRepository();
        _ = await RevokeRepository();
    }

    private Task<PostgresPlatformGrantRepository> IssueRepository() =>
        PostgresPlatformGrantRepository.CreateAuditedAsync(fixture.Platform, fixture.EnvironmentId, fixture.TableOwnerRole, fixture.PlatformDefinerRole, CancellationToken.None);

    private Task<PostgresPlatformGrantRevocationRepository> RevokeRepository() =>
        PostgresPlatformGrantRevocationRepository.CreateAuditedAsync(fixture.Revoker, fixture.EnvironmentId, fixture.TableOwnerRole, fixture.PlatformDefinerRole, CancellationToken.None);

    private Task<bool> HasExecute(string role, string signature) => fixture.Scalar<bool>(
        "SELECT pg_catalog.has_function_privilege(@role,@signature::pg_catalog.regprocedure,'EXECUTE')",
        new NpgsqlParameter("role", role), new NpgsqlParameter("signature", signature));

    private async Task<(bool IsValid, short Profile)> ReadAuditProfile(NpgsqlDataSource source)
    {
        await using var command = source.CreateCommand("SELECT is_valid,profile_version FROM agent_private.audit_platform_grant_privileges(@env,@owner,@definer)");
        command.Parameters.AddWithValue("env", fixture.EnvironmentId);
        command.Parameters.AddWithValue("owner", fixture.TableOwnerRole);
        command.Parameters.AddWithValue("definer", fixture.PlatformDefinerRole);
        await using var reader = await command.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());
        var result = (reader.GetBoolean(0), reader.GetInt16(1));
        Assert.False(await reader.ReadAsync());
        return result;
    }

    private async Task RestoreV2()
    {
        if (await fixture.Scalar<long>("SELECT count(*) FROM pg_catalog.pg_class WHERE oid=pg_catalog.to_regclass('agent_private.platform_grant_revocation_receipts')") == 0)
            await fixture.Script("upgrade-agent-platform-grants-v1-to-v2.sql", fixture.PlatformStore());
        if (!await fixture.Scalar<bool>("SELECT rolcanlogin FROM pg_catalog.pg_roles WHERE rolname=@role", new NpgsqlParameter("role", fixture.RevokerRole)))
            await fixture.Execute($"ALTER ROLE \"{fixture.RevokerRole}\" LOGIN");
        var database = new NpgsqlConnectionStringBuilder(fixture.Owner.ConnectionString).Database!;
        await fixture.Script("provision-agent-platform-grants.sql", fixture.PlatformProvision(database));
    }

    private Task<string> Fingerprint() => fixture.Scalar<string>("""
        SELECT pg_catalog.concat_ws('|',
          (SELECT count(*) FROM agent_private.platform_grant_revocation_receipts),
          (SELECT count(*) FROM agent_private.platform_grant_database_bindings WHERE purpose='RevokeInitialGrant'),
          (SELECT count(*) FROM agent_private.agent_capability_roles WHERE capability='PlatformGrant' AND role_kind='Runtime'),
          pg_catalog.to_regprocedure('agent_private.read_initial_enrollment_grant(uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz)')::text,
          pg_catalog.to_regprocedure('agent_private.revoke_initial_enrollment_grant(uuid,uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz,bytea)')::text,
          pg_catalog.md5((SELECT prosrc FROM pg_catalog.pg_proc WHERE oid='agent_private.audit_platform_grant_privileges(uuid,name,name)'::pg_catalog.regprocedure)))
        """);

    private Task<string> LifecycleFingerprint() => fixture.Scalar<string>("""
        SELECT pg_catalog.md5(pg_catalog.string_agg(
          pg_catalog.pg_get_functiondef(function.oid)||function.proowner::text||COALESCE(function.proacl::text,''),
          E'\n' ORDER BY function.oid))
        FROM pg_catalog.pg_proc function JOIN pg_catalog.pg_namespace namespace ON namespace.oid=function.pronamespace
        WHERE namespace.nspname='agent_private' AND function.oid=ANY(ARRAY[
          'agent_private.issue_initial_enrollment_grant(uuid,uuid,uuid,uuid,timestamptz,bytea,bytea)'::pg_catalog.regprocedure,
          'agent_private.read_initial_enrollment_grant(uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz)'::pg_catalog.regprocedure,
          'agent_private.revoke_initial_enrollment_grant(uuid,uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz,bytea)'::pg_catalog.regprocedure,
          'agent_private.audit_platform_grant_privileges(uuid,name,name)'::pg_catalog.regprocedure]::oid[])
        """);

    private static int Count(string value, string token) =>
        value.Split(token, StringSplitOptions.None).Length - 1;

    private const string IssueSignature = "agent_private.issue_initial_enrollment_grant(uuid,uuid,uuid,uuid,timestamptz,bytea,bytea)";
    private const string ReadSignature = "agent_private.read_initial_enrollment_grant(uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz)";
    private const string RevokeSignature = "agent_private.revoke_initial_enrollment_grant(uuid,uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz,bytea)";
}
