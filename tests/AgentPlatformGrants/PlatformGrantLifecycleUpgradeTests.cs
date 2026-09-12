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
        Assert.False(await HasExecute(fixture.PlatformRole, ReadV1Signature));
        Assert.False(await HasExecute(fixture.PlatformRole, ReadV2Signature));
        Assert.False(await HasExecute(fixture.PlatformRole, RevokeV1Signature));
        Assert.False(await HasExecute(fixture.PlatformRole, RevokeV2Signature));
        Assert.False(await HasExecute(fixture.RevokerRole, IssueV1Signature));
        Assert.False(await HasExecute(fixture.RevokerRole, IssueV2Signature));

        await AssertDriftRejected(
            $"GRANT EXECUTE ON FUNCTION {ReadV2Signature} TO \"{fixture.PlatformRole}\"",
            $"REVOKE EXECUTE ON FUNCTION {ReadV2Signature} FROM \"{fixture.PlatformRole}\"");
        await AssertDriftRejected(
            $"REVOKE EXECUTE ON FUNCTION {RevokeV2Signature} FROM \"{fixture.RevokerRole}\"",
            $"GRANT EXECUTE ON FUNCTION {RevokeV2Signature} TO \"{fixture.RevokerRole}\"");
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
    public async Task LegacyLifecycleDowngradeRejectsProfile3WithHistoryWithoutChangingState()
    {
        await fixture.Reset();
        var mapping = await fixture.SeedMapping();
        var issuer = await IssueRepository();
        var issued = await issuer.IssueAsync(Guid.NewGuid(),
            ValidatedGrantAuthorization.FromValidatedPlan(mapping.DirectoryObjectId, mapping.DeviceId, mapping.MappingCreatedAt, PermitDeadline(), RandomNumberGenerator.GetBytes(32)),
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
    public async Task Profile3PolicyDriftStillRejectsLegacyDowngradeBeforeMutation()
    {
        await fixture.Reset();
        await fixture.Execute("CREATE POLICY downgrade_public_drift ON agent_private.enrollment_grants FOR UPDATE TO PUBLIC USING(true) WITH CHECK(true)");
        var before = await Fingerprint();
        try
        {
            await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.Script("downgrade-agent-platform-grants-v2-to-v1.sql", fixture.PlatformDowngrade()));
            Assert.Equal(before, await Fingerprint());
            Assert.Equal(1, await fixture.Scalar<long>("SELECT count(*) FROM pg_catalog.pg_class WHERE oid=pg_catalog.to_regclass('agent_private.platform_grant_revocation_receipts')"));
            Assert.Equal((false, (short)3), await ReadAuditProfile(fixture.Platform));
        }
        finally
        {
            await fixture.Execute("DROP POLICY downgrade_public_drift ON agent_private.enrollment_grants");
        }
        await AssertAudited();
    }

    [Fact]
    public async Task LegacyLifecycleDowngradeRejectsEmptyProfile3WithoutMutation()
    {
        await fixture.Reset();
        var before = await Fingerprint();
        await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.Script("downgrade-agent-platform-grants-v2-to-v1.sql", fixture.PlatformDowngrade()));
        Assert.Equal(before, await Fingerprint());
        Assert.Equal((true, (short)3), await ReadAuditProfile(fixture.Platform));
        await AssertAudited();
    }

    [Fact]
    public async Task LifecycleV3MigrationCannotRunOverProfile3()
    {
        await fixture.Reset();
        var before = await Fingerprint();
        await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.Script("upgrade-agent-platform-grants-v2-to-v3.sql", fixture.PlatformProvision(new NpgsqlConnectionStringBuilder(fixture.Owner.ConnectionString).Database!)));
        Assert.Equal(before, await Fingerprint());
        Assert.Equal((true, (short)3), await ReadAuditProfile(fixture.Platform));
        await AssertAudited();
    }

    [Fact]
    public async Task CapabilityIsolationRerunPreservesLifecycleV3AuditAndRuntimeAccess()
    {
        await fixture.Reset();
        var before = await LifecycleFingerprint();
        Assert.Equal("64a11bee2af9f76b2d5e33c1b168934d", await fixture.Scalar<string>(
            "SELECT pg_catalog.md5(pg_catalog.btrim(prosrc,E' \\t\\r\\n')) FROM pg_catalog.pg_proc WHERE oid='agent_private.audit_platform_grant_privileges(uuid,name,name)'::pg_catalog.regprocedure"));

        await fixture.Script("upgrade-agent-capability-isolation-v2.sql", fixture.CapabilityUpgrade());

        Assert.Equal(before, await LifecycleFingerprint());
        Assert.Equal((true, (short)3), await ReadAuditProfile(fixture.Platform));
        Assert.Equal((true, (short)3), await ReadAuditProfile(fixture.Revoker));
        await AssertAudited();
    }

    [Fact]
    public Task ReceiptIssueContractDriftIsRejectedByAuditProvisionAndCapabilityUpgrade() =>
        AssertIssueContractDriftRejected(
            "platform_grant_receipts",
            "platform_grant_receipts_issue_contract",
            "(issue_contract_version=1 AND mint_permit_not_after IS NULL) OR (issue_contract_version=2 AND mint_permit_not_after IS NOT NULL AND pg_catalog.isfinite(mint_permit_not_after) AND created_at<mint_permit_not_after AND mint_permit_not_after<=created_at+interval '60 seconds')");

    [Fact]
    public Task RevocationReceiptIssueContractDriftIsRejectedByAuditProvisionAndCapabilityUpgrade() =>
        AssertIssueContractDriftRejected(
            "platform_grant_revocation_receipts",
            "platform_grant_revocation_receipts_issue_contract",
            "(issue_contract_version=1 AND issue_mint_permit_not_after IS NULL) OR (issue_contract_version=2 AND issue_mint_permit_not_after IS NOT NULL AND pg_catalog.isfinite(issue_mint_permit_not_after) AND issue_created_at<issue_mint_permit_not_after AND issue_mint_permit_not_after<=issue_created_at+interval '60 seconds')");

    private async Task AssertIssueContractDriftRejected(string table, string constraint, string expression)
    {
        await fixture.Reset();
        await fixture.Execute($"ALTER TABLE agent_private.{table} DROP CONSTRAINT {constraint}; ALTER TABLE agent_private.{table} ADD CONSTRAINT {constraint} CHECK(true OR ({expression}))");
        var before = await LifecycleFingerprint();
        try
        {
            await Assert.ThrowsAsync<InvalidOperationException>(IssueRepository);
            await Assert.ThrowsAsync<InvalidOperationException>(RevokeRepository);
            var database = new NpgsqlConnectionStringBuilder(fixture.Owner.ConnectionString).Database!;
            await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.Script(
                "provision-agent-platform-grants.sql", fixture.PlatformProvision(database)));
            await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.Script(
                "upgrade-agent-capability-isolation-v2.sql", fixture.CapabilityUpgrade()));
            Assert.Equal(before, await LifecycleFingerprint());
        }
        finally
        {
            await fixture.Execute($"ALTER TABLE agent_private.{table} DROP CONSTRAINT {constraint}; ALTER TABLE agent_private.{table} ADD CONSTRAINT {constraint} CHECK({expression})");
        }
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
          'agent_private.issue_initial_enrollment_grant(uuid,uuid,uuid,uuid,timestamptz,timestamptz,bytea,bytea)'::pg_catalog.regprocedure,
          'agent_private.read_initial_enrollment_grant(uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz)'::pg_catalog.regprocedure,
          'agent_private.read_initial_enrollment_grant(uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz,smallint,timestamptz)'::pg_catalog.regprocedure,
          'agent_private.revoke_initial_enrollment_grant(uuid,uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz,bytea)'::pg_catalog.regprocedure,
          'agent_private.revoke_initial_enrollment_grant(uuid,uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz,smallint,timestamptz,bytea)'::pg_catalog.regprocedure,
          'agent_private.audit_platform_grant_privileges(uuid,name,name)'::pg_catalog.regprocedure]::oid[])
        """);

    private const string IssueV1Signature = "agent_private.issue_initial_enrollment_grant(uuid,uuid,uuid,uuid,timestamptz,bytea,bytea)";
    private const string IssueV2Signature = "agent_private.issue_initial_enrollment_grant(uuid,uuid,uuid,uuid,timestamptz,timestamptz,bytea,bytea)";
    private const string ReadV1Signature = "agent_private.read_initial_enrollment_grant(uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz)";
    private const string ReadV2Signature = "agent_private.read_initial_enrollment_grant(uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz,smallint,timestamptz)";
    private const string RevokeV1Signature = "agent_private.revoke_initial_enrollment_grant(uuid,uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz,bytea)";
    private const string RevokeV2Signature = "agent_private.revoke_initial_enrollment_grant(uuid,uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz,smallint,timestamptz,bytea)";
    private static DateTimeOffset PermitDeadline()
    {
        var value = DateTimeOffset.UtcNow.AddSeconds(45);
        return new DateTimeOffset(value.Ticks - value.Ticks % 10, TimeSpan.Zero);
    }
}
