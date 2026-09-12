using System.Security.Cryptography;
using System.Diagnostics;
using Npgsql;

namespace ItManagement.AgentPlatformGrants.Tests;

[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class PlatformGrantStatusCollection : ICollectionFixture<PlatformGrantStatusFixture>
{
    public const string Name = "Agent platform grant status profile database";
}

public sealed class PlatformGrantStatusFixture : IAsyncLifetime
{
    public AgentPlatformGrantFixture Database { get; } = new();
    public (string Role, NpgsqlDataSource DataSource) Status { get; private set; }
    public AdditionalPlatformEnvironment Other { get; private set; } = null!;

    public async Task InitializeAsync()
    {
        try
        {
            await Database.InitializeAsync();
            Other = await Database.AddPlatformEnvironment();
            var before = await Fingerprint();
            var rollback = await Assert.ThrowsAsync<InvalidOperationException>(() => Database.Script(
                "upgrade-agent-platform-grants-v3-to-v4.sql", UpgradeParameters(),
                sql =>
                {
                    Assert.Equal(1, sql.Split("COMMIT;", StringSplitOptions.None).Length - 1);
                    return sql.Replace("COMMIT;",
                        "DO $test_rollback$ BEGIN RAISE EXCEPTION 'InjectedProfile4PostflightFailure'; END $test_rollback$; COMMIT;", StringComparison.Ordinal);
                }));
            Assert.Equal("InjectedProfile4PostflightFailure", Assert.IsType<PostgresException>(rollback.InnerException).MessageText);
            Assert.Equal(before, await Fingerprint());
            await Psql("upgrade-agent-platform-grants-v3-to-v4.sql");
            Status = await Database.CreateStatusLogin();
            await Provision(Status.Role, Database.EnvironmentId);
        }
        catch { await Database.DisposeAsync(); throw; }
    }

    public Task DisposeAsync() => Database.DisposeAsync();

    internal Dictionary<string, string> UpgradeParameters() =>
        Database.PlatformProvision(new NpgsqlConnectionStringBuilder(Database.Owner.ConnectionString).Database!);

    internal Task Provision(string role, Guid environmentId)
    {
        return Psql("provision-agent-platform-grant-status-reader.sql", role, environmentId);
    }

    internal async Task Psql(string file, string? statusRole = null, Guid? environmentId = null)
    {
        var owner = Database.OwnerConnectionSettings();
        var start = new ProcessStartInfo(Environment.GetEnvironmentVariable("CONSOLE_TEST_PSQL") ?? "psql")
        {
            UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true,
            WorkingDirectory = AppContext.BaseDirectory
        };
        start.Environment["PGPASSWORD"] = owner.Password;
        start.Environment["PGCONNECT_TIMEOUT"] = "10";
        foreach (var argument in new[] { "-X", "-w", "-h", owner.Host!, "-p", owner.Port.ToString(System.Globalization.CultureInfo.InvariantCulture),
            "-U", owner.Username!, "-d", owner.Database!, "-v", "ON_ERROR_STOP=1", "-f", Path.Combine(AppContext.BaseDirectory, file) })
            start.ArgumentList.Add(argument);
        var variables = new Dictionary<string, string>
        {
            ["agent_table_owner_role"] = Database.TableOwnerRole,
            ["agent_definer_role"] = Database.TableOwnerRole,
            ["agent_enrollment_definer_role"] = Database.EnrollmentDefinerRole,
            ["agent_projection_definer_role"] = Database.ProjectionDefinerRole,
            ["agent_platform_grant_definer_role"] = Database.PlatformDefinerRole,
            ["agent_platform_grant_role"] = Database.PlatformRole,
            ["agent_platform_grant_revoker_role"] = Database.RevokerRole,
            ["environment_id"] = (environmentId ?? Database.EnvironmentId).ToString()
        };
        if (statusRole is not null) variables["agent_platform_grant_status_role"] = statusRole;
        foreach (var (name, value) in variables)
        {
            start.ArgumentList.Add("-v");
            start.ArgumentList.Add($"{name}={value}");
        }
        using var process = Process.Start(start) ?? throw new InvalidOperationException("PsqlDidNotStart");
        var output = process.StandardOutput.ReadToEndAsync();
        var error = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(120));
        try { await process.WaitForExitAsync(timeout.Token); }
        catch
        {
            // Observe our child and its redirected streams before fixture teardown.
            try { if (!process.HasExited) process.Kill(entireProcessTree: true); }
            catch (InvalidOperationException) { }
            catch (System.ComponentModel.Win32Exception) { }
            try
            {
                using var cleanupTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                await process.WaitForExitAsync(cleanupTimeout.Token);
                await Task.WhenAll(output, error).WaitAsync(cleanupTimeout.Token);
            }
            catch { /* Keep the original timeout/error as the test failure. */ }
            throw;
        }
        _ = await output;
        var errors = await error;
        if (process.ExitCode != 0) throw new InvalidOperationException($"{file}: psql failed ({process.ExitCode}): {errors}");
    }

    internal Task<string> Fingerprint() => Database.Scalar<string>("""
        SELECT pg_catalog.md5(pg_catalog.concat_ws('|',
          (SELECT pg_catalog.string_agg(pg_catalog.pg_get_functiondef(p.oid)||p.proowner::text||COALESCE(p.proacl::text,''), E'\n' ORDER BY p.oid)
           FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='agent_private'),
          (SELECT pg_catalog.string_agg(pg_catalog.pg_get_constraintdef(c.oid), E'\n' ORDER BY c.oid)
           FROM pg_catalog.pg_constraint c JOIN pg_catalog.pg_namespace n ON n.oid=c.connamespace WHERE n.nspname='agent_private'),
          (SELECT pg_catalog.string_agg(b::text,E'\n' ORDER BY b.login_role COLLATE "C") FROM agent_private.platform_grant_database_bindings b),
          (SELECT pg_catalog.string_agg(r::text,E'\n' ORDER BY r.role_name COLLATE "C") FROM agent_private.agent_capability_roles r)))
        """);
}

[Collection(PlatformGrantStatusCollection.Name)]
public sealed class PlatformGrantStatusDatabaseTests(PlatformGrantStatusFixture fixture)
{
    private AgentPlatformGrantFixture Database => fixture.Database;

    [Fact]
    public async Task Profile4KeepsIssuerRevokerAndStatusCapabilitiesSeparate()
    {
        _ = await Issuer();
        _ = await Revoker();
        _ = await StatusReader();
        foreach (var signature in StatusSignatures)
        {
            Assert.True(await HasExecute(fixture.Status.Role, signature));
            Assert.False(await HasExecute(Database.PlatformRole, signature));
            Assert.False(await HasExecute(Database.RevokerRole, signature));
        }
        foreach (var signature in MutationAndLegacyReadSignatures)
            Assert.False(await HasExecute(fixture.Status.Role, signature));
        await Assert.ThrowsAsync<InvalidOperationException>(() => PostgresPlatformGrantRepository.CreateAuditedAsync(
            fixture.Status.DataSource, Database.EnvironmentId, Database.TableOwnerRole, Database.PlatformDefinerRole, CancellationToken.None));
        await Assert.ThrowsAsync<InvalidOperationException>(() => PostgresPlatformGrantRevocationRepository.CreateAuditedAsync(
            fixture.Status.DataSource, Database.EnvironmentId, Database.TableOwnerRole, Database.PlatformDefinerRole, CancellationToken.None));
        foreach (var source in new[] { Database.Platform, Database.Revoker })
            await Assert.ThrowsAsync<InvalidOperationException>(() => PostgresPlatformGrantStatusReader.CreateAuditedAsync(
                source, Database.EnvironmentId, Database.TableOwnerRole, Database.PlatformDefinerRole, CancellationToken.None));
    }

    [Fact]
    public async Task StatusReaderObservesExactReceiptAndRevocationWithoutWriting()
    {
        var receipt = await Issue();
        var reader = await StatusReader();
        var before = await GrantStateFingerprint(receipt);
        var available = await reader.ReadAsync(receipt, CancellationToken.None);
        Assert.Equal(PlatformGrantEffectiveState.Available, available.State);
        Assert.NotNull(available.ObservedAt);
        Assert.Null(available.StateChangedAt);
        Assert.Equal(before, await GrantStateFingerprint(receipt));
        var changed = new PlatformGrantReceipt(receipt.EnvironmentId, receipt.OperationId, receipt.GrantId,
            receipt.DirectoryObjectId, receipt.DeviceId, receipt.MappingCreatedAt, receipt.CreatedAt, receipt.ExpiresAt,
            receipt.IssueContractVersion, receipt.MintPermitNotAfter!.Value.AddSeconds(1), receipt.GetTokenSha256(), receipt.GetAuthorizationDigest());
        Assert.Equal(PlatformGrantDiagnostic.OperationConflict, (await reader.ReadAsync(changed, CancellationToken.None)).Diagnostic);
        var revoked = await (await Revoker()).RevokeAsync(Guid.NewGuid(),
            ValidatedGrantRevocationAuthorization.FromValidatedPlan(receipt, RandomNumberGenerator.GetBytes(32)), CancellationToken.None);
        Assert.Equal(PlatformGrantRevocationOutcome.Completed, revoked.Outcome);
        var observed = await reader.ReadAsync(receipt, CancellationToken.None);
        Assert.Equal(PlatformGrantEffectiveState.Revoked, observed.State);
        Assert.Equal(revoked.Receipt!.EffectiveRevokedAt, observed.StateChangedAt);
    }

    [Fact]
    public async Task CrossEnvironmentReceiptIsRejectedByTheDatabaseFunction()
    {
        var receipt = await Issue(fixture.Other);
        // Construct internally to bypass the C# environment guard and exercise SQL SESSION_USER binding.
        var reader = new PostgresPlatformGrantStatusReader(fixture.Status.DataSource, fixture.Other.EnvironmentId);
        var result = await reader.ReadAsync(receipt, CancellationToken.None);
        Assert.Equal(PlatformGrantEffectiveState.Unknown, result.State);
        Assert.Null(result.ObservedAt);
        await Assert.ThrowsAsync<InvalidOperationException>(() => PostgresPlatformGrantStatusReader.CreateAuditedAsync(
                fixture.Status.DataSource, fixture.Other.EnvironmentId, Database.TableOwnerRole, Database.PlatformDefinerRole, CancellationToken.None));
    }

    [Theory]
    [InlineData("Available")]
    [InlineData("Expired")]
    [InlineData("Consumed")]
    [InlineData("Revoked")]
    public async Task LegacyReceiptReadsEachLifecycleStateWithoutChangingHistory(string state)
    {
        var mapping = await Database.SeedMapping();
        var created = mapping.MappingCreatedAt.AddSeconds(state == "Expired" ? -660 : 0);
        var receipt = new PlatformGrantReceipt(mapping.EnvironmentId, Guid.NewGuid(), Guid.NewGuid(),
            mapping.DirectoryObjectId, mapping.DeviceId, created.AddMinutes(-1), created, created.AddSeconds(600),
            RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(32));
        await Database.Execute("""
            INSERT INTO agent_private.enrollment_grants(environment_id,grant_id,device_id,token_sha256,state,
              created_at,expires_at,consumed_at,consumed_request_id,revoked_at)
            VALUES(@env,@grant,@device,@token,@state,@created,@expires,
              CASE WHEN @state='Consumed' THEN @created END,
              CASE WHEN @state='Consumed' THEN @request END,
              CASE WHEN @state='Revoked' THEN @created END);
            INSERT INTO agent_private.platform_grant_receipts(environment_id,operation_id,grant_id,directory_object_id,
              device_id,mapping_created_at,token_sha256,authorization_digest,created_at,expires_at,
              issue_contract_version,mint_permit_not_after)
            VALUES(@env,@operation,@grant,@directory,@device,@mapping,@token,@digest,@created,@expires,1,NULL);
            """, new("env", receipt.EnvironmentId), new("grant", receipt.GrantId), new("device", receipt.DeviceId),
            new("token", receipt.GetTokenSha256()), new("state", state == "Expired" ? "Available" : state),
            new("created", receipt.CreatedAt), new("expires", receipt.ExpiresAt), new("request", Guid.NewGuid()),
            new("operation", receipt.OperationId), new("directory", receipt.DirectoryObjectId),
            new("mapping", receipt.MappingCreatedAt), new("digest", receipt.GetAuthorizationDigest()));
        var before = await GrantStateFingerprint(receipt);
        var result = await (await StatusReader()).ReadAsync(receipt, CancellationToken.None);
        Assert.Equal(Enum.Parse<PlatformGrantEffectiveState>(state), result.State);
        Assert.NotNull(result.ObservedAt);
        Assert.Equal(state is "Consumed" or "Revoked", result.StateChangedAt is not null);
        Assert.Equal(before, await GrantStateFingerprint(receipt));
    }

    [Fact]
    public async Task ForeignOperationAndMissingOperationHaveTheSameUnavailableResponse()
    {
        var foreign = await Issue(fixture.Other);
        PlatformGrantReceipt Probe(Guid operationId) => new(Database.EnvironmentId, operationId, foreign.GrantId,
            foreign.DirectoryObjectId, foreign.DeviceId, foreign.MappingCreatedAt, foreign.CreatedAt, foreign.ExpiresAt,
            foreign.IssueContractVersion, foreign.MintPermitNotAfter, foreign.GetTokenSha256(), foreign.GetAuthorizationDigest());
        var reader = await StatusReader();
        var existingElsewhere = await reader.ReadAsync(Probe(foreign.OperationId), CancellationToken.None);
        var absent = await reader.ReadAsync(Probe(Guid.NewGuid()), CancellationToken.None);
        Assert.Equal(PlatformGrantEffectiveState.Unknown, existingElsewhere.State);
        Assert.Equal(PlatformGrantDiagnostic.ReceiptUnavailable, existingElsewhere.Diagnostic);
        Assert.Null(existingElsewhere.ObservedAt);
        Assert.Null(existingElsewhere.StateChangedAt);
        Assert.Equal(absent, existingElsewhere);
    }

    [Fact]
    public async Task StatusProvisionIsIdempotentAndCannotRebindAnExistingLogin()
    {
        var before = await fixture.Fingerprint();
        await fixture.Provision(fixture.Status.Role, Database.EnvironmentId);
        Assert.Equal(before, await fixture.Fingerprint());
        await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.Provision(fixture.Status.Role, fixture.Other.EnvironmentId));
        Assert.Equal(before, await fixture.Fingerprint());
    }

    [Theory]
    [InlineData("issuer")]
    [InlineData("revoker")]
    [InlineData("ingest")]
    [InlineData("owner")]
    public async Task StatusProvisionRejectsExistingCapabilitiesWithoutMutation(string kind)
    {
        var role = kind switch
        {
            "issuer" => Database.PlatformRole,
            "revoker" => Database.RevokerRole,
            "ingest" => Database.IngestRole,
            _ => Database.TableOwnerRole
        };
        var before = await fixture.Fingerprint();
        await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.Provision(role, Database.EnvironmentId));
        Assert.Equal(before, await fixture.Fingerprint());
        _ = await StatusReader();
    }

    [Fact]
    public async Task CapabilityUpgradePreservesProfile4AndEveryRuntime()
    {
        var before = await fixture.Fingerprint();
        await fixture.Psql("upgrade-agent-capability-isolation-v2.sql");
        Assert.Equal(before, await fixture.Fingerprint());
        _ = await Issuer();
        _ = await Revoker();
        _ = await StatusReader();
    }

    [Fact]
    public async Task UnboundLoginWithDirectTableAccessCannotBeReservedOrProvisioned()
    {
        var unsafeLogin = await Database.CreateStatusLogin();
        await Database.Execute($"GRANT SELECT ON agent_private.devices TO \"{unsafeLogin.Role}\"");
        try
        {
            var before = await fixture.Fingerprint();
            await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.Provision(unsafeLogin.Role, Database.EnvironmentId));
            Assert.Equal(before, await fixture.Fingerprint());
            Assert.Equal(0, await Database.Scalar<long>(
                "SELECT count(*) FROM agent_private.agent_capability_roles WHERE role_name=@role::name", new NpgsqlParameter("role", unsafeLogin.Role)));
            Assert.Equal(0, await Database.Scalar<long>(
                "SELECT count(*) FROM agent_private.platform_grant_database_bindings WHERE login_role=@role::name", new NpgsqlParameter("role", unsafeLogin.Role)));
            Assert.True(await Database.Scalar<bool>(
                "SELECT pg_catalog.has_table_privilege(@role,'agent_private.devices','SELECT')", new NpgsqlParameter("role", unsafeLogin.Role)));
        }
        finally { await Database.Execute($"REVOKE SELECT ON agent_private.devices FROM \"{unsafeLogin.Role}\""); }
        _ = await StatusReader();
    }

    [Fact]
    public async Task LifecycleUpgradeCannotRunOverProfile4()
    {
        var before = await fixture.Fingerprint();
        await Assert.ThrowsAsync<InvalidOperationException>(() => Database.Script(
            "upgrade-agent-platform-grants-v3-to-v4.sql", fixture.UpgradeParameters()));
        Assert.Equal(before, await fixture.Fingerprint());
    }

    [Fact]
    public async Task ExtraMutatingExecuteMakesReaderAuditAndProvisionFailClosed()
    {
        var signature = MutationAndLegacyReadSignatures[0];
        await Database.Execute($"GRANT EXECUTE ON FUNCTION {signature} TO \"{fixture.Status.Role}\"");
        try
        {
            var before = await fixture.Fingerprint();
            await Assert.ThrowsAsync<InvalidOperationException>(StatusReader);
            await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.Provision(fixture.Status.Role, Database.EnvironmentId));
            Assert.Equal(before, await fixture.Fingerprint());
        }
        finally { await Database.Execute($"REVOKE EXECUTE ON FUNCTION {signature} FROM \"{fixture.Status.Role}\""); }
        _ = await StatusReader();
    }

    [Theory]
    [InlineData("issuer", false)]
    [InlineData("revoker", false)]
    [InlineData("reader", true)]
    public async Task UnexpectedStatusPrivilegeIsRejectedByRuntimeAndProvision(string kind, bool grantOption)
    {
        var role = kind switch
        {
            "issuer" => Database.PlatformRole,
            "revoker" => Database.RevokerRole,
            _ => fixture.Status.Role
        };
        var signature = StatusSignatures[1];
        await Database.Execute($"GRANT EXECUTE ON FUNCTION {signature} TO \"{role}\"{(grantOption ? " WITH GRANT OPTION" : "")}");
        try
        {
            var before = await fixture.Fingerprint();
            await Assert.ThrowsAsync<InvalidOperationException>(Issuer);
            await Assert.ThrowsAsync<InvalidOperationException>(Revoker);
            await Assert.ThrowsAsync<InvalidOperationException>(StatusReader);
            await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.Provision(fixture.Status.Role, Database.EnvironmentId));
            Assert.Equal(before, await fixture.Fingerprint());
        }
        finally
        {
            await Database.Execute($"REVOKE {(grantOption ? "GRANT OPTION FOR " : "")}EXECUTE ON FUNCTION {signature} FROM \"{role}\"");
        }
        _ = await Issuer();
        _ = await Revoker();
        _ = await StatusReader();
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    public async Task MissingStatusOverloadPreventsAllProfile4RepositoryStartup(int overload)
    {
        var signature = StatusSignatures[overload];
        var temporary = signature.Replace("read_initial_enrollment_grant_status", "test_missing_status", StringComparison.Ordinal);
        await Database.Execute($"ALTER FUNCTION {signature} RENAME TO test_missing_status");
        try
        {
            await Assert.ThrowsAnyAsync<Exception>(Issuer);
            await Assert.ThrowsAnyAsync<Exception>(Revoker);
            await Assert.ThrowsAnyAsync<Exception>(StatusReader);
        }
        finally { await Database.Execute($"ALTER FUNCTION {temporary} RENAME TO read_initial_enrollment_grant_status"); }
        _ = await Issuer();
        _ = await Revoker();
        _ = await StatusReader();
    }

    private async Task<PlatformGrantReceipt> Issue(AdditionalPlatformEnvironment? other = null)
    {
        var environmentId = other?.EnvironmentId ?? Database.EnvironmentId;
        var mapping = await Database.SeedMapping(environmentId);
        var repository = await PostgresPlatformGrantRepository.CreateAuditedAsync(other?.DataSource ?? Database.Platform,
            environmentId, Database.TableOwnerRole, Database.PlatformDefinerRole, CancellationToken.None);
        var now = DateTimeOffset.UtcNow.AddSeconds(45);
        var deadline = new DateTimeOffset(now.Ticks - now.Ticks % 10, TimeSpan.Zero);
        var result = await repository.IssueAsync(Guid.NewGuid(), ValidatedGrantAuthorization.FromValidatedPlan(
            mapping.DirectoryObjectId, mapping.DeviceId, mapping.MappingCreatedAt, deadline, RandomNumberGenerator.GetBytes(32)),
            ValidatedPersistedPlatformGrant.FromValidatedOutboxRecord(RandomNumberGenerator.GetBytes(32)), CancellationToken.None);
        Assert.Equal(PlatformGrantOutcome.Created, result.Outcome);
        return Assert.IsType<PlatformGrantReceipt>(result.Receipt);
    }

    private Task<PostgresPlatformGrantRepository> Issuer() => PostgresPlatformGrantRepository.CreateAuditedAsync(
        Database.Platform, Database.EnvironmentId, Database.TableOwnerRole, Database.PlatformDefinerRole, CancellationToken.None);
    private Task<PostgresPlatformGrantRevocationRepository> Revoker() => PostgresPlatformGrantRevocationRepository.CreateAuditedAsync(
        Database.Revoker, Database.EnvironmentId, Database.TableOwnerRole, Database.PlatformDefinerRole, CancellationToken.None);
    private Task<PostgresPlatformGrantStatusReader> StatusReader() => PostgresPlatformGrantStatusReader.CreateAuditedAsync(
        fixture.Status.DataSource, Database.EnvironmentId, Database.TableOwnerRole, Database.PlatformDefinerRole, CancellationToken.None);
    private Task<bool> HasExecute(string role, string signature) => Database.Scalar<bool>(
        "SELECT pg_catalog.has_function_privilege(@role,@signature::pg_catalog.regprocedure,'EXECUTE')", new("role", role), new("signature", signature));
    private Task<string> GrantStateFingerprint(PlatformGrantReceipt receipt) => Database.Scalar<string>("""
        SELECT pg_catalog.md5(pg_catalog.concat_ws('|',
          (SELECT g::text FROM agent_private.enrollment_grants g WHERE environment_id=@env AND grant_id=@grant),
          (SELECT pg_catalog.string_agg(r::text,E'\n' ORDER BY r.operation_id) FROM agent_private.platform_grant_receipts r),
          (SELECT pg_catalog.string_agg(r::text,E'\n' ORDER BY r.revocation_operation_id) FROM agent_private.platform_grant_revocation_receipts r),
          (SELECT count(*) FROM agent_private.enrollment_requests),
          (SELECT count(*) FROM agent_private.enrollment_results)))
        """, new("env", receipt.EnvironmentId), new("grant", receipt.GrantId));

    private static readonly string[] StatusSignatures =
    [
        "agent_private.read_initial_enrollment_grant_status(uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz)",
        "agent_private.read_initial_enrollment_grant_status(uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz,smallint,timestamptz)"
    ];
    private static readonly string[] MutationAndLegacyReadSignatures =
    [
        "agent_private.issue_initial_enrollment_grant(uuid,uuid,uuid,uuid,timestamptz,bytea,bytea)",
        "agent_private.issue_initial_enrollment_grant(uuid,uuid,uuid,uuid,timestamptz,timestamptz,bytea,bytea)",
        "agent_private.read_initial_enrollment_grant(uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz)",
        "agent_private.read_initial_enrollment_grant(uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz,smallint,timestamptz)",
        "agent_private.revoke_initial_enrollment_grant(uuid,uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz,bytea)",
        "agent_private.revoke_initial_enrollment_grant(uuid,uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz,smallint,timestamptz,bytea)"
    ];
}
