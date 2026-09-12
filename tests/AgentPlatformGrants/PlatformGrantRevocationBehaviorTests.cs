using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ItManagement.AgentEnrollment;
using ItManagement.AgentEnrollment.Crypto;
using Npgsql;

namespace ItManagement.AgentPlatformGrants.Tests;

[Collection(PlatformGrantCollection.Name)]
public sealed class PlatformGrantRevocationBehaviorTests(AgentPlatformGrantFixture fixture)
{
    [Fact]
    public async Task DeadlineBoundReceiptUsesVersionedReadAndRevokeTuple()
    {
        await fixture.Reset();
        var mapping = await fixture.SeedMapping();
        var issuer = await PostgresPlatformGrantRepository.CreateAuditedAsync(fixture.Platform,
            fixture.EnvironmentId, fixture.TableOwnerRole, fixture.PlatformDefinerRole, CancellationToken.None);
        var issued = await issuer.IssueAsync(Guid.NewGuid(),
            ValidatedGrantAuthorization.FromValidatedPlan(mapping.DirectoryObjectId, mapping.DeviceId,
                mapping.MappingCreatedAt, PermitDeadline(), RandomNumberGenerator.GetBytes(32)),
            ValidatedPersistedPlatformGrant.FromValidatedOutboxRecord(RandomNumberGenerator.GetBytes(32)), CancellationToken.None);
        Assert.Equal(PlatformGrantOutcome.Created, issued.Outcome);
        var receipt = Assert.IsType<PlatformGrantReceipt>(issued.Receipt);
        Assert.Equal((short)2, receipt.IssueContractVersion);

        var repository = await Repository();
        Assert.Equal(PlatformGrantEffectiveState.Available,
            (await repository.ReadAsync(receipt, CancellationToken.None)).State);
        var changedDeadline = new PlatformGrantReceipt(receipt.EnvironmentId, receipt.OperationId, receipt.GrantId,
            receipt.DirectoryObjectId, receipt.DeviceId, receipt.MappingCreatedAt, receipt.CreatedAt, receipt.ExpiresAt,
            2, receipt.MintPermitNotAfter!.Value.AddSeconds(1), receipt.GetTokenSha256(), receipt.GetAuthorizationDigest());
        Assert.Equal(PlatformGrantDiagnostic.OperationConflict,
            (await repository.ReadAsync(changedDeadline, CancellationToken.None)).Diagnostic);

        var revoked = await repository.RevokeAsync(Guid.NewGuid(), Authorization(receipt), CancellationToken.None);
        Assert.Equal(PlatformGrantRevocationOutcome.Completed, revoked.Outcome);
        Assert.Equal((short)2, revoked.Receipt!.IssueReceipt.IssueContractVersion);
        Assert.Equal(receipt.MintPermitNotAfter, revoked.Receipt.IssueReceipt.MintPermitNotAfter);
    }

    [Theory]
    [InlineData("Available", "Revoked")]
    [InlineData("Expired", "Expired")]
    [InlineData("Consumed", "Consumed")]
    [InlineData("Revoked", "AlreadyRevoked")]
    public async Task EachStateHasADurableDispositionAndExactRetry(string initial, string disposition)
    {
        await fixture.Reset();
        var seed = await Seed(initial);
        var repository = await Repository();
        var before = await repository.ReadAsync(seed.Receipt, CancellationToken.None);
        Assert.Equal(Enum.Parse<PlatformGrantEffectiveState>(initial), before.State);
        Assert.NotNull(before.ObservedAt);
        Assert.Equal(initial is "Consumed" or "Revoked", before.StateChangedAt is not null);
        Assert.Equal(0, await ReceiptCount());

        var operation = Guid.NewGuid(); var authorization = Authorization(seed.Receipt);
        var completed = await repository.RevokeAsync(operation, authorization, CancellationToken.None);
        Assert.Equal(PlatformGrantRevocationOutcome.Completed, completed.Outcome);
        Assert.Equal(Enum.Parse<PlatformGrantRevocationDisposition>(disposition), completed.Receipt!.Disposition);
        var replay = await repository.RevokeAsync(operation, authorization, CancellationToken.None);
        Assert.Equal(PlatformGrantRevocationOutcome.AlreadyCompleted, replay.Outcome);
        Assert.Equal(completed.Receipt, replay.Receipt);
        Assert.Equal(1, await ReceiptCount());
        var after = await repository.ReadAsync(seed.Receipt, CancellationToken.None);
        Assert.Equal(initial == "Consumed" ? PlatformGrantEffectiveState.Consumed : PlatformGrantEffectiveState.Revoked, after.State);
        if (initial is "Consumed" or "Revoked") Assert.Equal(before.StateChangedAt, after.StateChangedAt);
        else Assert.Equal(completed.Receipt.EffectiveRevokedAt, after.StateChangedAt);
    }

    [Fact]
    public async Task HistoricalRevocationSurvivesMappingRemovalAndDeviceDeactivation()
    {
        await fixture.Reset(); var seed = await Seed(); var repository = await Repository();
        await fixture.Execute("DELETE FROM agent_private.agent_device_directory_bindings WHERE environment_id=@env AND device_id=@device; UPDATE agent_private.devices SET state='Disabled' WHERE environment_id=@env AND device_id=@device",
            new("env", seed.Receipt.EnvironmentId), new("device", seed.Receipt.DeviceId));
        Assert.Equal(PlatformGrantEffectiveState.Available, (await repository.ReadAsync(seed.Receipt, CancellationToken.None)).State);
        var result = await repository.RevokeAsync(Guid.NewGuid(), Authorization(seed.Receipt), CancellationToken.None);
        Assert.Equal(PlatformGrantRevocationOutcome.Completed, result.Outcome);
        Assert.Equal(PlatformGrantRevocationDisposition.Revoked, result.Receipt!.Disposition);
        Assert.Equal(1, await ReceiptCount());
    }

    [Fact]
    public async Task ExpiredCleanupReleasesTheAvailableSlotWithoutChangingOldReceipt()
    {
        await fixture.Reset(); var seed = await Seed("Expired"); var repository = await Repository();
        var result = await repository.RevokeAsync(Guid.NewGuid(), Authorization(seed.Receipt), CancellationToken.None);
        Assert.Equal(PlatformGrantRevocationOutcome.Completed, result.Outcome);
        Assert.Equal(PlatformGrantRevocationDisposition.Expired, result.Receipt!.Disposition);
        var issuer = await PostgresPlatformGrantRepository.CreateAuditedAsync(fixture.Platform, fixture.EnvironmentId,
            fixture.TableOwnerRole, fixture.PlatformDefinerRole, CancellationToken.None);
        var issued = await issuer.IssueAsync(Guid.NewGuid(), ValidatedGrantAuthorization.FromValidatedPlan(
            seed.Receipt.DirectoryObjectId, seed.Receipt.DeviceId, seed.Receipt.MappingCreatedAt, PermitDeadline(), RandomNumberGenerator.GetBytes(32)),
            ValidatedPersistedPlatformGrant.FromValidatedOutboxRecord(RandomNumberGenerator.GetBytes(32)), CancellationToken.None);
        Assert.Equal(PlatformGrantOutcome.Created, issued.Outcome);
        Assert.NotEqual(seed.Receipt.GrantId, issued.Receipt!.GrantId);
        Assert.Equal(1, await fixture.Scalar<long>("SELECT count(*) FROM agent_private.enrollment_grants WHERE state='Available'"));
        Assert.Equal(PlatformGrantEffectiveState.Revoked, (await repository.ReadAsync(seed.Receipt, CancellationToken.None)).State);
    }

    [Fact]
    public async Task DifferentOperationOrDigestCannotReplaceThePermanentRevocation()
    {
        await fixture.Reset(); var seed = await Seed(); var repository = await Repository();
        var operation = Guid.NewGuid(); var authorization = Authorization(seed.Receipt);
        var completed = await repository.RevokeAsync(operation, authorization, CancellationToken.None);
        Assert.Equal(PlatformGrantRevocationOutcome.Completed, completed.Outcome);
        foreach (var result in new[]
        {
            await repository.RevokeAsync(Guid.NewGuid(), authorization, CancellationToken.None),
            await repository.RevokeAsync(operation, Authorization(seed.Receipt), CancellationToken.None)
        })
        {
            Assert.Equal(PlatformGrantRevocationOutcome.OutcomeUnknown, result.Outcome);
            Assert.Equal(PlatformGrantDiagnostic.OperationConflict, result.Diagnostic);
            Assert.Null(result.Receipt);
        }
        Assert.Equal(completed.Receipt, (await repository.RevokeAsync(operation, authorization, CancellationToken.None)).Receipt);
        Assert.Equal(1, await ReceiptCount());
    }

    [Fact]
    public async Task ConcurrentExactRetriesProduceOneReceipt()
    {
        await fixture.Reset(); var seed = await Seed(); var repository = await Repository();
        var operation = Guid.NewGuid(); var authorization = Authorization(seed.Receipt);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var results = await Task.WhenAll(Enumerable.Range(0, 4).Select(_ => repository.RevokeAsync(operation, authorization, timeout.Token)));
        Assert.Single(results, value => value.Outcome == PlatformGrantRevocationOutcome.Completed);
        Assert.Equal(3, results.Count(value => value.Outcome == PlatformGrantRevocationOutcome.AlreadyCompleted));
        Assert.All(results, value => Assert.Equal(results[0].Receipt, value.Receipt));
        Assert.Equal(1, await ReceiptCount());
    }

    [Fact]
    public async Task ConsumeAndRevokeCannotBothTransitionAnAvailableGrant()
    {
        await fixture.Reset(); var seed = await Seed(); var repository = await Repository();
        using var key = RSA.Create(3072);
        var csr = EnrollmentCsrValidator.Validate(new CertificateRequest("CN=synthetic", key,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).CreateSigningRequest());
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var consume = new EnrollmentSubmissionRepository(fixture.Enroll).SubmitOrRecoverAsync(
            EnrollmentBearerToken.FromBytes(seed.Token), Guid.NewGuid(), Guid.NewGuid(), csr, timeout.Token);
        var revoke = repository.RevokeAsync(Guid.NewGuid(), Authorization(seed.Receipt), timeout.Token);
        await Task.WhenAll(consume, revoke);
        var consumed = await consume; var revoked = await revoke;
        Assert.Equal(PlatformGrantRevocationOutcome.Completed, revoked.Outcome);
        if (revoked.Receipt!.Disposition == PlatformGrantRevocationDisposition.Consumed)
        {
            Assert.Equal(EnrollmentSubmissionOutcome.Pending, consumed.Outcome);
            Assert.Equal(1, await fixture.Scalar<long>("SELECT count(*) FROM agent_private.enrollment_requests"));
        }
        else
        {
            Assert.Equal(PlatformGrantRevocationDisposition.Revoked, revoked.Receipt.Disposition);
            Assert.Equal(EnrollmentSubmissionOutcome.PermanentRejected, consumed.Outcome);
            Assert.Equal(0, await fixture.Scalar<long>("SELECT count(*) FROM agent_private.enrollment_requests"));
        }
        Assert.Equal(1, await ReceiptCount());
    }

    [Theory]
    [InlineData("grant")]
    [InlineData("directory")]
    [InlineData("device")]
    [InlineData("mapping")]
    [InlineData("token")]
    [InlineData("digest")]
    [InlineData("issue-time")]
    public async Task OriginalReceiptMismatchDoesNotRevokeTheRealGrant(string field)
    {
        await fixture.Reset(); var seed = await Seed(); var repository = await Repository(); var r = seed.Receipt;
        var different = new PlatformGrantReceipt(r.EnvironmentId, r.OperationId,
            field == "grant" ? Guid.NewGuid() : r.GrantId,
            field == "directory" ? Guid.NewGuid() : r.DirectoryObjectId,
            field == "device" ? Guid.NewGuid() : r.DeviceId,
            field == "mapping" ? r.MappingCreatedAt.AddTicks(-10) : r.MappingCreatedAt,
            field == "issue-time" ? r.CreatedAt.AddTicks(-10) : r.CreatedAt,
            field == "issue-time" ? r.ExpiresAt.AddTicks(-10) : r.ExpiresAt,
            field == "token" ? RandomNumberGenerator.GetBytes(32) : r.GetTokenSha256(),
            field == "digest" ? RandomNumberGenerator.GetBytes(32) : r.GetAuthorizationDigest());
        var read = await repository.ReadAsync(different, CancellationToken.None);
        Assert.Equal(PlatformGrantEffectiveState.Unknown, read.State);
        Assert.Equal(PlatformGrantDiagnostic.OperationConflict, read.Diagnostic);
        var revoke = await repository.RevokeAsync(Guid.NewGuid(), Authorization(different), CancellationToken.None);
        Assert.Equal(PlatformGrantRevocationOutcome.OutcomeUnknown, revoke.Outcome);
        Assert.Equal(PlatformGrantDiagnostic.OperationConflict, revoke.Diagnostic);
        Assert.Null(revoke.Receipt); Assert.Equal(0, await ReceiptCount());
        Assert.Equal(PlatformGrantEffectiveState.Available, (await repository.ReadAsync(r, CancellationToken.None)).State);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task MissingOrInconsistentDurableEvidenceRemainsUnknown(bool inconsistentGrant)
    {
        await fixture.Reset(); var seed = await Seed(); var repository = await Repository();
        if (inconsistentGrant)
            await fixture.Execute("UPDATE agent_private.enrollment_grants SET token_sha256=@hash WHERE environment_id=@env AND grant_id=@id",
                new("hash", RandomNumberGenerator.GetBytes(32)), new("env", seed.Receipt.EnvironmentId), new("id", seed.Receipt.GrantId));
        else
            await fixture.Execute("DELETE FROM agent_private.platform_grant_receipts WHERE environment_id=@env AND operation_id=@id",
                new("env", seed.Receipt.EnvironmentId), new("id", seed.Receipt.OperationId));
        var read = await repository.ReadAsync(seed.Receipt, CancellationToken.None);
        Assert.Equal(PlatformGrantEffectiveState.Unknown, read.State);
        Assert.Equal(PlatformGrantDiagnostic.ReceiptUnavailable, read.Diagnostic);
        var revoke = await repository.RevokeAsync(Guid.NewGuid(), Authorization(seed.Receipt), CancellationToken.None);
        Assert.Equal(PlatformGrantRevocationOutcome.OutcomeUnknown, revoke.Outcome);
        Assert.Equal(PlatformGrantDiagnostic.ReceiptUnavailable, revoke.Diagnostic);
        Assert.Null(revoke.Receipt); Assert.Equal(0, await ReceiptCount());
        Assert.Equal("Available", await fixture.Scalar<string>("SELECT state FROM agent_private.enrollment_grants WHERE grant_id=@id",
            new NpgsqlParameter("id", seed.Receipt.GrantId)));
    }

    [Fact]
    public async Task RowLockWaitCrossingExpiryUsesTheTimeAfterTheLockIsAcquired()
    {
        await fixture.Reset(); var seed = await Seed(expiresSoon: true); var repository = await Repository();
        await using var connection = await fixture.Owner.OpenConnectionAsync();
        await using var transaction = await connection.BeginTransactionAsync();
        await using (var command = new NpgsqlCommand("SELECT 1 FROM agent_private.enrollment_grants WHERE grant_id=@id FOR UPDATE", connection, transaction))
        {
            command.Parameters.AddWithValue("id", seed.Receipt.GrantId);
            await command.ExecuteScalarAsync();
        }
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var revoke = repository.RevokeAsync(Guid.NewGuid(), Authorization(seed.Receipt), timeout.Token);
        try
        {
            while (!await fixture.Scalar<bool>("SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_stat_activity WHERE usename=@role AND wait_event_type='Lock')",
                new NpgsqlParameter("role", fixture.RevokerRole)))
            {
                Assert.False(revoke.IsCompleted, "Revoke must wait for the grant row lock.");
                await Task.Delay(25, timeout.Token);
            }
            Assert.True(await fixture.Scalar<bool>("SELECT clock_timestamp()<@expiry", new NpgsqlParameter("expiry", seed.Receipt.ExpiresAt)),
                "The blocked operation must begin before expiry to exercise the clock boundary.");
            while (!await fixture.Scalar<bool>("SELECT clock_timestamp()>=@expiry", new NpgsqlParameter("expiry", seed.Receipt.ExpiresAt)))
                await Task.Delay(25, timeout.Token);
        }
        finally
        {
            try { await transaction.RollbackAsync(CancellationToken.None); }
            finally
            {
                try { await revoke; }
                catch (OperationCanceledException) when (timeout.IsCancellationRequested) { }
            }
        }
        var result = await revoke;
        Assert.Equal(PlatformGrantRevocationOutcome.Completed, result.Outcome);
        Assert.Equal(PlatformGrantRevocationDisposition.Expired, result.Receipt!.Disposition);
        Assert.True(result.Receipt.CompletedAt >= seed.Receipt.ExpiresAt);
        Assert.Equal(result.Receipt.CompletedAt, result.Receipt.EffectiveRevokedAt);
        Assert.Equal(1, await ReceiptCount());
    }

    [Fact]
    public async Task CommittedConsumeWakesBlockedRevocationWithConsumedDisposition()
    {
        await fixture.Reset(); var seed = await Seed(); var repository = await Repository();
        using var key = RSA.Create(3072);
        var csr = EnrollmentCsrValidator.Validate(new CertificateRequest("CN=synthetic", key,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).CreateSigningRequest());
        await using var connection = await fixture.Enroll.OpenConnectionAsync();
        await using var transaction = await connection.BeginTransactionAsync();
        await using (var command = new NpgsqlCommand("""
            SELECT outcome FROM agent_private.submit_or_recover_enrollment(@token,@request,@device,@csr,@csr_hash,@spki_hash,1)
            """, connection, transaction))
        {
            command.Parameters.AddWithValue("token", seed.Token);
            command.Parameters.AddWithValue("request", Guid.NewGuid());
            command.Parameters.AddWithValue("device", Guid.NewGuid());
            command.Parameters.AddWithValue("csr", csr.GetDer());
            command.Parameters.AddWithValue("csr_hash", csr.GetCsrSha256());
            command.Parameters.AddWithValue("spki_hash", csr.GetSubjectPublicKeyInfoSha256());
            Assert.Equal("Pending", await command.ExecuteScalarAsync());
        }
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var revoke = repository.RevokeAsync(Guid.NewGuid(), Authorization(seed.Receipt), timeout.Token);
        var committed = false;
        try
        {
            while (!await fixture.Scalar<bool>("SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_stat_activity WHERE usename=@role AND wait_event_type='Lock')",
                new NpgsqlParameter("role", fixture.RevokerRole)))
            {
                Assert.False(revoke.IsCompleted, "Revoke must wait for the uncommitted consume.");
                await Task.Delay(25, timeout.Token);
            }
            await transaction.CommitAsync(CancellationToken.None);
            committed = true;
        }
        finally
        {
            try { if (!committed) await transaction.RollbackAsync(CancellationToken.None); }
            finally
            {
                try { await revoke; }
                catch (OperationCanceledException) when (timeout.IsCancellationRequested) { }
            }
        }
        var result = await revoke;
        Assert.Equal(PlatformGrantRevocationOutcome.Completed, result.Outcome);
        Assert.Equal(PlatformGrantRevocationDisposition.Consumed, result.Receipt!.Disposition);
        Assert.Null(result.Receipt.EffectiveRevokedAt);
        Assert.Equal(1, await ReceiptCount());
        Assert.Equal(1, await fixture.Scalar<long>("SELECT count(*) FROM agent_private.enrollment_requests"));
    }

    [Fact]
    public async Task CancellationWhileWaitingForTheGrantLockCannotCommitLater()
    {
        await fixture.Reset(); var seed = await Seed(); var repository = await Repository();
        await using var connection = await fixture.Owner.OpenConnectionAsync();
        await using var transaction = await connection.BeginTransactionAsync();
        await using (var command = new NpgsqlCommand("SELECT 1 FROM agent_private.enrollment_grants WHERE grant_id=@id FOR UPDATE", connection, transaction))
        {
            command.Parameters.AddWithValue("id", seed.Receipt.GrantId);
            await command.ExecuteScalarAsync();
        }
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var cancelRevoke = new CancellationTokenSource();
        var revoke = repository.RevokeAsync(Guid.NewGuid(), Authorization(seed.Receipt), cancelRevoke.Token);
        try
        {
            while (!await fixture.Scalar<bool>("SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_stat_activity WHERE usename=@role AND wait_event_type='Lock')",
                new NpgsqlParameter("role", fixture.RevokerRole)))
            {
                Assert.False(revoke.IsCompleted, "Revoke must reach the blocked grant row before cancellation.");
                await Task.Delay(25, timeout.Token);
            }
            await cancelRevoke.CancelAsync();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => revoke.WaitAsync(timeout.Token));
            Assert.True(revoke.IsCanceled, "The database operation itself must observe cancellation.");
        }
        finally
        {
            try
            {
                await cancelRevoke.CancelAsync();
                await transaction.RollbackAsync(CancellationToken.None);
            }
            finally
            {
                try { await revoke; }
                catch (OperationCanceledException) when (cancelRevoke.IsCancellationRequested) { }
            }
        }
        Assert.Equal(0, await ReceiptCount());
        Assert.Equal(PlatformGrantEffectiveState.Available, (await repository.ReadAsync(seed.Receipt, CancellationToken.None)).State);
    }

    [Fact]
    public async Task RevocationOperationIdIsGlobalAcrossEnvironmentBoundPools()
    {
        await fixture.Reset(); var additional = await fixture.AddPlatformEnvironment();
        var firstSeed = await Seed(); var secondSeed = await Seed(environmentId: additional.EnvironmentId);
        var first = await Repository();
        var second = await PostgresPlatformGrantRevocationRepository.CreateAuditedAsync(additional.RevokerDataSource,
            additional.EnvironmentId, fixture.TableOwnerRole, fixture.PlatformDefinerRole, CancellationToken.None);
        var operation = Guid.NewGuid();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var results = await Task.WhenAll(
            first.RevokeAsync(operation, Authorization(firstSeed.Receipt), timeout.Token),
            second.RevokeAsync(operation, Authorization(secondSeed.Receipt), timeout.Token));
        Assert.Single(results, value => value.Outcome == PlatformGrantRevocationOutcome.Completed);
        Assert.Single(results, value => value.Outcome == PlatformGrantRevocationOutcome.OutcomeUnknown &&
            value.Diagnostic == PlatformGrantDiagnostic.OperationConflict);
        Assert.Equal(1, await ReceiptCount());
        var reads = await Task.WhenAll(first.ReadAsync(firstSeed.Receipt, timeout.Token), second.ReadAsync(secondSeed.Receipt, timeout.Token));
        Assert.Single(reads, value => value.State == PlatformGrantEffectiveState.Revoked);
        Assert.Single(reads, value => value.State == PlatformGrantEffectiveState.Available);
    }

    private async Task<PostgresPlatformGrantRevocationRepository> Repository() =>
        await PostgresPlatformGrantRevocationRepository.CreateAuditedAsync(fixture.Revoker, fixture.EnvironmentId,
            fixture.TableOwnerRole, fixture.PlatformDefinerRole, CancellationToken.None);

    private Task<long> ReceiptCount() => fixture.Scalar<long>("SELECT count(*) FROM agent_private.platform_grant_revocation_receipts");
    private static ValidatedGrantRevocationAuthorization Authorization(PlatformGrantReceipt receipt) =>
        ValidatedGrantRevocationAuthorization.FromValidatedPlan(receipt, RandomNumberGenerator.GetBytes(32));
    private static DateTimeOffset PermitDeadline()
    {
        var value = DateTimeOffset.UtcNow.AddSeconds(45);
        return new DateTimeOffset(value.Ticks - value.Ticks % 10, TimeSpan.Zero);
    }

    // Owner-only historical seeding avoids waiting ten minutes or altering immutable issued receipts.
    private async Task<Seeded> Seed(string state = "Available", bool expiresSoon = false, Guid? environmentId = null)
    {
        var mapping = await fixture.SeedMapping(environmentId ?? fixture.EnvironmentId); var token = RandomNumberGenerator.GetBytes(32);
        var created = mapping.MappingCreatedAt.AddSeconds(expiresSoon ? -595 : state == "Expired" ? -660 : 0);
        var mappingCreated = created.AddMinutes(-1); var expires = created.AddSeconds(600);
        var receipt = new PlatformGrantReceipt(mapping.EnvironmentId, Guid.NewGuid(), Guid.NewGuid(),
            mapping.DirectoryObjectId, mapping.DeviceId, mappingCreated, created, expires,
            SHA256.HashData(token), RandomNumberGenerator.GetBytes(32));
        await fixture.Execute("""
            UPDATE agent_private.agent_device_directory_bindings SET created_at=@mapping
              WHERE environment_id=@env AND directory_object_id=@directory;
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
            new("created", created), new("expires", expires), new("request", Guid.NewGuid()),
            new("operation", receipt.OperationId), new("directory", receipt.DirectoryObjectId),
            new("mapping", mappingCreated), new("digest", receipt.GetAuthorizationDigest()));
        return new(receipt, token);
    }

    private sealed record Seeded(PlatformGrantReceipt Receipt, byte[] Token);
}
