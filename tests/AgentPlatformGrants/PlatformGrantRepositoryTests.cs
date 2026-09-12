using System.Security.Cryptography;
using ItManagement.AgentEnrollment;
using ItManagement.AgentIngestion;
using ItManagement.AgentProjection;
using Npgsql;

namespace ItManagement.AgentPlatformGrants.Tests;

[Collection(PlatformGrantCollection.Name)]
public sealed class PlatformGrantRepositoryTests(AgentPlatformGrantFixture fixture)
{
    [Fact]
    public async Task CreatesFixedTtlGrantAndExactRetryReturnsTheSameReceipt()
    {
        await fixture.Reset();
        var mapping = await fixture.SeedMapping();
        var repository = await Repository();
        var operation = Guid.NewGuid();
        var tokenHash = RandomNumberGenerator.GetBytes(32);
        var authorization = Authorization(mapping, RandomNumberGenerator.GetBytes(32));
        var prepared = ValidatedPersistedPlatformGrant.FromValidatedOutboxRecord(tokenHash);

        var created = await repository.IssueAsync(operation, authorization, prepared, CancellationToken.None);
        var replay = await repository.IssueAsync(operation, authorization, prepared, CancellationToken.None);

        Assert.Equal(PlatformGrantOutcome.Created, created.Outcome);
        Assert.Equal(PlatformGrantOutcome.AlreadyCreated, replay.Outcome);
        Assert.Equal(created.Receipt, replay.Receipt);
        Assert.Equal(TimeSpan.FromSeconds(600), created.Receipt!.ExpiresAt - created.Receipt.CreatedAt);
        Assert.Equal(1, await fixture.Scalar<long>("SELECT count(*) FROM agent_private.enrollment_grants"));
        Assert.Equal(1, await fixture.Scalar<long>("SELECT count(*) FROM agent_private.platform_grant_receipts"));
    }

    [Fact]
    public async Task ExactRecoverySurvivesMappingRemovalButAnyTupleChangeHalts()
    {
        await fixture.Reset();
        var mapping = await fixture.SeedMapping();
        var repository = await Repository();
        var operation = Guid.NewGuid();
        var digest = RandomNumberGenerator.GetBytes(32);
        var prepared = ValidatedPersistedPlatformGrant.FromValidatedOutboxRecord(RandomNumberGenerator.GetBytes(32));
        var authorization = Authorization(mapping, digest);
        var created = await repository.IssueAsync(operation, authorization, prepared, CancellationToken.None);
        await fixture.Execute("DELETE FROM agent_private.agent_device_directory_bindings WHERE environment_id=@env AND directory_object_id=@directory", new("env", mapping.EnvironmentId), new("directory", mapping.DirectoryObjectId));

        var recovered = await repository.IssueAsync(operation, authorization, prepared, CancellationToken.None);
        var conflict = await repository.IssueAsync(operation, Authorization(mapping, RandomNumberGenerator.GetBytes(32)), prepared, CancellationToken.None);

        Assert.Equal(PlatformGrantOutcome.AlreadyCreated, recovered.Outcome);
        Assert.Equal(created.Receipt, recovered.Receipt);
        Assert.Equal(PlatformGrantOutcome.OutcomeUnknown, conflict.Outcome);
        Assert.Equal(PlatformGrantDiagnostic.OperationConflict, conflict.Diagnostic);
    }

    [Fact]
    public async Task ExactDeadlineBoundRecoverySucceedsAfterPermitExpiryButChangedDeadlineConflicts()
    {
        await fixture.Reset();
        var mapping = await fixture.SeedMapping();
        var repository = await Repository();
        var operation = Guid.NewGuid();
        var digest = RandomNumberGenerator.GetBytes(32);
        var prepared = ValidatedPersistedPlatformGrant.FromValidatedOutboxRecord(RandomNumberGenerator.GetBytes(32));
        var deadline = CanonicalNow().AddSeconds(2);
        var authorization = ValidatedGrantAuthorization.FromValidatedPlan(
            mapping.DirectoryObjectId, mapping.DeviceId, mapping.MappingCreatedAt, deadline, digest);

        var created = await repository.IssueAsync(operation, authorization, prepared, CancellationToken.None);
        Assert.Equal(PlatformGrantOutcome.Created, created.Outcome);
        while (!await fixture.Scalar<bool>("SELECT pg_catalog.clock_timestamp()>=@deadline", new NpgsqlParameter("deadline", deadline)))
            await Task.Delay(25);

        var replay = await repository.IssueAsync(operation, authorization, prepared, CancellationToken.None);
        var changed = await repository.IssueAsync(operation,
            ValidatedGrantAuthorization.FromValidatedPlan(mapping.DirectoryObjectId, mapping.DeviceId,
                mapping.MappingCreatedAt, deadline.AddSeconds(1), digest), prepared, CancellationToken.None);

        Assert.Equal(PlatformGrantOutcome.AlreadyCreated, replay.Outcome);
        Assert.Equal(created.Receipt, replay.Receipt);
        Assert.Equal((short)2, replay.Receipt!.IssueContractVersion);
        Assert.Equal(deadline, replay.Receipt.MintPermitNotAfter);
        Assert.Equal(PlatformGrantOutcome.OutcomeUnknown, changed.Outcome);
        Assert.Equal(PlatformGrantDiagnostic.OperationConflict, changed.Diagnostic);
    }

    [Fact]
    public async Task ExpiredAndFarFutureMintPermitsAreDefinitivelyRejectedWithoutWrites()
    {
        await fixture.Reset();
        var mapping = await fixture.SeedMapping();
        var repository = await Repository();
        var prepared = ValidatedPersistedPlatformGrant.FromValidatedOutboxRecord(RandomNumberGenerator.GetBytes(32));
        var digest = RandomNumberGenerator.GetBytes(32);
        var now = CanonicalNow();

        var expired = await repository.IssueAsync(Guid.NewGuid(),
            ValidatedGrantAuthorization.FromValidatedPlan(mapping.DirectoryObjectId, mapping.DeviceId,
                mapping.MappingCreatedAt, now.AddSeconds(-1), digest), prepared, CancellationToken.None);
        var tooFar = await repository.IssueAsync(Guid.NewGuid(),
            ValidatedGrantAuthorization.FromValidatedPlan(mapping.DirectoryObjectId, mapping.DeviceId,
                mapping.MappingCreatedAt, now.AddMinutes(2), digest), prepared, CancellationToken.None);

        Assert.Equal(PlatformGrantDiagnostic.MintPermitExpired, expired.Diagnostic);
        Assert.Equal(PlatformGrantDiagnostic.InvalidMintPermit, tooFar.Diagnostic);
        Assert.Equal(0, await fixture.Scalar<long>("SELECT count(*) FROM agent_private.platform_grant_receipts"));
        Assert.Equal(0, await fixture.Scalar<long>("SELECT count(*) FROM agent_private.enrollment_grants"));
    }

    [Fact]
    public async Task LegacySignatureRecoversOnlyAnExistingVersion1Receipt()
    {
        await fixture.Reset();
        var mapping = await fixture.SeedMapping();
        var repository = await Repository();
        var operation = Guid.NewGuid();
        var digest = RandomNumberGenerator.GetBytes(32);
        var tokenHash = RandomNumberGenerator.GetBytes(32);
        var authorization = ValidatedGrantAuthorization.FromValidatedPlan(
            mapping.DirectoryObjectId, mapping.DeviceId, mapping.MappingCreatedAt, digest);
        var prepared = ValidatedPersistedPlatformGrant.FromValidatedOutboxRecord(tokenHash);

        var absent = await repository.IssueAsync(operation, authorization, prepared, CancellationToken.None);
        Assert.Equal(PlatformGrantOutcome.PermanentRejected, absent.Outcome);
        Assert.Equal(PlatformGrantDiagnostic.InvalidMintPermit, absent.Diagnostic);

        var createdAt = CanonicalNow();
        var grant = Guid.NewGuid();
        await fixture.Execute("""
            INSERT INTO agent_private.enrollment_grants(environment_id,grant_id,device_id,token_sha256,state,created_at,expires_at)
            VALUES(@env,@grant,@device,@token,'Available',@created,@expires);
            INSERT INTO agent_private.platform_grant_receipts(environment_id,operation_id,grant_id,directory_object_id,
              device_id,mapping_created_at,token_sha256,authorization_digest,created_at,expires_at,issue_contract_version,mint_permit_not_after)
            VALUES(@env,@operation,@grant,@directory,@device,@mapping,@token,@digest,@created,@expires,1,NULL);
            """, new("env", mapping.EnvironmentId), new("grant", grant), new("device", mapping.DeviceId),
            new("token", tokenHash), new("created", createdAt), new("expires", createdAt.AddSeconds(600)),
            new("operation", operation), new("directory", mapping.DirectoryObjectId),
            new("mapping", mapping.MappingCreatedAt), new("digest", digest));

        var recovered = await repository.IssueAsync(operation, authorization, prepared, CancellationToken.None);
        Assert.Equal(PlatformGrantOutcome.AlreadyCreated, recovered.Outcome);
        Assert.Equal((short)1, recovered.Receipt!.IssueContractVersion);
        Assert.Null(recovered.Receipt.MintPermitNotAfter);
        Assert.Equal(1, await fixture.Scalar<long>("SELECT count(*) FROM agent_private.platform_grant_receipts"));
    }

    [Fact]
    public async Task DeviceLockWaitCrossingPermitDeadlineCannotMint()
    {
        await fixture.Reset();
        var mapping = await fixture.SeedMapping();
        var repository = await Repository();
        var deadline = CanonicalNow().AddSeconds(2);
        await using var connection = await fixture.Owner.OpenConnectionAsync();
        await using var transaction = await connection.BeginTransactionAsync();
        await using (var command = new NpgsqlCommand(
            "SELECT 1 FROM agent_private.devices WHERE environment_id=@env AND device_id=@device FOR UPDATE", connection, transaction))
        {
            command.Parameters.AddWithValue("env", mapping.EnvironmentId);
            command.Parameters.AddWithValue("device", mapping.DeviceId);
            await command.ExecuteScalarAsync();
        }

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var issue = repository.IssueAsync(Guid.NewGuid(),
            ValidatedGrantAuthorization.FromValidatedPlan(mapping.DirectoryObjectId, mapping.DeviceId,
                mapping.MappingCreatedAt, deadline, RandomNumberGenerator.GetBytes(32)),
            ValidatedPersistedPlatformGrant.FromValidatedOutboxRecord(RandomNumberGenerator.GetBytes(32)), timeout.Token);
        try
        {
            while (!await fixture.Scalar<bool>("SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_stat_activity WHERE usename=@role AND wait_event_type='Lock')",
                new NpgsqlParameter("role", fixture.PlatformRole)))
            {
                Assert.False(issue.IsCompleted);
                await Task.Delay(25, timeout.Token);
            }
            while (!await fixture.Scalar<bool>("SELECT pg_catalog.clock_timestamp()>=@deadline", new NpgsqlParameter("deadline", deadline)))
                await Task.Delay(25, timeout.Token);
        }
        finally
        {
            try { await transaction.RollbackAsync(CancellationToken.None); }
            finally
            {
                try { await issue; }
                catch (OperationCanceledException) when (timeout.IsCancellationRequested) { }
            }
        }

        var result = await issue;
        Assert.Equal(PlatformGrantOutcome.PermanentRejected, result.Outcome);
        Assert.Equal(PlatformGrantDiagnostic.MintPermitExpired, result.Diagnostic);
        Assert.Equal(0, await fixture.Scalar<long>("SELECT count(*) FROM agent_private.platform_grant_receipts"));
    }

    [Fact]
    public async Task FreshOperationsRequireExactCurrentMappingAndActiveDevice()
    {
        await fixture.Reset();
        var mapping = await fixture.SeedMapping();
        var repository = await Repository();
        var prepared = ValidatedPersistedPlatformGrant.FromValidatedOutboxRecord(RandomNumberGenerator.GetBytes(32));
        var digest = RandomNumberGenerator.GetBytes(32);

        var wrongTimestamp = await repository.IssueAsync(Guid.NewGuid(),
            ValidatedGrantAuthorization.FromValidatedPlan(mapping.DirectoryObjectId, mapping.DeviceId, mapping.MappingCreatedAt.AddTicks(10), PermitDeadline(), digest), prepared, CancellationToken.None);
        await fixture.Execute("UPDATE agent_private.devices SET state='Disabled' WHERE environment_id=@env AND device_id=@device", new("env", mapping.EnvironmentId), new("device", mapping.DeviceId));
        var disabled = await repository.IssueAsync(Guid.NewGuid(), Authorization(mapping, digest), prepared, CancellationToken.None);

        Assert.Equal(PlatformGrantDiagnostic.MappingUnavailable, wrongTimestamp.Diagnostic);
        Assert.Equal(PlatformGrantDiagnostic.DeviceUnavailable, disabled.Diagnostic);
        Assert.Equal(0, await fixture.Scalar<long>("SELECT count(*) FROM agent_private.platform_grant_receipts"));
    }

    [Theory]
    [InlineData("registration")]
    [InlineData("request")]
    [InlineData("grant")]
    public async Task ExistingEnrollmentStateBlocksFreshGrant(string blocker)
    {
        await fixture.Reset();
        var mapping = await fixture.SeedMapping();
        if (blocker == "registration")
            await fixture.Execute("INSERT INTO agent_private.registrations(environment_id,registration_id,device_id,registration_epoch,device_guid,state) VALUES(@env,@id,@device,1,@guid,'Active')", new("env", mapping.EnvironmentId), new("id", Guid.NewGuid()), new("device", mapping.DeviceId), new("guid", Guid.NewGuid()));
        else if (blocker == "grant")
            await fixture.Execute("INSERT INTO agent_private.enrollment_grants(environment_id,grant_id,device_id,token_sha256,state,created_at,expires_at) VALUES(@env,@id,@device,@hash,'Available',clock_timestamp(),clock_timestamp()+interval '10 minutes')", new("env", mapping.EnvironmentId), new("id", Guid.NewGuid()), new("device", mapping.DeviceId), new("hash", RandomNumberGenerator.GetBytes(32)));
        else
        {
            var grant = Guid.NewGuid();
            await fixture.Execute("INSERT INTO agent_private.enrollment_grants(environment_id,grant_id,device_id,token_sha256,state,created_at,expires_at,consumed_at,consumed_request_id) VALUES(@env,@grant,@device,@hash,'Consumed',clock_timestamp(),clock_timestamp()+interval '10 minutes',clock_timestamp(),@request); INSERT INTO agent_private.enrollment_requests(environment_id,request_id,grant_id,device_id,device_guid,csr_der,csr_sha256,spki_sha256,profile_version,registration_id,registration_epoch,issuance_id,state) VALUES(@env,@request,@grant,@device,@guid,@csr,@csrhash,@spki,1,@registration,1,@issuance,'PendingIssuance')", new("env", mapping.EnvironmentId), new("grant", grant), new("device", mapping.DeviceId), new("hash", RandomNumberGenerator.GetBytes(32)), new("request", Guid.NewGuid()), new("guid", Guid.NewGuid()), new("csr", new byte[] { 1 }), new("csrhash", RandomNumberGenerator.GetBytes(32)), new("spki", RandomNumberGenerator.GetBytes(32)), new("registration", Guid.NewGuid()), new("issuance", Guid.NewGuid()));
        }
        var result = await (await Repository()).IssueAsync(Guid.NewGuid(), Authorization(mapping, RandomNumberGenerator.GetBytes(32)), ValidatedPersistedPlatformGrant.FromValidatedOutboxRecord(RandomNumberGenerator.GetBytes(32)), CancellationToken.None);
        Assert.Equal(blocker switch { "registration" => PlatformGrantDiagnostic.EnrollmentAlreadyExists, "request" => PlatformGrantDiagnostic.EnrollmentInProgress, _ => PlatformGrantDiagnostic.GrantAlreadyAvailable }, result.Diagnostic);
        Assert.Equal(0, await fixture.Scalar<long>("SELECT count(*) FROM agent_private.platform_grant_receipts"));
    }

    [Fact]
    public async Task ConcurrentIdenticalAndConflictingOperationsSerializeOnOneReceipt()
    {
        await fixture.Reset();
        var mapping = await fixture.SeedMapping();
        var repository = await Repository();
        var operation = Guid.NewGuid();
        var authorization = Authorization(mapping, RandomNumberGenerator.GetBytes(32));
        var prepared = ValidatedPersistedPlatformGrant.FromValidatedOutboxRecord(RandomNumberGenerator.GetBytes(32));
        var identical = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => repository.IssueAsync(operation, authorization, prepared, CancellationToken.None)));
        Assert.Single(identical, result => result.Outcome == PlatformGrantOutcome.Created);
        Assert.Equal(7, identical.Count(result => result.Outcome == PlatformGrantOutcome.AlreadyCreated));
        Assert.Single(identical.Select(result => result.Receipt!.GrantId).Distinct());

        var conflict = await repository.IssueAsync(operation, authorization, ValidatedPersistedPlatformGrant.FromValidatedOutboxRecord(RandomNumberGenerator.GetBytes(32)), CancellationToken.None);
        Assert.Equal(PlatformGrantOutcome.OutcomeUnknown, conflict.Outcome);
        Assert.Equal(1, await fixture.Scalar<long>("SELECT count(*) FROM agent_private.enrollment_grants"));
    }

    [Fact]
    public async Task NewAndExistingPrivilegeAuditsPassAndRuntimeHasNoTableAccess()
    {
        await fixture.Reset();
        _ = await Repository();
        Assert.True((await new AgentStorePrivilegeAuditor(fixture.Ingest, fixture.TableOwnerRole).AuditAsync(CancellationToken.None)).IsValid);
        Assert.True((await new EnrollmentStorePrivilegeAuditor(fixture.Enroll, fixture.TableOwnerRole, fixture.EnrollmentDefinerRole, "Enroll").AuditAsync(CancellationToken.None)).IsValid);
        Assert.True((await new EnrollmentStorePrivilegeAuditor(fixture.Issue, fixture.TableOwnerRole, fixture.EnrollmentDefinerRole, "Issue").AuditAsync(CancellationToken.None)).IsValid);
        Assert.True((await new AgentProjectionPrivilegeAuditor(fixture.Projection, fixture.EnvironmentId, fixture.TableOwnerRole, fixture.ProjectionDefinerRole).AuditAsync(CancellationToken.None)).IsValid);
        _ = await PostgresPlatformGrantRevocationRepository.CreateAuditedAsync(fixture.Revoker, fixture.EnvironmentId, fixture.TableOwnerRole, fixture.PlatformDefinerRole, CancellationToken.None);
        await using var command = fixture.Platform.CreateCommand("SELECT count(*) FROM agent_private.platform_grant_receipts");
        await Assert.ThrowsAsync<PostgresException>(() => command.ExecuteScalarAsync());
    }

    [Fact]
    public async Task WrongEnvironmentSessionCannotSelectAnEnvironmentOrMint()
    {
        await fixture.Reset();
        var mapping = await fixture.SeedMapping();
        await using var command = fixture.Platform.CreateCommand("SELECT outcome FROM agent_private.issue_initial_enrollment_grant(@environment,@operation,@directory,@device,@created,@token,@digest)");
        command.Parameters.AddWithValue("environment", Guid.NewGuid()); command.Parameters.AddWithValue("operation", Guid.NewGuid()); command.Parameters.AddWithValue("directory", Guid.NewGuid()); command.Parameters.AddWithValue("device", mapping.DeviceId);
        command.Parameters.AddWithValue("created", mapping.MappingCreatedAt); command.Parameters.AddWithValue("token", RandomNumberGenerator.GetBytes(32)); command.Parameters.AddWithValue("digest", RandomNumberGenerator.GetBytes(32));
        Assert.Equal("Unauthorized", (string)(await command.ExecuteScalarAsync())!);
        Assert.Equal(0, await fixture.Scalar<long>("SELECT count(*) FROM agent_private.enrollment_grants"));
    }

    [Fact]
    public void AuthorizationRequiresCanonicalUtcMicrosecondMappingTime()
    {
        var mapping = new TestMapping(fixture.EnvironmentId, Guid.NewGuid(), Guid.NewGuid(), DateTimeOffset.UtcNow);
        var digest = RandomNumberGenerator.GetBytes(32);
        Assert.Throws<ArgumentException>(() => ValidatedGrantAuthorization.FromValidatedPlan(
            mapping.DirectoryObjectId, mapping.DeviceId, mapping.MappingCreatedAt.ToOffset(TimeSpan.FromHours(1)), digest));
        var utc = mapping.MappingCreatedAt.ToUniversalTime();
        var nonCanonical = new DateTimeOffset(utc.Ticks - utc.Ticks % 10 + 1, TimeSpan.Zero);
        Assert.Throws<ArgumentException>(() => ValidatedGrantAuthorization.FromValidatedPlan(
            mapping.DirectoryObjectId, mapping.DeviceId, nonCanonical, digest));
    }

    [Fact]
    public void DatabaseResponsesUseAClosedOutcomeDiagnosticAndNullabilityMatrix()
    {
        var mapping = new TestMapping(fixture.EnvironmentId, Guid.NewGuid(), Guid.NewGuid(),
            new DateTimeOffset(638900000000000000, TimeSpan.Zero));
        var operation = Guid.NewGuid();
        var createdAt = mapping.MappingCreatedAt.AddHours(1);
        var authorization = ValidatedGrantAuthorization.FromValidatedPlan(mapping.DirectoryObjectId, mapping.DeviceId,
            mapping.MappingCreatedAt, createdAt.AddSeconds(30), RandomNumberGenerator.GetBytes(32));
        var prepared = ValidatedPersistedPlatformGrant.FromValidatedOutboxRecord(RandomNumberGenerator.GetBytes(32));
        PlatformGrantDatabaseResult Row(string? outcome, string? diagnostic, Guid? environment = null,
            Guid? operationId = null, Guid? grant = null, Guid? directory = null, Guid? device = null,
            DateTimeOffset? mapped = null, DateTimeOffset? created = null, DateTimeOffset? expires = null,
            short? contractVersion = null, DateTimeOffset? mintPermitNotAfter = null) =>
            new(outcome, diagnostic, environment, operationId, grant, directory, device, mapped, created, expires,
                contractVersion, mintPermitNotAfter);
        PlatformGrantResult Normalize(PlatformGrantDatabaseResult row) =>
            PostgresPlatformGrantRepository.NormalizeResult(row, mapping.EnvironmentId, operation, authorization, prepared);

        var complete = Row("Created", "None", mapping.EnvironmentId, operation, Guid.NewGuid(),
            mapping.DirectoryObjectId, mapping.DeviceId, mapping.MappingCreatedAt, createdAt, createdAt.AddSeconds(600),
            2, authorization.MintPermitNotAfter);
        Assert.Equal(PlatformGrantOutcome.Created, Normalize(complete).Outcome);
        Assert.Equal(PlatformGrantOutcome.Unknown, Normalize(complete with { Diagnostic = "OperationConflict" }).Outcome);
        Assert.Equal(PlatformGrantOutcome.Unknown, Normalize(complete with { GrantId = null }).Outcome);
        Assert.Equal(PlatformGrantOutcome.Unknown, Normalize(complete with { ExpiresAt = createdAt.AddSeconds(601) }).Outcome);
        Assert.Equal(PlatformGrantOutcome.Unknown, Normalize(complete with { MappingCreatedAt = createdAt.AddTicks(10) }).Outcome);

        var nearMaximumTicks = DateTimeOffset.MaxValue.Ticks - DateTimeOffset.MaxValue.Ticks % 10 - 10;
        var nearMaximumDeadline = new DateTimeOffset(nearMaximumTicks, TimeSpan.Zero);
        var nearMaximumAuthorization = ValidatedGrantAuthorization.FromValidatedPlan(mapping.DirectoryObjectId,
            mapping.DeviceId, mapping.MappingCreatedAt, nearMaximumDeadline, RandomNumberGenerator.GetBytes(32));
        var nearMaximum = complete with
        {
            CreatedAt = nearMaximumDeadline.AddTicks(-10),
            ExpiresAt = nearMaximumDeadline,
            MintPermitNotAfter = nearMaximumDeadline
        };
        Assert.Equal(PlatformGrantOutcome.Unknown, PostgresPlatformGrantRepository.NormalizeResult(nearMaximum,
            mapping.EnvironmentId, operation, nearMaximumAuthorization, prepared).Outcome);

        var rejected = Row("PermanentRejected", "MappingUnavailable", mapping.EnvironmentId, operation, null,
            mapping.DirectoryObjectId, mapping.DeviceId, mapping.MappingCreatedAt);
        Assert.Equal(PlatformGrantOutcome.PermanentRejected, Normalize(rejected).Outcome);
        Assert.Equal(PlatformGrantOutcome.Unknown, Normalize(rejected with { Diagnostic = "None" }).Outcome);
        Assert.Equal(PlatformGrantOutcome.Unknown, Normalize(rejected with { GrantId = Guid.NewGuid() }).Outcome);

        var conflict = rejected with { Outcome = "OutcomeUnknown", Diagnostic = "OperationConflict" };
        Assert.Equal(PlatformGrantOutcome.OutcomeUnknown, Normalize(conflict).Outcome);
        Assert.Equal(PlatformGrantOutcome.Unknown, Normalize(conflict with { EnvironmentId = Guid.NewGuid() }).Outcome);

        var unauthorized = Row("Unauthorized", "PrivilegeAuditFailed");
        Assert.Equal(PlatformGrantOutcome.Unauthorized, Normalize(unauthorized).Outcome);
        Assert.Equal(PlatformGrantOutcome.Unknown, Normalize(unauthorized with { OperationId = operation }).Outcome);
        Assert.Equal(PlatformGrantOutcome.Unknown, Normalize(unauthorized with { Diagnostic = "Unrecognized" }).Outcome);
    }

    [Fact]
    public async Task DatabaseConnectionFailureIsUnknownAndNeverPermanent()
    {
        var environment = Guid.NewGuid();
        await using var unavailable = NpgsqlDataSource.Create(
            "Host=127.0.0.1;Port=1;Database=unavailable;Username=unavailable;Password=unavailable;Timeout=1;Pooling=false");
        var repository = new PostgresPlatformGrantRepository(unavailable, environment);
        var mapping = new TestMapping(environment, Guid.NewGuid(), Guid.NewGuid(),
            new DateTimeOffset(638900000000000000, TimeSpan.Zero));

        var result = await repository.IssueAsync(Guid.NewGuid(),
            Authorization(mapping, RandomNumberGenerator.GetBytes(32)),
            ValidatedPersistedPlatformGrant.FromValidatedOutboxRecord(RandomNumberGenerator.GetBytes(32)),
            CancellationToken.None);

        Assert.Equal(PlatformGrantOutcome.Unknown, result.Outcome);
        Assert.Equal(PlatformGrantDiagnostic.ConnectionUnavailable, result.Diagnostic);
        Assert.Null(result.Receipt);
    }

    [Fact]
    public async Task TwoEnvironmentLoginsRetainExactAuditedFunctionAccess()
    {
        await fixture.Reset();
        var first = await Repository();
        var bindingCount = await fixture.Scalar<long>("SELECT count(*) FROM agent_private.platform_grant_database_bindings");
        var additional = await fixture.AddPlatformEnvironment();
        var currentBindingCount = await fixture.Scalar<long>("SELECT count(*) FROM agent_private.platform_grant_database_bindings");
        Assert.Equal(bindingCount + 2, currentBindingCount);
        Assert.Equal(3, await fixture.Scalar<long>("SELECT count(*) FROM pg_catalog.pg_proc function JOIN pg_catalog.pg_namespace namespace ON namespace.oid=function.pronamespace WHERE namespace.nspname='agent_private' AND pg_catalog.has_function_privilege(@role,function.oid,'EXECUTE')", new NpgsqlParameter("role", additional.Role)));
        Assert.Equal(5, await fixture.Scalar<long>("SELECT count(*) FROM pg_catalog.pg_proc function JOIN pg_catalog.pg_namespace namespace ON namespace.oid=function.pronamespace WHERE namespace.nspname='agent_private' AND pg_catalog.has_function_privilege(@role,function.oid,'EXECUTE')", new NpgsqlParameter("role", additional.RevokerRole)));
        var firstAfter = await Repository();
        var second = await PostgresPlatformGrantRepository.CreateAuditedAsync(additional.DataSource, additional.EnvironmentId,
            fixture.TableOwnerRole, fixture.PlatformDefinerRole, CancellationToken.None);
        var firstRevoker = await PostgresPlatformGrantRevocationRepository.CreateAuditedAsync(fixture.Revoker, fixture.EnvironmentId,
            fixture.TableOwnerRole, fixture.PlatformDefinerRole, CancellationToken.None);
        var secondRevoker = await PostgresPlatformGrantRevocationRepository.CreateAuditedAsync(additional.RevokerDataSource, additional.EnvironmentId,
            fixture.TableOwnerRole, fixture.PlatformDefinerRole, CancellationToken.None);
        Assert.NotNull(first);
        Assert.NotNull(firstAfter);
        Assert.NotNull(second);
        Assert.NotNull(firstRevoker);
        Assert.NotNull(secondRevoker);
    }

    [Fact]
    public async Task UnexpectedOldPurposeExecuteGrantFailsThePlatformAudit()
    {
        await fixture.Reset();
        await fixture.Execute($"GRANT EXECUTE ON FUNCTION agent_private.issue_initial_enrollment_grant(uuid,uuid,uuid,uuid,timestamptz,bytea,bytea) TO \"{fixture.IssueRole}\"");
        try
        {
            await Assert.ThrowsAsync<InvalidOperationException>(() => Repository());
        }
        finally
        {
            await fixture.Execute($"REVOKE EXECUTE ON FUNCTION agent_private.issue_initial_enrollment_grant(uuid,uuid,uuid,uuid,timestamptz,bytea,bytea) FROM \"{fixture.IssueRole}\"");
        }
    }

    [Fact]
    public async Task AuditRejectsMissingBoundExecuteCrossBindingAndDirectObjectGrants()
    {
        await fixture.Reset();
        var additional = await fixture.AddPlatformEnvironment();
        var signature = "agent_private.issue_initial_enrollment_grant(uuid,uuid,uuid,uuid,timestamptz,bytea,bytea)";

        await fixture.Execute($"REVOKE EXECUTE ON FUNCTION {signature} FROM \"{additional.Role}\"");
        await Assert.ThrowsAsync<InvalidOperationException>(() => Repository());
        await fixture.Execute($"GRANT EXECUTE ON FUNCTION {signature} TO \"{additional.Role}\"");

        await fixture.Execute($"ALTER ROLE \"{additional.Role}\" INHERIT");
        await Assert.ThrowsAsync<InvalidOperationException>(() => Repository());
        await fixture.Execute($"ALTER ROLE \"{additional.Role}\" NOINHERIT");

        await fixture.Execute("INSERT INTO agent_private.agent_database_bindings(login_role,environment_id,purpose) VALUES(@role,@env,'Ingest')",
            new("role", additional.Role), new("env", additional.EnvironmentId));
        await Assert.ThrowsAsync<InvalidOperationException>(() => Repository());
        await fixture.Execute("DELETE FROM agent_private.agent_database_bindings WHERE login_role=@role", new NpgsqlParameter("role", additional.Role));

        await fixture.Execute($"GRANT SELECT(grant_id) ON agent_private.platform_grant_receipts TO \"{fixture.IssueRole}\"");
        await Assert.ThrowsAsync<InvalidOperationException>(() => Repository());
        await fixture.Execute($"REVOKE SELECT(grant_id) ON agent_private.platform_grant_receipts FROM \"{fixture.IssueRole}\"");

        await fixture.Execute($"GRANT UPDATE ON agent_private.platform_grant_receipts TO \"{fixture.PlatformDefinerRole}\"");
        await Assert.ThrowsAsync<InvalidOperationException>(() => Repository());
        await fixture.Execute($"REVOKE UPDATE ON agent_private.platform_grant_receipts FROM \"{fixture.PlatformDefinerRole}\"");

        _ = await Repository();
    }

    [Fact]
    public async Task AuditRejectsABindingWhoseLoginRoleDoesNotExist()
    {
        await fixture.Reset();
        var missingRole = $"agp_missing_{Guid.NewGuid():N}"[..24];
        await fixture.Execute("INSERT INTO agent_private.platform_grant_database_bindings(login_role,environment_id,purpose) VALUES(@role,@env,'IssueInitialGrant')",
            new NpgsqlParameter("role", missingRole), new NpgsqlParameter("env", Guid.NewGuid()));
        try
        {
            await Assert.ThrowsAsync<InvalidOperationException>(() => Repository());
        }
        finally
        {
            await fixture.Execute("DELETE FROM agent_private.platform_grant_database_bindings WHERE login_role=@role",
                new NpgsqlParameter("role", missingRole));
        }
    }

    [Theory]
    [InlineData("ingest")]
    [InlineData("enrollment")]
    [InlineData("projection")]
    public async Task ExistingProvisionersRejectThePlatformDefinerAliasBeforeMutation(string capability)
    {
        await fixture.Reset();
        await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.RunOldProvisionWithPlatformDefinerAlias(capability));
        Assert.False(await fixture.Scalar<bool>("SELECT rolcanlogin FROM pg_catalog.pg_roles WHERE rolname=@role",
            new NpgsqlParameter("role", fixture.PlatformDefinerRole)));
        Assert.Equal(0, await fixture.Scalar<long>("SELECT (SELECT count(*) FROM agent_private.agent_database_bindings WHERE login_role=@role)+(SELECT count(*) FROM agent_private.enrollment_database_bindings WHERE login_role=@role)+(SELECT count(*) FROM agent_private.agent_projection_database_bindings WHERE login_role=@role)",
            new NpgsqlParameter("role", fixture.PlatformDefinerRole)));
        _ = await Repository();
    }

    [Fact]
    public async Task ProvisioningPostflightRollsBackAllLoginChangesWhenStoreAclHasDrifted()
    {
        await fixture.Reset();
        var additional = await fixture.CreateUnprovisionedPlatformEnvironment();
        await fixture.Execute($"REVOKE SELECT(state) ON agent_private.devices FROM \"{fixture.PlatformDefinerRole}\"");
        try
        {
            var error = await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.ProvisionPlatformEnvironment(additional));
            Assert.Equal(PostgresErrorCodes.DivisionByZero, Assert.IsType<PostgresException>(error.InnerException).SqlState);
            Assert.Equal(0, await fixture.Scalar<long>("SELECT count(*) FROM agent_private.platform_grant_database_bindings WHERE login_role=@role",
                new NpgsqlParameter("role", additional.Role)));
            Assert.Equal(0, await fixture.Scalar<long>("SELECT count(*) FROM pg_catalog.pg_proc function JOIN pg_catalog.pg_namespace namespace ON namespace.oid=function.pronamespace WHERE namespace.nspname='agent_private' AND pg_catalog.has_function_privilege(@role,function.oid,'EXECUTE')",
                new NpgsqlParameter("role", additional.Role)));
        }
        finally
        {
            await fixture.Execute($"GRANT SELECT(state) ON agent_private.devices TO \"{fixture.PlatformDefinerRole}\"");
        }
        _ = await Repository();
    }

    [Fact]
    public void ProvisioningPostflightRetainsTheRuntimeAuditPredicateSet()
    {
        var store = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "upgrade-agent-platform-grants-v2-to-v3.sql"));
        var provision = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "provision-agent-platform-grants.sql"));
        const string profile3AuditHash = "64a11bee2af9f76b2d5e33c1b168934d";
        Assert.Equal(2, provision.Replace("\r", string.Empty, StringComparison.Ordinal).Split('\n')
            .Count(line => line.Contains(profile3AuditHash, StringComparison.Ordinal) &&
                line.Contains("pg_get_function_result", StringComparison.Ordinal)));
        static string Cte(string sql, string startToken, string endToken, int after = 0)
        {
            var start = sql.IndexOf(startToken, after, StringComparison.Ordinal);
            var end = sql.IndexOf(endToken, start + startToken.Length, StringComparison.Ordinal);
            Assert.True(start >= 0 && end > start);
            return sql[start..end].Replace("\r", string.Empty, StringComparison.Ordinal).Trim();
        }
        var audit = store.IndexOf("CREATE OR REPLACE FUNCTION agent_private.audit_platform_grant_privileges", StringComparison.Ordinal);
        Assert.True(audit >= 0);
        var runtime = Cte(store, "WITH login AS(", "SELECT valid,'None'", audit);
        foreach (var (role, marker) in new[]
        {
            ("agent_platform_grant_role", "SELECT 1/pg_catalog.count(*) AS exact_issuer_privilege_postflight"),
            ("agent_platform_grant_revoker_role", "SELECT 1/pg_catalog.count(*) AS exact_revoker_privilege_postflight")
        })
        {
            var expected = runtime
                .Replace("SESSION_USER::name", $":'{role}'::name", StringComparison.Ordinal)
                .Replace("SESSION_USER", $":'{role}'", StringComparison.Ordinal)
                .Replace("p_expected_environment_id", ":'environment_id'::uuid", StringComparison.Ordinal)
                .Replace("p_expected_table_owner", ":'agent_table_owner_role'::name", StringComparison.Ordinal)
                .Replace("p_expected_function_owner", ":'agent_platform_grant_definer_role'::name", StringComparison.Ordinal);
            var actual = Cte(provision, $"WITH login AS(SELECT role.* FROM pg_catalog.pg_roles role WHERE role.rolname=:'{role}')", marker);
            actual = string.Join('\n', actual.Split('\n').Where(line =>
                !(line.Contains(profile3AuditHash, StringComparison.Ordinal) &&
                  line.Contains("pg_get_function_result", StringComparison.Ordinal))));
            Assert.Equal(expected, actual);
        }
    }

    [Fact]
    public async Task GlobalOperationLockSerializesDifferentEnvironmentsWithoutConstraintErrors()
    {
        await fixture.Reset();
        var additional = await fixture.AddPlatformEnvironment();
        var firstMapping = await fixture.SeedMapping();
        var secondMapping = await fixture.SeedMapping(additional.EnvironmentId);
        var first = await Repository();
        var second = await PostgresPlatformGrantRepository.CreateAuditedAsync(additional.DataSource,
            additional.EnvironmentId, fixture.TableOwnerRole, fixture.PlatformDefinerRole, CancellationToken.None);
        var operation = Guid.NewGuid();

        var results = await Task.WhenAll(
            first.IssueAsync(operation, Authorization(firstMapping, RandomNumberGenerator.GetBytes(32)),
                ValidatedPersistedPlatformGrant.FromValidatedOutboxRecord(RandomNumberGenerator.GetBytes(32)), CancellationToken.None),
            second.IssueAsync(operation, Authorization(secondMapping, RandomNumberGenerator.GetBytes(32)),
                ValidatedPersistedPlatformGrant.FromValidatedOutboxRecord(RandomNumberGenerator.GetBytes(32)), CancellationToken.None));

        Assert.Single(results, result => result.Outcome == PlatformGrantOutcome.Created);
        Assert.Single(results, result => result.Outcome == PlatformGrantOutcome.OutcomeUnknown &&
            result.Diagnostic == PlatformGrantDiagnostic.OperationConflict);
        Assert.Equal(1, await fixture.Scalar<long>("SELECT count(*) FROM agent_private.platform_grant_receipts"));
    }

    [Fact]
    public async Task MappingRowLockSerializesMintAgainstAnAuthoritativeWriter()
    {
        await fixture.Reset();
        var mapping = await fixture.SeedMapping();
        var repository = await Repository();
        await using var connection = await fixture.Owner.OpenConnectionAsync();
        await using var transaction = await connection.BeginTransactionAsync();
        await using (var lockCommand = new NpgsqlCommand(
            "SELECT 1 FROM agent_private.agent_device_directory_bindings WHERE environment_id=@env AND directory_object_id=@directory FOR UPDATE",
            connection, transaction))
        {
            lockCommand.Parameters.AddWithValue("env", mapping.EnvironmentId);
            lockCommand.Parameters.AddWithValue("directory", mapping.DirectoryObjectId);
            await lockCommand.ExecuteScalarAsync();
        }

        var issue = repository.IssueAsync(Guid.NewGuid(), Authorization(mapping, RandomNumberGenerator.GetBytes(32)),
            ValidatedPersistedPlatformGrant.FromValidatedOutboxRecord(RandomNumberGenerator.GetBytes(32)), CancellationToken.None);
        await Task.Delay(100);
        Assert.False(issue.IsCompleted);
        await transaction.RollbackAsync();
        Assert.Equal(PlatformGrantOutcome.Created, (await issue).Outcome);
    }

    private async Task<PostgresPlatformGrantRepository> Repository() => await PostgresPlatformGrantRepository.CreateAuditedAsync(fixture.Platform, fixture.EnvironmentId, fixture.TableOwnerRole, fixture.PlatformDefinerRole, CancellationToken.None);
    private static ValidatedGrantAuthorization Authorization(TestMapping mapping, byte[] digest) => ValidatedGrantAuthorization.FromValidatedPlan(mapping.DirectoryObjectId, mapping.DeviceId, mapping.MappingCreatedAt, PermitDeadline(), digest);
    private static DateTimeOffset PermitDeadline()
    {
        var value = DateTimeOffset.UtcNow.AddSeconds(45);
        return new DateTimeOffset(value.Ticks - value.Ticks % 10, TimeSpan.Zero);
    }
    private static DateTimeOffset CanonicalNow()
    {
        var value = DateTimeOffset.UtcNow;
        return new DateTimeOffset(value.Ticks - value.Ticks % 10, TimeSpan.Zero);
    }
}
