using System.Data;
using ItManagement.AgentEnrollment.Crypto;
using ItManagement.Core;
using ItManagement.EnrollmentGrantExecution;
using ItManagement.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Npgsql;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantPlanTests
{
    [Fact]
    public async Task ExecutionTransitionStoresOnePermitAndPreservesFirstEnvelopeOnRetry()
    {
        var operation = await QueuedJournalOperation();
        await using var db = Db();
        await using var tx = await db.Database.BeginTransactionAsync(IsolationLevel.Serializable);
        var first = SealedEnrollmentGrant.Seal(operation.RecipientSpki, operation.EnvironmentId, operation.Id);
        Assert.Equal(("Stored", (string?)null), await StoreCandidate(db, operation, first));
        var before = await ReadSqlExecution(db, operation.EnvironmentId, operation.Id);
        Assert.Equal(EnrollmentGrantExecutionState.PermitStored, before.Record!.State);
        Assert.Equal(first.GetCiphertext(), before.Record.Envelope!.GetCiphertext());
        Assert.True(before.Record.Permit!.MintPermitNotAfter <= operation.AuthorizationNotAfter);
        Assert.InRange(before.Record.Permit.MintPermitNotAfter - before.Record.Permit.PermitIssuedAt,
            TimeSpan.FromTicks(10), TimeSpan.FromSeconds(60));

        var second = SealedEnrollmentGrant.Seal(operation.RecipientSpki, operation.EnvironmentId, operation.Id);
        Assert.Equal(("Existing", (string?)null), await StoreCandidate(db, operation, second));
        await db.Database.ExecuteSqlRawAsync("SET CONSTRAINTS ALL IMMEDIATE");
        var after = await ReadSqlExecution(db, operation.EnvironmentId, operation.Id);
        Assert.Equal(before.Record.Permit.GetAuthorizationDigest(), after.Record!.Permit!.GetAuthorizationDigest());
        Assert.Equal(first.GetCiphertext(), after.Record.Envelope!.GetCiphertext());
        Assert.NotEqual(second.GetCiphertext(), after.Record.Envelope.GetCiphertext());
    }

    [Fact]
    public async Task ExecutionTransitionRollbackLeavesNeitherPermitNorEnvelope()
    {
        var operation = await QueuedJournalOperation();
        await using var db = Db();
        await using (var tx = await db.Database.BeginTransactionAsync(IsolationLevel.Serializable))
        {
            Assert.Equal("Stored", (await StoreCandidate(db, operation,
                SealedEnrollmentGrant.Seal(operation.RecipientSpki, operation.EnvironmentId, operation.Id))).Outcome);
            await tx.RollbackAsync();
        }
        await db.Database.OpenConnectionAsync();
        var after = await ReadSqlExecution(db, operation.EnvironmentId, operation.Id);
        Assert.Equal(EnrollmentGrantExecutionState.Queued, after.Record!.State);
        Assert.Null(after.Record.Permit);
        Assert.Null(after.Record.Envelope);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ExecutionTransitionPersistsAuthorizationRejectionWithoutMinting(bool expired)
    {
        var operation = expired ? await InsertExpiredQueuedOperation() : await QueuedJournalOperation();
        await using var db = Db();
        await using var tx = await db.Database.BeginTransactionAsync(IsolationLevel.Serializable);
        if (!expired)
            await db.Memberships.Where(x => x.EnvironmentId == operation.EnvironmentId && x.PrincipalId == operation.RequesterId)
                .ExecuteUpdateAsync(x => x.SetProperty(m => m.Active, false));
        var expected = expired ? "AuthorizationExpired" : "AuthorizationChanged";
        var candidate = SealedEnrollmentGrant.Seal(operation.RecipientSpki, operation.EnvironmentId, operation.Id);
        Assert.Equal(("AuthorizationRejected", expected), await StoreCandidate(db, operation, candidate));
        Assert.Equal(("AuthorizationRejected", expected), await StoreCandidate(db, operation, candidate));
        await db.Database.ExecuteSqlRawAsync("SET CONSTRAINTS ALL IMMEDIATE");
        var read = await ReadSqlExecution(db, operation.EnvironmentId, operation.Id);
        Assert.Equal(EnrollmentGrantExecutionState.PermanentRejected, read.Record!.State);
        Assert.Null(read.Record.Permit);
        Assert.Null(read.Record.Envelope);
    }

    [Fact]
    public async Task ExecutionTransitionRequiresSerializableAndExactVerifiedHash()
    {
        var operation = await QueuedJournalOperation();
        var candidate = SealedEnrollmentGrant.Seal(operation.RecipientSpki, operation.EnvironmentId, operation.Id);
        await using var db = Db();
        await db.Database.OpenConnectionAsync();
        var error = await Assert.ThrowsAsync<PostgresException>(() => StoreCandidate(db, operation, candidate));
        Assert.Equal("25001", error.SqlState);
        await using var tx = await db.Database.BeginTransactionAsync(IsolationLevel.Serializable);
        error = await Assert.ThrowsAsync<PostgresException>(() => StoreCandidate(db, operation, candidate, new string('a', 64)));
        Assert.Equal("22023", error.SqlState);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ExecutionTransitionStoresExactResultAndOnlyErasesRejectedEnvelope(bool rejected)
    {
        var operation = await QueuedJournalOperation();
        await using var db = Db();
        await using var tx = await db.Database.BeginTransactionAsync(IsolationLevel.Serializable);
        await StoreCandidate(db, operation, SealedEnrollmentGrant.Seal(operation.RecipientSpki, operation.EnvironmentId, operation.Id));
        var permit = (await ReadSqlExecution(db, operation.EnvironmentId, operation.Id)).Record!.Permit!;
        var grant = Guid.NewGuid();
        Assert.Equal("Recorded", (await StoreResult(db, operation, permit, rejected, grant)).Outcome);
        Assert.Equal("AlreadyRecorded", (await StoreResult(db, operation, permit, rejected, grant)).Outcome);
        if (!rejected) Assert.Equal("Conflict", (await StoreResult(db, operation, permit, rejected, Guid.NewGuid())).Outcome);
        await db.Database.ExecuteSqlRawAsync("SET CONSTRAINTS ALL IMMEDIATE");
        var read = await ReadSqlExecution(db, operation.EnvironmentId, operation.Id);
        Assert.Equal(rejected ? EnrollmentGrantExecutionState.PermanentRejected : EnrollmentGrantExecutionState.Completed, read.Record!.State);
        Assert.Equal(!rejected, read.Record.Envelope is not null);
        Assert.Equal("Conflict", (await StoreQuarantine(db, operation, permit.GetAuthorizationDigest(), "StoredDataInvalid")).Outcome);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ExecutionTransitionQuarantinePreservesExistingPermitAndEnvelope(bool hasPermit)
    {
        var operation = await QueuedJournalOperation();
        await using var db = Db();
        await using var tx = await db.Database.BeginTransactionAsync(IsolationLevel.Serializable);
        if (hasPermit)
            await StoreCandidate(db, operation, SealedEnrollmentGrant.Seal(operation.RecipientSpki, operation.EnvironmentId, operation.Id));
        Assert.Equal("Recorded", (await StoreQuarantine(db, operation, null, "StoredDataInvalid")).Outcome);
        Assert.Equal("AlreadyRecorded", (await StoreQuarantine(db, operation, null, "StoredDataInvalid")).Outcome);
        await db.Database.ExecuteSqlRawAsync("SET CONSTRAINTS ALL IMMEDIATE");
        var read = await ReadSqlExecution(db, operation.EnvironmentId, operation.Id);
        Assert.Equal(EnrollmentGrantExecutionState.Quarantined, read.Record!.State);
        Assert.Equal(hasPermit, read.Record.Permit is not null);
        Assert.Equal(hasPermit, read.Record.Envelope is not null);
    }

    [Fact]
    public async Task ExecutionTransitionCommitsInvalidDataStopForAmbiguousPlanItems()
    {
        // Simulate legacy owner-imported history using legal parent transitions, without
        // disabling immutable triggers. The platform API never creates this plan shape.
        var operation = await InsertExpiredQueuedOperation(extraItem: true);
        await using var db = Db();
        await using (var tx = await db.Database.BeginTransactionAsync(IsolationLevel.Serializable))
        {
            Assert.Equal(EnrollmentGrantContextReadOutcome.OutcomeUnknown,
                (await ReadExecutionContext(db, operation.EnvironmentId, operation.Id, ToExecutionOperation(operation))).Outcome);
            Assert.Equal(("Conflict", "StoredDataInvalid"), await StoreCandidate(db, operation,
                SealedEnrollmentGrant.Seal(operation.RecipientSpki, operation.EnvironmentId, operation.Id)));
            await tx.CommitAsync();
        }
        await db.Database.OpenConnectionAsync();
        var read = await ReadSqlExecution(db, operation.EnvironmentId, operation.Id);
        Assert.Equal(EnrollmentGrantExecutionState.Quarantined, read.Record!.State);
        Assert.Equal(EnrollmentGrantExecutionStopReason.StoredDataInvalid, read.Record.StopReason);
        Assert.Null(read.Record.Permit);
        Assert.Null(read.Record.Envelope);
    }

    private static Task<(string Outcome, string? Reason)> StoreCandidate(ConsoleDbContext db,
        EnrollmentGrantOperation operation, SealedEnrollmentGrant candidate, string? hash = null) =>
        ReadTransition(db, "SELECT * FROM enrollment_execution.store_candidate(@env,@op,@hash,@token,@fingerprint,@cipher)",
            ("env", operation.EnvironmentId), ("op", operation.Id), ("hash", hash ?? operation.PlanHash),
            ("token", candidate.GetTokenSha256()), ("fingerprint", candidate.GetRecipientSubjectPublicKeyInfoSha256()),
            ("cipher", candidate.GetCiphertext()));

    private static Task<(string Outcome, string? Reason)> StoreResult(ConsoleDbContext db,
        EnrollmentGrantOperation operation, PersistedEnrollmentGrantPermit permit, bool rejected, Guid grant) =>
        ReadTransition(db, """
            SELECT * FROM enrollment_execution.store_result(@env,@op,@permit_digest,@outcome,@diagnostic,
                @grant::uuid,@receipt_env::uuid,@directory::uuid,@device::uuid,@mapping::timestamptz,
                @created::timestamptz,@expires::timestamptz,@version::smallint,@deadline::timestamptz,@token::bytea,@digest::bytea)
            """, ("env", operation.EnvironmentId), ("op", operation.Id), ("permit_digest", permit.GetAuthorizationDigest()),
            ("outcome", rejected ? "Rejected" : "Issued"), ("diagnostic", rejected ? "MappingUnavailable" : "None"),
            ("grant", rejected ? null : grant), ("receipt_env", rejected ? null : operation.EnvironmentId),
            ("directory", rejected ? null : operation.DirectoryObjectId), ("device", rejected ? null : operation.ServerDeviceId),
            ("mapping", rejected ? null : operation.MappingCreatedAt), ("created", rejected ? null : permit.PermitIssuedAt),
            ("expires", rejected ? null : permit.PermitIssuedAt.AddSeconds(600)), ("version", rejected ? null : (short)2),
            ("deadline", rejected ? null : permit.MintPermitNotAfter), ("token", rejected ? null : permit.GetTokenSha256()),
            ("digest", rejected ? null : permit.GetAuthorizationDigest()));

    private static Task<(string Outcome, string? Reason)> StoreQuarantine(ConsoleDbContext db,
        EnrollmentGrantOperation operation, byte[]? digest, string reason) => ReadTransition(db,
            "SELECT * FROM enrollment_execution.store_quarantine(@env,@op,@digest::bytea,@reason)",
            ("env", operation.EnvironmentId), ("op", operation.Id), ("digest", digest), ("reason", reason));

    private static async Task<(string Outcome, string? Reason)> ReadTransition(ConsoleDbContext db, string sql,
        params (string Name, object? Value)[] parameters)
    {
        await using var command = new NpgsqlCommand(sql, (NpgsqlConnection)db.Database.GetDbConnection(),
            (NpgsqlTransaction?)db.Database.CurrentTransaction?.GetDbTransaction());
        foreach (var parameter in parameters) command.Parameters.AddWithValue(parameter.Name, parameter.Value ?? DBNull.Value);
        await using var reader = await command.ExecuteReaderAsync();
        Assert.Equal(3, reader.FieldCount);
        Assert.True(await reader.ReadAsync());
        Assert.Equal((short)1, reader.GetInt16(0));
        var result = (reader.GetString(1), reader.IsDBNull(2) ? null : reader.GetString(2));
        Assert.False(await reader.ReadAsync());
        return result;
    }
}
