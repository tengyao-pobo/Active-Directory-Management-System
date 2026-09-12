using System.Data;
using ItManagement.Core;
using ItManagement.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Npgsql;
using NpgsqlTypes;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantPlanTests
{
    private sealed record StatusEvidence(string Outcome, Guid? Id, long? Sequence, string? State,
        DateTimeOffset? RecordedAt, DateTimeOffset? AvailableUntil);

    private static async Task SeedStatusReceipt(ConsoleDbContext db, EnrollmentGrantOperation operation)
    {
        await InsertJournalPermit(db, operation);
        var grant = Guid.NewGuid();
        var created = operation.QueuedAt;
        await db.Database.ExecuteSqlInterpolatedAsync($"""
            INSERT INTO enrollment_execution.issue_results
                (operation_id,outcome,diagnostic,recorded_at,grant_id,environment_id,directory_object_id,device_id,
                mapping_created_at,grant_created_at,grant_expires_at,issue_contract_version,mint_permit_not_after,
                token_sha256,authorization_digest)
            SELECT operation_id,'Issued','None',{created},{grant},{operation.EnvironmentId},{operation.DirectoryObjectId},
                {operation.ServerDeviceId},{operation.MappingCreatedAt},{created},{created.AddSeconds(600)},2,
                not_after,token_sha256,authorization_digest
            FROM enrollment_execution.mint_permits WHERE operation_id={operation.Id}
            """);
        await db.Database.ExecuteSqlRawAsync("SET CONSTRAINTS ALL IMMEDIATE");
    }

    private static async Task<StatusEvidence> RecordStatus(ConsoleDbContext db, EnrollmentGrantOperation operation,
        Guid id, string state, DateTimeOffset? observed = null, DateTimeOffset? changed = null,
        string diagnostic = "None", bool wrongReceipt = false, Guid? environment = null)
    {
        await using var command = new NpgsqlCommand("""
            SELECT s.* FROM enrollment_execution.issue_results AS r
            CROSS JOIN LATERAL enrollment_execution.record_status_observation(
                @environment,@operation,@id,@state,@diagnostic,@observed,@changed,
                r.grant_id,r.directory_object_id,r.device_id,r.mapping_created_at,
                r.grant_created_at,r.grant_expires_at,r.issue_contract_version,r.mint_permit_not_after,
                CASE WHEN @wrong THEN decode(repeat('ff',32),'hex') ELSE r.token_sha256 END,r.authorization_digest) AS s
            WHERE r.operation_id=@operation
            """, (NpgsqlConnection)db.Database.GetDbConnection(),
            (NpgsqlTransaction?)db.Database.CurrentTransaction?.GetDbTransaction());
        command.Parameters.AddWithValue("environment", environment ?? operation.EnvironmentId);
        command.Parameters.AddWithValue("operation", operation.Id);
        command.Parameters.AddWithValue("id", id);
        command.Parameters.AddWithValue("state", state);
        command.Parameters.AddWithValue("diagnostic", diagnostic);
        command.Parameters.AddWithValue("observed", NpgsqlDbType.TimestampTz, (object?)observed ?? DBNull.Value);
        command.Parameters.AddWithValue("changed", NpgsqlDbType.TimestampTz, (object?)changed ?? DBNull.Value);
        command.Parameters.AddWithValue("wrong", wrongReceipt);
        await using var reader = await command.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());
        Assert.Equal((short)1, reader.GetInt16(0));
        var result = new StatusEvidence(reader.GetString(1), reader.IsDBNull(2) ? null : reader.GetGuid(2),
            reader.IsDBNull(5) ? null : reader.GetInt64(5), reader.IsDBNull(6) ? null : reader.GetString(6),
            reader.IsDBNull(10) ? null : reader.GetFieldValue<DateTimeOffset>(10),
            reader.IsDBNull(11) ? null : reader.GetFieldValue<DateTimeOffset>(11));
        Assert.False(await reader.ReadAsync());
        return result;
    }

    [Fact]
    public async Task StatusObservationExactRetryPreservesSequenceAndDeadline()
    {
        var operation = await QueuedJournalOperation();
        await using var db = Db();
        await using var tx = await db.Database.BeginTransactionAsync(IsolationLevel.Serializable);
        await SeedStatusReceipt(db, operation);
        var at = Canonical(DateTimeOffset.UtcNow);
        var id = Guid.NewGuid();
        var first = await RecordStatus(db, operation, id, "Available", at);
        Assert.Equal("Recorded", first.Outcome);
        Assert.Equal(1L, first.Sequence);
        Assert.True(first.RecordedAt >= at);
        Assert.Equal(at.AddSeconds(15), first.AvailableUntil);
        var retry = await RecordStatus(db, operation, id, "Available", at);
        Assert.Equal(first with { Outcome = "AlreadyRecorded" }, retry);
    }

    [Theory]
    [InlineData("receipt")]
    [InlineData("replay")]
    public async Task StatusObservationRejectsConflictingIdentity(string fault)
    {
        var operation = await QueuedJournalOperation();
        await using var db = Db();
        await using var tx = await db.Database.BeginTransactionAsync(IsolationLevel.Serializable);
        await SeedStatusReceipt(db, operation);
        var id = Guid.NewGuid();
        await RecordStatus(db, operation, id, "Unknown", diagnostic: "ConnectionUnavailable");
        var error = await Assert.ThrowsAsync<PostgresException>(() => RecordStatus(db, operation, id, "Unknown",
            diagnostic: fault == "replay" ? "ResponseUnavailable" : "ConnectionUnavailable", wrongReceipt: fault == "receipt"));
        Assert.Equal("22023", error.SqlState);
    }

    [Fact]
    public async Task StatusObservationUnknownBlocksInflightPositiveAndAllowsFreshRecovery()
    {
        var operation = await QueuedJournalOperation();
        await using var db = Db();
        await using var tx = await db.Database.BeginTransactionAsync(IsolationLevel.Serializable);
        await SeedStatusReceipt(db, operation);
        var oldTime = Canonical(DateTimeOffset.UtcNow);
        await RecordStatus(db, operation, Guid.NewGuid(), "Available", oldTime);
        var unknown = await RecordStatus(db, operation, Guid.NewGuid(), "Unknown", diagnostic: "ResponseUnavailable");
        Assert.Equal(2L, unknown.Sequence);
        Assert.Null(unknown.AvailableUntil);
        await tx.CreateSavepointAsync("stale");
        Assert.Equal("23514", (await Assert.ThrowsAsync<PostgresException>(() =>
            RecordStatus(db, operation, Guid.NewGuid(), "Available", oldTime))).SqlState);
        await tx.RollbackToSavepointAsync("stale");
        var recovered = await RecordStatus(db, operation, Guid.NewGuid(), "Available", Canonical(DateTimeOffset.UtcNow));
        Assert.Equal(3L, recovered.Sequence);
        Assert.Equal("Available", recovered.State);
    }

    [Theory]
    [InlineData("Consumed")]
    [InlineData("Revoked")]
    [InlineData("Expired")]
    public async Task StatusObservationTerminalCannotBeReopened(string terminal)
    {
        var operation = terminal == "Expired" ? await InsertExpiredQueuedOperation() : await QueuedJournalOperation();
        await using var db = Db();
        await using var tx = await db.Database.BeginTransactionAsync(IsolationLevel.Serializable);
        await SeedStatusReceipt(db, operation);
        var id = Guid.NewGuid();
        var original = await RecordStatus(db, operation, id, "Unknown", diagnostic: "ConnectionUnavailable");
        var at = Canonical(DateTimeOffset.UtcNow);
        var final = await RecordStatus(db, operation, Guid.NewGuid(), terminal, at,
            terminal == "Expired" ? null : operation.QueuedAt);
        Assert.Equal(2L, final.Sequence);
        Assert.Null(final.AvailableUntil);
        var after = await RecordStatus(db, operation, Guid.NewGuid(), "Unknown", diagnostic: "ResponseUnavailable");
        Assert.Equal(final with { Outcome = "Terminal" }, after);
        var positive = await RecordStatus(db, operation, Guid.NewGuid(), "Available", at);
        Assert.Equal(final with { Outcome = "Terminal" }, positive);
        Assert.Equal(original with { Outcome = "AlreadyRecorded" },
            await RecordStatus(db, operation, id, "Unknown", diagnostic: "ConnectionUnavailable"));
    }

    [Theory]
    [InlineData(-16)]
    [InlineData(60)]
    public async Task StatusObservationRejectsStaleOrFuturePositiveWithoutAppend(int seconds)
    {
        var operation = seconds > 0 ? await QueuedJournalOperation() : await InsertExpiredQueuedOperation();
        await using var db = Db();
        await using var tx = await db.Database.BeginTransactionAsync(IsolationLevel.Serializable);
        await SeedStatusReceipt(db, operation);
        await tx.CreateSavepointAsync("invalid");
        Assert.Equal("23514", (await Assert.ThrowsAsync<PostgresException>(() => RecordStatus(db, operation,
            Guid.NewGuid(), "Available", Canonical(DateTimeOffset.UtcNow.AddSeconds(seconds))))).SqlState);
        await tx.RollbackToSavepointAsync("invalid");
        Assert.Equal(0, await db.Database.SqlQuery<int>($"""
            SELECT count(*)::int AS "Value" FROM enrollment_execution.status_observations WHERE operation_id={operation.Id}
            """).SingleAsync());
    }

    [Fact]
    public async Task StatusObservationWrongEnvironmentReturnsNoEvidence()
    {
        var operation = await QueuedJournalOperation();
        await using var db = Db();
        await using var tx = await db.Database.BeginTransactionAsync(IsolationLevel.Serializable);
        await SeedStatusReceipt(db, operation);
        Assert.Equal(new StatusEvidence("NotFound", null, null, null, null, null),
            await RecordStatus(db, operation, Guid.NewGuid(), "Unknown", diagnostic: "ReceiptUnavailable", environment: Guid.NewGuid()));
    }

    [Theory]
    [InlineData("UPDATE enrollment_execution.status_observations SET diagnostic='ResponseUnavailable' WHERE observation_id={0}")]
    [InlineData("DELETE FROM enrollment_execution.status_observations WHERE observation_id={0}")]
    public async Task StatusObservationHistoryIsImmutable(string sql)
    {
        var operation = await QueuedJournalOperation();
        await using var db = Db();
        await using var tx = await db.Database.BeginTransactionAsync(IsolationLevel.Serializable);
        await SeedStatusReceipt(db, operation);
        var id = Guid.NewGuid();
        await RecordStatus(db, operation, id, "Unknown", diagnostic: "ConnectionUnavailable");
        Assert.Equal("55000", (await Assert.ThrowsAsync<PostgresException>(() => db.Database.ExecuteSqlRawAsync(sql, id))).SqlState);
    }

    [Fact]
    public async Task StatusObservationRequiresSerializableTransaction()
    {
        var operation = await QueuedJournalOperation();
        await using var db = Db();
        await using var tx = await db.Database.BeginTransactionAsync();
        await SeedStatusReceipt(db, operation);
        Assert.Equal("25001", (await Assert.ThrowsAsync<PostgresException>(() =>
            RecordStatus(db, operation, Guid.NewGuid(), "Unknown", diagnostic: "ConnectionUnavailable"))).SqlState);
    }

    [Fact]
    public async Task StatusObservationFoundationPreservesProfileThreeAndExcludesExistingRoles()
    {
        var seed = await _fixture.SeedAsync();
        await using var profile = await ProvisionExecutionRuntime(seed.Environment.Id);
        await using var connection = await profile.DataSource.OpenConnectionAsync();
        await using (var audit = new NpgsqlCommand(
            "SELECT is_valid AND profile_version=3 FROM enrollment_execution.audit_execution_privileges(@environment)", connection))
        {
            audit.Parameters.AddWithValue("environment", seed.Environment.Id);
            Assert.Equal(true, await audit.ExecuteScalarAsync());
        }
        await using var db = Db();
        var apiRole = new NpgsqlConnectionStringBuilder(Environment.GetEnvironmentVariable("CONSOLE_TEST_RUNTIME_DB")!).Username!;
        foreach (var role in new[] { apiRole, profile.RuntimeRole, profile.DefinerRole, profile.QueueDefinerRole })
        {
            Assert.Equal(0, await db.Database.SqlQuery<int>($"""
                SELECT count(*)::int AS "Value" FROM pg_catalog.pg_proc p
                WHERE p.pronamespace='enrollment_execution'::regnamespace
                  AND p.proname IN ('record_status_observation','guard_status_observation')
                  AND has_function_privilege({role},p.oid,'EXECUTE')
                """).SingleAsync());
            Assert.False(await db.Database.SqlQuery<bool>($"""
                SELECT has_table_privilege({role},'enrollment_execution.status_observations',
                    'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') AS "Value"
                """).SingleAsync());
        }
    }

    [Fact]
    public async Task StatusObservationDirectInsertCannotChooseSequenceOrTime()
    {
        var operation = await QueuedJournalOperation();
        await using var db = Db();
        await using var tx = await db.Database.BeginTransactionAsync(IsolationLevel.Serializable);
        await SeedStatusReceipt(db, operation);
        var id = Guid.NewGuid();
        var before = Canonical(DateTimeOffset.UtcNow);
        await db.Database.ExecuteSqlInterpolatedAsync($"""
            INSERT INTO enrollment_execution.status_observations
                (observation_id,environment_id,operation_id,sequence,state,diagnostic,recorded_at,available_until)
            VALUES ({id},{operation.EnvironmentId},{operation.Id},987,'Unknown','ConnectionUnavailable',
                {before.AddDays(-1)},{before.AddDays(1)})
            """);
        var record = await RecordStatus(db, operation, id, "Unknown", diagnostic: "ConnectionUnavailable");
        Assert.Equal(1L, record.Sequence);
        Assert.True(record.RecordedAt >= before);
        Assert.Null(record.AvailableUntil);
    }

    [Theory]
    [InlineData("Unknown", "None", false, false)]
    [InlineData("Unknown", "ConnectionUnavailable", true, false)]
    [InlineData("Available", "ConnectionUnavailable", true, false)]
    [InlineData("Expired", "None", true, false)]
    [InlineData("Consumed", "None", true, false)]
    [InlineData("Revoked", "None", true, true)]
    public async Task StatusObservationRejectsMalformedOrImpossibleState(string state, string diagnostic,
        bool hasObserved, bool futureChange)
    {
        var operation = await QueuedJournalOperation();
        await using var db = Db();
        await using var tx = await db.Database.BeginTransactionAsync(IsolationLevel.Serializable);
        await SeedStatusReceipt(db, operation);
        var at = Canonical(DateTimeOffset.UtcNow);
        var error = await Assert.ThrowsAsync<PostgresException>(() => RecordStatus(db, operation,
            Guid.NewGuid(), state, hasObserved ? at : null, futureChange ? at.AddSeconds(1) : null, diagnostic));
        Assert.Contains(error.SqlState, new[] { "22023", "23514" });
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task StatusObservationConcurrentWritersKeepOneOrderedHistory(bool sameId)
    {
        var operation = await QueuedJournalOperation();
        await using (var db = Db())
        await using (var tx = await db.Database.BeginTransactionAsync(IsolationLevel.Serializable))
        {
            await SeedStatusReceipt(db, operation);
            await tx.CommitAsync();
        }
        var firstId = Guid.NewGuid();
        var secondId = sameId ? firstId : Guid.NewGuid();
        var ready = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var arrivals = 0;
        async Task<StatusEvidence> Write(Guid id)
        {
            for (var attempt = 0; attempt < 5; attempt++)
            {
                await using var db = Db();
                await using var tx = await db.Database.BeginTransactionAsync(IsolationLevel.Serializable);
                if (attempt == 0)
                {
                    // Establish both serializable snapshots before either writer obtains the operation lock.
                    await db.Database.ExecuteSqlRawAsync("SELECT count(*) FROM enrollment_execution.status_observations");
                    if (Interlocked.Increment(ref arrivals) == 2) ready.TrySetResult();
                    await ready.Task.WaitAsync(TimeSpan.FromSeconds(10));
                }
                try
                {
                    var result = await RecordStatus(db, operation, id, "Unknown", diagnostic: "ConnectionUnavailable");
                    await tx.CommitAsync();
                    return result;
                }
                catch (PostgresException error) when (attempt < 4 && error.SqlState is "40001" or "23505")
                {
                    await tx.RollbackAsync();
                }
            }
            throw new InvalidOperationException("Bounded status observation retry exhausted.");
        }
        var results = await Task.WhenAll(Write(firstId), Write(secondId));
        if (sameId)
        {
            Assert.Equal(new[] { "AlreadyRecorded", "Recorded" }, results.Select(x => x.Outcome).Order().ToArray());
            Assert.Equal(results[0] with { Outcome = "Recorded" }, results[1] with { Outcome = "Recorded" });
        }
        else
        {
            Assert.All(results, result => Assert.Equal("Recorded", result.Outcome));
            Assert.Equal(new long?[] { 1, 2 }, results.Select(x => x.Sequence).Order().ToArray());
        }
        await using var final = Db();
        Assert.Equal(sameId ? 1 : 2, await final.Database.SqlQuery<int>($"""
            SELECT count(*)::int AS "Value" FROM enrollment_execution.status_observations WHERE operation_id={operation.Id}
            """).SingleAsync());
    }
}
