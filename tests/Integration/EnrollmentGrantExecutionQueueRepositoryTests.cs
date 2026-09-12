using ItManagement.EnrollmentGrantExecution;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantPlanTests
{
    private static Task<PostgresEnrollmentGrantWorkQueue> OpenWorkQueue(ExecutionRuntimeProfile profile, Guid environment) =>
        PostgresEnrollmentGrantWorkQueue.CreateAuditedAsync(profile.DataSource, environment,
            new NpgsqlConnectionStringBuilder(Environment.GetEnvironmentVariable("CONSOLE_TEST_DB")!).Username!,
            profile.DefinerRole, profile.QueueDefinerRole, CancellationToken.None);

    [Fact]
    public async Task QueueRepositoryReplaysAssignmentAndPreservesTheFirstRetryTime()
    {
        var operation = await QueuedJournalOperation();
        await using var profile = await ProvisionExecutionRuntime(operation.EnvironmentId);
        var queue = await OpenWorkQueue(profile, operation.EnvironmentId);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(40));
        var token = Guid.NewGuid();
        var first = await queue.ClaimNextAsync(token, timeout.Token);
        Assert.Equal(EnrollmentWorkClaimOutcome.Claimed, first.Outcome);
        Assert.Equal(operation.Id, first.Claim!.OperationId);
        var recovered = await queue.ClaimNextAsync(token, timeout.Token);
        Assert.Equal(EnrollmentWorkClaimOutcome.Existing, recovered.Outcome);
        Assert.Equal(first.Claim, recovered.Claim);
        Assert.Equal(EnrollmentWorkTransitionOutcome.NotTerminal, (await queue.CompleteAsync(first.Claim, timeout.Token)).Outcome);

        var deferred = await queue.DeferAsync(first.Claim, EnrollmentWorkRetryReason.OutcomeUnknown, timeout.Token);
        Assert.Equal(EnrollmentWorkTransitionOutcome.Deferred, deferred.Outcome);
        var retry = await queue.DeferAsync(first.Claim, EnrollmentWorkRetryReason.Retryable, timeout.Token);
        Assert.Equal(EnrollmentWorkTransitionOutcome.AlreadyDeferred, retry.Outcome);
        Assert.Equal(deferred.NextAttemptAt, retry.NextAttemptAt);
        var replay = await queue.ClaimNextAsync(token, timeout.Token);
        Assert.Equal(EnrollmentWorkClaimOutcome.AlreadyDeferred, replay.Outcome);
        Assert.Null(replay.Claim);
        await using var db = Db();
        Assert.Null((await db.Outbox.AsNoTracking().SingleAsync(x => x.Id == operation.Id, timeout.Token)).DeliveredAt);
    }

    [Fact]
    public async Task QueueRepositoryConcurrentDifferentTokensCannotBothOwnOneOperation()
    {
        var operation = await QueuedJournalOperation();
        await using var profile = await ProvisionExecutionRuntime(operation.EnvironmentId);
        var queue = await OpenWorkQueue(profile, operation.EnvironmentId);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(40));
        var tokens = new[] { Guid.NewGuid(), Guid.NewGuid() };
        var results = await Task.WhenAll(tokens.Select(token => queue.ClaimNextAsync(token, timeout.Token)));
        var winner = Assert.Single(results, result => result.Outcome == EnrollmentWorkClaimOutcome.Claimed);
        Assert.Equal(operation.Id, winner.Claim!.OperationId);
        foreach (var token in tokens)
        {
            var retry = await queue.ClaimNextAsync(token, timeout.Token);
            if (token == winner.Claim.ClaimToken) Assert.Equal(winner.Claim, retry.Claim);
            else Assert.Equal(EnrollmentWorkClaimOutcome.NoWork, retry.Outcome);
        }
        await using var db = Db();
        Assert.Equal(1L, await db.Database.SqlQuery<long>($"""
            SELECT count(*) AS "Value" FROM enrollment_execution.claim_leases WHERE operation_id={operation.Id}
            """).SingleAsync(timeout.Token));
    }

    [Fact]
    public async Task QueueRepositoryConcurrentIdenticalTokensRecoverTheSamePersistentAssignment()
    {
        var operation = await QueuedJournalOperation();
        await using var profile = await ProvisionExecutionRuntime(operation.EnvironmentId);
        var queue = await OpenWorkQueue(profile, operation.EnvironmentId);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(40));
        var token = Guid.NewGuid();
        var results = await Task.WhenAll(queue.ClaimNextAsync(token, timeout.Token), queue.ClaimNextAsync(token, timeout.Token));
        var assigned = results.Where(result => result.Claim is not null).ToArray();
        Assert.NotEmpty(assigned);
        Assert.All(assigned, result => Assert.Equal(operation.Id, result.Claim!.OperationId));
        var recovered = await queue.ClaimNextAsync(token, timeout.Token);
        Assert.Equal(EnrollmentWorkClaimOutcome.Existing, recovered.Outcome);
        Assert.All(assigned, result => Assert.Equal(recovered.Claim, result.Claim));
        await using var db = Db();
        Assert.Equal(1L, await db.Database.SqlQuery<long>($"""
            SELECT count(*) AS "Value" FROM enrollment_execution.claim_leases WHERE claim_token={token}
            """).SingleAsync(timeout.Token));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task QueueRepositoryCompletesOnlyAfterADurableTerminalStateAndReplaysCompletion(bool defer)
    {
        var operation = await QueuedJournalOperation();
        await using var profile = await ProvisionExecutionRuntime(operation.EnvironmentId);
        var queue = await OpenWorkQueue(profile, operation.EnvironmentId);
        var store = await OpenExecutionStore(profile.DataSource, operation.EnvironmentId, profile.DefinerRole);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(40));
        var token = Guid.NewGuid();
        var claim = (await queue.ClaimNextAsync(token, timeout.Token)).Claim!;
        Assert.Equal(EnrollmentWorkTransitionOutcome.NotTerminal, (await queue.CompleteAsync(claim, timeout.Token)).Outcome);
        Assert.Equal(EnrollmentGrantRecordOutcome.Recorded, (await store.QuarantineAsync(operation.EnvironmentId, operation.Id,
            null, null, EnrollmentGrantExecutionStopReason.StoredDataInvalid, timeout.Token)).Outcome);
        var finished = defer ? await queue.DeferAsync(claim, EnrollmentWorkRetryReason.OutcomeUnknown, timeout.Token)
            : await queue.CompleteAsync(claim, timeout.Token);
        Assert.Equal(EnrollmentWorkTransitionOutcome.Completed, finished.Outcome);
        var replayed = defer ? await queue.DeferAsync(claim, EnrollmentWorkRetryReason.Retryable, timeout.Token)
            : await queue.CompleteAsync(claim, timeout.Token);
        Assert.Equal(EnrollmentWorkTransitionOutcome.AlreadyCompleted, replayed.Outcome);
        Assert.Equal(EnrollmentWorkClaimOutcome.AlreadyCompleted, (await queue.ClaimNextAsync(token, timeout.Token)).Outcome);
        Assert.Equal(EnrollmentWorkClaimOutcome.NoWork, (await queue.ClaimNextAsync(Guid.NewGuid(), timeout.Token)).Outcome);
        await using var db = Db();
        var deliveredAt = (await db.Outbox.AsNoTracking().SingleAsync(x => x.Id == operation.Id, timeout.Token)).DeliveredAt;
        Assert.NotNull(deliveredAt);
        Assert.Equal(deliveredAt, await db.Database.SqlQuery<DateTimeOffset?>($"""
            SELECT completed_at AS "Value" FROM enrollment_execution.work_queue WHERE operation_id={operation.Id}
            """).SingleAsync(timeout.Token));
    }

    [Fact]
    public async Task QueueRepositoryRejectsAnotherEnvironmentTokenWithoutReturningAnOperation()
    {
        var first = await QueuedJournalOperation();
        var second = await QueuedJournalOperation();
        await using var firstProfile = await ProvisionExecutionRuntime(first.EnvironmentId);
        await using var secondProfile = await ProvisionExecutionRuntime(second.EnvironmentId);
        var firstQueue = await OpenWorkQueue(firstProfile, first.EnvironmentId);
        var secondQueue = await OpenWorkQueue(secondProfile, second.EnvironmentId);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(40));
        var token = Guid.NewGuid();
        Assert.Equal(EnrollmentWorkClaimOutcome.Claimed, (await firstQueue.ClaimNextAsync(token, timeout.Token)).Outcome);
        var conflict = await secondQueue.ClaimNextAsync(token, timeout.Token);
        Assert.Equal(EnrollmentWorkClaimOutcome.TokenConflict, conflict.Outcome);
        Assert.Null(conflict.Claim);
        Assert.Equal(second.Id, (await secondQueue.ClaimNextAsync(Guid.NewGuid(), timeout.Token)).Claim!.OperationId);
    }

    [Fact]
    public async Task QueueRepositoryCancellationDuringTokenLockCannotCreateALateClaim()
    {
        var operation = await QueuedJournalOperation();
        await using var profile = await ProvisionExecutionRuntime(operation.EnvironmentId);
        var queue = await OpenWorkQueue(profile, operation.EnvironmentId);
        var token = Guid.NewGuid();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(40));
        using var caller = new CancellationTokenSource();
        await using var gate = Db();
        await using var transaction = await gate.Database.BeginTransactionAsync(timeout.Token);
        await gate.Database.ExecuteSqlInterpolatedAsync($"""
            SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended({token.ToString()}::text,1162235478))
            """, timeout.Token);
        var pid = await gate.Database.SqlQueryRaw<int>("SELECT pg_backend_pid() AS \"Value\"").SingleAsync(timeout.Token);
        var pending = queue.ClaimNextAsync(token, caller.Token);
        try
        {
            await WaitForExecutionWaiters(profile.RuntimeRole, pid, 1, timeout.Token);
            await caller.CancelAsync();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending.WaitAsync(TimeSpan.FromSeconds(10)));
            await transaction.RollbackAsync(CancellationToken.None);
            await using var verification = Db();
            Assert.Equal(0L, await verification.Database.SqlQuery<long>($"""
                SELECT count(*) AS "Value" FROM enrollment_execution.claim_leases WHERE claim_token={token}
                """).SingleAsync(timeout.Token));
        }
        finally
        {
            try { await transaction.RollbackAsync(CancellationToken.None); } catch { }
            try { await caller.CancelAsync(); }
            finally { try { await pending; } catch { } }
        }
    }

    [Fact]
    public async Task QueueRepositoryFactoryRejectsAnUnexpectedQueueFunctionOwner()
    {
        var seed = await _fixture.SeedAsync();
        await using var profile = await ProvisionExecutionRuntime(seed.Environment.Id);
        await Assert.ThrowsAsync<InvalidOperationException>(() => PostgresEnrollmentGrantWorkQueue.CreateAuditedAsync(
            profile.DataSource, seed.Environment.Id,
            new NpgsqlConnectionStringBuilder(Environment.GetEnvironmentVariable("CONSOLE_TEST_DB")!).Username!,
            profile.DefinerRole, "unexpected_queue_function_owner", CancellationToken.None));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task QueueRepositoryCancelledTransitionCannotChangeTheClaim(bool complete)
    {
        var operation = await QueuedJournalOperation();
        await using var profile = await ProvisionExecutionRuntime(operation.EnvironmentId);
        var queue = await OpenWorkQueue(profile, operation.EnvironmentId);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(40));
        var token = Guid.NewGuid();
        var claim = (await queue.ClaimNextAsync(token, timeout.Token)).Claim!;
        if (complete)
        {
            var store = await OpenExecutionStore(profile.DataSource, operation.EnvironmentId, profile.DefinerRole);
            Assert.Equal(EnrollmentGrantRecordOutcome.Recorded, (await store.QuarantineAsync(operation.EnvironmentId,
                operation.Id, null, null, EnrollmentGrantExecutionStopReason.StoredDataInvalid, timeout.Token)).Outcome);
        }
        using var caller = new CancellationTokenSource();
        await using var gate = Db();
        await using var transaction = await gate.Database.BeginTransactionAsync(timeout.Token);
        await gate.Database.ExecuteSqlInterpolatedAsync($"""
            SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended({token.ToString()}::text,1162235478))
            """, timeout.Token);
        var pid = await gate.Database.SqlQueryRaw<int>("SELECT pg_backend_pid() AS \"Value\"").SingleAsync(timeout.Token);
        var pending = complete ? queue.CompleteAsync(claim, caller.Token)
            : queue.DeferAsync(claim, EnrollmentWorkRetryReason.OutcomeUnknown, caller.Token);
        try
        {
            await WaitForExecutionWaiters(profile.RuntimeRole, pid, 1, timeout.Token);
            await caller.CancelAsync();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending.WaitAsync(TimeSpan.FromSeconds(10)));
            await transaction.RollbackAsync(CancellationToken.None);
            await using var verification = Db();
            Assert.Equal("Claimed", await verification.Database.SqlQuery<string>($"""
                SELECT state AS "Value" FROM enrollment_execution.work_queue WHERE operation_id={operation.Id}
                """).SingleAsync(timeout.Token));
            Assert.Null((await verification.Outbox.AsNoTracking().SingleAsync(x => x.Id == operation.Id, timeout.Token)).DeliveredAt);
        }
        finally
        {
            try { await transaction.RollbackAsync(CancellationToken.None); } catch { }
            try { await caller.CancelAsync(); }
            finally { try { await pending; } catch { } }
        }
    }
}
