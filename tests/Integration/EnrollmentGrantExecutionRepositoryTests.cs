using ItManagement.AgentEnrollment.Crypto;
using ItManagement.AgentPlatformGrants;
using ItManagement.Core;
using ItManagement.EnrollmentGrantExecution;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace ItManagement.IntegrationTests;

public sealed partial class EnrollmentGrantPlanTests
{
    [Fact]
    public async Task ExecutionRepositoryCancellationWhileBlockedCannotCommitAfterGateRelease()
    {
        var operation = await QueuedJournalOperation();
        await using var capability = await ProvisionExecutionRuntime(operation.EnvironmentId);
        var store = await OpenExecutionStore(capability.DataSource, operation.EnvironmentId, capability.DefinerRole);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(40));
        using var cancelWorker = new CancellationTokenSource();
        await using var gate = Db();
        await using var gateTx = await gate.Database.BeginTransactionAsync(timeout.Token);
        await gate.Database.ExecuteSqlInterpolatedAsync($"SELECT 1 FROM public.\"Environments\" WHERE \"Id\"={operation.EnvironmentId} FOR NO KEY UPDATE", timeout.Token);
        var gatePid = await gate.Database.SqlQueryRaw<int>("SELECT pg_backend_pid() AS \"Value\"").SingleAsync(timeout.Token);
        var pending = store.AuthorizeAndStoreCandidateAsync(ToExecutionOperation(operation),
            new EnrollmentGrantEnvelopeCandidate(SealedEnrollmentGrant.Seal(operation.RecipientSpki, operation.EnvironmentId, operation.Id)),
            cancelWorker.Token);
        try
        {
            await WaitForExecutionWaiters(capability.RuntimeRole, gatePid, 1, timeout.Token);
            Assert.False(pending.IsCompleted);
            await cancelWorker.CancelAsync();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending.WaitAsync(TimeSpan.FromSeconds(10)));
            await gateTx.RollbackAsync(CancellationToken.None);
            var read = await store.ReadAsync(operation.EnvironmentId, operation.Id, timeout.Token);
            Assert.Equal(EnrollmentGrantExecutionState.Queued, read.Record!.State);
            Assert.Null(read.Record.Permit);
            Assert.Null(read.Record.Envelope);
        }
        finally
        {
            try { await gateTx.RollbackAsync(CancellationToken.None); } catch { }
            try { await cancelWorker.CancelAsync(); }
            finally { try { await pending; } catch { } }
        }
    }

    [Fact]
    public async Task ExecutionRepositoryStoresIssuedReceiptAndRecoversExactRetryWithoutErasingEnvelope()
    {
        var operation = await QueuedJournalOperation();
        await using var capability = await ProvisionExecutionRuntime(operation.EnvironmentId);
        var store = await OpenExecutionStore(capability.DataSource, operation.EnvironmentId, capability.DefinerRole);
        var expected = ToExecutionOperation(operation);
        var candidate = new EnrollmentGrantEnvelopeCandidate(SealedEnrollmentGrant.Seal(operation.RecipientSpki, operation.EnvironmentId, operation.Id));
        var stored = await store.AuthorizeAndStoreCandidateAsync(expected, candidate, default);
        Assert.Equal(EnrollmentGrantPermitStoreOutcome.Stored, stored.Outcome);

        // Obtain a typed synthetic private receipt through the existing strict SQL codec.
        // Roll back this fixture write so only the restricted repository commits the result.
        PlatformGrantReceipt receipt;
        await using (var owner = Db())
        await using (var transaction = await owner.Database.BeginTransactionAsync(System.Data.IsolationLevel.Serializable))
        {
            Assert.Equal("Recorded", (await StoreResult(owner, operation, stored.Permit!, false, Guid.NewGuid())).Outcome);
            receipt = (await ReadSqlExecution(owner, operation.EnvironmentId, operation.Id)).Record!.Result!.Receipt!;
            await transaction.RollbackAsync();
        }
        Assert.Equal(EnrollmentGrantExecutionState.PermitStored,
            (await store.ReadAsync(operation.EnvironmentId, operation.Id, default)).Record!.State);
        Assert.Equal(EnrollmentGrantRecordOutcome.Recorded,
            (await store.RecordDefiniteResultAsync(expected, stored.Permit!,
                new(PlatformGrantOutcome.Created, PlatformGrantDiagnostic.None, receipt), default)).Outcome);
        Assert.Equal(EnrollmentGrantRecordOutcome.AlreadyRecorded,
            (await store.RecordDefiniteResultAsync(expected, stored.Permit!,
                new(PlatformGrantOutcome.AlreadyCreated, PlatformGrantDiagnostic.None, receipt), default)).Outcome);
        var read = await store.ReadAsync(operation.EnvironmentId, operation.Id, default);
        Assert.Equal(EnrollmentGrantExecutionState.Completed, read.Record!.State);
        Assert.Equal(receipt, read.Record.Result!.Receipt);
        Assert.Equal(candidate.GetCiphertext(), read.Record.Envelope!.GetCiphertext());
    }

    [Fact]
    public async Task ExecutionRepositoryUsesAuditedPoolAndRecoversDurableFirstCandidate()
    {
        var operation = await QueuedJournalOperation();
        var capability = await ProvisionExecutionRuntime(operation.EnvironmentId);
        await using var source = capability.DataSource;
        var store = await OpenExecutionStore(source, operation.EnvironmentId, capability.DefinerRole);
        var expected = ToExecutionOperation(operation);
        Assert.Equal(EnrollmentGrantExecutionState.Queued,
            (await store.ReadAsync(operation.EnvironmentId, operation.Id, default)).Record!.State);
        var first = new EnrollmentGrantEnvelopeCandidate(SealedEnrollmentGrant.Seal(operation.RecipientSpki, operation.EnvironmentId, operation.Id));
        var stored = await store.AuthorizeAndStoreCandidateAsync(expected, first, default);
        Assert.Equal(EnrollmentGrantPermitStoreOutcome.Stored, stored.Outcome);
        var second = new EnrollmentGrantEnvelopeCandidate(SealedEnrollmentGrant.Seal(operation.RecipientSpki, operation.EnvironmentId, operation.Id));
        var existing = await store.AuthorizeAndStoreCandidateAsync(expected, second, default);
        Assert.Equal(EnrollmentGrantPermitStoreOutcome.Existing, existing.Outcome);
        Assert.Equal(first.GetCiphertext(), existing.Envelope!.GetCiphertext());
        Assert.Equal(stored.Permit!.GetAuthorizationDigest(), existing.Permit!.GetAuthorizationDigest());
        Assert.Equal(EnrollmentGrantStoreReadOutcome.OutcomeUnknown,
            (await store.ReadAsync(Guid.NewGuid(), operation.Id, default)).Outcome);
        await Assert.ThrowsAsync<InvalidOperationException>(() => OpenExecutionStore(source, Guid.NewGuid(), capability.DefinerRole));
    }

    [Fact]
    public async Task ExecutionRepositoryConcurrentCandidatesConvergeOnOneCommittedEnvelope()
    {
        var operation = await QueuedJournalOperation();
        var capability = await ProvisionExecutionRuntime(operation.EnvironmentId);
        await using var source = capability.DataSource;
        var store = await OpenExecutionStore(source, operation.EnvironmentId, capability.DefinerRole);
        var expected = ToExecutionOperation(operation);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(40));
        await using var gate = Db();
        await using var gateTx = await gate.Database.BeginTransactionAsync(timeout.Token);
        await gate.Database.ExecuteSqlInterpolatedAsync($"SELECT 1 FROM public.\"Environments\" WHERE \"Id\"={operation.EnvironmentId} FOR NO KEY UPDATE", timeout.Token);
        var gatePid = await gate.Database.SqlQueryRaw<int>("SELECT pg_backend_pid() AS \"Value\"").SingleAsync(timeout.Token);
        var candidates = Enumerable.Range(0, 2).Select(_ => new EnrollmentGrantEnvelopeCandidate(
            SealedEnrollmentGrant.Seal(operation.RecipientSpki, operation.EnvironmentId, operation.Id))).ToArray();
        Task<EnrollmentGrantPermitStoreResult>[] pending = [];
        try
        {
            pending = candidates.Select(candidate => store.AuthorizeAndStoreCandidateAsync(expected, candidate, timeout.Token)).ToArray();
            await WaitForExecutionWaiters(capability.RuntimeRole, gatePid, 2, timeout.Token);
            Assert.All(pending, task => Assert.False(task.IsCompleted));
            await gateTx.RollbackAsync(CancellationToken.None);
            var results = await Task.WhenAll(pending);
            var winner = Assert.Single(results, result => result.Outcome == EnrollmentGrantPermitStoreOutcome.Stored);
            Assert.All(results, result => Assert.Contains(result.Outcome, new[]
                { EnrollmentGrantPermitStoreOutcome.Stored, EnrollmentGrantPermitStoreOutcome.Existing, EnrollmentGrantPermitStoreOutcome.OutcomeUnknown }));
            var read = await store.ReadAsync(operation.EnvironmentId, operation.Id, timeout.Token);
            Assert.Equal(EnrollmentGrantExecutionState.PermitStored, read.Record!.State);
            Assert.Equal(winner.Envelope!.GetCiphertext(), read.Record.Envelope!.GetCiphertext());
            Assert.Equal(winner.Permit!.GetAuthorizationDigest(), read.Record.Permit!.GetAuthorizationDigest());
            var retry = await store.AuthorizeAndStoreCandidateAsync(expected, candidates[0], timeout.Token);
            Assert.Equal(EnrollmentGrantPermitStoreOutcome.Existing, retry.Outcome);
            Assert.Equal(winner.Envelope.GetCiphertext(), retry.Envelope!.GetCiphertext());
        }
        finally
        {
            try { await gateTx.RollbackAsync(CancellationToken.None); } catch { }
            try { if (pending.Any(task => !task.IsCompleted)) await timeout.CancelAsync(); }
            finally { foreach (var task in pending) { try { await task; } catch { } } }
        }
    }

    [Fact]
    public async Task ExecutionRepositoryResultAndQuarantineRaceHasOneDurableDisposition()
    {
        var operation = await QueuedJournalOperation();
        var capability = await ProvisionExecutionRuntime(operation.EnvironmentId);
        await using var source = capability.DataSource;
        var store = await OpenExecutionStore(source, operation.EnvironmentId, capability.DefinerRole);
        var expected = ToExecutionOperation(operation);
        var candidate = new EnrollmentGrantEnvelopeCandidate(SealedEnrollmentGrant.Seal(operation.RecipientSpki, operation.EnvironmentId, operation.Id));
        var stored = await store.AuthorizeAndStoreCandidateAsync(expected, candidate, default);
        Assert.Equal(EnrollmentGrantPermitStoreOutcome.Stored, stored.Outcome);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(40));
        await using var gate = Db();
        await using var gateTx = await gate.Database.BeginTransactionAsync(timeout.Token);
        await gate.Database.ExecuteSqlInterpolatedAsync($"SELECT 1 FROM public.\"EnrollmentGrantOperations\" WHERE \"Id\"={operation.Id} FOR NO KEY UPDATE", timeout.Token);
        var gatePid = await gate.Database.SqlQueryRaw<int>("SELECT pg_backend_pid() AS \"Value\"").SingleAsync(timeout.Token);
        Task<EnrollmentGrantRecordResult>[] pending = [];
        try
        {
            pending = [store.RecordDefiniteResultAsync(expected, stored.Permit!,
                new(PlatformGrantOutcome.PermanentRejected, PlatformGrantDiagnostic.MappingUnavailable, null), timeout.Token),
                store.QuarantineAsync(operation.EnvironmentId, operation.Id, expected, stored.Permit,
                    EnrollmentGrantExecutionStopReason.StoredDataInvalid, timeout.Token)];
            await WaitForExecutionWaiters(capability.RuntimeRole, gatePid, 2, timeout.Token);
            await gateTx.RollbackAsync(CancellationToken.None);
            var results = await Task.WhenAll(pending);
            Assert.Single(results, result => result.Outcome == EnrollmentGrantRecordOutcome.Recorded);
            Assert.All(results, result => Assert.Contains(result.Outcome, new[]
                { EnrollmentGrantRecordOutcome.Recorded, EnrollmentGrantRecordOutcome.Conflict, EnrollmentGrantRecordOutcome.OutcomeUnknown }));
            var read = await store.ReadAsync(operation.EnvironmentId, operation.Id, timeout.Token);
            Assert.Contains(read.Record!.State, new[] { EnrollmentGrantExecutionState.PermanentRejected, EnrollmentGrantExecutionState.Quarantined });
            Assert.NotNull(read.Record.Permit);
            if (read.Record.State == EnrollmentGrantExecutionState.PermanentRejected)
            {
                Assert.NotNull(read.Record.Result); Assert.Null(read.Record.StopReason); Assert.Null(read.Record.Envelope);
            }
            else
            {
                Assert.Null(read.Record.Result); Assert.Equal(EnrollmentGrantExecutionStopReason.StoredDataInvalid, read.Record.StopReason);
                Assert.Equal(candidate.GetCiphertext(), read.Record.Envelope!.GetCiphertext());
            }
        }
        finally
        {
            try { await gateTx.RollbackAsync(CancellationToken.None); } catch { }
            try { if (pending.Any(task => !task.IsCompleted)) await timeout.CancelAsync(); }
            finally { foreach (var task in pending) { try { await task; } catch { } } }
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ExecutionRepositoryReadsAndResolvesOperationAfterRequesterRevocation(bool afterPermit)
    {
        var operation = await QueuedJournalOperation();
        var capability = await ProvisionExecutionRuntime(operation.EnvironmentId);
        await using var source = capability.DataSource;
        var store = await OpenExecutionStore(source, operation.EnvironmentId, capability.DefinerRole);
        var expected = ToExecutionOperation(operation);
        var candidate = new EnrollmentGrantEnvelopeCandidate(SealedEnrollmentGrant.Seal(operation.RecipientSpki, operation.EnvironmentId, operation.Id));
        EnrollmentGrantPermitStoreResult? permit = null;
        if (afterPermit)
        {
            permit = await store.AuthorizeAndStoreCandidateAsync(expected, candidate, default);
            Assert.Equal(EnrollmentGrantPermitStoreOutcome.Stored, permit.Outcome);
        }
        await using (var owner = Db())
            await owner.Memberships.Where(x => x.EnvironmentId == operation.EnvironmentId && x.PrincipalId == operation.RequesterId)
                .ExecuteUpdateAsync(x => x.SetProperty(m => m.Active, false));
        Assert.Equal(EnrollmentGrantStoreReadOutcome.Found, (await store.ReadAsync(operation.EnvironmentId, operation.Id, default)).Outcome);
        if (afterPermit)
        {
            var recorded = await store.RecordDefiniteResultAsync(expected, permit!.Permit!,
                new(PlatformGrantOutcome.PermanentRejected, PlatformGrantDiagnostic.MappingUnavailable, null), default);
            Assert.Equal(EnrollmentGrantRecordOutcome.Recorded, recorded.Outcome);
        }
        else
        {
            var rejected = await store.AuthorizeAndStoreCandidateAsync(expected, candidate, default);
            Assert.Equal(EnrollmentGrantPermitStoreOutcome.AuthorizationRejected, rejected.Outcome);
            Assert.Equal(EnrollmentGrantExecutionStopReason.AuthorizationChanged, rejected.StopReason);
            Assert.Null(rejected.Permit);
        }
        Assert.Equal(EnrollmentGrantExecutionState.PermanentRejected,
            (await store.ReadAsync(operation.EnvironmentId, operation.Id, default)).Record!.State);
    }

    [Fact]
    public async Task ExecutionRepositoryQuarantinesAmbiguousContextWithoutMinting()
    {
        var operation = await InsertExpiredQueuedOperation(extraItem: true);
        var capability = await ProvisionExecutionRuntime(operation.EnvironmentId);
        await using var source = capability.DataSource;
        var store = await OpenExecutionStore(source, operation.EnvironmentId, capability.DefinerRole);
        var candidate = new EnrollmentGrantEnvelopeCandidate(SealedEnrollmentGrant.Seal(operation.RecipientSpki, operation.EnvironmentId, operation.Id));
        Assert.Equal(EnrollmentGrantPermitStoreOutcome.OutcomeUnknown,
            (await store.AuthorizeAndStoreCandidateAsync(ToExecutionOperation(operation), candidate, default)).Outcome);
        var read = await store.ReadAsync(operation.EnvironmentId, operation.Id, default);
        Assert.Equal(EnrollmentGrantExecutionState.Quarantined, read.Record!.State);
        Assert.Equal(EnrollmentGrantExecutionStopReason.StoredDataInvalid, read.Record.StopReason);
        Assert.Null(read.Record.Permit); Assert.Null(read.Record.Envelope);
    }

    [Fact]
    public async Task ExecutionRepositoryRejectsCallerOperationDriftWithoutChangingStoredOperation()
    {
        var operation = await QueuedJournalOperation();
        var capability = await ProvisionExecutionRuntime(operation.EnvironmentId);
        await using var source = capability.DataSource;
        var store = await OpenExecutionStore(source, operation.EnvironmentId, capability.DefinerRole);
        operation.RequesterOperatorId = Guid.NewGuid(); // Detached caller copy only.
        var candidate = new EnrollmentGrantEnvelopeCandidate(SealedEnrollmentGrant.Seal(operation.RecipientSpki, operation.EnvironmentId, operation.Id));
        Assert.Equal(EnrollmentGrantPermitStoreOutcome.OutcomeUnknown,
            (await store.AuthorizeAndStoreCandidateAsync(ToExecutionOperation(operation), candidate, default)).Outcome);
        var read = await store.ReadAsync(operation.EnvironmentId, operation.Id, default);
        Assert.Equal(EnrollmentGrantExecutionState.Queued, read.Record!.State);
        Assert.NotEqual(operation.RequesterOperatorId, read.Record.Operation.RequesterOperatorId);
        Assert.Null(read.Record.Permit);
    }

    private static Task<PostgresEnrollmentGrantExecutionStore> OpenExecutionStore(NpgsqlDataSource source, Guid environment, string definer) =>
        PostgresEnrollmentGrantExecutionStore.CreateAuditedAsync(source, environment,
            new NpgsqlConnectionStringBuilder(Environment.GetEnvironmentVariable("CONSOLE_TEST_DB")!).Username!, definer, default);

    private static async Task WaitForExecutionWaiters(string runtime, int holder, int count, CancellationToken cancellationToken)
    {
        await using var observer = Db();
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var blocked = await observer.Database.SqlQuery<int>($"""
                WITH RECURSIVE blockers(worker_pid, blocker_pid) AS (
                    SELECT pid, unnest(pg_catalog.pg_blocking_pids(pid))
                    FROM pg_catalog.pg_stat_activity WHERE usename={runtime}
                    UNION
                    SELECT worker_pid, unnest(pg_catalog.pg_blocking_pids(blocker_pid)) FROM blockers
                )
                SELECT count(DISTINCT worker_pid)::int AS "Value" FROM blockers WHERE blocker_pid={holder}
                """).SingleAsync(cancellationToken);
            if (blocked >= count) return;
            await Task.Delay(50, cancellationToken);
        }
    }
}
