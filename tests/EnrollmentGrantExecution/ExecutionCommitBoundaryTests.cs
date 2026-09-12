using System.Data;
using System.Data.Common;
using Xunit;

namespace ItManagement.EnrollmentGrantExecution.Tests;

public sealed class ExecutionCommitBoundaryTests
{
    [Fact]
    public async Task CancellationBeforeCommitDoesNotSubmitTransaction()
    {
        using var caller = new CancellationTokenSource(); caller.Cancel();
        await using var transaction = new CommitProbe(_ => Task.CompletedTask);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            PostgresEnrollmentGrantExecutionStore.CommitAsync(transaction, caller.Token));
        Assert.False(transaction.Called);
    }

    [Fact]
    public async Task CancellationAfterCommitStartsStillObservesConfirmedOutcome()
    {
        using var caller = new CancellationTokenSource();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var finish = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var transaction = new CommitProbe(async token =>
        {
            Assert.False(token.CanBeCanceled);
            started.SetResult();
            await finish.Task;
        });
        var pending = PostgresEnrollmentGrantExecutionStore.CommitAsync(transaction, caller.Token);
        try
        {
            await started.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await caller.CancelAsync();
            Assert.False(pending.IsCompleted);
        }
        finally { finish.TrySetResult(); }
        await pending.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.True(transaction.Called);
    }

    [Fact]
    public async Task ProviderCancellationDuringCommitIsAnUnknownOutcomeNotCallerCancellation()
    {
        await using var transaction = new CommitProbe(_ => Task.FromException(new OperationCanceledException()));
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            PostgresEnrollmentGrantExecutionStore.CommitAsync(transaction, CancellationToken.None));
        Assert.Equal("EnrollmentExecutionCommitOutcomeUnknown", error.Message);
    }

    private sealed class CommitProbe(Func<CancellationToken, Task> commit) : DbTransaction
    {
        internal bool Called { get; private set; }
        public override IsolationLevel IsolationLevel => IsolationLevel.Serializable;
        protected override DbConnection? DbConnection => null;
        public override void Commit() => throw new NotSupportedException();
        public override void Rollback() { }
        public override Task CommitAsync(CancellationToken cancellationToken = default)
        {
            Called = true;
            return commit(cancellationToken);
        }
    }
}
