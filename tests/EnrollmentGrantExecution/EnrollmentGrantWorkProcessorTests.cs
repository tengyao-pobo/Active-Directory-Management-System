using ItManagement.AgentPlatformGrants;
using Xunit;

namespace ItManagement.EnrollmentGrantExecution.Tests;

public sealed class EnrollmentGrantWorkProcessorTests
{
    private static readonly Guid EnvironmentId = Guid.Parse("ad910000-0000-0000-0000-000000000001");
    private static readonly DateTimeOffset Now = new(2026, 9, 12, 0, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task UnknownClaimCommitRetriesTheSameTokenBeforeRequestingMoreWork()
    {
        var queue = new QueueStub();
        queue.Claim = (_, _) => Task.FromResult(new EnrollmentWorkClaimResult(EnrollmentWorkClaimOutcome.OutcomeUnknown));
        var executor = new ExecutorStub();
        var processor = new EnrollmentGrantWorkProcessor(EnvironmentId, queue, executor);
        Assert.Equal(EnrollmentWorkProcessOutcome.OutcomeUnknown, await processor.ProcessOnceAsync(CancellationToken.None));
        queue.Claim = (token, _) => Task.FromResult(Assigned(token, EnrollmentWorkClaimOutcome.Existing));
        Assert.Equal(EnrollmentWorkProcessOutcome.Completed, await processor.ProcessOnceAsync(CancellationToken.None));
        Assert.Equal(2, queue.Tokens.Count);
        Assert.Equal(queue.Tokens[0], queue.Tokens[1]);
        Assert.Single(executor.Operations);
    }

    [Theory]
    [InlineData("environment")]
    [InlineData("token")]
    [InlineData("duration")]
    [InlineData("expired")]
    public async Task InvalidAssignmentsNeverReachTheExecutorOrTransitionAnotherOperation(string defect)
    {
        var queue = new QueueStub();
        queue.Claim = (token, _) =>
        {
            var result = Assigned(token);
            var claim = result.Claim!;
            return Task.FromResult(defect switch
            {
                "environment" => result with { Claim = claim with { EnvironmentId = Guid.NewGuid() } },
                "token" => result with { Claim = claim with { ClaimToken = Guid.NewGuid() } },
                "duration" => result with { Claim = claim with { LeaseUntil = claim.LeaseUntil.AddSeconds(1) } },
                _ => result with { QueriedAt = claim.LeaseUntil }
            });
        };
        var executor = new ExecutorStub();
        var processor = new EnrollmentGrantWorkProcessor(EnvironmentId, queue, executor);
        Assert.Equal(EnrollmentWorkProcessOutcome.OutcomeUnknown, await processor.ProcessOnceAsync(CancellationToken.None));
        Assert.Empty(executor.Operations);
        Assert.Empty(queue.Completed);
        Assert.Empty(queue.Deferred);
    }

    [Fact]
    public async Task ExpensiveClaimReadConsumesTheLeaseBudgetBeforeExecution()
    {
        var time = new MonotonicTime();
        var queue = new QueueStub();
        queue.Claim = (token, _) => { time.Advance(TimeSpan.FromSeconds(116)); return Task.FromResult(Assigned(token)); };
        var executor = new ExecutorStub();
        var processor = new EnrollmentGrantWorkProcessor(EnvironmentId, queue, executor, time);
        Assert.Equal(EnrollmentWorkProcessOutcome.Deferred, await processor.ProcessOnceAsync(CancellationToken.None));
        Assert.Empty(executor.Operations);
        Assert.Single(queue.Deferred);
        Assert.Empty(queue.Completed);
    }

    [Fact]
    public async Task ExecutorSuccessCannotCompleteWorkWithoutDatabaseTerminalConfirmation()
    {
        var queue = new QueueStub { Complete = (_, _) => Task.FromResult(Transition(EnrollmentWorkTransitionOutcome.NotTerminal)) };
        var executor = new ExecutorStub();
        var processor = new EnrollmentGrantWorkProcessor(EnvironmentId, queue, executor);
        Assert.Equal(EnrollmentWorkProcessOutcome.Deferred, await processor.ProcessOnceAsync(CancellationToken.None));
        Assert.Single(executor.Operations);
        Assert.Single(queue.Completed);
        Assert.Single(queue.Deferred);
    }

    [Fact]
    public async Task UnknownExecutionCanStillReconcileAnAlreadyCommittedTerminalState()
    {
        var queue = new QueueStub { Complete = (_, _) => Task.FromResult(Transition(EnrollmentWorkTransitionOutcome.AlreadyCompleted)) };
        var executor = new ExecutorStub { Execute = (_, _, _) => Task.FromResult(new EnrollmentGrantExecutionResult(
            EnrollmentGrantExecutionOutcome.OutcomeUnknown, PlatformGrantDiagnostic.ResponseUnavailable)) };
        var processor = new EnrollmentGrantWorkProcessor(EnvironmentId, queue, executor);
        Assert.Equal(EnrollmentWorkProcessOutcome.Completed, await processor.ProcessOnceAsync(CancellationToken.None));
        Assert.Empty(queue.Deferred);
    }

    [Fact]
    public async Task UnexpectedExecutionFailureOnlyDefersWork()
    {
        var queue = new QueueStub();
        var executor = new ExecutorStub { Execute = (_, _, _) => Task.FromException<EnrollmentGrantExecutionResult>(new InvalidOperationException("Synthetic failure")) };
        var processor = new EnrollmentGrantWorkProcessor(EnvironmentId, queue, executor);
        Assert.Equal(EnrollmentWorkProcessOutcome.Deferred, await processor.ProcessOnceAsync(CancellationToken.None));
        Assert.Empty(queue.Completed);
        Assert.Single(queue.Deferred);
        Assert.Equal(EnrollmentWorkRetryReason.OutcomeUnknown, queue.Reasons[0]);
    }

    [Fact]
    public async Task CallerCancellationLeavesTheLeaseForRecoveryWithoutAFalseTransition()
    {
        using var caller = new CancellationTokenSource();
        var queue = new QueueStub();
        var executor = new ExecutorStub { Execute = (_, _, token) =>
        {
            caller.Cancel();
            token.ThrowIfCancellationRequested();
            throw new InvalidOperationException("Cancellation was ignored");
        } };
        var processor = new EnrollmentGrantWorkProcessor(EnvironmentId, queue, executor);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => processor.ProcessOnceAsync(caller.Token));
        Assert.Empty(queue.Completed);
        Assert.Empty(queue.Deferred);
    }

    [Theory]
    [InlineData(EnrollmentWorkTransitionOutcome.Completed)]
    [InlineData(EnrollmentWorkTransitionOutcome.AlreadyCompleted)]
    public async Task FailedExecutionCanReconcileTerminalStateWhileDeferring(EnrollmentWorkTransitionOutcome terminal)
    {
        var queue = new QueueStub { Defer = (_, _, _) => Task.FromResult(Transition(terminal)) };
        var executor = new ExecutorStub { Execute = (_, _, _) =>
            Task.FromException<EnrollmentGrantExecutionResult>(new InvalidOperationException("Synthetic lost response")) };
        var processor = new EnrollmentGrantWorkProcessor(EnvironmentId, queue, executor);
        Assert.Equal(EnrollmentWorkProcessOutcome.Completed, await processor.ProcessOnceAsync(CancellationToken.None));
        Assert.Empty(queue.Completed);
        Assert.Single(queue.Deferred);
    }

    [Theory]
    [InlineData(EnrollmentWorkTransitionOutcome.StaleClaim, EnrollmentWorkProcessOutcome.LeaseLost)]
    [InlineData(EnrollmentWorkTransitionOutcome.TokenConflict, EnrollmentWorkProcessOutcome.LeaseLost)]
    [InlineData(EnrollmentWorkTransitionOutcome.OutcomeUnknown, EnrollmentWorkProcessOutcome.OutcomeUnknown)]
    public async Task UncertainOrLostCompletionNeverReportsSuccess(EnrollmentWorkTransitionOutcome database, EnrollmentWorkProcessOutcome expected)
    {
        var queue = new QueueStub { Complete = (_, _) => Task.FromResult(Transition(database)) };
        var processor = new EnrollmentGrantWorkProcessor(EnvironmentId, queue, new ExecutorStub());
        Assert.Equal(expected, await processor.ProcessOnceAsync(CancellationToken.None));
        Assert.Empty(queue.Deferred);
    }

    [Fact]
    public async Task CompletionWithoutItsTimestampIsAnInvalidResponse()
    {
        var queue = new QueueStub { Complete = (_, _) => Task.FromResult(new EnrollmentWorkTransitionResult(EnrollmentWorkTransitionOutcome.Completed)) };
        var processor = new EnrollmentGrantWorkProcessor(EnvironmentId, queue, new ExecutorStub());
        Assert.Equal(EnrollmentWorkProcessOutcome.OutcomeUnknown, await processor.ProcessOnceAsync(CancellationToken.None));
    }

    [Fact]
    public async Task ConcurrentCallsSerializeClaimTokenRecovery()
    {
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var queue = new QueueStub();
        queue.Claim = async (token, cancellation) =>
        {
            if (queue.Tokens.Count == 1)
            {
                entered.SetResult();
                await release.Task.WaitAsync(cancellation);
                return new(EnrollmentWorkClaimOutcome.OutcomeUnknown);
            }
            return Assigned(token);
        };
        var executor = new ExecutorStub();
        var processor = new EnrollmentGrantWorkProcessor(EnvironmentId, queue, executor);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var first = processor.ProcessOnceAsync(deadline.Token);
        Task<EnrollmentWorkProcessOutcome>? second = null;
        try
        {
            await entered.Task.WaitAsync(deadline.Token);
            second = processor.ProcessOnceAsync(deadline.Token);
            Assert.Single(queue.Tokens);
            release.TrySetResult();
            Assert.Equal(EnrollmentWorkProcessOutcome.OutcomeUnknown, await first);
            Assert.Equal(EnrollmentWorkProcessOutcome.Completed, await second);
            Assert.Equal(queue.Tokens[0], queue.Tokens[1]);
        }
        finally
        {
            release.TrySetResult();
            await deadline.CancelAsync();
            try { await first; } catch { }
            if (second is not null) { try { await second; } catch { } }
        }
    }

    private static EnrollmentWorkClaimResult Assigned(Guid token, EnrollmentWorkClaimOutcome outcome = EnrollmentWorkClaimOutcome.Claimed) =>
        new(outcome, Now, new(EnvironmentId, Guid.NewGuid(), token, 1, Now, Now.AddSeconds(120)));

    private static EnrollmentWorkTransitionResult Transition(EnrollmentWorkTransitionOutcome outcome) =>
        new(outcome, Now, outcome is EnrollmentWorkTransitionOutcome.Deferred or EnrollmentWorkTransitionOutcome.AlreadyDeferred ? Now.AddSeconds(5) : null);

    private sealed class QueueStub : IEnrollmentGrantWorkQueue
    {
        public List<Guid> Tokens { get; } = [];
        public List<EnrollmentWorkClaim> Completed { get; } = [];
        public List<EnrollmentWorkClaim> Deferred { get; } = [];
        public List<EnrollmentWorkRetryReason> Reasons { get; } = [];
        public Func<Guid, CancellationToken, Task<EnrollmentWorkClaimResult>> Claim { get; set; } = (token, _) => Task.FromResult(Assigned(token));
        public Func<EnrollmentWorkClaim, CancellationToken, Task<EnrollmentWorkTransitionResult>> Complete { get; init; } = (_, _) => Task.FromResult(Transition(EnrollmentWorkTransitionOutcome.Completed));
        public Func<EnrollmentWorkClaim, EnrollmentWorkRetryReason, CancellationToken, Task<EnrollmentWorkTransitionResult>> Defer { get; init; } = (_, _, _) => Task.FromResult(Transition(EnrollmentWorkTransitionOutcome.Deferred));
        public Task<EnrollmentWorkClaimResult> ClaimNextAsync(Guid token, CancellationToken cancellationToken) { Tokens.Add(token); return Claim(token, cancellationToken); }
        public Task<EnrollmentWorkTransitionResult> CompleteAsync(EnrollmentWorkClaim claim, CancellationToken cancellationToken) { Completed.Add(claim); return Complete(claim, cancellationToken); }
        public Task<EnrollmentWorkTransitionResult> DeferAsync(EnrollmentWorkClaim claim, EnrollmentWorkRetryReason reason, CancellationToken cancellationToken)
        { Deferred.Add(claim); Reasons.Add(reason); return Defer(claim, reason, cancellationToken); }
    }

    private sealed class ExecutorStub : IEnrollmentGrantExecutor
    {
        public List<Guid> Operations { get; } = [];
        public Func<Guid, Guid, CancellationToken, Task<EnrollmentGrantExecutionResult>> Execute { get; init; } = (_, _, _) =>
            Task.FromResult(new EnrollmentGrantExecutionResult(EnrollmentGrantExecutionOutcome.GrantAvailable, PlatformGrantDiagnostic.None));
        public Task<EnrollmentGrantExecutionResult> ExecuteAsync(Guid environmentId, Guid operationId, CancellationToken cancellationToken)
        { Operations.Add(operationId); return Execute(environmentId, operationId, cancellationToken); }
    }

    private sealed class MonotonicTime : TimeProvider
    {
        private long _timestamp;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => _timestamp;
        public void Advance(TimeSpan duration) => _timestamp += duration.Ticks;
    }
}
