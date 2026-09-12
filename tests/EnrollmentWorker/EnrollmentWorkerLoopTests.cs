using ItManagement.EnrollmentGrantExecution;
using ItManagement.EnrollmentWorker;
using Xunit;

namespace EnrollmentWorker.Tests;

public sealed class EnrollmentWorkerLoopTests
{
    [Fact]
    public void RequiresBetweenOneAndThirtyTwoEnvironments()
    {
        Assert.Throws<ArgumentNullException>(() => new EnrollmentWorkerLoop(null!));
        Assert.Throws<ArgumentOutOfRangeException>(() => new EnrollmentWorkerLoop([]));
        Assert.Throws<ArgumentOutOfRangeException>(() => new EnrollmentWorkerLoop(
            Enumerable.Range(0, 33).Select(_ => Environment()).ToArray()));
    }

    [Fact]
    public void RequiresConcurrencyBetweenOneAndEight()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new EnrollmentWorkerLoop([Environment()], maximumConcurrency: 0));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new EnrollmentWorkerLoop([Environment()], maximumConcurrency: 9));

        _ = new EnrollmentWorkerLoop([Environment()], maximumConcurrency: 1);
        _ = new EnrollmentWorkerLoop([Environment()], maximumConcurrency: 8);
    }

    [Fact]
    public void RejectsNullEmptyAndDuplicateEnvironmentIdentities()
    {
        Assert.Throws<ArgumentException>(() => new EnrollmentWorkerLoop([null!]));
        Assert.Throws<ArgumentException>(() => new EnrollmentWorkerLoop([Environment(Guid.Empty)]));

        var identifier = Guid.NewGuid();
        Assert.Throws<ArgumentException>(() => new EnrollmentWorkerLoop(
            [Environment(identifier), Environment(identifier)]));
    }

    [Fact]
    public async Task RunIsSingleUse()
    {
        var started = Signal();
        var environment = Environment(process: async cancellationToken =>
        {
            started.TrySetResult();
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            return EnrollmentWorkProcessOutcome.NoWork;
        });
        var loop = new EnrollmentWorkerLoop([environment]);
        using var cancellation = new CancellationTokenSource();

        var running = loop.RunAsync(cancellation.Token);
        await started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await Assert.ThrowsAsync<InvalidOperationException>(() => loop.RunAsync(CancellationToken.None));
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => running);
    }

    [Fact]
    public async Task UnknownBackoffIsCappedAndResetsAfterSuccess()
    {
        EnrollmentWorkProcessOutcome[] outcomes =
        [
            EnrollmentWorkProcessOutcome.OutcomeUnknown,
            EnrollmentWorkProcessOutcome.OutcomeUnknown,
            EnrollmentWorkProcessOutcome.OutcomeUnknown,
            EnrollmentWorkProcessOutcome.OutcomeUnknown,
            EnrollmentWorkProcessOutcome.OutcomeUnknown,
            EnrollmentWorkProcessOutcome.OutcomeUnknown,
            EnrollmentWorkProcessOutcome.Completed,
            EnrollmentWorkProcessOutcome.OutcomeUnknown
        ];
        var next = 0;
        var delays = new List<TimeSpan>();
        using var cancellation = new CancellationTokenSource();
        var environment = Environment(process: _ => Task.FromResult(outcomes[next++]));
        var loop = new EnrollmentWorkerLoop([environment], (delay, cancellationToken) =>
        {
            delays.Add(delay);
            if (delays.Count != outcomes.Length) return Task.CompletedTask;
            cancellation.Cancel();
            return Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
        });

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => loop.RunAsync(cancellation.Token));

        Assert.Equal(
            [2, 4, 8, 16, 32, 60, 0.1, 2],
            delays.Select(value => value.TotalSeconds).ToArray());
    }

    [Theory]
    [InlineData(EnrollmentWorkProcessOutcome.Completed, 100)]
    [InlineData(EnrollmentWorkProcessOutcome.Deferred, 100)]
    [InlineData(EnrollmentWorkProcessOutcome.LeaseLost, 1_000)]
    [InlineData(EnrollmentWorkProcessOutcome.NoWork, 5_000)]
    public async Task KnownOutcomesUseTheirFixedDelay(
        EnrollmentWorkProcessOutcome outcome,
        int expectedMilliseconds)
    {
        TimeSpan? observed = null;
        using var cancellation = new CancellationTokenSource();
        var loop = new EnrollmentWorkerLoop([Environment(process: _ => Task.FromResult(outcome))],
            (delay, cancellationToken) =>
            {
                observed = delay;
                cancellation.Cancel();
                return Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            });

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => loop.RunAsync(cancellation.Token));
        Assert.Equal(TimeSpan.FromMilliseconds(expectedMilliseconds), observed);
    }

    [Fact]
    public async Task ExternalCancellationEndsAndObservesEveryLane()
    {
        var first = BlockingEnvironment();
        var second = BlockingEnvironment();
        var loop = new EnrollmentWorkerLoop([first.Environment, second.Environment]);
        using var cancellation = new CancellationTokenSource();

        var running = loop.RunAsync(cancellation.Token);
        await Task.WhenAll(first.Started.Task, second.Started.Task).WaitAsync(TimeSpan.FromSeconds(5));
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => running);
        Assert.True(first.Finished.Task.IsCompletedSuccessfully);
        Assert.True(second.Finished.Task.IsCompletedSuccessfully);
    }

    [Fact]
    public async Task ProcessCallsShareTheConfiguredConcurrencyLimit()
    {
        const int environmentCount = 8;
        const int maximumConcurrency = 3;
        var firstWaveStarted = Signal();
        var everyEnvironmentStarted = Signal();
        var release = Signal();
        var current = 0;
        var maximum = 0;
        var started = 0;
        var environments = Enumerable.Range(0, environmentCount).Select(_ => Environment(process: async cancellationToken =>
        {
            var active = Interlocked.Increment(ref current);
            UpdateMaximum(ref maximum, active);
            var observedStarted = Interlocked.Increment(ref started);
            if (observedStarted == maximumConcurrency) firstWaveStarted.TrySetResult();
            if (observedStarted == environmentCount) everyEnvironmentStarted.TrySetResult();
            try
            {
                await release.Task.WaitAsync(cancellationToken);
                return EnrollmentWorkProcessOutcome.NoWork;
            }
            finally
            {
                Interlocked.Decrement(ref current);
            }
        })).ToArray();
        using var cancellation = new CancellationTokenSource();
        var loop = new EnrollmentWorkerLoop(environments,
            (_, cancellationToken) => Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken),
            maximumConcurrency);

        var running = loop.RunAsync(cancellation.Token);
        await firstWaveStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(maximumConcurrency, Volatile.Read(ref started));
        release.TrySetResult();
        await everyEnvironmentStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => running);

        Assert.Equal(maximumConcurrency, maximum);
        Assert.Equal(environmentCount, started);
    }

    [Fact]
    public async Task CancellationEndsRunningProcessAndSemaphoreWaiter()
    {
        var runningStarted = Signal();
        var runningFinished = Signal();
        var waitingCalls = 0;
        var runningEnvironment = Environment(process: async cancellationToken =>
        {
            runningStarted.TrySetResult();
            try
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
                return EnrollmentWorkProcessOutcome.NoWork;
            }
            finally
            {
                runningFinished.TrySetResult();
            }
        });
        var waitingEnvironment = Environment(process: _ =>
        {
            Interlocked.Increment(ref waitingCalls);
            return Task.FromResult(EnrollmentWorkProcessOutcome.NoWork);
        });
        using var cancellation = new CancellationTokenSource();
        var loop = new EnrollmentWorkerLoop([runningEnvironment, waitingEnvironment],
            (_, cancellationToken) => Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken),
            maximumConcurrency: 1);

        var running = loop.RunAsync(cancellation.Token);
        await runningStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => running);

        Assert.True(runningFinished.Task.IsCompletedSuccessfully);
        Assert.Equal(0, waitingCalls);
    }

    [Fact]
    public async Task LaneFailureCancelsAndObservesSibling()
    {
        var sibling = BlockingEnvironment();
        var failure = new InvalidDataException("SyntheticLaneFailure");
        var failed = Environment(process: async _ =>
        {
            await sibling.Started.Task;
            throw failure;
        });
        var loop = new EnrollmentWorkerLoop([failed, sibling.Environment]);

        var thrown = await Assert.ThrowsAsync<InvalidDataException>(() => loop.RunAsync(CancellationToken.None));

        Assert.Same(failure, thrown);
        Assert.True(sibling.Finished.Task.IsCompletedSuccessfully);
    }

    [Fact]
    public async Task UndefinedOutcomeCancelsAndObservesSibling()
    {
        var sibling = BlockingEnvironment();
        var invalid = Environment(process: async _ =>
        {
            await sibling.Started.Task;
            return (EnrollmentWorkProcessOutcome)int.MaxValue;
        });
        var loop = new EnrollmentWorkerLoop([invalid, sibling.Environment]);

        await Assert.ThrowsAsync<InvalidOperationException>(() => loop.RunAsync(CancellationToken.None));
        Assert.True(sibling.Finished.Task.IsCompletedSuccessfully);
    }

    [Fact]
    public async Task CallerRetainsEnvironmentOwnership()
    {
        var blocking = BlockingEnvironment();
        var loop = new EnrollmentWorkerLoop([blocking.Environment]);
        using var cancellation = new CancellationTokenSource();

        var running = loop.RunAsync(cancellation.Token);
        await blocking.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => running);

        Assert.Equal(0, blocking.Environment.DisposeCount);
    }

    private static TestEnvironment Environment(
        Guid? identifier = null,
        Func<CancellationToken, Task<EnrollmentWorkProcessOutcome>>? process = null) =>
        new(identifier ?? Guid.NewGuid(), process ?? (_ => Task.FromResult(EnrollmentWorkProcessOutcome.NoWork)));

    private static BlockingFixture BlockingEnvironment()
    {
        var started = Signal();
        var finished = Signal();
        var environment = Environment(process: async cancellationToken =>
        {
            started.TrySetResult();
            try
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
                return EnrollmentWorkProcessOutcome.NoWork;
            }
            finally
            {
                finished.TrySetResult();
            }
        });
        return new BlockingFixture(environment, started, finished);
    }

    private static TaskCompletionSource Signal() =>
        new(TaskCreationOptions.RunContinuationsAsynchronously);

    private static void UpdateMaximum(ref int maximum, int candidate)
    {
        while (true)
        {
            var observed = Volatile.Read(ref maximum);
            if (observed >= candidate || Interlocked.CompareExchange(ref maximum, candidate, observed) == observed)
                return;
        }
    }

    private sealed record BlockingFixture(
        TestEnvironment Environment,
        TaskCompletionSource Started,
        TaskCompletionSource Finished);

    private sealed class TestEnvironment(
        Guid environmentId,
        Func<CancellationToken, Task<EnrollmentWorkProcessOutcome>> process) : IEnrollmentWorkerEnvironment
    {
        public Guid EnvironmentId { get; } = environmentId;
        public int DisposeCount { get; private set; }

        public Task<EnrollmentWorkProcessOutcome> ProcessOnceAsync(CancellationToken cancellationToken) =>
            process(cancellationToken);

        public ValueTask DisposeAsync()
        {
            DisposeCount++;
            return ValueTask.CompletedTask;
        }
    }
}
