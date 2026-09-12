using ItManagement.EnrollmentGrantExecution;

namespace ItManagement.EnrollmentWorker;

public sealed class EnrollmentWorkerLoop
{
    private static readonly TimeSpan FastPollDelay = TimeSpan.FromMilliseconds(100);
    private static readonly TimeSpan LeaseLostDelay = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan NoWorkDelay = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan InitialUnknownDelay = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan MaximumUnknownDelay = TimeSpan.FromSeconds(60);

    private readonly IEnrollmentWorkerEnvironment[] _environments;
    private readonly Func<TimeSpan, CancellationToken, Task> _delay;
    private readonly int _maximumConcurrency;
    private int _started;

    public EnrollmentWorkerLoop(
        IReadOnlyList<IEnrollmentWorkerEnvironment> environments,
        TimeProvider? timeProvider = null,
        int maximumConcurrency = 4)
        : this(environments, DelayWith(timeProvider ?? TimeProvider.System), maximumConcurrency) { }

    internal EnrollmentWorkerLoop(
        IReadOnlyList<IEnrollmentWorkerEnvironment> environments,
        Func<TimeSpan, CancellationToken, Task> delay,
        int maximumConcurrency = 4)
    {
        ArgumentNullException.ThrowIfNull(environments);
        ArgumentNullException.ThrowIfNull(delay);

        if (environments.Count is < 1 or > 32)
            throw new ArgumentOutOfRangeException(nameof(environments), "EnvironmentCountOutOfRange");
        if (maximumConcurrency is < 1 or > 8)
            throw new ArgumentOutOfRangeException(nameof(maximumConcurrency), "ConcurrencyOutOfRange");

        _environments = new IEnrollmentWorkerEnvironment[environments.Count];
        var identifiers = new HashSet<Guid>();
        for (var index = 0; index < environments.Count; index++)
        {
            var environment = environments[index]
                ?? throw new ArgumentException("NullEnvironment", nameof(environments));
            if (environment.EnvironmentId == Guid.Empty || !identifiers.Add(environment.EnvironmentId))
                throw new ArgumentException("InvalidOrDuplicateEnvironment", nameof(environments));
            _environments[index] = environment;
        }

        _delay = delay;
        _maximumConcurrency = maximumConcurrency;
    }

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        if (Interlocked.Exchange(ref _started, 1) != 0)
            throw new InvalidOperationException("EnrollmentWorkerLoopAlreadyStarted");

        cancellationToken.ThrowIfCancellationRequested();
        using var lanesCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        using var processGate = new SemaphoreSlim(_maximumConcurrency, _maximumConcurrency);
        var lanes = _environments
            .Select(environment => RunLaneAsync(environment, processGate, lanesCancellation))
            .ToArray();

        try
        {
            await Task.WhenAll(lanes).ConfigureAwait(false);
        }
        catch
        {
            CancelWithoutThrow(lanesCancellation);
            cancellationToken.ThrowIfCancellationRequested();
            throw;
        }
    }

    private async Task RunLaneAsync(
        IEnrollmentWorkerEnvironment environment,
        SemaphoreSlim processGate,
        CancellationTokenSource lanesCancellation)
    {
        var unknownDelay = InitialUnknownDelay;
        try
        {
            while (true)
            {
                await processGate.WaitAsync(lanesCancellation.Token).ConfigureAwait(false);
                EnrollmentWorkProcessOutcome outcome;
                try
                {
                    // A released permit can win the race with a queued waiter's cancellation.
                    lanesCancellation.Token.ThrowIfCancellationRequested();
                    outcome = await environment.ProcessOnceAsync(lanesCancellation.Token).ConfigureAwait(false);
                }
                finally
                {
                    processGate.Release();
                }
                TimeSpan delay;
                switch (outcome)
                {
                    case EnrollmentWorkProcessOutcome.Completed:
                    case EnrollmentWorkProcessOutcome.Deferred:
                        unknownDelay = InitialUnknownDelay;
                        delay = FastPollDelay;
                        break;
                    case EnrollmentWorkProcessOutcome.LeaseLost:
                        unknownDelay = InitialUnknownDelay;
                        delay = LeaseLostDelay;
                        break;
                    case EnrollmentWorkProcessOutcome.NoWork:
                        unknownDelay = InitialUnknownDelay;
                        delay = NoWorkDelay;
                        break;
                    case EnrollmentWorkProcessOutcome.OutcomeUnknown:
                        delay = unknownDelay;
                        unknownDelay = TimeSpan.FromSeconds(Math.Min(
                            MaximumUnknownDelay.TotalSeconds,
                            unknownDelay.TotalSeconds * 2));
                        break;
                    default:
                        throw new InvalidOperationException("UndefinedEnrollmentWorkProcessOutcome");
                }

                await _delay(delay, lanesCancellation.Token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (lanesCancellation.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            CancelWithoutThrow(lanesCancellation);
            throw;
        }
    }

    private static Func<TimeSpan, CancellationToken, Task> DelayWith(TimeProvider timeProvider) =>
        (delay, cancellationToken) => Task.Delay(delay, timeProvider, cancellationToken);

    private static void CancelWithoutThrow(CancellationTokenSource source)
    {
        try { source.Cancel(); }
        catch { }
    }
}
