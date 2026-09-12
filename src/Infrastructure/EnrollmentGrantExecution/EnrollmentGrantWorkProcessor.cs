namespace ItManagement.EnrollmentGrantExecution;

public enum EnrollmentWorkProcessOutcome { NoWork, Completed, Deferred, LeaseLost, OutcomeUnknown }

/// <summary>Processes one assignment. Scheduling claims never replace the executor's authorization checks.</summary>
public sealed class EnrollmentGrantWorkProcessor
{
    private static readonly TimeSpan MaximumAttempt = TimeSpan.FromSeconds(45);
    private static readonly TimeSpan TransitionTimeout = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan LeaseMargin = TimeSpan.FromSeconds(5);
    private readonly Guid _environment;
    private readonly IEnrollmentGrantWorkQueue _queue;
    private readonly IEnrollmentGrantExecutor _executor;
    private readonly TimeProvider _time;
    private readonly Func<Guid> _newToken;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private Guid? _pendingToken;

    public EnrollmentGrantWorkProcessor(Guid environment, IEnrollmentGrantWorkQueue queue,
        IEnrollmentGrantExecutor executor, TimeProvider? time = null)
        : this(environment, queue, executor, time ?? TimeProvider.System, Guid.NewGuid) { }

    internal EnrollmentGrantWorkProcessor(Guid environment, IEnrollmentGrantWorkQueue queue,
        IEnrollmentGrantExecutor executor, TimeProvider time, Func<Guid> newToken)
    {
        if (environment == Guid.Empty) throw new ArgumentException("InvalidEnvironment", nameof(environment));
        ArgumentNullException.ThrowIfNull(queue);
        ArgumentNullException.ThrowIfNull(executor);
        ArgumentNullException.ThrowIfNull(time);
        ArgumentNullException.ThrowIfNull(newToken);
        _environment = environment; _queue = queue; _executor = executor; _time = time; _newToken = newToken;
    }

    public async Task<EnrollmentWorkProcessOutcome> ProcessOnceAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try { return await ProcessCoreAsync(cancellationToken).ConfigureAwait(false); }
        finally { _gate.Release(); }
    }

    private async Task<EnrollmentWorkProcessOutcome> ProcessCoreAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var token = _pendingToken ?? _newToken();
        _pendingToken = token;
        if (token == Guid.Empty) { _pendingToken = null; return EnrollmentWorkProcessOutcome.OutcomeUnknown; }
        var started = _time.GetTimestamp();
        EnrollmentWorkClaimResult result;
        try { result = await _queue.ClaimNextAsync(token, cancellationToken).ConfigureAwait(false); }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch { return EnrollmentWorkProcessOutcome.OutcomeUnknown; }

        if (result.Outcome == EnrollmentWorkClaimOutcome.OutcomeUnknown) return EnrollmentWorkProcessOutcome.OutcomeUnknown;
        if (result.Outcome is not (EnrollmentWorkClaimOutcome.Claimed or EnrollmentWorkClaimOutcome.Existing))
        {
            if (result.Claim is not null || result.QueriedAt is not { } query ||
                !PostgresExecutionQueueCodec.Canonical(query) || !Enum.IsDefined(result.Outcome))
                return EnrollmentWorkProcessOutcome.OutcomeUnknown;
            _pendingToken = null;
            return result.Outcome is EnrollmentWorkClaimOutcome.NoWork or EnrollmentWorkClaimOutcome.AlreadyDeferred
                or EnrollmentWorkClaimOutcome.AlreadyCompleted ? EnrollmentWorkProcessOutcome.NoWork : EnrollmentWorkProcessOutcome.LeaseLost;
        }
        if (result.Claim is not { } claim || result.QueriedAt is not { } queriedAt ||
            !PostgresExecutionQueueCodec.ValidClaim(claim, _environment, token) || !PostgresExecutionQueueCodec.Canonical(queriedAt) ||
            queriedAt < claim.ClaimedAt || queriedAt >= claim.LeaseUntil)
            return EnrollmentWorkProcessOutcome.OutcomeUnknown;

        _pendingToken = null;
        // Subtract monotonic time spent obtaining the assignment, rather than trusting the host's wall clock.
        var available = claim.LeaseUntil - queriedAt - _time.GetElapsedTime(started) - LeaseMargin;
        if (available <= TimeSpan.Zero) return await DeferAsync(claim, cancellationToken).ConfigureAwait(false);
        var duration = available < MaximumAttempt ? available : MaximumAttempt;
        using var deadline = new CancellationTokenSource(duration, _time);
        using var attempt = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
        try
        {
            _ = await _executor.ExecuteAsync(_environment, claim.OperationId, attempt.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch { return await DeferAsync(claim, cancellationToken).ConfigureAwait(false); }

        // Only the database may decide that a durable execution state is terminal.
        EnrollmentWorkTransitionResult completed;
        try
        {
            using var finishDeadline = new CancellationTokenSource(TransitionTimeout, _time);
            using var finish = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, finishDeadline.Token);
            completed = await _queue.CompleteAsync(claim, finish.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch { return EnrollmentWorkProcessOutcome.OutcomeUnknown; }

        if (!ValidTransition(completed)) return EnrollmentWorkProcessOutcome.OutcomeUnknown;
        return completed.Outcome switch
        {
            EnrollmentWorkTransitionOutcome.Completed or EnrollmentWorkTransitionOutcome.AlreadyCompleted => EnrollmentWorkProcessOutcome.Completed,
            EnrollmentWorkTransitionOutcome.StaleClaim or EnrollmentWorkTransitionOutcome.TokenConflict or EnrollmentWorkTransitionOutcome.NotFound => EnrollmentWorkProcessOutcome.LeaseLost,
            EnrollmentWorkTransitionOutcome.NotTerminal => await DeferAsync(claim, cancellationToken).ConfigureAwait(false),
            _ => EnrollmentWorkProcessOutcome.OutcomeUnknown
        };
    }

    private async Task<EnrollmentWorkProcessOutcome> DeferAsync(EnrollmentWorkClaim claim, CancellationToken cancellationToken)
    {
        try
        {
            using var deadline = new CancellationTokenSource(TransitionTimeout, _time);
            using var deferred = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
            var result = await _queue.DeferAsync(claim, EnrollmentWorkRetryReason.OutcomeUnknown, deferred.Token).ConfigureAwait(false);
            if (!ValidTransition(result)) return EnrollmentWorkProcessOutcome.OutcomeUnknown;
            return result.Outcome switch
            {
                EnrollmentWorkTransitionOutcome.Completed or EnrollmentWorkTransitionOutcome.AlreadyCompleted => EnrollmentWorkProcessOutcome.Completed,
                EnrollmentWorkTransitionOutcome.Deferred or EnrollmentWorkTransitionOutcome.AlreadyDeferred => EnrollmentWorkProcessOutcome.Deferred,
                EnrollmentWorkTransitionOutcome.StaleClaim or EnrollmentWorkTransitionOutcome.TokenConflict or EnrollmentWorkTransitionOutcome.NotFound => EnrollmentWorkProcessOutcome.LeaseLost,
                _ => EnrollmentWorkProcessOutcome.OutcomeUnknown
            };
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch { return EnrollmentWorkProcessOutcome.OutcomeUnknown; }
    }

    private static bool ValidTransition(EnrollmentWorkTransitionResult result) =>
        result.QueriedAt is { } queried && PostgresExecutionQueueCodec.Canonical(queried) &&
        (result.Outcome is EnrollmentWorkTransitionOutcome.Deferred or EnrollmentWorkTransitionOutcome.AlreadyDeferred
            ? result.NextAttemptAt is { } next && PostgresExecutionQueueCodec.Canonical(next) &&
              next - queried <= TimeSpan.FromSeconds(300) && (result.Outcome != EnrollmentWorkTransitionOutcome.Deferred || next > queried)
            : result.NextAttemptAt is null);
}
