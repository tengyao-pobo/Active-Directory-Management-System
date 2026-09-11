namespace ItManagement.Agent.Collectors;

/// <summary>Allows one underlying native query per instance, including after caller timeout or cancellation.</summary>
public sealed class BoundedBitLockerQueryReader : IBitLockerQueryReader
{
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly Func<CancellationToken, Task<BitLockerQueryResult>> _query;
    private readonly TimeSpan _timeout;
    private readonly TimeProvider _clock;

    public BoundedBitLockerQueryReader(
        Func<CancellationToken, Task<BitLockerQueryResult>> query,
        TimeSpan timeout,
        TimeProvider? clock = null)
    {
        _query = query ?? throw new ArgumentNullException(nameof(query));
        if (timeout <= TimeSpan.Zero || timeout > TimeSpan.FromSeconds(10)) throw new ArgumentOutOfRangeException(nameof(timeout));
        _timeout = timeout;
        _clock = clock ?? TimeProvider.System;
    }

    public async ValueTask<BitLockerQueryResult> ReadAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!await _gate.WaitAsync(0, cancellationToken).ConfigureAwait(false)) throw new InvalidOperationException("native_query_busy");
        var operation = Task.Run(async () =>
        {
            try { return await _query(cancellationToken).ConfigureAwait(false); }
            finally { _gate.Release(); }
        }, CancellationToken.None);
        try { return await operation.WaitAsync(_timeout, _clock, cancellationToken).ConfigureAwait(false); }
        catch
        {
            _ = operation.ContinueWith(task => _ = task.Exception, CancellationToken.None,
                TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            throw;
        }
    }
}
