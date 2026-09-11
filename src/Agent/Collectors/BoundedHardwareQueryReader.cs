namespace ItManagement.Agent.Collectors;

/// <summary>One underlying query per instance, including after timeout or cancellation.</summary>
public sealed class BoundedHardwareQueryReader : IHardwareQueryReader
{
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly Func<HardwareQueryKind, CancellationToken, Task<HardwareQueryResult>> _query;
    private readonly TimeSpan _timeout;
    private readonly TimeProvider _clock;

    public BoundedHardwareQueryReader(Func<HardwareQueryKind, CancellationToken, Task<HardwareQueryResult>> query,
        TimeSpan timeout, TimeProvider? clock = null)
    {
        _query = query ?? throw new ArgumentNullException(nameof(query));
        if (timeout <= TimeSpan.Zero || timeout > TimeSpan.FromSeconds(10)) throw new ArgumentOutOfRangeException(nameof(timeout));
        _timeout = timeout;
        _clock = clock ?? TimeProvider.System;
    }

    public async ValueTask<HardwareQueryResult> ReadAsync(HardwareQueryKind kind, CancellationToken cancellationToken)
    {
        _ = HardwareQueryCatalog.Get(kind);
        cancellationToken.ThrowIfCancellationRequested();
        if (!await _gate.WaitAsync(0, cancellationToken)) throw new InvalidOperationException("native_query_busy");
        var operation = Task.Run(async () =>
        {
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                return await _query(kind, cancellationToken);
            }
            finally { _gate.Release(); }
        }, CancellationToken.None);
        try { return await operation.WaitAsync(_timeout, _clock, cancellationToken); }
        catch
        {
            _ = operation.ContinueWith(t => _ = t.Exception, CancellationToken.None,
                TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            throw;
        }
    }
}

public static class HardwareFailureClassifier
{
    // WBEM_E_ACCESS_DENIED and standard E_ACCESSDENIED, respectively.
    public static bool IsAccessDenied(int nativeCode) => nativeCode is unchecked((int)0x80041003) or unchecked((int)0x80070005);
}
