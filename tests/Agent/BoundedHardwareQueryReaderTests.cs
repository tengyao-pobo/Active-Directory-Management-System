using System.Collections.Concurrent;
using ItManagement.Agent.Collectors;
using ItManagement.Agent.Inventory;

namespace ItManagement.Agent.Tests;

public sealed class BoundedHardwareQueryReaderTests
{
    [Fact]
    public async Task Timeout_keeps_gate_until_underlying_operation_returns()
    {
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var result = new TaskCompletionSource<HardwareQueryResult>(TaskCreationOptions.RunContinuationsAsynchronously);
        var finished = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var clock = new ManualClock();
        var calls = 0;
        var reader = new BoundedHardwareQueryReader(async (_, _) =>
        {
            Interlocked.Increment(ref calls);
            entered.TrySetResult();
            var value = await result.Task;
            finished.TrySetResult();
            return value;
        }, TimeSpan.FromSeconds(1), clock);
        var first = reader.ReadAsync(HardwareQueryKind.Bios, default).AsTask();
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            clock.Fire();
            await Assert.ThrowsAsync<TimeoutException>(() => first);
            await Assert.ThrowsAsync<InvalidOperationException>(() => reader.ReadAsync(HardwareQueryKind.Bios, default).AsTask());
            Assert.Equal(1, calls);
        }
        finally { result.TrySetResult(new(ObservationQuality.Observed, DateTimeOffset.UnixEpoch, [])); }
        await finished.Task.WaitAsync(TimeSpan.FromSeconds(5));
        // Observe eventual release, without assuming scheduling order between completion continuations.
        using var releaseDeadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        while (true)
        {
            releaseDeadline.Token.ThrowIfCancellationRequested();
            try { await reader.ReadAsync(HardwareQueryKind.Bios, releaseDeadline.Token); break; }
            catch (InvalidOperationException) { await Task.Yield(); }
        }
        Assert.Equal(2, calls);
    }

    [Fact]
    public async Task Cancellation_does_not_start_a_second_underlying_query()
    {
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var result = new TaskCompletionSource<HardwareQueryResult>(TaskCreationOptions.RunContinuationsAsynchronously);
        var reader = new BoundedHardwareQueryReader((_, _) => { entered.TrySetResult(); return result.Task; }, TimeSpan.FromSeconds(10));
        using var cts = new CancellationTokenSource();
        var first = reader.ReadAsync(HardwareQueryKind.Bios, cts.Token).AsTask();
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            cts.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => first);
            await Assert.ThrowsAsync<InvalidOperationException>(() => reader.ReadAsync(HardwareQueryKind.Bios, default).AsTask());
        }
        finally { result.TrySetResult(new(ObservationQuality.Observed, DateTimeOffset.UnixEpoch, [])); }
    }

    private sealed class ManualClock : TimeProvider
    {
        private readonly ConcurrentQueue<ManualTimer> _timers = new();
        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            var timer = new ManualTimer(callback, state);
            _timers.Enqueue(timer);
            return timer;
        }
        public void Fire() { while (_timers.TryDequeue(out var timer)) timer.Fire(); }
        private sealed class ManualTimer(TimerCallback callback, object? state) : ITimer
        {
            private volatile bool _disposed;
            public bool Change(TimeSpan dueTime, TimeSpan period) => !_disposed;
            public void Fire() { if (!_disposed) callback(state); }
            public void Dispose() => _disposed = true;
            public ValueTask DisposeAsync() { Dispose(); return ValueTask.CompletedTask; }
        }
    }
}
