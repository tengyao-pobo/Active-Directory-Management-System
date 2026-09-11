using ItManagement.Agent.Collectors;
using ItManagement.Agent.Inventory;
using ItManagement.Agent.Runtime;
using ItManagement.Agent.Spool;

namespace ItManagement.Agent.Tests;

public sealed class AgentRunLoopTests
{
    [Fact]
    public async Task RunAsync_DeletesOnlyAfterAuthenticatedFullyBoundAcknowledgement()
    {
        using var directory = new TemporaryDirectory();
        await using var spool = await OfflineSpool.OpenAsync(directory.Path, 1);
        var queued = await EnqueueTestPayloadAsync(spool);
        var secondSend = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var transport = new ScriptedTransport(async (envelope, call, cancellationToken) =>
        {
            if (call == 1)
            {
                return Accept(envelope);
            }

            secondSend.TrySetResult();
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            throw new InvalidOperationException("unreachable");
        });
        using var cancellation = new CancellationTokenSource();
        var runTask = CreateRuntime(spool, transport).RunAsync(cancellation.Token);

        try
        {
            await secondSend.Task.WaitAsync(TimeSpan.FromSeconds(30));
            Assert.DoesNotContain(await spool.ReadPendingAsync(), item => item.Sequence == queued.Sequence);
        }
        finally
        {
            // Even a failed assertion/slow CI runner must finish the writer before disposing its spool.
            cancellation.Cancel();
            try { await runTask; }
            catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { }
        }
        Assert.True(runTask.IsCanceled);
    }

    [Fact]
    public async Task RunAsync_RetainsAndStopsOnAcknowledgementMismatch()
    {
        using var directory = new TemporaryDirectory();
        await using var spool = await OfflineSpool.OpenAsync(directory.Path, 1);
        var queued = await EnqueueTestPayloadAsync(spool);
        var transport = new ScriptedTransport((envelope, _, _) => Task.FromResult(
            AgentTransportResult.AcceptedFromAuthenticatedChannel(
                Acknowledge(envelope) with { RequestId = Guid.NewGuid() })));

        await CreateRuntime(spool, transport).RunAsync(CancellationToken.None);

        AssertEnvelopeEqual(queued, Assert.Single(await spool.ReadPendingAsync()));
    }

    [Theory]
    [InlineData(AgentTransportOutcome.PermanentRejected)]
    [InlineData(AgentTransportOutcome.IdentityConflict)]
    public async Task RunAsync_RetainsAndStopsOnPermanentOutcome(AgentTransportOutcome outcome)
    {
        using var directory = new TemporaryDirectory();
        await using var spool = await OfflineSpool.OpenAsync(directory.Path, 1);
        var queued = await EnqueueTestPayloadAsync(spool);
        var transport = new ScriptedTransport((_, _, _) => Task.FromResult(
            outcome == AgentTransportOutcome.PermanentRejected
                ? AgentTransportResult.PermanentRejected()
                : AgentTransportResult.IdentityConflict()));

        await CreateRuntime(spool, transport).RunAsync(CancellationToken.None);

        AssertEnvelopeEqual(queued, Assert.Single(await spool.ReadPendingAsync()));
    }

    [Fact]
    public async Task RunAsync_AuthenticationFailureHaltsDespiteRetryableOutcome()
    {
        using var directory = new TemporaryDirectory();
        await using var spool = await OfflineSpool.OpenAsync(directory.Path, 1);
        var queued = await EnqueueTestPayloadAsync(spool);
        var transport = new ScriptedTransport((_, _, _) => Task.FromResult(
            AgentTransportResult.Retryable(
                diagnosticCode: AgentTransportDiagnosticCode.AuthenticationFailed)));

        await CreateRuntime(spool, transport).RunAsync(CancellationToken.None);

        AssertEnvelopeEqual(queued, Assert.Single(await spool.ReadPendingAsync()));
    }

    [Fact]
    public async Task RunAsync_RetriesTheExactEnvelopeAfterResponseLoss()
    {
        using var directory = new TemporaryDirectory();
        await using var spool = await OfflineSpool.OpenAsync(directory.Path, 1);
        var queued = await EnqueueTestPayloadAsync(spool);
        var thirdSend = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var transport = new ScriptedTransport(async (envelope, call, cancellationToken) =>
        {
            if (call == 1)
            {
                return AgentTransportResult.Unknown();
            }

            if (call == 2)
            {
                return Accept(envelope, AgentTransportOutcome.AlreadyAccepted);
            }

            thirdSend.TrySetResult();
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            throw new InvalidOperationException("unreachable");
        });
        using var cancellation = new CancellationTokenSource();
        var runTask = CreateRuntime(spool, transport).RunAsync(cancellation.Token);

        await thirdSend.Task.WaitAsync(TimeSpan.FromSeconds(2));
        AssertEnvelopeEqual(queued, transport.Sent[0]);
        AssertEnvelopeEqual(queued, transport.Sent[1]);
        Assert.DoesNotContain(await spool.ReadPendingAsync(), item => item.Sequence == queued.Sequence);
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => runTask);
    }

    [Fact]
    public async Task RunAsync_NotConfiguredTransportRetainsQueueAndHalts()
    {
        using var directory = new TemporaryDirectory();
        await using var spool = await OfflineSpool.OpenAsync(directory.Path, 1);
        var queued = await EnqueueTestPayloadAsync(spool);
        await CreateRuntime(spool, new NotConfiguredAgentTransport()).RunAsync(CancellationToken.None);

        AssertEnvelopeEqual(queued, (await spool.ReadPendingAsync()).First(item => item.Sequence == queued.Sequence));
    }

    [Fact]
    public async Task RunAsync_QueueFullAppliesBackpressureWithoutOverwriting()
    {
        using var directory = new TemporaryDirectory();
        var spoolOptions = new OfflineSpoolOptions(1, 100_000, 10_000);
        await using var spool = await OfflineSpool.OpenAsync(directory.Path, 1, spoolOptions);
        var queued = await EnqueueTestPayloadAsync(spool);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(50));

        var transport = new ScriptedTransport((_, _, _) => Task.FromResult(AgentTransportResult.Retryable()));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            CreateRuntime(spool, transport).RunAsync(cancellation.Token));

        AssertEnvelopeEqual(queued, Assert.Single(await spool.ReadPendingAsync()));
    }

    [Fact]
    public async Task RunAsync_NeverStartsConcurrentTransportSends()
    {
        using var directory = new TemporaryDirectory();
        await using var spool = await OfflineSpool.OpenAsync(directory.Path, 1);
        await EnqueueTestPayloadAsync(spool);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
        var transport = new ConcurrencyTrackingTransport();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            CreateRuntime(spool, transport).RunAsync(cancellation.Token));

        Assert.Equal(1, transport.MaximumConcurrency);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RunAsync_BoundsJitteredBackoffAndRetryAfter(bool useShortRetryAfter)
    {
        using var directory = new TemporaryDirectory();
        await using var spool = await OfflineSpool.OpenAsync(directory.Path, 1);
        await EnqueueTestPayloadAsync(spool);
        var timeProvider = new ManualTimeProvider(optionsTransportTimeout: TimeSpan.FromSeconds(1));
        var transport = new ScriptedTransport((_, _, _) => Task.FromResult(
            AgentTransportResult.Retryable(
                useShortRetryAfter ? TimeSpan.FromMilliseconds(1) : null)));
        var options = CreateOptions() with
        {
            InitialRetryDelay = TimeSpan.FromMilliseconds(20),
            MaxRetryDelay = TimeSpan.FromMilliseconds(20),
            RetryJitterFraction = 0.5
        };
        using var cancellation = new CancellationTokenSource();

        var runTask = new AgentRunLoop(
            [new CountingCollector()],
            new CollectorRunner(),
            spool,
            transport,
            "1.2.3",
            timeProvider,
            new FixedJitter(1),
            options).RunAsync(cancellation.Token);

        var retryDelay = await timeProvider.RetryDelayScheduled.Task.WaitAsync(TimeSpan.FromSeconds(2));
        Assert.Equal(options.MaxRetryDelay, retryDelay);
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => runTask);
    }

    [Fact]
    public async Task RunAsync_NonCooperativeTransportTimeoutRetainsQueueAndHalts()
    {
        using var directory = new TemporaryDirectory();
        await using var spool = await OfflineSpool.OpenAsync(directory.Path, 1);
        var queued = await EnqueueTestPayloadAsync(spool);
        var neverCompletes = new TaskCompletionSource<AgentTransportResult>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var transport = new ScriptedTransport((_, _, _) => neverCompletes.Task);
        var runtime = CreateRuntime(
            spool,
            transport,
            options: CreateOptions() with { TransportTimeout = TimeSpan.FromMilliseconds(20) });

        await runtime.RunAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(2));

        Assert.Single(transport.Sent);
        AssertEnvelopeEqual(queued, Assert.Single(await spool.ReadPendingAsync()));
    }

    [Fact]
    public async Task RunAsync_CallerCancellationObservesNonCooperativeOutstandingSend()
    {
        using var directory = new TemporaryDirectory();
        await using var spool = await OfflineSpool.OpenAsync(directory.Path, 1);
        var queued = await EnqueueTestPayloadAsync(spool);
        var sendStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var neverCompletes = new TaskCompletionSource<AgentTransportResult>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var transport = new ScriptedTransport((_, _, _) =>
        {
            sendStarted.TrySetResult();
            return neverCompletes.Task;
        });
        using var cancellation = new CancellationTokenSource();
        var runTask = CreateRuntime(spool, transport).RunAsync(cancellation.Token);
        await sendStarted.Task.WaitAsync(TimeSpan.FromSeconds(2));

        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => runTask);
        Assert.Single(transport.Sent);
        AssertEnvelopeEqual(queued, Assert.Single(await spool.ReadPendingAsync()));
    }

    [Fact]
    public async Task RunAsync_RejectsASecondInvocationOnTheSameInstance()
    {
        using var directory = new TemporaryDirectory();
        await using var spool = await OfflineSpool.OpenAsync(directory.Path, 1);
        await EnqueueTestPayloadAsync(spool);
        var sendStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var transport = new ScriptedTransport(async (_, _, cancellationToken) =>
        {
            sendStarted.TrySetResult();
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            throw new InvalidOperationException("unreachable");
        });
        var runtime = CreateRuntime(spool, transport);
        using var cancellation = new CancellationTokenSource();
        var firstRun = runtime.RunAsync(cancellation.Token);
        await sendStarted.Task.WaitAsync(TimeSpan.FromSeconds(2));

        await Assert.ThrowsAsync<InvalidOperationException>(() => runtime.RunAsync(CancellationToken.None));

        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => firstRun);
    }

    [Fact]
    public async Task RunAsync_HeartbeatContainsNoHostOrUserInventory()
    {
        using var directory = new TemporaryDirectory();
        await using var spool = await OfflineSpool.OpenAsync(directory.Path, 1);
        var transport = new ScriptedTransport((_, _, _) => Task.FromResult(
            AgentTransportResult.PermanentRejected()));

        await CreateRuntime(spool, transport).RunAsync(CancellationToken.None);

        var heartbeat = transport.Sent[0].Payload;
        Assert.Equal((int)AgentMessageKind.Heartbeat, heartbeat.GetProperty("kind").GetInt32());
        var body = heartbeat.GetProperty("body").GetRawText();
        Assert.Contains("AgentVersion", body, StringComparison.Ordinal);
        Assert.DoesNotContain("host", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("user", body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Constructor_DoesNotCollectOrSend()
    {
        using var directory = new TemporaryDirectory();
        await using var spool = await OfflineSpool.OpenAsync(directory.Path, 1);
        var collector = new CountingCollector();
        var transport = new ScriptedTransport((_, _, _) => throw new InvalidOperationException());

        _ = CreateRuntime(spool, transport, collector);

        Assert.Equal(0, collector.CallCount);
        Assert.Empty(transport.Sent);
    }

    [Fact]
    public async Task Constructor_BoundsFixedCollectorMaterialization()
    {
        using var directory = new TemporaryDirectory();
        await using var spool = await OfflineSpool.OpenAsync(directory.Path, 1);
        var collectors = new IInventoryCollector[] { new CountingCollector(), new CountingCollector() };

        Assert.Throws<ArgumentOutOfRangeException>(() => new AgentRunLoop(
            collectors,
            new CollectorRunner(),
            spool,
            new NotConfiguredAgentTransport(),
            "1.0",
            options: CreateOptions() with { MaxCollectors = 1 }));
    }

    [Fact]
    public async Task Constructor_RejectsNonFiniteJitter()
    {
        using var directory = new TemporaryDirectory();
        await using var spool = await OfflineSpool.OpenAsync(directory.Path, 1);

        Assert.Throws<ArgumentOutOfRangeException>(() => CreateRuntime(
            spool,
            new NotConfiguredAgentTransport(),
            options: CreateOptions() with { RetryJitterFraction = double.NaN }));
    }

    private static AgentRunLoop CreateRuntime(
        OfflineSpool spool,
        IAgentTransport transport,
        IInventoryCollector? collector = null,
        AgentRuntimeOptions? options = null) =>
        new(
            [collector ?? new CountingCollector()],
            new CollectorRunner(new CollectorRunnerOptions(TimeSpan.FromSeconds(1), 100_000, 4)),
            spool,
            transport,
            "1.2.3",
            TimeProvider.System,
            new FixedJitter(),
            options ?? CreateOptions());

    private static AgentRuntimeOptions CreateOptions() =>
        new(
            TimeSpan.FromHours(1),
            TimeSpan.FromHours(1),
            0,
            TimeSpan.FromSeconds(1),
            TimeSpan.FromMilliseconds(5),
            TimeSpan.FromMilliseconds(20),
            0,
            32);

    private static Task<SpoolEnvelope> EnqueueTestPayloadAsync(OfflineSpool spool) =>
        spool.EnqueueAsync(Guid.NewGuid(), DateTimeOffset.UnixEpoch, new { kind = "test" });

    private static AgentTransportResult Accept(
        SpoolEnvelope envelope,
        AgentTransportOutcome outcome = AgentTransportOutcome.Accepted) =>
        AgentTransportResult.AcceptedFromAuthenticatedChannel(
            Acknowledge(envelope),
            alreadyAccepted: outcome == AgentTransportOutcome.AlreadyAccepted);

    private static EnvelopeAcknowledgement Acknowledge(SpoolEnvelope envelope) =>
        new(
            1,
            envelope.ProtocolVersion,
            envelope.DeviceGuid,
            envelope.RegistrationEpoch,
            envelope.Sequence,
            envelope.RequestId,
            envelope.ObservedAt,
            envelope.PayloadHash,
            envelope.EnvelopeHash);

    private static void AssertEnvelopeEqual(SpoolEnvelope expected, SpoolEnvelope actual)
    {
        Assert.Equal(expected.ProtocolVersion, actual.ProtocolVersion);
        Assert.Equal(expected.DeviceGuid, actual.DeviceGuid);
        Assert.Equal(expected.RegistrationEpoch, actual.RegistrationEpoch);
        Assert.Equal(expected.Sequence, actual.Sequence);
        Assert.Equal(expected.RequestId, actual.RequestId);
        Assert.Equal(expected.ObservedAt, actual.ObservedAt);
        Assert.Equal(expected.PayloadHash, actual.PayloadHash);
        Assert.Equal(expected.EnvelopeHash, actual.EnvelopeHash);
        Assert.Equal(expected.Payload.GetRawText(), actual.Payload.GetRawText());
    }

    private sealed class FixedJitter(double value = 0.5) : IRuntimeJitterSource
    {
        public double NextUnitInterval() => value;
    }

    private sealed class ManualTimeProvider(TimeSpan optionsTransportTimeout) : TimeProvider
    {
        public TaskCompletionSource<TimeSpan> RetryDelayScheduled { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public override DateTimeOffset GetUtcNow() => DateTimeOffset.UnixEpoch;

        public override ITimer CreateTimer(
            TimerCallback callback,
            object? state,
            TimeSpan dueTime,
            TimeSpan period)
        {
            if (dueTime < optionsTransportTimeout)
            {
                RetryDelayScheduled.TrySetResult(dueTime);
            }

            return new ManualTimer();
        }

        private sealed class ManualTimer : ITimer
        {
            public bool Change(TimeSpan dueTime, TimeSpan period) => true;

            public void Dispose()
            {
            }

            public ValueTask DisposeAsync() => ValueTask.CompletedTask;
        }
    }

    private sealed class CountingCollector : IInventoryCollector
    {
        public int CallCount { get; private set; }

        public string Name => "fake";

        public ValueTask<CollectorPayload> CollectAsync(CancellationToken cancellationToken)
        {
            CallCount++;
            return ValueTask.FromResult(CollectorPayload.Create(
                ObservationQuality.Observed,
                "fake",
                DateTimeOffset.UnixEpoch,
                new { value = 1 }));
        }
    }

    private sealed class ScriptedTransport(
        Func<SpoolEnvelope, int, CancellationToken, Task<AgentTransportResult>> send) : IAgentTransport
    {
        public List<SpoolEnvelope> Sent { get; } = [];

        public Task<AgentTransportResult> SendAsync(
            SpoolEnvelope envelope,
            CancellationToken cancellationToken)
        {
            Sent.Add(envelope);
            return send(envelope, Sent.Count, cancellationToken);
        }
    }

    private sealed class ConcurrencyTrackingTransport : IAgentTransport
    {
        private int _concurrency;

        public int MaximumConcurrency { get; private set; }

        public async Task<AgentTransportResult> SendAsync(
            SpoolEnvelope envelope,
            CancellationToken cancellationToken)
        {
            var concurrency = Interlocked.Increment(ref _concurrency);
            MaximumConcurrency = Math.Max(MaximumConcurrency, concurrency);
            try
            {
                await Task.Delay(TimeSpan.FromMilliseconds(10), cancellationToken);
                return AgentTransportResult.Retryable();
            }
            finally
            {
                Interlocked.Decrement(ref _concurrency);
            }
        }
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        public TemporaryDirectory()
        {
            Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"agent-runtime-tests-{Guid.NewGuid():N}");
            Directory.CreateDirectory(Path);
        }

        public string Path { get; }

        public void Dispose()
        {
            if (Directory.Exists(Path))
            {
                Directory.Delete(Path, recursive: true);
            }
        }
    }
}
