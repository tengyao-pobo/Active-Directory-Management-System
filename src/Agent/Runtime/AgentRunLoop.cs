using System.Text.Json;
using ItManagement.Agent.Collectors;
using ItManagement.Agent.Spool;

namespace ItManagement.Agent.Runtime;

public sealed class AgentRunLoop : IAgentRunLoop
{
    private readonly IReadOnlyList<IInventoryCollector> _collectors;
    private readonly CollectorRunner _collectorRunner;
    private readonly OfflineSpool _spool;
    private readonly IAgentTransport _transport;
    private readonly TimeProvider _timeProvider;
    private readonly IRuntimeJitterSource _jitter;
    private readonly AgentRuntimeOptions _options;
    private readonly string _agentVersion;
    private int _runStarted;

    public AgentRunLoop(
        IReadOnlyList<IInventoryCollector> collectors,
        CollectorRunner collectorRunner,
        OfflineSpool spool,
        IAgentTransport transport,
        string agentVersion,
        TimeProvider? timeProvider = null,
        IRuntimeJitterSource? jitter = null,
        AgentRuntimeOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(collectors);
        _collectorRunner = collectorRunner ?? throw new ArgumentNullException(nameof(collectorRunner));
        _spool = spool ?? throw new ArgumentNullException(nameof(spool));
        _transport = transport ?? throw new ArgumentNullException(nameof(transport));
        ArgumentException.ThrowIfNullOrWhiteSpace(agentVersion);
        _options = options ?? AgentRuntimeOptions.Default;
        _options.Validate();
        if (agentVersion.Length > _options.MaxAgentVersionLength)
        {
            throw new ArgumentOutOfRangeException(nameof(agentVersion));
        }

        _collectors = collectors.Take(_options.MaxCollectors + 1).ToArray();
        if (_collectors.Count > _options.MaxCollectors)
        {
            throw new ArgumentOutOfRangeException(nameof(collectors));
        }

        if (_collectors.Any(static collector => collector is null))
        {
            throw new ArgumentException("Collector list cannot contain null entries.", nameof(collectors));
        }

        _agentVersion = agentVersion;
        _timeProvider = timeProvider ?? TimeProvider.System;
        _jitter = jitter ?? new RandomRuntimeJitterSource();
    }

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        if (Interlocked.CompareExchange(ref _runStarted, 1, 0) != 0)
        {
            throw new InvalidOperationException("This agent run loop instance has already been started.");
        }

        var now = _timeProvider.GetUtcNow();
        var nextHeartbeat = now;
        var nextInventory = now;
        var nextDelivery = now;
        var retryAttempt = 0;

        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            now = _timeProvider.GetUtcNow();
            var pending = await _spool.ReadPendingAsync(cancellationToken).ConfigureAwait(false);

            if (pending.Count > 0 && now >= nextDelivery)
            {
                var delivery = await DeliverAsync(pending[0], cancellationToken).ConfigureAwait(false);
                if (delivery.Stop)
                {
                    return;
                }

                if (delivery.Accepted)
                {
                    retryAttempt = 0;
                    nextDelivery = now;
                    continue;
                }

                if (retryAttempt < int.MaxValue)
                {
                    retryAttempt++;
                }

                now = _timeProvider.GetUtcNow();
                nextDelivery = now + GetRetryDelay(retryAttempt, delivery.RetryAfter);
            }

            var enqueued = false;
            if (now >= nextHeartbeat)
            {
                enqueued |= await TryEnqueueHeartbeatAsync(now, cancellationToken).ConfigureAwait(false);
                nextHeartbeat = now + ApplyJitter(
                    _options.HeartbeatInterval,
                    _options.HeartbeatJitterFraction);
            }

            if (now >= nextInventory)
            {
                enqueued |= await TryEnqueueInventoryAsync(now, cancellationToken).ConfigureAwait(false);
                nextInventory = now + _options.InventoryInterval;
            }

            if (enqueued && pending.Count == 0)
            {
                nextDelivery = now;
                continue;
            }

            pending = await _spool.ReadPendingAsync(cancellationToken).ConfigureAwait(false);
            var wakeAt = nextHeartbeat < nextInventory ? nextHeartbeat : nextInventory;
            if (pending.Count > 0 && nextDelivery < wakeAt)
            {
                wakeAt = nextDelivery;
            }

            var delay = wakeAt - _timeProvider.GetUtcNow();
            if (delay > TimeSpan.Zero)
            {
                await Task.Delay(delay, _timeProvider, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private async Task<DeliveryDecision> DeliverAsync(
        SpoolEnvelope envelope,
        CancellationToken cancellationToken)
    {
        AgentTransportResult result;
        Task<AgentTransportResult>? sendTask = null;
        try
        {
            using var timeout = new CancellationTokenSource(_options.TransportTimeout, _timeProvider);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeout.Token);
            sendTask = _transport.SendAsync(envelope, linked.Token);
            result = await sendTask
                .WaitAsync(_options.TransportTimeout, _timeProvider, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            if (sendTask is { IsCompleted: false })
            {
                ObserveEventually(sendTask);
                return DeliveryDecision.Halt();
            }

            return DeliveryDecision.Retry();
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            if (sendTask is { IsCompleted: false })
            {
                ObserveEventually(sendTask);
            }

            throw;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return DeliveryDecision.Retry();
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            return DeliveryDecision.Retry();
        }

        if (result.DiagnosticCode == AgentTransportDiagnosticCode.AuthenticationFailed)
        {
            return DeliveryDecision.Halt();
        }

        if (!Enum.IsDefined(result.Outcome) ||
            !Enum.IsDefined(result.DiagnosticCode) ||
            !IsConsistent(result))
        {
            return DeliveryDecision.Halt();
        }

        switch (result.Outcome)
        {
            case AgentTransportOutcome.Accepted:
            case AgentTransportOutcome.AlreadyAccepted:
                if (!result.IsAuthenticatedChannel ||
                    result.Acknowledgement is null ||
                    result.DiagnosticCode != AgentTransportDiagnosticCode.None)
                {
                    return DeliveryDecision.Halt();
                }

                try
                {
                    await _spool.MarkDeliveredAsync(
                        envelope,
                        result.Acknowledgement,
                        cancellationToken).ConfigureAwait(false);
                    return DeliveryDecision.Success();
                }
                catch (EnvelopeAcknowledgementMismatchException)
                {
                    return DeliveryDecision.Halt();
                }
                catch (InvalidDataException)
                {
                    return DeliveryDecision.Halt();
                }

            case AgentTransportOutcome.PermanentRejected:
            case AgentTransportOutcome.IdentityConflict:
                return DeliveryDecision.Halt();

            case AgentTransportOutcome.Retryable:
                return DeliveryDecision.Retry(result.RetryAfter);

            case AgentTransportOutcome.Unknown:
                return DeliveryDecision.Retry();

            case AgentTransportOutcome.NotConfigured:
            default:
                return DeliveryDecision.Halt();
        }
    }

    private static void ObserveEventually(Task task)
    {
        _ = task.ContinueWith(
            static completed => _ = completed.Exception,
            CancellationToken.None,
            TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);
    }

    private static bool IsConsistent(AgentTransportResult result) =>
        result.Outcome switch
        {
            AgentTransportOutcome.Accepted or AgentTransportOutcome.AlreadyAccepted =>
                result.DiagnosticCode == AgentTransportDiagnosticCode.None,
            AgentTransportOutcome.Retryable or AgentTransportOutcome.Unknown =>
                result.DiagnosticCode is AgentTransportDiagnosticCode.None or
                    AgentTransportDiagnosticCode.Timeout or
                    AgentTransportDiagnosticCode.ConnectionUnavailable or
                    AgentTransportDiagnosticCode.ResponseUnavailable,
            AgentTransportOutcome.PermanentRejected =>
                result.DiagnosticCode == AgentTransportDiagnosticCode.ProtocolRejected,
            AgentTransportOutcome.IdentityConflict =>
                result.DiagnosticCode == AgentTransportDiagnosticCode.AuthenticationFailed,
            AgentTransportOutcome.NotConfigured =>
                result.DiagnosticCode == AgentTransportDiagnosticCode.ConnectionUnavailable,
            _ => false
        };

    private async Task<bool> TryEnqueueHeartbeatAsync(
        DateTimeOffset observedAt,
        CancellationToken cancellationToken)
    {
        var body = JsonSerializer.SerializeToElement(new AgentHeartbeatPayload(1, _agentVersion));
        return await TryEnqueueAsync(
            new AgentMessagePayload(1, AgentMessageKind.Heartbeat, body),
            observedAt,
            cancellationToken).ConfigureAwait(false);
    }

    private async Task<bool> TryEnqueueInventoryAsync(
        DateTimeOffset observedAt,
        CancellationToken cancellationToken)
    {
        var snapshot = await _collectorRunner.CollectAsync(_collectors, cancellationToken).ConfigureAwait(false);
        var body = JsonSerializer.SerializeToElement(snapshot);
        return await TryEnqueueAsync(
            new AgentMessagePayload(1, AgentMessageKind.InventorySnapshot, body),
            observedAt,
            cancellationToken).ConfigureAwait(false);
    }

    private async Task<bool> TryEnqueueAsync(
        AgentMessagePayload payload,
        DateTimeOffset observedAt,
        CancellationToken cancellationToken)
    {
        try
        {
            await _spool.EnqueueAsync(
                Guid.NewGuid(),
                observedAt,
                payload,
                cancellationToken).ConfigureAwait(false);
            return true;
        }
        catch (SpoolCapacityExceededException)
        {
            return false;
        }
    }

    private TimeSpan GetRetryDelay(int attempt, TimeSpan? retryAfter)
    {
        if (retryAfter is { } requested)
        {
            if (requested < _options.InitialRetryDelay)
            {
                return _options.InitialRetryDelay;
            }

            return requested < _options.MaxRetryDelay ? requested : _options.MaxRetryDelay;
        }

        var multiplier = Math.Pow(2, Math.Min(attempt - 1, 30));
        var ticks = Math.Min(_options.InitialRetryDelay.Ticks * multiplier, _options.MaxRetryDelay.Ticks);
        var jittered = ApplyJitter(TimeSpan.FromTicks((long)ticks), _options.RetryJitterFraction);
        return jittered < _options.MaxRetryDelay ? jittered : _options.MaxRetryDelay;
    }

    private TimeSpan ApplyJitter(TimeSpan interval, double fraction)
    {
        var unit = Math.Clamp(_jitter.NextUnitInterval(), 0, 1);
        if (!double.IsFinite(unit))
        {
            throw new InvalidOperationException("Jitter source returned a nonfinite value.");
        }

        var factor = 1 + (((unit * 2) - 1) * fraction);
        return TimeSpan.FromTicks(Math.Max(1, (long)(interval.Ticks * factor)));
    }

    private readonly record struct DeliveryDecision(bool Accepted, bool Stop, TimeSpan? RetryAfter)
    {
        public static DeliveryDecision Success() => new(true, false, null);

        public static DeliveryDecision Retry(TimeSpan? retryAfter = null) => new(false, false, retryAfter);

        public static DeliveryDecision Halt() => new(false, true, null);
    }
}
