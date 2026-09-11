using System.Text;
using ItManagement.Agent.Inventory;

namespace ItManagement.Agent.Collectors;

public sealed record CollectorRunnerOptions(
    TimeSpan PerCollectorTimeout,
    int MaxCollectorPayloadBytes,
    int MaxCollectors,
    int MaxCollectorItems = 10_000,
    int MaxMetadataLength = 256)
{
    private const int HardMaxCollectors = 1_024;
    public static CollectorRunnerOptions Default { get; } = new(
        TimeSpan.FromSeconds(30),
        256 * 1024,
        32);

    internal void Validate()
    {
        if (PerCollectorTimeout <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(PerCollectorTimeout));
        }

        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaxCollectorPayloadBytes);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaxCollectors);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaxCollectorItems);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaxMetadataLength);
        if (MaxCollectors > HardMaxCollectors)
        {
            throw new ArgumentOutOfRangeException(nameof(MaxCollectors));
        }
    }
}

public sealed class CollectorRunner
{
    private readonly CollectorRunnerOptions _options;
    private readonly TimeProvider _timeProvider;

    public CollectorRunner(CollectorRunnerOptions? options = null, TimeProvider? timeProvider = null)
    {
        _options = options ?? CollectorRunnerOptions.Default;
        _options.Validate();
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public async Task<InventorySnapshot> CollectAsync(
        IEnumerable<IInventoryCollector> collectors,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(collectors);

        var materialized = collectors.Take(_options.MaxCollectors + 1).ToArray();
        if (materialized.Length > _options.MaxCollectors)
        {
            throw new ArgumentOutOfRangeException(
                nameof(collectors),
                $"At most {_options.MaxCollectors} collectors are allowed.");
        }

        if (materialized.Any(static collector => collector is null))
        {
            throw new ArgumentException("Collector list cannot contain null entries.", nameof(collectors));
        }

        var collectedAt = _timeProvider.GetUtcNow();
        var tasks = materialized.Select(collector => RunOneAsync(collector, cancellationToken));
        var results = await Task.WhenAll(tasks).ConfigureAwait(false);
        return new InventorySnapshot(1, collectedAt, results);
    }

    private async Task<CollectorSnapshot> RunOneAsync(
        IInventoryCollector collector,
        CancellationToken cancellationToken)
    {
        var fallbackTime = _timeProvider.GetUtcNow();
        string collectorName;
        try
        {
            collectorName = BoundMetadata(collector.Name);
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            return FailedSnapshot("unknown", CollectorStatus.Failed, fallbackTime, "collector_failed");
        }

        using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(_options.PerCollectorTimeout);

        try
        {
            var payload = await collector.CollectAsync(timeoutSource.Token).AsTask()
                .WaitAsync(_options.PerCollectorTimeout, cancellationToken)
                .ConfigureAwait(false);
            if (payload.ItemCount < 0)
            {
                return FailedSnapshot(
                    collectorName,
                    CollectorStatus.Failed,
                    fallbackTime,
                    "invalid_output");
            }

            if (!Enum.IsDefined(payload.Quality))
            {
                return FailedSnapshot(
                    collectorName,
                    CollectorStatus.Failed,
                    fallbackTime,
                    "invalid_output");
            }

            var payloadBytes = Encoding.UTF8.GetByteCount(payload.Data.GetRawText());
            if (payloadBytes > _options.MaxCollectorPayloadBytes || payload.ItemCount > _options.MaxCollectorItems)
            {
                return FailedSnapshot(
                    collectorName,
                    CollectorStatus.OutputLimitExceeded,
                    fallbackTime,
                    "output_limit_exceeded");
            }

            return new CollectorSnapshot(
                collectorName,
                CollectorStatus.Completed,
                payload.Quality,
                BoundMetadata(payload.Source),
                payload.ObservedAt,
                payload.Data.Clone(),
                payload.ItemCount,
                null);
        }
        catch (TimeoutException)
        {
            timeoutSource.Cancel();
            return FailedSnapshot(collectorName, CollectorStatus.TimedOut, fallbackTime, "timeout");
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return FailedSnapshot(collectorName, CollectorStatus.TimedOut, fallbackTime, "timeout");
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            return FailedSnapshot(collectorName, CollectorStatus.Failed, fallbackTime, "collector_failed");
        }
    }

    private string BoundMetadata(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "unknown";
        }

        return value.Length <= _options.MaxMetadataLength ? value : value[.._options.MaxMetadataLength];
    }

    private static CollectorSnapshot FailedSnapshot(
        string collector,
        CollectorStatus status,
        DateTimeOffset observedAt,
        string errorCode) =>
        new(
            collector,
            status,
            ObservationQuality.Unknown,
            collector,
            observedAt,
            null,
            0,
            errorCode);
}
