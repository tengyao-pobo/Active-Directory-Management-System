using System.Text.Json;

namespace ItManagement.Agent.Inventory;

public enum ObservationQuality
{
    Observed,
    Unknown,
    NotApplicable,
    AccessDenied
}

public sealed record Observation<T>(
    ObservationQuality Quality,
    string Source,
    DateTimeOffset ObservedAt,
    T? Value,
    string? Detail = null);

public enum CollectorStatus
{
    Completed,
    TimedOut,
    Failed,
    OutputLimitExceeded
}

public sealed record CollectorPayload(
    ObservationQuality Quality,
    string Source,
    DateTimeOffset ObservedAt,
    JsonElement Data,
    int ItemCount)
{
    public static CollectorPayload Create<T>(
        ObservationQuality quality,
        string source,
        DateTimeOffset observedAt,
        T data,
        int itemCount = 1,
        JsonSerializerOptions? serializerOptions = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(source);
        ArgumentOutOfRangeException.ThrowIfNegative(itemCount);

        return new CollectorPayload(
            quality,
            source,
            observedAt,
            JsonSerializer.SerializeToElement(data, serializerOptions),
            itemCount);
    }
}

public sealed record CollectorSnapshot(
    string Collector,
    CollectorStatus Status,
    ObservationQuality Quality,
    string Source,
    DateTimeOffset ObservedAt,
    JsonElement? Data,
    int ItemCount,
    string? ErrorCode);

public sealed record InventorySnapshot(
    int SchemaVersion,
    DateTimeOffset CollectedAt,
    IReadOnlyList<CollectorSnapshot> Collectors);
