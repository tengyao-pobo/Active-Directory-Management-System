using System.Collections.Frozen;
using System.Text.Json;
using ItManagement.Agent.Inventory;

namespace ItManagement.Agent.Collectors;

public static class BitLockerQueryCatalog
{
    public const string NamespacePath = @"root\cimv2\Security\MicrosoftVolumeEncryption";
    public const string ClassName = "Win32_EncryptableVolume";
    public const string Source = @"root\cimv2\Security\MicrosoftVolumeEncryption:Win32_EncryptableVolume";
    public static FrozenSet<string> Properties { get; } = new[]
    {
        "DeviceID", "PersistentVolumeID", "DriveLetter", "VolumeType", "ProtectionStatus",
        "ConversionStatus", "EncryptionMethod", "IsVolumeInitializedForProtection"
    }.ToFrozenSet(StringComparer.Ordinal);
}

public sealed record BitLockerVolume(
    string DeviceId,
    string? PersistentVolumeId,
    string? DriveLetter,
    uint? VolumeType,
    uint? ProtectionStatus,
    uint? ConversionStatus,
    uint? EncryptionMethod,
    bool? IsVolumeInitializedForProtection);

public sealed record BitLockerInventory(
    int SchemaVersion,
    IReadOnlyList<BitLockerVolume> Volumes,
    bool IsTruncated,
    string? ErrorCode);

public sealed record BitLockerQueryResult(
    ObservationQuality Quality,
    DateTimeOffset ObservedAt,
    IReadOnlyList<JsonElement> Rows,
    bool IsTruncated = false,
    string? ErrorCode = null);

public interface IBitLockerQueryReader
{
    ValueTask<BitLockerQueryResult> ReadAsync(CancellationToken cancellationToken);
}

public sealed class BitLockerCollector(IBitLockerQueryReader reader, TimeProvider? timeProvider = null) : IInventoryCollector
{
    public const int MaxVolumes = 128;
    public const int MaxIdentifierLength = 512;
    private static readonly FrozenSet<string> UnknownErrorCodes = new[]
    {
        "query_timeout", "query_unavailable", "native_query_busy", "invalid_output"
    }.ToFrozenSet(StringComparer.Ordinal);
    private readonly IBitLockerQueryReader _reader = reader ?? throw new ArgumentNullException(nameof(reader));
    private readonly TimeProvider _clock = timeProvider ?? TimeProvider.System;
    public string Name => "bitlocker";

    public async ValueTask<CollectorPayload> CollectAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            var read = await _reader.ReadAsync(cancellationToken).ConfigureAwait(false);
            return read.Quality switch
            {
                ObservationQuality.Observed when read.ErrorCode is null => Observed(read),
                ObservationQuality.AccessDenied => Failure(ObservationQuality.AccessDenied, read.ObservedAt, "access_denied"),
                ObservationQuality.Unknown when read.ErrorCode is not null && UnknownErrorCodes.Contains(read.ErrorCode) =>
                    Failure(ObservationQuality.Unknown, read.ObservedAt, read.ErrorCode),
                _ => Failure(ObservationQuality.Unknown, read.ObservedAt, "invalid_output")
            };
        }
        catch (UnauthorizedAccessException) { return Failure(ObservationQuality.AccessDenied, _clock.GetUtcNow(), "access_denied"); }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (TimeoutException) { return Failure(ObservationQuality.Unknown, _clock.GetUtcNow(), "query_timeout"); }
        catch (InvalidOperationException error) when (error.Message == "native_query_busy")
        { return Failure(ObservationQuality.Unknown, _clock.GetUtcNow(), "native_query_busy"); }
        catch (Exception) { return Failure(ObservationQuality.Unknown, _clock.GetUtcNow(), "query_unavailable"); }
    }

    private static CollectorPayload Observed(BitLockerQueryResult read)
    {
        var truncated = read.IsTruncated || read.Rows.Count > MaxVolumes;
        var volumes = new List<BitLockerVolume>(Math.Min(read.Rows.Count, MaxVolumes));
        var deviceIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var row in read.Rows.Take(MaxVolumes))
        {
            if (row.ValueKind != JsonValueKind.Object) { truncated = true; continue; }
            if (row.EnumerateObject().Any(property => !BitLockerQueryCatalog.Properties.Contains(property.Name))) truncated = true;
            var deviceId = RequiredIdentifier(row, "DeviceID", ref truncated);
            if (deviceId is null || !deviceIds.Add(deviceId)) { truncated = true; continue; }
            volumes.Add(new BitLockerVolume(
                deviceId,
                OptionalIdentifier(row, "PersistentVolumeID", ref truncated),
                DriveLetter(row, ref truncated),
                OptionalUInt32(row, "VolumeType", ref truncated),
                OptionalUInt32(row, "ProtectionStatus", ref truncated),
                OptionalUInt32(row, "ConversionStatus", ref truncated),
                OptionalUInt32(row, "EncryptionMethod", ref truncated),
                OptionalBoolean(row, "IsVolumeInitializedForProtection", ref truncated)));
        }
        var inventory = new BitLockerInventory(1, volumes.AsReadOnly(), truncated, null);
        return CollectorPayload.Create(ObservationQuality.Observed, BitLockerQueryCatalog.Source, read.ObservedAt, inventory, volumes.Count);
    }

    private static CollectorPayload Failure(ObservationQuality quality, DateTimeOffset observedAt, string errorCode) =>
        CollectorPayload.Create(quality, BitLockerQueryCatalog.Source, observedAt,
            new BitLockerInventory(1, [], false, errorCode), 0);

    private static string? RequiredIdentifier(JsonElement row, string name, ref bool truncated)
    {
        if (!row.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.String) { truncated = true; return null; }
        var text = value.GetString()!;
        if (string.IsNullOrWhiteSpace(text) || text.Length > MaxIdentifierLength || text.Any(char.IsControl))
        { truncated = true; return null; }
        return text;
    }

    private static string? OptionalIdentifier(JsonElement row, string name, ref bool truncated)
    {
        if (!row.TryGetProperty(name, out var value) || value.ValueKind == JsonValueKind.Null) return null;
        if (value.ValueKind != JsonValueKind.String) { truncated = true; return null; }
        var text = value.GetString()!;
        if (text.Length > MaxIdentifierLength || text.Any(char.IsControl)) { truncated = true; return null; }
        return text;
    }

    private static string? DriveLetter(JsonElement row, ref bool truncated)
    {
        var value = OptionalIdentifier(row, "DriveLetter", ref truncated);
        if (value is null || value.Length == 0) return null;
        if (value.Length != 2 || !char.IsAsciiLetter(value[0]) || value[1] != ':') { truncated = true; return null; }
        return string.Concat(char.ToUpperInvariant(value[0]), ':');
    }

    private static uint? OptionalUInt32(JsonElement row, string name, ref bool truncated)
    {
        if (!row.TryGetProperty(name, out var value) || value.ValueKind == JsonValueKind.Null) return null;
        if (value.ValueKind == JsonValueKind.Number && value.TryGetUInt32(out var number)) return number;
        truncated = true;
        return null;
    }

    private static bool? OptionalBoolean(JsonElement row, string name, ref bool truncated)
    {
        if (!row.TryGetProperty(name, out var value) || value.ValueKind == JsonValueKind.Null) return null;
        if (value.ValueKind is JsonValueKind.True or JsonValueKind.False) return value.GetBoolean();
        truncated = true;
        return null;
    }
}
