using System.Collections.Frozen;
using System.Text.Json;
using ItManagement.Agent.Inventory;

namespace ItManagement.Agent.Collectors;

public enum HardwareQueryKind { System, Product, Bios, OperatingSystem, Processor, Memory, Video, Disk, Battery }
public sealed record HardwareQueryDefinition(string ClassName, FrozenSet<string> Properties, bool Optional);
public static class HardwareQueryCatalog
{
    private static HardwareQueryDefinition Define(string name, bool optional, params string[] properties) => new(name, properties.ToFrozenSet(StringComparer.Ordinal), optional);
    private static readonly FrozenDictionary<HardwareQueryKind, HardwareQueryDefinition> Queries = new Dictionary<HardwareQueryKind, HardwareQueryDefinition>
    {
        [HardwareQueryKind.System] = Define("Win32_ComputerSystem", false, "Manufacturer", "Model", "TotalPhysicalMemory"),
        [HardwareQueryKind.Product] = Define("Win32_ComputerSystemProduct", false, "UUID"),
        [HardwareQueryKind.Bios] = Define("Win32_BIOS", false, "Manufacturer", "SerialNumber", "SMBIOSBIOSVersion", "ReleaseDate"),
        [HardwareQueryKind.OperatingSystem] = Define("Win32_OperatingSystem", false, "Caption", "Version", "BuildNumber", "InstallDate", "LastBootUpTime"),
        [HardwareQueryKind.Processor] = Define("Win32_Processor", false, "Name", "Manufacturer", "NumberOfCores", "NumberOfLogicalProcessors"),
        [HardwareQueryKind.Memory] = Define("Win32_PhysicalMemory", false, "BankLabel", "DeviceLocator", "Capacity", "Speed"),
        [HardwareQueryKind.Video] = Define("Win32_VideoController", true, "Name", "AdapterRAM"),
        [HardwareQueryKind.Disk] = Define("Win32_DiskDrive", false, "Model", "SerialNumber", "Size", "MediaType"),
        [HardwareQueryKind.Battery] = Define("Win32_Battery", true, "Name", "EstimatedChargeRemaining", "DesignCapacity", "FullChargeCapacity")
    }.ToFrozenDictionary();
    public static HardwareQueryDefinition Get(HardwareQueryKind kind) => Queries.TryGetValue(kind, out var value) ? value : throw new ArgumentOutOfRangeException(nameof(kind));
}

public sealed record HardwareQueryResult(ObservationQuality Quality, DateTimeOffset ObservedAt, IReadOnlyList<JsonElement> Rows, bool IsTruncated = false);
public interface IHardwareQueryReader
{
    ValueTask<HardwareQueryResult> ReadAsync(HardwareQueryKind kind, CancellationToken cancellationToken);
}
public sealed record HardwareSection(HardwareQueryKind Kind, string Source, ObservationQuality Quality,
    DateTimeOffset ObservedAt, IReadOnlyList<JsonElement> Rows, bool IsTruncated, string? ErrorCode);
public sealed record HardwareInventory(int SchemaVersion, IReadOnlyList<HardwareSection> Sections);

public sealed class HardwareCollector(IHardwareQueryReader reader, TimeProvider? timeProvider = null) : IInventoryCollector
{
    public const int MaxRowsPerQuery = 128;
    public const int MaxStringLength = 512;
    private readonly TimeProvider _clock = timeProvider ?? TimeProvider.System;
    private readonly IHardwareQueryReader _reader = reader ?? throw new ArgumentNullException(nameof(reader));
    public string Name => "hardware";

    public async ValueTask<CollectorPayload> CollectAsync(CancellationToken cancellationToken)
    {
        var sections = new List<HardwareSection>();
        foreach (var kind in Enum.GetValues<HardwareQueryKind>())
        {
            cancellationToken.ThrowIfCancellationRequested();
            var definition = HardwareQueryCatalog.Get(kind);
            try
            {
                var read = await _reader.ReadAsync(kind, cancellationToken);
                if (!Enum.IsDefined(read.Quality)) throw new InvalidDataException();
                var truncated = read.IsTruncated || read.Rows.Count > MaxRowsPerQuery;
                var rows = new List<JsonElement>();
                foreach (var row in read.Rows.Take(MaxRowsPerQuery))
                {
                    if (row.ValueKind != JsonValueKind.Object) throw new InvalidDataException();
                    var filtered = new Dictionary<string, object?>();
                    foreach (var property in definition.Properties)
                    {
                        if (!row.TryGetProperty(property, out var value) || value.ValueKind == JsonValueKind.Null) { filtered[property] = null; continue; }
                        if (value.ValueKind == JsonValueKind.String)
                        {
                            var text = value.GetString()!;
                            truncated |= text.Length > MaxStringLength;
                            filtered[property] = string.IsNullOrWhiteSpace(text) ? null : text[..Math.Min(text.Length, MaxStringLength)];
                        }
                        else if (value.ValueKind == JsonValueKind.Number && value.TryGetUInt64(out var number)) filtered[property] = number;
                        else if (value.ValueKind is JsonValueKind.True or JsonValueKind.False) filtered[property] = value.GetBoolean();
                        else filtered[property] = null;
                    }
                    if (filtered.Values.Any(value => value is not null)) rows.Add(JsonSerializer.SerializeToElement(filtered));
                    else truncated = true;
                }
                var quality = read.Quality;
                if (quality == ObservationQuality.Observed && rows.Count == 0)
                    quality = definition.Optional && read.Rows.Count == 0 && !truncated ? ObservationQuality.NotApplicable : ObservationQuality.Unknown;
                // Unavailable/error sources cannot carry apparently usable values.
                if (quality != ObservationQuality.Observed) rows.Clear();
                sections.Add(new(kind, definition.ClassName, quality, read.ObservedAt, rows.AsReadOnly(), truncated, null));
            }
            catch (UnauthorizedAccessException) { sections.Add(Failed(kind, definition, ObservationQuality.AccessDenied, "access_denied")); }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (TimeoutException) { sections.Add(Failed(kind, definition, ObservationQuality.Unknown, "query_timeout")); }
            catch (Exception) { sections.Add(Failed(kind, definition, ObservationQuality.Unknown, "query_unavailable")); }
        }
        return CollectorPayload.Create(sections.Any(s => s.Quality == ObservationQuality.Observed) ? ObservationQuality.Observed : ObservationQuality.Unknown,
            Name, _clock.GetUtcNow(), new HardwareInventory(1, sections.AsReadOnly()), sections.Sum(s => s.Rows.Count));
    }

    private HardwareSection Failed(HardwareQueryKind kind, HardwareQueryDefinition definition, ObservationQuality quality, string code) =>
        new(kind, definition.ClassName, quality, _clock.GetUtcNow(), [], false, code);
}
