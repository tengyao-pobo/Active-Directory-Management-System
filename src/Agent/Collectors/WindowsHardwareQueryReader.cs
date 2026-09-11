using System.Management;
using System.Runtime.Versioning;
using System.Runtime.InteropServices;
using System.Text.Json;
using ItManagement.Agent.Inventory;

namespace ItManagement.Agent.Collectors;

[SupportedOSPlatform("windows")]
public sealed class WindowsHardwareQueryReader : IHardwareQueryReader
{
    private readonly TimeSpan _timeout;
    private readonly BoundedHardwareQueryReader _bounded;
    public WindowsHardwareQueryReader(TimeSpan? timeout = null)
    {
        _timeout = timeout ?? TimeSpan.FromSeconds(5);
        if (_timeout <= TimeSpan.Zero || _timeout > TimeSpan.FromSeconds(10)) throw new ArgumentOutOfRangeException(nameof(timeout));
        _bounded = new((kind, ct) => Task.FromResult(ReadLocal(HardwareQueryCatalog.Get(kind), ct)), _timeout);
    }

    public ValueTask<HardwareQueryResult> ReadAsync(HardwareQueryKind kind, CancellationToken cancellationToken) =>
        _bounded.ReadAsync(kind, cancellationToken);

    private HardwareQueryResult ReadLocal(HardwareQueryDefinition definition, CancellationToken cancellationToken)
    {
        try { return ReadLocalCore(definition, cancellationToken); }
        catch (ManagementException error) when (HardwareFailureClassifier.IsAccessDenied((int)error.ErrorCode))
        { throw new UnauthorizedAccessException("hardware_access_denied"); }
        catch (COMException error) when (HardwareFailureClassifier.IsAccessDenied(error.ErrorCode))
        { throw new UnauthorizedAccessException("hardware_access_denied"); }
    }

    private HardwareQueryResult ReadLocalCore(HardwareQueryDefinition definition, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var rows = new List<JsonElement>();
        var truncated = false;
        // Definitions are compiled constants. No caller-controlled host, namespace, WQL or method invocation.
        using var search = new ManagementObjectSearcher(new ManagementScope(@"\\.\root\cimv2"),
            new ObjectQuery($"SELECT {string.Join(',', definition.Properties.Order(StringComparer.Ordinal))} FROM {definition.ClassName}"),
            new System.Management.EnumerationOptions { ReturnImmediately = false, Timeout = _timeout, Rewindable = false });
        using var results = search.Get();
        foreach (ManagementBaseObject row in results)
        {
            using (row)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (rows.Count == HardwareCollector.MaxRowsPerQuery) { truncated = true; break; }
                var values = new Dictionary<string, object?>();
                foreach (var property in definition.Properties)
                {
                    var value = row[property];
                    if (value is string text)
                    {
                        truncated |= text.Length > HardwareCollector.MaxStringLength;
                        values[property] = text[..Math.Min(text.Length, HardwareCollector.MaxStringLength)];
                    }
                    else values[property] = value is byte or ushort or uint or ulong or bool ? value : null;
                }
                rows.Add(JsonSerializer.SerializeToElement(values));
            }
        }
        return new(ObservationQuality.Observed, DateTimeOffset.UtcNow, rows.AsReadOnly(), truncated);
    }
}
