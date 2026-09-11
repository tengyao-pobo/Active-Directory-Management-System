using System.Management;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text.Json;
using ItManagement.Agent.Inventory;

namespace ItManagement.Agent.Collectors;

[SupportedOSPlatform("windows")]
public sealed class WindowsBitLockerQueryReader : IBitLockerQueryReader
{
    private readonly TimeSpan _timeout;
    private readonly BoundedBitLockerQueryReader _bounded;

    public WindowsBitLockerQueryReader(TimeSpan? timeout = null)
    {
        _timeout = timeout ?? TimeSpan.FromSeconds(5);
        if (_timeout <= TimeSpan.Zero || _timeout > TimeSpan.FromSeconds(10)) throw new ArgumentOutOfRangeException(nameof(timeout));
        _bounded = new(cancellationToken => Task.FromResult(ReadLocal(cancellationToken)), _timeout);
    }

    public ValueTask<BitLockerQueryResult> ReadAsync(CancellationToken cancellationToken) => _bounded.ReadAsync(cancellationToken);

    private BitLockerQueryResult ReadLocal(CancellationToken cancellationToken)
    {
        try { return ReadLocalCore(cancellationToken); }
        catch (ManagementException error) when (HardwareFailureClassifier.IsAccessDenied((int)error.ErrorCode))
        { throw new UnauthorizedAccessException("bitlocker_access_denied"); }
        catch (COMException error) when (HardwareFailureClassifier.IsAccessDenied(error.ErrorCode))
        { throw new UnauthorizedAccessException("bitlocker_access_denied"); }
    }

    private BitLockerQueryResult ReadLocalCore(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var rows = new List<JsonElement>();
        var truncated = false;
        using var search = new ManagementObjectSearcher(
            new ManagementScope($@"\\.\{BitLockerQueryCatalog.NamespacePath}"),
            new ObjectQuery($"SELECT {string.Join(',', BitLockerQueryCatalog.Properties.Order(StringComparer.Ordinal))} FROM {BitLockerQueryCatalog.ClassName}"),
            new System.Management.EnumerationOptions { ReturnImmediately = false, Timeout = _timeout, Rewindable = false });
        using var results = search.Get();
        foreach (ManagementBaseObject row in results)
        {
            using (row)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (rows.Count == BitLockerCollector.MaxVolumes) { truncated = true; break; }
                var values = new Dictionary<string, object?>();
                foreach (var property in BitLockerQueryCatalog.Properties)
                {
                    var value = row[property];
                    values[property] = BitLockerNativeValueBoundary.Bound(value, ref truncated);
                }
                rows.Add(JsonSerializer.SerializeToElement(values));
            }
        }
        return new(ObservationQuality.Observed, DateTimeOffset.UtcNow, rows.AsReadOnly(), truncated);
    }

}

internal static class BitLockerNativeValueBoundary
{
    internal static object? Bound(object? value, ref bool truncated)
    {
        if (value is string text)
        {
            if (text.Length <= BitLockerCollector.MaxIdentifierLength && !text.Any(char.IsControl)) return text;
            truncated = true;
            return null;
        }
        if (value is uint or bool || value is null) return value;
        truncated = true;
        return null;
    }
}
