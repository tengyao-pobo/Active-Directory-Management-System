using ItManagement.Agent.Inventory;

namespace ItManagement.Agent.Collectors;

public sealed record OperatingSystemInventory(string Description, string Version, string Architecture);

public sealed record NetworkInterfaceInventory(
    string Name,
    string InterfaceType,
    IReadOnlyList<string> Addresses,
    IReadOnlyList<string> Gateways,
    IReadOnlyList<string> DnsServers,
    string? MacAddress);

public sealed record BasicDeviceInventory(
    string HostName,
    OperatingSystemInventory OperatingSystem,
    IReadOnlyList<NetworkInterfaceInventory> NetworkInterfaces,
    bool IsTruncated = false);

public interface IBasicDeviceDataSource
{
    ValueTask<BasicDeviceInventory> ReadAsync(CancellationToken cancellationToken);
}

public sealed record BasicDeviceCollectorOptions(int MaxNetworkInterfaces, int MaxValuesPerInterface, int MaxStringLength)
{
    public static BasicDeviceCollectorOptions Default { get; } = new(64, 32, 512);

    internal void Validate()
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaxNetworkInterfaces);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaxValuesPerInterface);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaxStringLength);
    }
}

public sealed class BasicDeviceCollector : IInventoryCollector
{
    private readonly IBasicDeviceDataSource _dataSource;
    private readonly BasicDeviceCollectorOptions _options;
    private readonly TimeProvider _timeProvider;

    public BasicDeviceCollector(
        IBasicDeviceDataSource dataSource,
        BasicDeviceCollectorOptions? options = null,
        TimeProvider? timeProvider = null)
    {
        _dataSource = dataSource ?? throw new ArgumentNullException(nameof(dataSource));
        _options = options ?? BasicDeviceCollectorOptions.Default;
        _options.Validate();
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public string Name => "basic-device";

    public async ValueTask<CollectorPayload> CollectAsync(CancellationToken cancellationToken)
    {
        var value = await _dataSource.ReadAsync(cancellationToken).ConfigureAwait(false);
        var isTruncated = value.IsTruncated || value.NetworkInterfaces.Count > _options.MaxNetworkInterfaces;
        var networkInterfaces = new List<NetworkInterfaceInventory>(
            Math.Min(value.NetworkInterfaces.Count, _options.MaxNetworkInterfaces));
        foreach (var networkInterface in value.NetworkInterfaces.Take(_options.MaxNetworkInterfaces))
        {
            networkInterfaces.Add(Bound(networkInterface, ref isTruncated));
        }

        var bounded = new BasicDeviceInventory(
            Bound(value.HostName, ref isTruncated),
            new OperatingSystemInventory(
                Bound(value.OperatingSystem.Description, ref isTruncated),
                Bound(value.OperatingSystem.Version, ref isTruncated),
                Bound(value.OperatingSystem.Architecture, ref isTruncated)),
            networkInterfaces,
            isTruncated);

        return CollectorPayload.Create(
            ObservationQuality.Observed,
            Name,
            _timeProvider.GetUtcNow(),
            bounded,
            1 + bounded.NetworkInterfaces.Count);
    }

    private NetworkInterfaceInventory Bound(NetworkInterfaceInventory value, ref bool isTruncated) =>
        new(
            Bound(value.Name, ref isTruncated),
            Bound(value.InterfaceType, ref isTruncated),
            Bound(value.Addresses, _options.MaxValuesPerInterface, ref isTruncated),
            Bound(value.Gateways, _options.MaxValuesPerInterface, ref isTruncated),
            Bound(value.DnsServers, _options.MaxValuesPerInterface, ref isTruncated),
            value.MacAddress is null ? null : Bound(value.MacAddress, ref isTruncated));

    private IReadOnlyList<string> Bound(IReadOnlyList<string> values, int count, ref bool isTruncated)
    {
        isTruncated |= values.Count > count;
        var bounded = new List<string>(Math.Min(values.Count, count));
        foreach (var value in values.Take(count))
        {
            bounded.Add(Bound(value, ref isTruncated));
        }

        return bounded;
    }

    private string Bound(string value, ref bool isTruncated)
    {
        if (value.Length <= _options.MaxStringLength)
        {
            return value;
        }

        isTruncated = true;
        return value[.._options.MaxStringLength];
    }
}
