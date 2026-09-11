using System.Net.NetworkInformation;
using System.Runtime.InteropServices;

namespace ItManagement.Agent.Collectors;

public sealed class RuntimeBasicDeviceDataSource : IBasicDeviceDataSource
{
    private readonly BasicDeviceCollectorOptions _options;

    public RuntimeBasicDeviceDataSource(BasicDeviceCollectorOptions? options = null)
    {
        _options = options ?? BasicDeviceCollectorOptions.Default;
        _options.Validate();
    }

    public ValueTask<BasicDeviceInventory> ReadAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var interfaces = new List<NetworkInterfaceInventory>();
        var allInterfaces = NetworkInterface.GetAllNetworkInterfaces();
        var isTruncated = allInterfaces.Length > _options.MaxNetworkInterfaces;

        foreach (var networkInterface in allInterfaces.Take(_options.MaxNetworkInterfaces))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var properties = networkInterface.GetIPProperties();
            var macAddress = networkInterface.GetPhysicalAddress().ToString();
            isTruncated |=
                properties.UnicastAddresses.Count > _options.MaxValuesPerInterface ||
                properties.GatewayAddresses.Count > _options.MaxValuesPerInterface ||
                properties.DnsAddresses.Count > _options.MaxValuesPerInterface;
            interfaces.Add(new NetworkInterfaceInventory(
                Bound(networkInterface.Name, ref isTruncated),
                Bound(networkInterface.NetworkInterfaceType.ToString(), ref isTruncated),
                BoundValues(
                    properties.UnicastAddresses.Take(_options.MaxValuesPerInterface)
                        .Select(static address => address.Address.ToString()),
                    ref isTruncated),
                BoundValues(
                    properties.GatewayAddresses.Take(_options.MaxValuesPerInterface)
                        .Select(static address => address.Address.ToString()),
                    ref isTruncated),
                BoundValues(
                    properties.DnsAddresses.Take(_options.MaxValuesPerInterface)
                        .Select(static address => address.ToString()),
                    ref isTruncated),
                string.IsNullOrEmpty(macAddress) ? null : Bound(macAddress, ref isTruncated)));
        }

        var inventory = new BasicDeviceInventory(
            Bound(Environment.MachineName, ref isTruncated),
            new OperatingSystemInventory(
                Bound(RuntimeInformation.OSDescription, ref isTruncated),
                Bound(Environment.OSVersion.Version.ToString(), ref isTruncated),
                Bound(RuntimeInformation.OSArchitecture.ToString(), ref isTruncated)),
            interfaces,
            isTruncated);
        return ValueTask.FromResult(inventory);
    }

    private IReadOnlyList<string> BoundValues(IEnumerable<string> values, ref bool isTruncated)
    {
        var bounded = new List<string>();
        foreach (var value in values)
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
