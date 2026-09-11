using ItManagement.Agent.Collectors;

namespace ItManagement.Agent.Tests;

public sealed class BasicDeviceCollectorTests
{
    [Fact]
    public async Task CollectAsync_BoundsPortableOsAndNetworkDataWithoutPrivateIdentityFields()
    {
        var source = new FakeSource(new BasicDeviceInventory(
            "host-name",
            new OperatingSystemInventory("Operating System", "10.0", "x64"),
            [
                new NetworkInterfaceInventory(
                    "ethernet-long-name",
                    "ethernet",
                    ["10.0.0.1", "10.0.0.2", "10.0.0.3"],
                    ["10.0.0.254"],
                    ["10.0.0.53"],
                    "001122334455"),
                new NetworkInterfaceInventory("second", "loopback", [], [], [], null)
            ]));
        var collector = new BasicDeviceCollector(
            source,
            new BasicDeviceCollectorOptions(MaxNetworkInterfaces: 1, MaxValuesPerInterface: 2, MaxStringLength: 8));

        var payload = await collector.CollectAsync(CancellationToken.None);
        var json = payload.Data.GetRawText();

        Assert.Equal(2, payload.ItemCount);
        Assert.DoesNotContain("ssid", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("user", json, StringComparison.OrdinalIgnoreCase);
        Assert.Equal("host-nam", payload.Data.GetProperty("HostName").GetString());
        Assert.True(payload.Data.GetProperty("IsTruncated").GetBoolean());
        var network = Assert.Single(payload.Data.GetProperty("NetworkInterfaces").EnumerateArray());
        Assert.Equal(2, network.GetProperty("Addresses").GetArrayLength());
        Assert.Equal("ethernet", network.GetProperty("Name").GetString());
    }

    private sealed class FakeSource(BasicDeviceInventory inventory) : IBasicDeviceDataSource
    {
        public ValueTask<BasicDeviceInventory> ReadAsync(CancellationToken cancellationToken) =>
            ValueTask.FromResult(inventory);
    }
}
