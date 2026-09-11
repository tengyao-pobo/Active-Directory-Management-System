using ItManagement.Agent.Collectors;
using ItManagement.Agent.Inventory;

namespace ItManagement.Agent.Tests;

public sealed class InstalledSoftwareCollectorTests
{
    [Fact]
    public async Task CollectAsync_ReadsBothRegistryViewsAndBoundsResults()
    {
        var registry = new FakeRegistry(new Dictionary<RegistryArchitectureView, InstalledSoftwareRegistryReadResult>
        {
            [RegistryArchitectureView.Registry32] =
                new(
                    [
                        new("First application", "1.0", "Publisher", "20260101", RegistryArchitectureView.Registry32),
                        new(null, "2.0", null, null, RegistryArchitectureView.Registry32)
                    ],
                    false),
            [RegistryArchitectureView.Registry64] =
                new(
                    [
                        new("Second", "2.0", "Publisher", "20260202", RegistryArchitectureView.Registry64),
                        new("Third", "3.0", "Publisher", "20260303", RegistryArchitectureView.Registry64)
                    ],
                    false)
        });
        var collector = new InstalledSoftwareCollector(
            registry,
            new InstalledSoftwareCollectorOptions(MaxApplications: 2, MaxStringLength: 6));

        var payload = await collector.CollectAsync(CancellationToken.None);

        Assert.Equal(
            [RegistryArchitectureView.Registry32, RegistryArchitectureView.Registry64],
            registry.ReadViews);
        Assert.Equal(2, payload.ItemCount);
        Assert.True(payload.Data.GetProperty("IsTruncated").GetBoolean());
        var applications = payload.Data.GetProperty("Applications").EnumerateArray().ToArray();
        Assert.Equal("First ", applications[0].GetProperty("Name").GetString());
        Assert.Equal("x86", applications[0].GetProperty("Architecture").GetString());
        Assert.Equal("Second", applications[1].GetProperty("Name").GetString());
        Assert.Equal("x64", applications[1].GetProperty("Architecture").GetString());
    }

    [Fact]
    public async Task CollectAsync_PropagatesRegistrySourceTruncationAtCollectorCapacity()
    {
        var registry = new FakeRegistry(new Dictionary<RegistryArchitectureView, InstalledSoftwareRegistryReadResult>
        {
            [RegistryArchitectureView.Registry32] = new(
                [new("Only visible entry", "1.0", null, null, RegistryArchitectureView.Registry32)],
                true),
            [RegistryArchitectureView.Registry64] = new([], false)
        });
        var collector = new InstalledSoftwareCollector(
            registry,
            new InstalledSoftwareCollectorOptions(MaxApplications: 1, MaxStringLength: 100));

        var payload = await collector.CollectAsync(CancellationToken.None);

        Assert.Equal(1, payload.ItemCount);
        Assert.True(payload.Data.GetProperty("IsTruncated").GetBoolean());
    }

    [Fact]
    public async Task CollectAsync_ReportsAccessDeniedWithoutExceptionDetails()
    {
        var collector = new InstalledSoftwareCollector(new DeniedRegistry());

        var payload = await collector.CollectAsync(CancellationToken.None);

        Assert.Equal(ObservationQuality.AccessDenied, payload.Quality);
        Assert.Equal(0, payload.ItemCount);
        Assert.Empty(payload.Data.GetProperty("Applications").EnumerateArray());
        Assert.False(payload.Data.GetProperty("IsTruncated").GetBoolean());
    }

    private sealed class FakeRegistry(
        IReadOnlyDictionary<RegistryArchitectureView, InstalledSoftwareRegistryReadResult> entries) :
        IInstalledSoftwareRegistry
    {
        public List<RegistryArchitectureView> ReadViews { get; } = [];

        public ValueTask<InstalledSoftwareRegistryReadResult> ReadUninstallEntriesAsync(
            RegistryArchitectureView view,
            CancellationToken cancellationToken)
        {
            ReadViews.Add(view);
            return ValueTask.FromResult(entries[view]);
        }
    }

    private sealed class DeniedRegistry : IInstalledSoftwareRegistry
    {
        public ValueTask<InstalledSoftwareRegistryReadResult> ReadUninstallEntriesAsync(
            RegistryArchitectureView view,
            CancellationToken cancellationToken) =>
            ValueTask.FromException<InstalledSoftwareRegistryReadResult>(new UnauthorizedAccessException("private detail"));
    }
}
