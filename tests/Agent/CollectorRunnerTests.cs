using ItManagement.Agent.Collectors;
using ItManagement.Agent.Inventory;
using System.Text.Json;

namespace ItManagement.Agent.Tests;

public sealed class CollectorRunnerTests
{
    [Fact]
    public async Task CollectAsync_IsolatesFailureAndTimeoutWhileKeepingSuccessfulOutput()
    {
        var runner = new CollectorRunner(new CollectorRunnerOptions(
            TimeSpan.FromMilliseconds(50),
            1_024,
            8));
        IInventoryCollector[] collectors =
        [
            new DelegateCollector("success", _ => ValueTask.FromResult(
                CollectorPayload.Create(ObservationQuality.Observed, "fake", DateTimeOffset.UnixEpoch, new { value = 7 }))),
            new DelegateCollector("failure", _ => ValueTask.FromException<CollectorPayload>(new InvalidOperationException("secret detail"))),
            new DelegateCollector("timeout", async cancellationToken =>
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
                throw new InvalidOperationException("unreachable");
            })
        ];

        var snapshot = await runner.CollectAsync(collectors);

        Assert.Equal(1, snapshot.SchemaVersion);
        Assert.Equal(CollectorStatus.Completed, snapshot.Collectors[0].Status);
        Assert.Equal(7, snapshot.Collectors[0].Data!.Value.GetProperty("value").GetInt32());
        Assert.Equal("collector_failed", snapshot.Collectors[1].ErrorCode);
        Assert.Equal(CollectorStatus.TimedOut, snapshot.Collectors[2].Status);
        Assert.All(snapshot.Collectors.Skip(1), result => Assert.Null(result.Data));
    }

    [Fact]
    public async Task CollectAsync_RejectsOversizedCollectorOutput()
    {
        var runner = new CollectorRunner(new CollectorRunnerOptions(TimeSpan.FromSeconds(1), 16, 1));
        var collector = new DelegateCollector("large", _ => ValueTask.FromResult(
            CollectorPayload.Create(ObservationQuality.Observed, "fake", DateTimeOffset.UnixEpoch, new string('x', 100))));

        var snapshot = await runner.CollectAsync([collector]);

        var result = Assert.Single(snapshot.Collectors);
        Assert.Equal(CollectorStatus.OutputLimitExceeded, result.Status);
        Assert.Equal("output_limit_exceeded", result.ErrorCode);
        Assert.Null(result.Data);
    }

    [Fact]
    public async Task CollectAsync_BoundsCollectorMetadata()
    {
        var runner = new CollectorRunner(new CollectorRunnerOptions(
            TimeSpan.FromSeconds(1),
            1_024,
            1,
            MaxMetadataLength: 4));
        var collector = new DelegateCollector("long-collector-name", _ => ValueTask.FromResult(
            CollectorPayload.Create(ObservationQuality.Observed, "long-source", DateTimeOffset.UnixEpoch, new { value = 1 })));

        var result = Assert.Single((await runner.CollectAsync([collector])).Collectors);

        Assert.Equal("long", result.Collector);
        Assert.Equal("long", result.Source);
    }

    [Fact]
    public async Task CollectAsync_RejectsNegativeItemCount()
    {
        var runner = new CollectorRunner(new CollectorRunnerOptions(TimeSpan.FromSeconds(1), 1_024, 1));
        var collector = new DelegateCollector("invalid", _ => ValueTask.FromResult(
            new CollectorPayload(
                ObservationQuality.Observed,
                "fake",
                DateTimeOffset.UnixEpoch,
                JsonSerializer.SerializeToElement(new { value = 1 }),
                -1)));

        var result = Assert.Single((await runner.CollectAsync([collector])).Collectors);

        Assert.Equal(CollectorStatus.Failed, result.Status);
        Assert.Equal("invalid_output", result.ErrorCode);
    }

    [Fact]
    public async Task CollectAsync_RejectsUndefinedObservationQuality()
    {
        var runner = new CollectorRunner(new CollectorRunnerOptions(TimeSpan.FromSeconds(1), 1_024, 1));
        var collector = new DelegateCollector("invalid", _ => ValueTask.FromResult(
            new CollectorPayload(
                (ObservationQuality)999,
                "fake",
                DateTimeOffset.UnixEpoch,
                JsonSerializer.SerializeToElement(new { value = 1 }),
                1)));

        var result = Assert.Single((await runner.CollectAsync([collector])).Collectors);

        Assert.Equal(CollectorStatus.Failed, result.Status);
        Assert.Equal("invalid_output", result.ErrorCode);
    }

    [Fact]
    public void Options_RejectCollectorCountThatWouldBreakBoundedEnumeration()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new CollectorRunner(new CollectorRunnerOptions(TimeSpan.FromSeconds(1), 1_024, int.MaxValue)));
    }

    [Fact]
    public async Task CollectAsync_StopsEnumeratingAfterConfiguredLimitPlusOne()
    {
        var runner = new CollectorRunner(new CollectorRunnerOptions(TimeSpan.FromSeconds(1), 1_024, 2));

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => runner.CollectAsync(GetCollectors()));

        static IEnumerable<IInventoryCollector> GetCollectors()
        {
            for (var index = 0; index < 3; index++)
            {
                yield return new DelegateCollector(index.ToString(), _ => ValueTask.FromResult(
                    CollectorPayload.Create(ObservationQuality.Observed, "fake", DateTimeOffset.UnixEpoch, index)));
            }

            throw new InvalidOperationException("Enumeration was not bounded.");
        }
    }

    private sealed class DelegateCollector(
        string name,
        Func<CancellationToken, ValueTask<CollectorPayload>> collect) : IInventoryCollector
    {
        public string Name { get; } = name;

        public ValueTask<CollectorPayload> CollectAsync(CancellationToken cancellationToken) => collect(cancellationToken);
    }
}
