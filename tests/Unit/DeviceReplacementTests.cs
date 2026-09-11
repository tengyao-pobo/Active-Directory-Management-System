using ItManagement.Core;

namespace ItManagement.UnitTests;

public sealed class DeviceReplacementTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 12, 0, 0, 0, TimeSpan.Zero);
    private static ReplacementObservation Fact(ReplacementFactor factor, decimal? concern) => new(factor, concern, Now, "synthetic");

    [Theory]
    [InlineData(0, ReplacementPriority.Low)]
    [InlineData(35, ReplacementPriority.Medium)]
    [InlineData(65, ReplacementPriority.High)]
    public void Uses_all_seven_factors_and_retains_reasons(int concern, ReplacementPriority priority)
    {
        var result = DeviceReplacementPolicy.Default.Evaluate(Enum.GetValues<ReplacementFactor>().Select(f => Fact(f, concern)), Now);
        Assert.Equal(priority, result.Priority);
        Assert.Equal(1, result.EvidenceCoverage);
        Assert.Equal(7, result.Reasons.Count);
        Assert.Empty(result.MissingFactors);
    }

    [Fact]
    public void Age_alone_cannot_decide_replacement()
    {
        var result = DeviceReplacementPolicy.Default.Evaluate([Fact(ReplacementFactor.Age, 100)], Now);
        Assert.Equal(ReplacementPriority.Unknown, result.Priority);
        Assert.Equal(6, result.MissingFactors.Count);
    }

    [Fact]
    public void Missing_facts_cannot_result_in_low_priority() =>
        Assert.Equal(ReplacementPriority.Unknown, DeviceReplacementPolicy.Default.Evaluate([], Now).Priority);

    [Fact]
    public void Stale_future_and_invalid_values_are_missing()
    {
        var result = DeviceReplacementPolicy.Default.Evaluate([
            Fact(ReplacementFactor.Age, 0) with { ObservedAt = Now.AddDays(-8) },
            Fact(ReplacementFactor.Disk, 0) with { ObservedAt = Now.AddSeconds(1) },
            Fact(ReplacementFactor.Health, 101)], Now);
        Assert.Equal(0, result.EvidenceCoverage);
        Assert.Null(result.Concern);
        Assert.Equal(7, result.MissingFactors.Count);
    }

    [Fact]
    public void Policy_version_and_weight_changes_are_visible()
    {
        var policy = new DeviceReplacementPolicy(3, Enum.GetValues<ReplacementFactor>().Select(f => KeyValuePair.Create(f, f == ReplacementFactor.Health ? 10m : 1m)));
        var result = policy.Evaluate(Enum.GetValues<ReplacementFactor>().Select(f => Fact(f, f == ReplacementFactor.Health ? 100 : 0)), Now);
        Assert.Equal(3, result.PolicyVersion);
        Assert.Equal(62.5m, result.Concern);
        Assert.Equal(ReplacementPriority.Medium, result.Priority);
    }

    [Fact]
    public void Duplicate_observations_are_rejected() =>
        Assert.Throws<ArgumentException>(() => DeviceReplacementPolicy.Default.Evaluate([Fact(ReplacementFactor.Age, 0), Fact(ReplacementFactor.Age, 100)], Now));

    [Fact]
    public void Duplicate_weight_cannot_hide_a_missing_required_factor()
    {
        var weights = Enum.GetValues<ReplacementFactor>().Select(f =>
            KeyValuePair.Create(f == ReplacementFactor.Tpm ? ReplacementFactor.Age : f, 1m));
        Assert.Throws<ArgumentException>(() => new DeviceReplacementPolicy(1, weights));
    }
}
