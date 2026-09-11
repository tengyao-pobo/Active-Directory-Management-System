using ItManagement.Core;

namespace ItManagement.UnitTests;

public sealed class DeviceHealthTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 12, 0, 0, 0, TimeSpan.Zero);
    private static HealthRule Rule(string id, bool critical = false) => new(id, 1, TimeSpan.FromMinutes(5), critical);
    private static HealthEvidence Evidence(string id, decimal? score = 100, bool critical = false) =>
        new(id, Guid.NewGuid(), "synthetic", Now, HealthEvidenceQuality.Observed, score, critical);

    [Theory]
    [InlineData(100, DeviceHealthState.Healthy)]
    [InlineData(80, DeviceHealthState.Healthy)]
    [InlineData(79.99, DeviceHealthState.Warning)]
    [InlineData(60, DeviceHealthState.Warning)]
    [InlineData(59.99, DeviceHealthState.Critical)]
    public void Thresholds_use_unrounded_score(double value, DeviceHealthState expected) =>
        Assert.Equal(expected, new DeviceHealthPolicy(1, [Rule("a")]).Evaluate([Evidence("a", (decimal)value)], Now).State);

    [Fact]
    public void Missing_evidence_does_not_become_a_pass()
    {
        var result = new DeviceHealthPolicy(7, [Rule("a"), Rule("b")]).Evaluate([Evidence("a")], Now);
        Assert.Equal(7, result.RuleVersion);
        Assert.Equal(100, result.Score);
        Assert.Equal(0.5m, result.EvidenceCoverage);
        Assert.Equal(DeviceHealthState.Unknown, result.State);
        Assert.Equal(["b"], result.MissingRules);
    }

    [Fact]
    public void Fresh_critical_overrides_low_coverage_and_high_score()
    {
        var result = new DeviceHealthPolicy(1, [Rule("a", true), Rule("b")]).Evaluate([Evidence("a", 100, true)], Now);
        Assert.Equal(DeviceHealthState.Critical, result.State);
        Assert.Equal(["a"], result.CriticalReasons);
    }

    [Fact]
    public void Confirmed_critical_does_not_require_a_numeric_score()
    {
        var result = new DeviceHealthPolicy(1, [Rule("a", true)]).Evaluate([Evidence("a", null, true)], Now);
        Assert.Equal(DeviceHealthState.Critical, result.State);
        Assert.Null(result.Score);
        Assert.Single(result.EvidenceIds);
    }

    [Theory]
    [InlineData(-301)]
    [InlineData(1)]
    public void Old_or_future_critical_evidence_cannot_describe_current_health(int seconds)
    {
        var result = new DeviceHealthPolicy(1, [Rule("a", true)]).Evaluate([Evidence("a", 0, true) with { ObservedAt = Now.AddSeconds(seconds) }], Now);
        Assert.Equal(DeviceHealthState.Unknown, result.State);
        Assert.Null(result.Score);
        Assert.Empty(result.CriticalReasons);
    }

    [Fact]
    public void Fresh_not_applicable_excludes_weight_but_unavailable_does_not()
    {
        var policy = new DeviceHealthPolicy(1, [Rule("a"), Rule("b")]);
        Assert.Equal(DeviceHealthState.Healthy, policy.Evaluate([Evidence("a"), Evidence("b") with { Quality = HealthEvidenceQuality.NotApplicable }], Now).State);
        Assert.Equal(DeviceHealthState.Unknown, policy.Evaluate([Evidence("a"), Evidence("b") with { Quality = HealthEvidenceQuality.Unavailable }], Now).State);
        Assert.Equal(DeviceHealthState.Unknown, policy.Evaluate([Evidence("a") with { Quality = HealthEvidenceQuality.NotApplicable }, Evidence("b") with { Quality = HealthEvidenceQuality.NotApplicable }], Now).State);
    }

    [Fact]
    public void Overrides_are_configurable_and_weights_are_applied()
    {
        var policy = new DeviceHealthPolicy(1, [Rule("a") with { Weight = 3 }, Rule("b")]);
        var result = policy.Evaluate([Evidence("a", 100, true), Evidence("b", 0)], Now);
        Assert.Equal(75, result.Score);
        Assert.Equal(DeviceHealthState.Warning, result.State);
    }

    [Theory]
    [InlineData(HealthEvidenceQuality.Unknown)]
    [InlineData(HealthEvidenceQuality.Unavailable)]
    public void Current_unscoreable_evidence_keeps_its_traceability(HealthEvidenceQuality quality)
    {
        var evidence = Evidence("a") with { Quality = quality };
        var result = new DeviceHealthPolicy(1, [Rule("a")]).Evaluate([evidence], Now);
        Assert.Equal(DeviceHealthState.Unknown, result.State);
        Assert.Equal([evidence.EvidenceId], result.EvidenceIds);
        Assert.Equal(0, result.EvidenceCoverage);
    }

    [Fact]
    public void Duplicate_or_unknown_rules_are_rejected()
    {
        var policy = new DeviceHealthPolicy(1, [Rule("a")]);
        Assert.Throws<ArgumentException>(() => policy.Evaluate([Evidence("a"), Evidence("a")], Now));
        Assert.Throws<ArgumentException>(() => policy.Evaluate([Evidence("b")], Now));
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(101)]
    public void Invalid_scores_remain_unknown(int score) =>
        Assert.Equal(DeviceHealthState.Unknown, new DeviceHealthPolicy(1, [Rule("a")]).Evaluate([Evidence("a", score)], Now).State);

    [Fact]
    public void Policy_is_immutable_and_bounded()
    {
        var rules = new List<HealthRule> { Rule("a") };
        var policy = new DeviceHealthPolicy(1, rules);
        rules.Clear();
        Assert.Single(policy.Rules);
        Assert.Throws<ArgumentException>(() => new DeviceHealthPolicy(1, [Rule("a"), Rule("a")]));
        Assert.Throws<ArgumentException>(() => new DeviceHealthPolicy(1, Enumerable.Range(0, 129).Select(i => Rule(i.ToString()))));
    }
}
