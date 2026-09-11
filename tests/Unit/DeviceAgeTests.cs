using ItManagement.Core;

namespace ItManagement.UnitTests;

public sealed class DeviceAgeTests
{
    private static readonly DateOnly Today = new(2026, 9, 12);

    [Theory]
    [InlineData(2023, 9, 13, DeviceAgeBand.Green)]
    [InlineData(2023, 9, 12, DeviceAgeBand.Yellow)]
    [InlineData(2021, 9, 13, DeviceAgeBand.Yellow)]
    [InlineData(2021, 9, 12, DeviceAgeBand.Red)]
    public void Calendar_anniversary_controls_band_even_if_display_rounds_up(int year, int month, int day, DeviceAgeBand expected) =>
        Assert.Equal(expected, DeviceAgePolicy.Default.Estimate(new DateOnly(year, month, day), null, null, Today).Band);

    [Fact]
    public void Manufacturing_precedes_firmware_and_first_seen()
    {
        var result = DeviceAgePolicy.Default.Estimate(new(2020, 1, 1), new(2026, 1, 1), Today, Today);
        Assert.Equal(DeviceAgeSource.ManufacturingDate, result.Source);
        Assert.Equal(DeviceAgeBand.Red, result.Band);
    }

    [Fact]
    public void Invalid_dates_fall_back_without_negative_age()
    {
        var result = DeviceAgePolicy.Default.Estimate(Today.AddDays(1), new(1, 1, 1), Today.AddYears(-1), Today);
        Assert.Equal(DeviceAgeSource.AgentFirstSeen, result.Source);
        Assert.Equal(DeviceAgeConfidence.ObservedLowerBound, result.Confidence);
        Assert.Equal(1m, result.EstimatedYears);
    }

    [Fact]
    public void Missing_evidence_is_unknown_not_zero_years()
    {
        var result = DeviceAgePolicy.Default.Estimate(null, null, null, Today);
        Assert.Equal(DeviceAgeBand.Unknown, result.Band);
        Assert.Null(result.EstimatedYears);
    }

    [Fact]
    public void Bios_fallback_preserves_its_weaker_source()
    {
        var result = DeviceAgePolicy.Default.Estimate(null, new(2022, 1, 1), Today, Today);
        Assert.Equal(DeviceAgeSource.BiosDate, result.Source);
        Assert.Equal(DeviceAgeConfidence.Low, result.Confidence);
        Assert.Equal(DeviceAgeBand.Yellow, result.Band);
    }

    [Theory]
    [InlineData(0, DeviceAgeBand.Unknown)]
    [InlineData(3, DeviceAgeBand.Unknown)]
    [InlineData(5, DeviceAgeBand.Red)]
    public void First_seen_is_a_lower_bound_not_proof_of_recent_manufacture(int years, DeviceAgeBand expected) =>
        Assert.Equal(expected, DeviceAgePolicy.Default.Estimate(null, null, Today.AddYears(-years), Today).Band);

    [Fact]
    public void Leap_day_and_custom_notebook_policy_use_calendar_rules()
    {
        var result = new DeviceAgePolicy(2, 4).Estimate(new(2020, 2, 29), null, null, new(2024, 2, 28));
        Assert.Equal(DeviceAgeBand.Yellow, result.Band);
    }

    [Theory]
    [InlineData(0, 5)]
    [InlineData(5, 5)]
    [InlineData(5, 4)]
    [InlineData(3, 51)]
    public void Rejects_invalid_policy(int warning, int critical) =>
        Assert.Throws<ArgumentOutOfRangeException>(() => new DeviceAgePolicy(warning, critical));
}
