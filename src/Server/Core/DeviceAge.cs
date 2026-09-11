namespace ItManagement.Core;

public enum DeviceAgeSource { ManufacturingDate, BiosDate, AgentFirstSeen, Unknown }
public enum DeviceAgeBand { Green, Yellow, Red, Unknown }
public enum DeviceAgeConfidence { Verified, Low, ObservedLowerBound, Unknown }
public sealed record DeviceAgeEstimate(DeviceAgeSource Source, DateOnly? ReferenceDate, decimal? EstimatedYears, DeviceAgeBand Band)
{
    public DeviceAgeConfidence Confidence => Source switch
    {
        DeviceAgeSource.ManufacturingDate => DeviceAgeConfidence.Verified,
        DeviceAgeSource.BiosDate => DeviceAgeConfidence.Low,
        DeviceAgeSource.AgentFirstSeen => DeviceAgeConfidence.ObservedLowerBound,
        _ => DeviceAgeConfidence.Unknown
    };
}

/// <summary>Approximate equipment age, not purchase date or warranty entitlement.</summary>
public sealed record DeviceAgePolicy
{
    public int WarningYears { get; }
    public int CriticalYears { get; }
    public static DeviceAgePolicy Default { get; } = new(3, 5);

    public DeviceAgePolicy(int warningYears, int criticalYears)
    {
        if (warningYears < 1 || criticalYears <= warningYears || criticalYears > 50)
            throw new ArgumentOutOfRangeException(nameof(criticalYears));
        WarningYears = warningYears;
        CriticalYears = criticalYears;
    }

    // Manufacturing dates must be verified by the caller; BIOS may reflect a later firmware update.
    // First-seen is an observed lower bound; Windows installation is deliberately absent.
    public DeviceAgeEstimate Estimate(DateOnly? manufacturingDate, DateOnly? biosDate, DateOnly? agentFirstSeen, DateOnly today)
    {
        foreach (var candidate in new[]
        {
            (Date: manufacturingDate, Source: DeviceAgeSource.ManufacturingDate),
            (Date: biosDate, Source: DeviceAgeSource.BiosDate),
            (Date: agentFirstSeen, Source: DeviceAgeSource.AgentFirstSeen)
        })
        {
            if (candidate.Date is not { } date || date > today || date.Year < 1980) continue;
            var elapsedDays = today.DayNumber - date.DayNumber;
            var age = Math.Round(elapsedDays / 365.2425m, 1, MidpointRounding.AwayFromZero);
            // Compare calendar anniversaries; a rounded display value never decides the band.
            var years = today.Year - date.Year;
            if (today < date.AddYears(years)) years--;
            var band = years >= CriticalYears ? DeviceAgeBand.Red : years >= WarningYears ? DeviceAgeBand.Yellow : DeviceAgeBand.Green;
            // Recent first-seen cannot prove recent manufacture. Only a critical lower bound is conclusive.
            if (candidate.Source == DeviceAgeSource.AgentFirstSeen && years < CriticalYears) band = DeviceAgeBand.Unknown;
            return new(candidate.Source, date, age, band);
        }
        return new(DeviceAgeSource.Unknown, null, null, DeviceAgeBand.Unknown);
    }
}
