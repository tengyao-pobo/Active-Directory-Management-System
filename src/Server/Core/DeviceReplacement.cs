using System.Collections.Frozen;

namespace ItManagement.Core;

public enum ReplacementPriority { Low, Medium, High, Unknown }
public enum ReplacementFactor { Age, Health, Disk, Ram, WindowsSupport, Tpm, RepairHistory }
public sealed record ReplacementObservation(ReplacementFactor Factor, decimal? Concern, DateTimeOffset ObservedAt, string Source);
public sealed record ReplacementReason(ReplacementFactor Factor, decimal Concern, decimal Weight, string Source);
public sealed record ReplacementAssessment(long PolicyVersion, ReplacementPriority Priority, decimal? Concern,
    decimal EvidenceCoverage, IReadOnlyList<ReplacementReason> Reasons, IReadOnlyList<ReplacementFactor> MissingFactors);

/// <summary>Combines normalized, sourced concerns (0 good, 100 adverse); no purchase or deletion action.</summary>
public sealed class DeviceReplacementPolicy
{
    public long Version { get; }
    public FrozenDictionary<ReplacementFactor, decimal> Weights { get; }
    public decimal MinimumCoverage { get; }
    public decimal MediumThreshold { get; }
    public decimal HighThreshold { get; }
    public TimeSpan MaxEvidenceAge { get; }

    public DeviceReplacementPolicy(long version, IEnumerable<KeyValuePair<ReplacementFactor, decimal>> weights,
        decimal minimumCoverage = 0.8m, decimal mediumThreshold = 35, decimal highThreshold = 65,
        TimeSpan? maxEvidenceAge = null)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(version);
        ArgumentNullException.ThrowIfNull(weights);
        var values = weights.Take(8).ToArray();
        if (values.Length != 7 || values.Select(x => x.Key).Distinct().Count() != 7 ||
            values.Any(x => !Enum.IsDefined(x.Key) || x.Value is <= 0 or > 100))
            throw new ArgumentException("Each replacement factor must have a bounded positive weight.", nameof(weights));
        Weights = values.ToFrozenDictionary();
        if (minimumCoverage is <= 0 or > 1 || mediumThreshold < 0 || highThreshold <= mediumThreshold || highThreshold > 100)
            throw new ArgumentOutOfRangeException(nameof(minimumCoverage));
        MaxEvidenceAge = maxEvidenceAge ?? TimeSpan.FromDays(7);
        if (MaxEvidenceAge <= TimeSpan.Zero || MaxEvidenceAge > TimeSpan.FromDays(365))
            throw new ArgumentOutOfRangeException(nameof(maxEvidenceAge));
        Version = version;
        MinimumCoverage = minimumCoverage;
        MediumThreshold = mediumThreshold;
        HighThreshold = highThreshold;
    }

    public static DeviceReplacementPolicy Default { get; } = new(1,
        Enum.GetValues<ReplacementFactor>().Select(f => KeyValuePair.Create(f, 1m)));

    public ReplacementAssessment Evaluate(IEnumerable<ReplacementObservation> observations, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(observations);
        var values = observations.Take(8).ToArray();
        if (values.Length > 7 || values.Any(x => x is null || !Enum.IsDefined(x.Factor)))
            throw new ArgumentException("Unexpected replacement observations.", nameof(observations));
        var byFactor = values.ToDictionary(x => x.Factor);
        var reasons = new List<ReplacementReason>();
        var missing = new List<ReplacementFactor>();
        decimal weighted = 0, available = 0;
        foreach (var (factor, weight) in Weights.OrderBy(x => x.Key))
        {
            if (!byFactor.TryGetValue(factor, out var observation) || observation.Concern is null or < 0 or > 100 ||
                observation.ObservedAt > now || now - observation.ObservedAt > MaxEvidenceAge ||
                string.IsNullOrWhiteSpace(observation.Source) || observation.Source.Length > 256)
            {
                missing.Add(factor);
                continue;
            }
            available += weight;
            weighted += observation.Concern.Value * weight;
            reasons.Add(new(factor, observation.Concern.Value, weight, observation.Source));
        }
        var coverage = available / Weights.Values.Sum();
        decimal? concern = available == 0 ? null : weighted / available;
        var priority = concern is null || coverage < MinimumCoverage ? ReplacementPriority.Unknown :
            concern >= HighThreshold ? ReplacementPriority.High : concern >= MediumThreshold ? ReplacementPriority.Medium : ReplacementPriority.Low;
        return new(Version, priority, concern is null ? null : Math.Round(concern.Value, 2), coverage,
            reasons.AsReadOnly(), missing.AsReadOnly());
    }
}
