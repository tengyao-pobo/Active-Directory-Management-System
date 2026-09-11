using System.Collections.Frozen;

namespace ItManagement.Core;

public enum DeviceHealthState { Healthy, Warning, Critical, Unknown }
public enum HealthEvidenceQuality { Observed, Unknown, NotApplicable, Unavailable }
public sealed record HealthRule(string Id, decimal Weight, TimeSpan MaxAge, bool CriticalOverride);
public sealed record HealthEvidence(string RuleId, Guid EvidenceId, string Source, DateTimeOffset ObservedAt,
    HealthEvidenceQuality Quality, decimal? Score, bool IsCritical);
public sealed record HealthAssessment(long RuleVersion, decimal? Score, decimal EvidenceCoverage,
    DeviceHealthState State, IReadOnlyList<string> CriticalReasons, IReadOnlyList<string> MissingRules,
    IReadOnlyList<Guid> EvidenceIds);

/// <summary>Scores previously classified observations; it performs no probes or authorization decisions.</summary>
public sealed class DeviceHealthPolicy
{
    public long Version { get; }
    public decimal HealthyMinimum { get; }
    public decimal WarningMinimum { get; }
    public decimal MinimumCoverage { get; }
    public FrozenDictionary<string, HealthRule> Rules { get; }

    public DeviceHealthPolicy(long version, IEnumerable<HealthRule> rules, decimal healthyMinimum = 80,
        decimal warningMinimum = 60, decimal minimumCoverage = 0.8m)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(version);
        ArgumentNullException.ThrowIfNull(rules);
        if (healthyMinimum > 100 || healthyMinimum <= warningMinimum || warningMinimum < 0 || minimumCoverage is <= 0 or > 1)
            throw new ArgumentOutOfRangeException(nameof(healthyMinimum));
        var materialized = rules.Take(129).ToArray();
        if (materialized.Length is 0 or > 128 || materialized.Any(r => r is null ||
            string.IsNullOrWhiteSpace(r.Id) || r.Id.Length > 64 || r.Weight is <= 0 or > 100 ||
            r.MaxAge <= TimeSpan.Zero || r.MaxAge > TimeSpan.FromDays(365)))
            throw new ArgumentException("Invalid bounded health rules.", nameof(rules));
        if (materialized.Select(r => r.Id).Distinct(StringComparer.Ordinal).Count() != materialized.Length)
            throw new ArgumentException("Health rule IDs must be unique.", nameof(rules));
        Rules = materialized.ToFrozenDictionary(r => r.Id, StringComparer.Ordinal);
        Version = version;
        HealthyMinimum = healthyMinimum;
        WarningMinimum = warningMinimum;
        MinimumCoverage = minimumCoverage;
    }

    public HealthAssessment Evaluate(IEnumerable<HealthEvidence> evidence, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        var items = evidence.Take(129).ToArray();
        if (items.Length > 128 || items.Any(e => e is null || !Rules.ContainsKey(e.RuleId)))
            throw new ArgumentException("Unexpected health evidence.", nameof(evidence));
        // Multiple observations for one rule need reconciliation upstream, not last-write-wins here.
        var byRule = items.ToDictionary(e => e.RuleId, StringComparer.Ordinal);
        decimal possibleWeight = 0, observedWeight = 0, weightedScore = 0;
        var missing = new List<string>();
        var critical = new List<string>();
        var ids = new List<Guid>();
        foreach (var rule in Rules.Values.OrderBy(r => r.Id, StringComparer.Ordinal))
        {
            byRule.TryGetValue(rule.Id, out var item);
            var valid = item is not null && item.EvidenceId != Guid.Empty && !string.IsNullOrWhiteSpace(item.Source) &&
                item.Source.Length <= 256 && item.ObservedAt <= now && now - item.ObservedAt <= rule.MaxAge;
            if (valid && !ids.Contains(item!.EvidenceId)) ids.Add(item.EvidenceId);
            if (valid && item!.Quality == HealthEvidenceQuality.NotApplicable)
            {
                continue;
            }
            possibleWeight += rule.Weight;
            if (valid && item!.Quality == HealthEvidenceQuality.Observed && rule.CriticalOverride && item.IsCritical)
            {
                critical.Add(rule.Id);
            }
            if (!valid || item!.Quality != HealthEvidenceQuality.Observed || item.Score is null or < 0 or > 100)
            {
                missing.Add(rule.Id);
                continue;
            }
            observedWeight += rule.Weight;
            weightedScore += rule.Weight * item.Score.Value;
        }
        var coverage = possibleWeight == 0 ? 0 : observedWeight / possibleWeight;
        decimal? score = observedWeight == 0 ? null : weightedScore / observedWeight;
        var state = critical.Count > 0 ? DeviceHealthState.Critical :
            score is null || coverage < MinimumCoverage ? DeviceHealthState.Unknown :
            score >= HealthyMinimum ? DeviceHealthState.Healthy :
            score >= WarningMinimum ? DeviceHealthState.Warning : DeviceHealthState.Critical;
        return new(Version, score is null ? null : Math.Round(score.Value, 2), coverage, state,
            critical.AsReadOnly(), missing.AsReadOnly(), ids.AsReadOnly());
    }
}
