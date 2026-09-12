namespace ItManagement.EnrollmentGrantDelivery.Tests;

using Xunit;

public sealed class EnrollmentGrantStatusObservationTests
{
    private static readonly DateTimeOffset Created = At(0);
    private static readonly DateTimeOffset Expires = At(600);

    public static IEnumerable<object?[]> ValidCandidates()
    {
        yield return [EnrollmentGrantStatus.Available, EnrollmentGrantStatusDiagnostic.None, At(100), null];
        yield return [EnrollmentGrantStatus.Unknown, EnrollmentGrantStatusDiagnostic.ResponseUnavailable, null, null];
        yield return [EnrollmentGrantStatus.Expired, EnrollmentGrantStatusDiagnostic.None, At(600), null];
        yield return [EnrollmentGrantStatus.Consumed, EnrollmentGrantStatusDiagnostic.None, At(500), At(499)];
        yield return [EnrollmentGrantStatus.Revoked, EnrollmentGrantStatusDiagnostic.None, At(700), At(650)];
    }

    [Theory]
    [MemberData(nameof(ValidCandidates))]
    public void CandidateAcceptsEachClosedStateShape(
        EnrollmentGrantStatus state,
        EnrollmentGrantStatusDiagnostic diagnostic,
        DateTimeOffset? observed,
        DateTimeOffset? changed)
    {
        Assert.True(TryCandidate(state, diagnostic, observed, changed, out var candidate));
        Assert.NotNull(candidate);
        Assert.Equal(state, candidate.State);
        Assert.Equal(diagnostic, candidate.Diagnostic);
        Assert.Equal(observed, candidate.PrivateObservedAt);
        Assert.Equal(changed, candidate.StateChangedAt);
        Assert.Equal(nameof(EnrollmentGrantStatusObservationCandidate), candidate.ToString());
    }

    [Theory]
    [InlineData(EnrollmentGrantStatus.Available, EnrollmentGrantStatusDiagnostic.ResponseUnavailable, 100, null)]
    [InlineData(EnrollmentGrantStatus.Unknown, EnrollmentGrantStatusDiagnostic.None, null, null)]
    [InlineData(EnrollmentGrantStatus.Unknown, EnrollmentGrantStatusDiagnostic.ConnectionUnavailable, 100, null)]
    [InlineData(EnrollmentGrantStatus.Expired, EnrollmentGrantStatusDiagnostic.None, 599, null)]
    [InlineData(EnrollmentGrantStatus.Consumed, EnrollmentGrantStatusDiagnostic.None, 500, 600)]
    [InlineData(EnrollmentGrantStatus.Consumed, EnrollmentGrantStatusDiagnostic.None, 500, -1)]
    [InlineData(EnrollmentGrantStatus.Revoked, EnrollmentGrantStatusDiagnostic.None, 500, 501)]
    public void CandidateRejectsContradictoryDiagnosticsAndTimes(
        EnrollmentGrantStatus state,
        EnrollmentGrantStatusDiagnostic diagnostic,
        int? observedSeconds,
        int? changedSeconds) =>
        Assert.False(TryCandidate(state, diagnostic, Time(observedSeconds), Time(changedSeconds), out _));

    [Fact]
    public void CandidateRejectsIdentityEnumAndCanonicalTimeFailures()
    {
        Assert.False(EnrollmentGrantStatusObservationCandidate.TryCreate(
            Guid.Empty, Guid.NewGuid(), Guid.NewGuid(), EnrollmentGrantStatus.Unknown,
            EnrollmentGrantStatusDiagnostic.ReceiptUnavailable, null, null, Created, Expires, out _));
        Assert.False(TryCandidate((EnrollmentGrantStatus)99,
            EnrollmentGrantStatusDiagnostic.ResponseUnavailable, null, null, out _));
        Assert.False(TryCandidate(EnrollmentGrantStatus.Unknown,
            (EnrollmentGrantStatusDiagnostic)99, null, null, out _));
        Assert.False(TryCandidate(EnrollmentGrantStatus.Available,
            EnrollmentGrantStatusDiagnostic.None, At(100).ToOffset(TimeSpan.FromHours(1)), null, out _));
        Assert.False(TryCandidate(EnrollmentGrantStatus.Available,
            EnrollmentGrantStatusDiagnostic.None, At(100).AddTicks(1), null, out _));
        Assert.False(EnrollmentGrantStatusObservationCandidate.TryCreate(
            Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), EnrollmentGrantStatus.Available,
            EnrollmentGrantStatusDiagnostic.None, At(100), null,
            DateTimeOffset.MinValue, Expires, out _));
        Assert.False(EnrollmentGrantStatusObservationCandidate.TryCreate(
            Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), EnrollmentGrantStatus.Available,
            EnrollmentGrantStatusDiagnostic.None, At(100), null,
            Created, DateTimeOffset.MaxValue, out _));
        Assert.False(EnrollmentGrantStatusObservationCandidate.TryCreate(
            Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), EnrollmentGrantStatus.Available,
            EnrollmentGrantStatusDiagnostic.None, At(100), null,
            Expires, Expires, out _));
    }

    [Fact]
    public void AvailableRecordRequiresTheExactBoundedDatabaseWindow()
    {
        var candidate = Candidate(EnrollmentGrantStatus.Available,
            EnrollmentGrantStatusDiagnostic.None, At(100), null);
        var recorded = At(110);
        var until = At(115);

        Assert.True(Normalize(candidate, recorded, until, out var record));
        Assert.NotNull(record);
        Assert.Equal(1, record.Sequence);
        Assert.Equal(until, record.AvailableUntil);
        Assert.Equal(nameof(EnrollmentGrantStatusObservationRecord), record.ToString());
        Assert.False(Normalize(candidate, recorded, At(116), out _));
        Assert.False(Normalize(candidate, At(115), At(115), out _));
        Assert.False(Normalize(candidate, At(99), At(114), out _));
    }

    [Fact]
    public void AvailableWindowClampsToExpiryWithoutOverflow()
    {
        var expires = new DateTimeOffset(DateTimeOffset.MaxValue.Ticks - 9, TimeSpan.Zero);
        var observed = expires.AddSeconds(-5);
        Assert.True(EnrollmentGrantStatusObservationCandidate.TryCreate(
            Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), EnrollmentGrantStatus.Available,
            EnrollmentGrantStatusDiagnostic.None, observed, null, observed.AddSeconds(-1), expires,
            out var candidate));

        Assert.True(Normalize(candidate!, observed.AddSeconds(1), expires, out var record));
        Assert.Equal(expires, record!.AvailableUntil);
    }

    [Theory]
    [InlineData(EnrollmentGrantStatus.Unknown, EnrollmentGrantStatusDiagnostic.OperationConflict, null, null, 200)]
    [InlineData(EnrollmentGrantStatus.Expired, EnrollmentGrantStatusDiagnostic.None, 600, null, 601)]
    [InlineData(EnrollmentGrantStatus.Consumed, EnrollmentGrantStatusDiagnostic.None, 500, 499, 501)]
    [InlineData(EnrollmentGrantStatus.Revoked, EnrollmentGrantStatusDiagnostic.None, 700, 650, 701)]
    public void NonAvailableRecordsRequireNoAvailabilityWindowAndOrderedDatabaseTime(
        EnrollmentGrantStatus state,
        EnrollmentGrantStatusDiagnostic diagnostic,
        int? observedSeconds,
        int? changedSeconds,
        int recordedSeconds)
    {
        var candidate = Candidate(state, diagnostic, Time(observedSeconds), Time(changedSeconds));
        Assert.True(Normalize(candidate, At(recordedSeconds), null, out _));
        Assert.False(Normalize(candidate, At(recordedSeconds), At(recordedSeconds + 1), out _));
        if (observedSeconds is not null)
            Assert.False(Normalize(candidate, At(observedSeconds.Value - 1), null, out _));
    }

    [Fact]
    public void NormalizationBindsEveryReplayFieldAndRejectsInvalidPersistenceMetadata()
    {
        var candidate = Candidate(EnrollmentGrantStatus.Unknown,
            EnrollmentGrantStatusDiagnostic.PrivilegeAuditFailed, null, null);
        Assert.False(Normalize(candidate, At(200), null, out _, observationId: Guid.NewGuid()));
        Assert.False(Normalize(candidate, At(200), null, out _, environmentId: Guid.NewGuid()));
        Assert.False(Normalize(candidate, At(200), null, out _, operationId: Guid.NewGuid()));
        Assert.False(Normalize(candidate, At(200), null, out _, state: EnrollmentGrantStatus.Expired));
        Assert.False(Normalize(candidate, At(200), null, out _, diagnostic: EnrollmentGrantStatusDiagnostic.ConnectionUnavailable));
        Assert.False(Normalize(candidate, At(200), null, out _, privateObservedAt: At(100)));
        Assert.False(Normalize(candidate, At(200), null, out _, sequence: 0));
        Assert.False(Normalize(candidate, At(200).AddTicks(1), null, out _));
        Assert.False(Normalize(candidate, DateTimeOffset.MaxValue, null, out _));

        var available = Candidate(EnrollmentGrantStatus.Available,
            EnrollmentGrantStatusDiagnostic.None, At(100), null);
        Assert.False(EnrollmentGrantStatusObservationRecord.TryNormalize(
            available, available.ObservationId, available.EnvironmentId, available.OperationId,
            available.State, available.Diagnostic, null, null, 1, At(101), At(115), out _));

        var consumed = Candidate(EnrollmentGrantStatus.Consumed,
            EnrollmentGrantStatusDiagnostic.None, At(500), At(499));
        Assert.False(EnrollmentGrantStatusObservationRecord.TryNormalize(
            consumed, consumed.ObservationId, consumed.EnvironmentId, consumed.OperationId,
            consumed.State, consumed.Diagnostic, consumed.PrivateObservedAt, null,
            1, At(501), null, out _));
    }

    private static bool TryCandidate(
        EnrollmentGrantStatus state,
        EnrollmentGrantStatusDiagnostic diagnostic,
        DateTimeOffset? observed,
        DateTimeOffset? changed,
        out EnrollmentGrantStatusObservationCandidate? candidate) =>
        EnrollmentGrantStatusObservationCandidate.TryCreate(
            Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), state, diagnostic, observed, changed,
            Created, Expires, out candidate);

    private static EnrollmentGrantStatusObservationCandidate Candidate(
        EnrollmentGrantStatus state,
        EnrollmentGrantStatusDiagnostic diagnostic,
        DateTimeOffset? observed,
        DateTimeOffset? changed)
    {
        Assert.True(TryCandidate(state, diagnostic, observed, changed, out var candidate));
        return candidate!;
    }

    private static bool Normalize(
        EnrollmentGrantStatusObservationCandidate candidate,
        DateTimeOffset recordedAt,
        DateTimeOffset? availableUntil,
        out EnrollmentGrantStatusObservationRecord? record,
        Guid? observationId = null,
        Guid? environmentId = null,
        Guid? operationId = null,
        EnrollmentGrantStatus? state = null,
        EnrollmentGrantStatusDiagnostic? diagnostic = null,
        DateTimeOffset? privateObservedAt = null,
        bool overridePrivateObservedAt = false,
        DateTimeOffset? stateChangedAt = null,
        bool overrideStateChangedAt = false,
        long sequence = 1) => EnrollmentGrantStatusObservationRecord.TryNormalize(
            candidate,
            observationId ?? candidate.ObservationId,
            environmentId ?? candidate.EnvironmentId,
            operationId ?? candidate.OperationId,
            state ?? candidate.State,
            diagnostic ?? candidate.Diagnostic,
            overridePrivateObservedAt ? privateObservedAt : privateObservedAt ?? candidate.PrivateObservedAt,
            overrideStateChangedAt ? stateChangedAt : stateChangedAt ?? candidate.StateChangedAt,
            sequence,
            recordedAt,
            availableUntil,
            out record);

    private static DateTimeOffset At(int seconds) =>
        new DateTimeOffset(2026, 9, 12, 0, 0, 0, TimeSpan.Zero).AddSeconds(seconds);

    private static DateTimeOffset? Time(int? seconds) => seconds is null ? null : At(seconds.Value);
}
