using ItManagement.EnrollmentGrantDelivery;
using Xunit;

namespace EnrollmentGrantDelivery.Tests;

public sealed class EnrollmentGrantStatusObservationWriteResultTests
{
    private static readonly DateTimeOffset Created = At(0);
    private static readonly DateTimeOffset Expires = At(600);

    [Theory]
    [InlineData("Recorded", EnrollmentGrantStatusObservationWriteOutcome.Recorded)]
    [InlineData("AlreadyRecorded", EnrollmentGrantStatusObservationWriteOutcome.AlreadyRecorded)]
    public void RecordedOutcomesRequireExactExpectedCandidate(
        string databaseOutcome,
        EnrollmentGrantStatusObservationWriteOutcome expectedOutcome)
    {
        var candidate = AvailableCandidate();
        var result = Normalize(candidate, databaseOutcome, availableUntil: At(115));

        Assert.Equal(expectedOutcome, result.Outcome);
        Assert.NotNull(result.Evidence);
        Assert.Equal(candidate.ObservationId, result.Evidence.ObservationId);
        Assert.Equal(7, result.Evidence.Sequence);
        Assert.Equal(nameof(EnrollmentGrantStatusObservationWriteResult), result.ToString());
    }

    [Theory]
    [InlineData("Consumed", 500, 499)]
    [InlineData("Revoked", 700, 650)]
    [InlineData("Expired", 600, null)]
    public void TerminalReturnsExistingTerminalEvidence(
        string state,
        int observedSeconds,
        int? changedSeconds)
    {
        var expected = AvailableCandidate();
        var priorId = Guid.NewGuid();
        var result = Normalize(expected, "Terminal", observationId: priorId, state: state,
            privateObservedAt: At(observedSeconds),
            privateStateChangedAt: changedSeconds is { } changed ? At(changed) : null,
            recordedAt: At(observedSeconds + 1), availableUntil: null);

        Assert.Equal(EnrollmentGrantStatusObservationWriteOutcome.Terminal, result.Outcome);
        Assert.Equal(priorId, result.Evidence!.ObservationId);
        Assert.Equal(expected.EnvironmentId, result.Evidence.EnvironmentId);
        Assert.Equal(expected.OperationId, result.Evidence.OperationId);
        Assert.Equal(state, result.Evidence.State.ToString());
    }

    [Fact]
    public void TerminalRejectsNewObservationIdentityAndNonterminalEvidence()
    {
        var expected = AvailableCandidate();
        AssertUnknown(Normalize(expected, "Terminal", state: "Consumed", privateObservedAt: At(500),
            privateStateChangedAt: At(499), recordedAt: At(501), availableUntil: null));
        AssertUnknown(Normalize(expected, "Terminal", observationId: Guid.NewGuid(), state: "Available",
            privateObservedAt: At(100), recordedAt: At(110), availableUntil: At(115)));
        AssertUnknown(Normalize(expected, "Terminal", observationId: Guid.NewGuid(), state: "Unknown",
            diagnostic: "ResponseUnavailable", privateObservedAt: null, useExpectedPrivateObservedAt: false,
            recordedAt: At(110), availableUntil: null));
    }

    [Fact]
    public void TerminalBindsEnvironmentOperationAndGrantTimeRules()
    {
        var expected = AvailableCandidate();
        AssertUnknown(Normalize(expected, "Terminal", observationId: Guid.NewGuid(), environmentId: Guid.NewGuid(),
            state: "Expired", privateObservedAt: At(600), recordedAt: At(601), availableUntil: null));
        AssertUnknown(Normalize(expected, "Terminal", observationId: Guid.NewGuid(), operationId: Guid.NewGuid(),
            state: "Revoked", privateObservedAt: At(400), privateStateChangedAt: At(-1),
            recordedAt: At(401), availableUntil: null));
        AssertUnknown(Normalize(expected, "Terminal", observationId: Guid.NewGuid(), state: "Expired",
            privateObservedAt: At(599), recordedAt: At(601), availableUntil: null));
    }

    [Fact]
    public void NotFoundRequiresEveryPayloadColumnNull()
    {
        var expected = AvailableCandidate();
        var valid = EnrollmentGrantStatusObservationWriteResult.Normalize(
            expected, 1, "NotFound", null, null, null, null, null, null, null, null, null, null);
        Assert.Equal(EnrollmentGrantStatusObservationWriteOutcome.NotFound, valid.Outcome);
        Assert.Null(valid.Evidence);

        var residue = EnrollmentGrantStatusObservationWriteResult.Normalize(
            expected, 1, "NotFound", null, null, null, null, null, null, null, null, At(1), null);
        AssertUnknown(residue);
    }

    [Theory]
    [InlineData((short)0, "Recorded")]
    [InlineData((short)2, "Recorded")]
    [InlineData((short)1, "OutcomeUnknown")]
    [InlineData((short)1, "recorded")]
    [InlineData((short)1, "FutureOutcome")]
    public void UnknownVersionOrOutcomeReturnsNoEvidence(short version, string outcome)
    {
        var result = Normalize(AvailableCandidate(), outcome, contractVersion: version, availableUntil: At(115));
        AssertUnknown(result);
    }

    [Fact]
    public void RecordedMalformedReplayOrPersistenceShapeReturnsNoEvidence()
    {
        var candidate = AvailableCandidate();
        AssertUnknown(Normalize(candidate, "Recorded", observationId: Guid.NewGuid(), availableUntil: At(115)));
        AssertUnknown(Normalize(candidate, "Recorded", environmentId: Guid.NewGuid(), availableUntil: At(115)));
        AssertUnknown(Normalize(candidate, "Recorded", operationId: Guid.NewGuid(), availableUntil: At(115)));
        AssertUnknown(Normalize(candidate, "Recorded", sequence: 0, availableUntil: At(115)));
        AssertUnknown(Normalize(candidate, "Recorded", state: "Expired", availableUntil: At(115)));
        AssertUnknown(Normalize(candidate, "Recorded", diagnostic: "ResponseUnavailable", availableUntil: At(115)));
        AssertUnknown(Normalize(candidate, "Recorded", privateObservedAt: null,
            useExpectedPrivateObservedAt: false, availableUntil: At(115)));
        AssertUnknown(Normalize(candidate, "Recorded", recordedAt: At(110).AddTicks(1), availableUntil: At(115)));
        AssertUnknown(Normalize(candidate, "Recorded", availableUntil: null));
    }

    [Fact]
    public void NullAndUnknownTypedFieldsReturnNoEvidence()
    {
        var candidate = AvailableCandidate();
        AssertUnknown(Normalize(candidate, "Recorded", state: null, availableUntil: At(115)));
        AssertUnknown(Normalize(candidate, "Recorded", diagnostic: null, availableUntil: At(115)));
        AssertUnknown(Normalize(candidate, "Recorded", recordedAt: null,
            useDefaultRecordedAt: false, availableUntil: At(115)));
        AssertUnknown(Normalize(candidate, "Recorded", state: "FutureState", availableUntil: At(115)));
        AssertUnknown(Normalize(candidate, "Recorded", diagnostic: "FutureDiagnostic", availableUntil: At(115)));
    }

    private static EnrollmentGrantStatusObservationCandidate AvailableCandidate()
    {
        Assert.True(EnrollmentGrantStatusObservationCandidate.TryCreate(
            Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), EnrollmentGrantStatus.Available,
            EnrollmentGrantStatusDiagnostic.None, At(100), null, Created, Expires, out var candidate));
        return candidate!;
    }

    private static EnrollmentGrantStatusObservationWriteResult Normalize(
        EnrollmentGrantStatusObservationCandidate candidate,
        string? outcome,
        short contractVersion = 1,
        Guid? observationId = null,
        Guid? environmentId = null,
        Guid? operationId = null,
        long? sequence = 7,
        string? state = "Available",
        string? diagnostic = "None",
        DateTimeOffset? privateObservedAt = default,
        bool useExpectedPrivateObservedAt = true,
        DateTimeOffset? privateStateChangedAt = null,
        DateTimeOffset? recordedAt = default,
        bool useDefaultRecordedAt = true,
        DateTimeOffset? availableUntil = default)
    {
        if (useExpectedPrivateObservedAt) privateObservedAt ??= candidate.PrivateObservedAt;
        if (useDefaultRecordedAt) recordedAt ??= At(110);
        return EnrollmentGrantStatusObservationWriteResult.Normalize(
            candidate, contractVersion, outcome, observationId ?? candidate.ObservationId,
            environmentId ?? candidate.EnvironmentId, operationId ?? candidate.OperationId,
            sequence, state, diagnostic, privateObservedAt, privateStateChangedAt, recordedAt, availableUntil);
    }

    private static void AssertUnknown(EnrollmentGrantStatusObservationWriteResult result)
    {
        Assert.Equal(EnrollmentGrantStatusObservationWriteOutcome.OutcomeUnknown, result.Outcome);
        Assert.Null(result.Evidence);
    }

    private static DateTimeOffset At(int seconds) =>
        new DateTimeOffset(2026, 9, 12, 0, 0, 0, TimeSpan.Zero).AddSeconds(seconds);
}
