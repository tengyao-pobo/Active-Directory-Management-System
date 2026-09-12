namespace ItManagement.EnrollmentGrantDelivery;

public enum EnrollmentGrantStatus
{
    Available,
    Unknown,
    Consumed,
    Revoked,
    Expired
}

public enum EnrollmentGrantStatusDiagnostic
{
    None,
    ResponseUnavailable,
    ConnectionUnavailable,
    ReceiptUnavailable,
    OperationConflict,
    PrivilegeAuditFailed
}

public sealed class EnrollmentGrantStatusObservationCandidate
{
    private EnrollmentGrantStatusObservationCandidate(
        Guid observationId,
        Guid environmentId,
        Guid operationId,
        EnrollmentGrantStatus state,
        EnrollmentGrantStatusDiagnostic diagnostic,
        DateTimeOffset? privateObservedAt,
        DateTimeOffset? stateChangedAt,
        DateTimeOffset grantCreatedAt,
        DateTimeOffset grantExpiresAt)
    {
        ObservationId = observationId;
        EnvironmentId = environmentId;
        OperationId = operationId;
        State = state;
        Diagnostic = diagnostic;
        PrivateObservedAt = privateObservedAt;
        StateChangedAt = stateChangedAt;
        GrantCreatedAt = grantCreatedAt;
        GrantExpiresAt = grantExpiresAt;
    }

    public Guid ObservationId { get; }
    public Guid EnvironmentId { get; }
    public Guid OperationId { get; }
    public EnrollmentGrantStatus State { get; }
    public EnrollmentGrantStatusDiagnostic Diagnostic { get; }
    public DateTimeOffset? PrivateObservedAt { get; }
    public DateTimeOffset? StateChangedAt { get; }
    internal DateTimeOffset GrantCreatedAt { get; }
    internal DateTimeOffset GrantExpiresAt { get; }

    public static bool TryCreate(
        Guid observationId,
        Guid environmentId,
        Guid operationId,
        EnrollmentGrantStatus state,
        EnrollmentGrantStatusDiagnostic diagnostic,
        DateTimeOffset? privateObservedAt,
        DateTimeOffset? stateChangedAt,
        DateTimeOffset grantCreatedAt,
        DateTimeOffset grantExpiresAt,
        out EnrollmentGrantStatusObservationCandidate? candidate)
    {
        candidate = null;
        if (observationId == Guid.Empty || environmentId == Guid.Empty || operationId == Guid.Empty ||
            !Enum.IsDefined(state) || !Enum.IsDefined(diagnostic) ||
            !CanonicalTime(grantCreatedAt) || !CanonicalTime(grantExpiresAt) ||
            grantCreatedAt >= grantExpiresAt ||
            privateObservedAt is { } observed && !CanonicalTime(observed) ||
            stateChangedAt is { } changed && !CanonicalTime(changed) ||
            !ValidState(state, diagnostic, privateObservedAt, stateChangedAt, grantCreatedAt, grantExpiresAt))
            return false;

        candidate = new EnrollmentGrantStatusObservationCandidate(
            observationId, environmentId, operationId, state, diagnostic, privateObservedAt, stateChangedAt,
            grantCreatedAt, grantExpiresAt);
        return true;
    }

    public override string ToString() => nameof(EnrollmentGrantStatusObservationCandidate);

    internal static bool CanonicalTime(DateTimeOffset value) =>
        value != DateTimeOffset.MinValue && value != DateTimeOffset.MaxValue &&
        value.Offset == TimeSpan.Zero && value.Ticks % 10 == 0;

    private static bool ValidState(
        EnrollmentGrantStatus state,
        EnrollmentGrantStatusDiagnostic diagnostic,
        DateTimeOffset? observed,
        DateTimeOffset? changed,
        DateTimeOffset created,
        DateTimeOffset expires) => state switch
    {
        EnrollmentGrantStatus.Unknown => diagnostic != EnrollmentGrantStatusDiagnostic.None &&
            observed is null && changed is null,
        EnrollmentGrantStatus.Available => diagnostic == EnrollmentGrantStatusDiagnostic.None &&
            observed is { } availableAt && availableAt >= created && availableAt < expires && changed is null,
        EnrollmentGrantStatus.Expired => diagnostic == EnrollmentGrantStatusDiagnostic.None &&
            observed is { } expiredAt && expiredAt >= expires && changed is null,
        EnrollmentGrantStatus.Consumed => diagnostic == EnrollmentGrantStatusDiagnostic.None &&
            observed is { } consumedObserved && changed is { } consumedAt &&
            consumedAt >= created && consumedAt <= consumedObserved && consumedAt < expires,
        EnrollmentGrantStatus.Revoked => diagnostic == EnrollmentGrantStatusDiagnostic.None &&
            observed is { } revokedObserved && changed is { } revokedAt &&
            revokedAt >= created && revokedAt <= revokedObserved,
        _ => false
    };
}

public sealed class EnrollmentGrantStatusObservationRecord
{
    private static readonly TimeSpan ObservationFreshness = TimeSpan.FromSeconds(15);

    private EnrollmentGrantStatusObservationRecord(
        EnrollmentGrantStatusObservationCandidate candidate,
        long sequence,
        DateTimeOffset publicRecordedAt,
        DateTimeOffset? availableUntil)
    {
        ObservationId = candidate.ObservationId;
        EnvironmentId = candidate.EnvironmentId;
        OperationId = candidate.OperationId;
        State = candidate.State;
        Diagnostic = candidate.Diagnostic;
        PrivateObservedAt = candidate.PrivateObservedAt;
        StateChangedAt = candidate.StateChangedAt;
        Sequence = sequence;
        PublicRecordedAt = publicRecordedAt;
        AvailableUntil = availableUntil;
    }

    public Guid ObservationId { get; }
    public Guid EnvironmentId { get; }
    public Guid OperationId { get; }
    public EnrollmentGrantStatus State { get; }
    public EnrollmentGrantStatusDiagnostic Diagnostic { get; }
    public DateTimeOffset? PrivateObservedAt { get; }
    public DateTimeOffset? StateChangedAt { get; }
    public long Sequence { get; }
    public DateTimeOffset PublicRecordedAt { get; }
    public DateTimeOffset? AvailableUntil { get; }

    public static bool TryNormalize(
        EnrollmentGrantStatusObservationCandidate expected,
        Guid observationId,
        Guid environmentId,
        Guid operationId,
        EnrollmentGrantStatus state,
        EnrollmentGrantStatusDiagnostic diagnostic,
        DateTimeOffset? privateObservedAt,
        DateTimeOffset? stateChangedAt,
        long sequence,
        DateTimeOffset publicRecordedAt,
        DateTimeOffset? availableUntil,
        out EnrollmentGrantStatusObservationRecord? record)
    {
        ArgumentNullException.ThrowIfNull(expected);
        record = null;
        if (observationId != expected.ObservationId || environmentId != expected.EnvironmentId ||
            operationId != expected.OperationId || state != expected.State || diagnostic != expected.Diagnostic ||
            privateObservedAt != expected.PrivateObservedAt || stateChangedAt != expected.StateChangedAt ||
            sequence < 1 || !EnrollmentGrantStatusObservationCandidate.CanonicalTime(publicRecordedAt) ||
            availableUntil is { } until && !EnrollmentGrantStatusObservationCandidate.CanonicalTime(until))
            return false;

        var valid = state switch
        {
            EnrollmentGrantStatus.Unknown => availableUntil is null,
            EnrollmentGrantStatus.Available => ValidAvailable(expected, publicRecordedAt, availableUntil),
            EnrollmentGrantStatus.Expired or EnrollmentGrantStatus.Consumed or EnrollmentGrantStatus.Revoked =>
                availableUntil is null && privateObservedAt is { } observed && observed <= publicRecordedAt,
            _ => false
        };
        if (!valid) return false;

        record = new EnrollmentGrantStatusObservationRecord(expected, sequence, publicRecordedAt, availableUntil);
        return true;
    }

    public override string ToString() => nameof(EnrollmentGrantStatusObservationRecord);

    private static bool ValidAvailable(
        EnrollmentGrantStatusObservationCandidate candidate,
        DateTimeOffset recordedAt,
        DateTimeOffset? availableUntil)
    {
        if (candidate.PrivateObservedAt is not { } observed || observed > recordedAt ||
            recordedAt - observed >= ObservationFreshness)
            return false;

        var expectedUntil = Minimum(
            ClampedAdd(observed, ObservationFreshness),
            ClampedAdd(recordedAt, ObservationFreshness),
            candidate.GrantExpiresAt);
        return availableUntil == expectedUntil && expectedUntil > recordedAt;
    }

    private static DateTimeOffset ClampedAdd(DateTimeOffset value, TimeSpan increment) =>
        DateTimeOffset.MaxValue - value < increment ? DateTimeOffset.MaxValue : value + increment;

    private static DateTimeOffset Minimum(DateTimeOffset first, DateTimeOffset second, DateTimeOffset third) =>
        first <= second ? first <= third ? first : third : second <= third ? second : third;
}
