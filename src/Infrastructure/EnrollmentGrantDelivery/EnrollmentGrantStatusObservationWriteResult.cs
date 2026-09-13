namespace ItManagement.EnrollmentGrantDelivery;

public enum EnrollmentGrantStatusObservationWriteOutcome
{
    Recorded,
    AlreadyRecorded,
    Terminal,
    NotFound,
    OutcomeUnknown
}

public sealed class EnrollmentGrantStatusObservationWriteResult
{
    private EnrollmentGrantStatusObservationWriteResult(
        EnrollmentGrantStatusObservationWriteOutcome outcome,
        EnrollmentGrantStatusObservationRecord? evidence)
    {
        Outcome = outcome;
        Evidence = evidence;
    }

    public EnrollmentGrantStatusObservationWriteOutcome Outcome { get; }
    public EnrollmentGrantStatusObservationRecord? Evidence { get; }

    public static EnrollmentGrantStatusObservationWriteResult Normalize(
        EnrollmentGrantStatusObservationCandidate expected,
        short contractVersion,
        string? outcome,
        Guid? observationId,
        Guid? environmentId,
        Guid? operationId,
        long? sequence,
        string? state,
        string? diagnostic,
        DateTimeOffset? privateObservedAt,
        DateTimeOffset? privateStateChangedAt,
        DateTimeOffset? recordedAt,
        DateTimeOffset? availableUntil)
    {
        ArgumentNullException.ThrowIfNull(expected);
        if (contractVersion != 1)
            return Unknown();

        if (outcome == "NotFound")
            return AllPayloadNull(observationId, environmentId, operationId, sequence, state, diagnostic,
                privateObservedAt, privateStateChangedAt, recordedAt, availableUntil)
                ? new(EnrollmentGrantStatusObservationWriteOutcome.NotFound, null)
                : Unknown();

        if (!TryOutcome(outcome, out var parsedOutcome) ||
            observationId is not { } returnedObservationId ||
            environmentId is not { } returnedEnvironmentId ||
            operationId is not { } returnedOperationId ||
            sequence is not { } returnedSequence ||
            !TryState(state, out var returnedState) ||
            !TryDiagnostic(diagnostic, out var returnedDiagnostic) ||
            recordedAt is not { } returnedRecordedAt)
            return Unknown();

        if (parsedOutcome is EnrollmentGrantStatusObservationWriteOutcome.Recorded or
            EnrollmentGrantStatusObservationWriteOutcome.AlreadyRecorded)
        {
            return EnrollmentGrantStatusObservationRecord.TryNormalize(
                expected, returnedObservationId, returnedEnvironmentId, returnedOperationId,
                returnedState, returnedDiagnostic, privateObservedAt, privateStateChangedAt,
                returnedSequence, returnedRecordedAt, availableUntil, out var evidence)
                ? new(parsedOutcome, evidence)
                : Unknown();
        }

        if (returnedObservationId == expected.ObservationId ||
            returnedEnvironmentId != expected.EnvironmentId || returnedOperationId != expected.OperationId ||
            returnedState is not (EnrollmentGrantStatus.Consumed or EnrollmentGrantStatus.Revoked or
                EnrollmentGrantStatus.Expired) || availableUntil is not null ||
            !EnrollmentGrantStatusObservationCandidate.TryCreate(
                returnedObservationId, returnedEnvironmentId, returnedOperationId, returnedState,
                returnedDiagnostic, privateObservedAt, privateStateChangedAt,
                expected.GrantCreatedAt, expected.GrantExpiresAt, out var terminalCandidate) ||
            !EnrollmentGrantStatusObservationRecord.TryNormalize(
                terminalCandidate!, returnedObservationId, returnedEnvironmentId, returnedOperationId,
                returnedState, returnedDiagnostic, privateObservedAt, privateStateChangedAt,
                returnedSequence, returnedRecordedAt, null, out var terminalEvidence))
            return Unknown();

        return new(EnrollmentGrantStatusObservationWriteOutcome.Terminal, terminalEvidence);
    }

    public override string ToString() => nameof(EnrollmentGrantStatusObservationWriteResult);

    internal static EnrollmentGrantStatusObservationWriteResult Unknown() =>
        new(EnrollmentGrantStatusObservationWriteOutcome.OutcomeUnknown, null);

    private static bool AllPayloadNull(
        Guid? observationId,
        Guid? environmentId,
        Guid? operationId,
        long? sequence,
        string? state,
        string? diagnostic,
        DateTimeOffset? privateObservedAt,
        DateTimeOffset? privateStateChangedAt,
        DateTimeOffset? recordedAt,
        DateTimeOffset? availableUntil) =>
        observationId is null && environmentId is null && operationId is null && sequence is null &&
        state is null && diagnostic is null && privateObservedAt is null && privateStateChangedAt is null &&
        recordedAt is null && availableUntil is null;

    private static bool TryOutcome(string? value, out EnrollmentGrantStatusObservationWriteOutcome outcome)
    {
        outcome = value switch
        {
            "Recorded" => EnrollmentGrantStatusObservationWriteOutcome.Recorded,
            "AlreadyRecorded" => EnrollmentGrantStatusObservationWriteOutcome.AlreadyRecorded,
            "Terminal" => EnrollmentGrantStatusObservationWriteOutcome.Terminal,
            _ => EnrollmentGrantStatusObservationWriteOutcome.OutcomeUnknown
        };
        return value is "Recorded" or "AlreadyRecorded" or "Terminal";
    }

    private static bool TryState(string? value, out EnrollmentGrantStatus state)
    {
        state = value switch
        {
            "Available" => EnrollmentGrantStatus.Available,
            "Unknown" => EnrollmentGrantStatus.Unknown,
            "Consumed" => EnrollmentGrantStatus.Consumed,
            "Revoked" => EnrollmentGrantStatus.Revoked,
            "Expired" => EnrollmentGrantStatus.Expired,
            _ => default
        };
        return value is "Available" or "Unknown" or "Consumed" or "Revoked" or "Expired";
    }

    private static bool TryDiagnostic(string? value, out EnrollmentGrantStatusDiagnostic diagnostic)
    {
        diagnostic = value switch
        {
            "None" => EnrollmentGrantStatusDiagnostic.None,
            "ResponseUnavailable" => EnrollmentGrantStatusDiagnostic.ResponseUnavailable,
            "ConnectionUnavailable" => EnrollmentGrantStatusDiagnostic.ConnectionUnavailable,
            "ReceiptUnavailable" => EnrollmentGrantStatusDiagnostic.ReceiptUnavailable,
            "OperationConflict" => EnrollmentGrantStatusDiagnostic.OperationConflict,
            "PrivilegeAuditFailed" => EnrollmentGrantStatusDiagnostic.PrivilegeAuditFailed,
            _ => default
        };
        return value is "None" or "ResponseUnavailable" or "ConnectionUnavailable" or
            "ReceiptUnavailable" or "OperationConflict" or "PrivilegeAuditFailed";
    }
}
