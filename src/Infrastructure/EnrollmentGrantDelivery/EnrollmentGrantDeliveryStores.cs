using ItManagement.AgentPlatformGrants;

namespace ItManagement.EnrollmentGrantDelivery;

public enum EnrollmentGrantStatusReceiptOutcome { Found, NotFound, OutcomeUnknown }

public sealed record EnrollmentGrantStatusReceiptResult(EnrollmentGrantStatusReceiptOutcome Outcome, PlatformGrantReceipt? Receipt)
{
    public override string ToString() => nameof(EnrollmentGrantStatusReceiptResult);
}

public enum EnrollmentGrantAcknowledgementOutcome { Acknowledged, AlreadyAcknowledged, NotFound, Conflict, OutcomeUnknown }

public interface IEnrollmentGrantStatusStore
{
    Task<EnrollmentGrantStatusReceiptResult> ReadReceiptAsync(Guid environmentId, Guid operationId, CancellationToken cancellationToken);
    Task<EnrollmentGrantStatusObservationWriteResult> RecordAsync(PlatformGrantReceipt receipt,
        EnrollmentGrantStatusObservationCandidate candidate, CancellationToken cancellationToken);
}

public interface IEnrollmentGrantDeliveryStore
{
    Task<EnrollmentGrantDeliveryResponse> ReadAsync(Guid environmentId, Guid operationId, Guid requesterId,
        string sessionHash, CancellationToken cancellationToken);
    Task<EnrollmentGrantAcknowledgementOutcome> AcknowledgeAsync(Guid environmentId, Guid operationId, Guid requesterId,
        string sessionHash, EnrollmentGrantDeliveryAcknowledgement acknowledgement, CancellationToken cancellationToken);
}
