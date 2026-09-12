using ItManagement.AgentPlatformGrants;

namespace ItManagement.EnrollmentGrantExecution;

public interface IEnrollmentGrantExecutionStore
{
    Task<EnrollmentGrantStoreReadResult> ReadAsync(Guid environmentId, Guid operationId, CancellationToken cancellationToken);
    Task<EnrollmentGrantPermitStoreResult> AuthorizeAndStoreCandidateAsync(
        EnrollmentGrantExecutionOperation operation, EnrollmentGrantEnvelopeCandidate candidate, CancellationToken cancellationToken);
    Task<EnrollmentGrantRecordResult> RecordDefiniteResultAsync(EnrollmentGrantExecutionOperation operation,
        PersistedEnrollmentGrantPermit permit, EnrollmentGrantDefiniteResult result, CancellationToken cancellationToken);
    Task<EnrollmentGrantRecordResult> QuarantineAsync(Guid environmentId, Guid operationId,
        EnrollmentGrantExecutionOperation? observedOperation, PersistedEnrollmentGrantPermit? permit,
        EnrollmentGrantExecutionStopReason reason, CancellationToken cancellationToken);
}

public interface IPlatformGrantIssuer
{
    Task<PlatformGrantResult> IssueAsync(Guid operationId, ValidatedGrantAuthorization authorization,
        ValidatedPersistedPlatformGrant persistedGrant, CancellationToken cancellationToken);
}

public sealed class PostgresPlatformGrantIssuer(PostgresPlatformGrantRepository repository) : IPlatformGrantIssuer
{
    public Task<PlatformGrantResult> IssueAsync(Guid operationId, ValidatedGrantAuthorization authorization,
        ValidatedPersistedPlatformGrant persistedGrant, CancellationToken cancellationToken) =>
        repository.IssueAsync(operationId, authorization, persistedGrant, cancellationToken);
}
