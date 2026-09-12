namespace ItManagement.EnrollmentGrantExecution;

public enum EnrollmentWorkClaimOutcome
{
    Claimed, Existing, NoWork, AlreadyDeferred, AlreadyCompleted, StaleClaim, TokenConflict, OutcomeUnknown
}

public enum EnrollmentWorkTransitionOutcome
{
    Deferred, AlreadyDeferred, Completed, AlreadyCompleted, StaleClaim, NotTerminal, NotFound, TokenConflict, OutcomeUnknown
}

public enum EnrollmentWorkRetryReason { Retryable, OutcomeUnknown }

public sealed record EnrollmentWorkClaim(Guid EnvironmentId, Guid OperationId, Guid ClaimToken,
    int Attempt, DateTimeOffset ClaimedAt, DateTimeOffset LeaseUntil);

public sealed record EnrollmentWorkClaimResult(EnrollmentWorkClaimOutcome Outcome,
    DateTimeOffset? QueriedAt = null, EnrollmentWorkClaim? Claim = null);

public sealed record EnrollmentWorkTransitionResult(EnrollmentWorkTransitionOutcome Outcome,
    DateTimeOffset? QueriedAt = null, DateTimeOffset? NextAttemptAt = null);

/// <summary>One audited environment pool; leases schedule work but do not authorize grant issuance.</summary>
public interface IEnrollmentGrantWorkQueue
{
    Task<EnrollmentWorkClaimResult> ClaimNextAsync(Guid claimToken, CancellationToken cancellationToken);
    Task<EnrollmentWorkTransitionResult> DeferAsync(EnrollmentWorkClaim claim,
        EnrollmentWorkRetryReason reason, CancellationToken cancellationToken);
    Task<EnrollmentWorkTransitionResult> CompleteAsync(EnrollmentWorkClaim claim, CancellationToken cancellationToken);
}

public interface IEnrollmentGrantExecutor
{
    Task<EnrollmentGrantExecutionResult> ExecuteAsync(Guid environmentId, Guid operationId, CancellationToken cancellationToken);
}
