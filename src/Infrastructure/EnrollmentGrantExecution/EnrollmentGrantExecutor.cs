using System.Security.Cryptography;
using ItManagement.AgentEnrollment.Crypto;
using ItManagement.AgentPlatformGrants;

namespace ItManagement.EnrollmentGrantExecution;

public sealed class EnrollmentGrantExecutor(IEnrollmentGrantExecutionStore store, IPlatformGrantIssuer issuer)
{
    public async Task<EnrollmentGrantExecutionResult> ExecuteAsync(Guid environmentId, Guid operationId,
        CancellationToken cancellationToken)
    {
        if (environmentId == Guid.Empty || operationId == Guid.Empty)
            return Unknown(PlatformGrantDiagnostic.InvalidRequest);
        var read = await store.ReadAsync(environmentId, operationId, cancellationToken).ConfigureAwait(false);
        if (read.Outcome == EnrollmentGrantStoreReadOutcome.NotFound) return new(EnrollmentGrantExecutionOutcome.NoWork, PlatformGrantDiagnostic.None);
        if (read.Outcome != EnrollmentGrantStoreReadOutcome.Found || read.Record is null) return Unknown();
        var record = read.Record;
        if (!ValidRecordIdentity(record, environmentId, operationId)) return await Quarantine(environmentId, operationId, record, EnrollmentGrantExecutionStopReason.StoredDataInvalid, cancellationToken).ConfigureAwait(false);
        var terminal = Terminal(record);
        if (terminal is not null) return terminal;
        if (record.State is EnrollmentGrantExecutionState.Completed or EnrollmentGrantExecutionState.PermanentRejected or EnrollmentGrantExecutionState.Quarantined)
            return await Quarantine(environmentId, operationId, record, EnrollmentGrantExecutionStopReason.StoredDataInvalid, cancellationToken).ConfigureAwait(false);

        var permit = record.Permit;
        var envelope = record.Envelope;
        if (permit is null)
        {
            EnrollmentGrantEnvelopeCandidate candidate;
            try
            {
                var key = EnrollmentGrantRecipientKey.Validate(record.Operation.GetRecipientSpki());
                candidate = new(SealedEnrollmentGrant.Seal(key, environmentId, operationId));
            }
            catch (SealedEnrollmentGrantException)
            {
                return await Quarantine(environmentId, operationId, record, EnrollmentGrantExecutionStopReason.StoredDataInvalid, cancellationToken).ConfigureAwait(false);
            }

            var stored = await store.AuthorizeAndStoreCandidateAsync(record.Operation, candidate, cancellationToken).ConfigureAwait(false);
            if (stored.Outcome == EnrollmentGrantPermitStoreOutcome.AuthorizationRejected)
            {
                if (stored.Permit is not null || stored.Envelope is not null || stored.StopReason is not (EnrollmentGrantExecutionStopReason.AuthorizationChanged or EnrollmentGrantExecutionStopReason.AuthorizationExpired))
                    return await Quarantine(environmentId, operationId, record, EnrollmentGrantExecutionStopReason.StoredDataInvalid, cancellationToken).ConfigureAwait(false);
                return new(EnrollmentGrantExecutionOutcome.PermanentRejected, PlatformGrantDiagnostic.None, stored.StopReason);
            }
            if (stored.Outcome == EnrollmentGrantPermitStoreOutcome.OutcomeUnknown)
            {
                var recovered = await store.ReadAsync(environmentId, operationId, cancellationToken).ConfigureAwait(false);
                if (recovered.Outcome != EnrollmentGrantStoreReadOutcome.Found || recovered.Record is null)
                    return Unknown();
                record = recovered.Record;
                if (!ValidRecordIdentity(record, environmentId, operationId)) return await Quarantine(environmentId, operationId, record, EnrollmentGrantExecutionStopReason.StoredDataInvalid, cancellationToken).ConfigureAwait(false);
                terminal = Terminal(record);
                if (terminal is not null) return terminal;
                permit = record.Permit;
                envelope = record.Envelope;
                if (permit is null || envelope is null) return Unknown();
            }
            else
            {
                if (stored.Outcome is not (EnrollmentGrantPermitStoreOutcome.Stored or EnrollmentGrantPermitStoreOutcome.Existing) ||
                    stored.Permit is null || stored.Envelope is null || stored.StopReason is not null)
                    return Unknown();
                permit = stored.Permit;
                envelope = stored.Envelope;
                record = new(record.Operation, EnrollmentGrantExecutionState.PermitStored, permit, envelope, null, null);
            }
        }

        if (envelope is null || !permit.IsValid(record.Operation) || !envelope.IsValid(permit))
            return await Quarantine(environmentId, operationId, record, EnrollmentGrantExecutionStopReason.StoredDataInvalid, cancellationToken).ConfigureAwait(false);
        var authorization = ValidatedGrantAuthorization.FromValidatedPlan(record.Operation.DirectoryObjectId,
            record.Operation.ServerDeviceId, record.Operation.MappingCreatedAt, permit.MintPermitNotAfter,
            permit.GetAuthorizationDigest());
        var persisted = ValidatedPersistedPlatformGrant.FromValidatedOutboxRecord(permit.GetTokenSha256());
        var issued = await issuer.IssueAsync(operationId, authorization, persisted, cancellationToken).ConfigureAwait(false);
        if (issued.Outcome is PlatformGrantOutcome.Created or PlatformGrantOutcome.AlreadyCreated)
        {
            if (issued.Diagnostic != PlatformGrantDiagnostic.None || issued.Receipt is null ||
                !ReceiptMatches(issued.Receipt, record.Operation, permit))
                return await Quarantine(environmentId, operationId, record, EnrollmentGrantExecutionStopReason.ReceiptMismatch, cancellationToken).ConfigureAwait(false);
            return await Record(record.Operation, permit,
                new(issued.Outcome, issued.Diagnostic, issued.Receipt), cancellationToken).ConfigureAwait(false);
        }
        if (issued.Outcome == PlatformGrantOutcome.PermanentRejected)
        {
            if (!PermanentDiagnostic(issued.Diagnostic)) return await Quarantine(environmentId, operationId, record, EnrollmentGrantExecutionStopReason.StoredDataInvalid, cancellationToken).ConfigureAwait(false);
            return await Record(record.Operation, permit,
                new(issued.Outcome, issued.Diagnostic, null), cancellationToken).ConfigureAwait(false);
        }
        if (issued.Outcome == PlatformGrantOutcome.OutcomeUnknown && issued.Diagnostic == PlatformGrantDiagnostic.OperationConflict)
            return await Quarantine(environmentId, operationId, record, EnrollmentGrantExecutionStopReason.OperationConflict, cancellationToken).ConfigureAwait(false);
        return Unknown(issued.Diagnostic);
    }

    private async Task<EnrollmentGrantExecutionResult> Record(EnrollmentGrantExecutionOperation operation,
        PersistedEnrollmentGrantPermit permit, EnrollmentGrantDefiniteResult result, CancellationToken cancellationToken)
    {
        var recorded = await store.RecordDefiniteResultAsync(operation, permit, result, cancellationToken).ConfigureAwait(false);
        if (recorded.Outcome == EnrollmentGrantRecordOutcome.Conflict)
            return await Quarantine(operation.EnvironmentId, operation.Id, new(operation, EnrollmentGrantExecutionState.PermitStored, permit, null, null, null),
                EnrollmentGrantExecutionStopReason.StoredDataInvalid, cancellationToken).ConfigureAwait(false);
        if (recorded.Outcome == EnrollmentGrantRecordOutcome.Recorded)
            return result.Outcome is PlatformGrantOutcome.Created or PlatformGrantOutcome.AlreadyCreated
                ? new(EnrollmentGrantExecutionOutcome.GrantAvailable, PlatformGrantDiagnostic.None)
                : new(EnrollmentGrantExecutionOutcome.PermanentRejected, result.Diagnostic);
        return recorded.Outcome is EnrollmentGrantRecordOutcome.AlreadyRecorded or EnrollmentGrantRecordOutcome.OutcomeUnknown
            ? await ReadBackTerminal(operation.EnvironmentId, operation.Id, cancellationToken).ConfigureAwait(false)
            : Unknown();
    }

    private async Task<EnrollmentGrantExecutionResult> Quarantine(Guid environmentId, Guid operationId,
        EnrollmentGrantExecutionRecord record,
        EnrollmentGrantExecutionStopReason reason, CancellationToken cancellationToken)
    {
        var result = await store.QuarantineAsync(environmentId, operationId, record.Operation, record.Permit, reason, cancellationToken).ConfigureAwait(false);
        if (result.Outcome == EnrollmentGrantRecordOutcome.Recorded)
            return new(EnrollmentGrantExecutionOutcome.Quarantined, PlatformGrantDiagnostic.None, reason);
        return result.Outcome is EnrollmentGrantRecordOutcome.AlreadyRecorded or EnrollmentGrantRecordOutcome.OutcomeUnknown
            ? await ReadBackTerminal(environmentId, operationId, cancellationToken).ConfigureAwait(false)
            : Unknown();
    }

    private async Task<EnrollmentGrantExecutionResult> ReadBackTerminal(Guid environmentId, Guid operationId,
        CancellationToken cancellationToken)
    {
        var read = await store.ReadAsync(environmentId, operationId, cancellationToken).ConfigureAwait(false);
        if (read.Outcome != EnrollmentGrantStoreReadOutcome.Found || read.Record is null ||
            !ValidRecordIdentity(read.Record, environmentId, operationId)) return Unknown();
        return Terminal(read.Record) ?? Unknown();
    }

    private static EnrollmentGrantExecutionResult? Terminal(EnrollmentGrantExecutionRecord record) => record.State switch
    {
        EnrollmentGrantExecutionState.Completed when record.Permit is not null && record.Envelope is not null &&
            record.Acknowledgement is null && record.StopReason is null &&
            record.Permit.IsValid(record.Operation) && record.Envelope.IsValid(record.Permit) &&
            record.Result is { Outcome: PlatformGrantOutcome.Created or PlatformGrantOutcome.AlreadyCreated, Diagnostic: PlatformGrantDiagnostic.None, Receipt: not null } result &&
            ValidRecordedResult(result, record.Operation, record.Permit) => new(EnrollmentGrantExecutionOutcome.GrantAvailable, PlatformGrantDiagnostic.None),
        EnrollmentGrantExecutionState.Acknowledged when record.Permit is not null && record.Envelope is null && record.StopReason is null &&
            record.Permit.IsValid(record.Operation) && record.Result is { Outcome: PlatformGrantOutcome.Created or PlatformGrantOutcome.AlreadyCreated, Diagnostic: PlatformGrantDiagnostic.None, Receipt: not null } result &&
            ValidRecordedResult(result, record.Operation, record.Permit) && record.Acknowledgement is { } acknowledgement &&
            acknowledgement.IsValid(record.Operation, record.Permit, result) => new(EnrollmentGrantExecutionOutcome.NoWork, PlatformGrantDiagnostic.None),
        EnrollmentGrantExecutionState.PermanentRejected when record.Permit is not null && record.Envelope is null &&
            record.Permit.IsValid(record.Operation) && record.Acknowledgement is null && record.StopReason is null &&
            record.Result is { Outcome: PlatformGrantOutcome.PermanentRejected, Receipt: null } result &&
            ValidRecordedTime(result, record.Permit) && PermanentDiagnostic(result.Diagnostic) => new(EnrollmentGrantExecutionOutcome.PermanentRejected, result.Diagnostic),
        EnrollmentGrantExecutionState.PermanentRejected when record.Permit is null && record.Envelope is null &&
            record.Result is null && record.Acknowledgement is null &&
            record.StopReason is EnrollmentGrantExecutionStopReason.AuthorizationChanged or EnrollmentGrantExecutionStopReason.AuthorizationExpired =>
            new(EnrollmentGrantExecutionOutcome.PermanentRejected, PlatformGrantDiagnostic.None, record.StopReason),
        EnrollmentGrantExecutionState.Quarantined when record.Result is null && record.Acknowledgement is null &&
            ((record.StopReason == EnrollmentGrantExecutionStopReason.StoredDataInvalid &&
                ((record.Permit is null && record.Envelope is null) || (record.Permit is not null && record.Envelope is not null))) ||
             (record.StopReason is EnrollmentGrantExecutionStopReason.OperationConflict or EnrollmentGrantExecutionStopReason.ReceiptMismatch &&
                record.Permit is not null && record.Envelope is not null)) =>
            new(EnrollmentGrantExecutionOutcome.Quarantined, PlatformGrantDiagnostic.None, record.StopReason),
        _ => null
    };

    private static bool ValidRecordIdentity(EnrollmentGrantExecutionRecord record, Guid environmentId, Guid operationId) =>
        record.Operation is not null && record.Operation.IsValid() && record.Operation.EnvironmentId == environmentId &&
        record.Operation.Id == operationId && ((record.State == EnrollmentGrantExecutionState.Queued && record.Permit is null && record.Envelope is null && record.Result is null && record.Acknowledgement is null && record.StopReason is null) ||
        (record.State == EnrollmentGrantExecutionState.PermitStored && record.Permit is not null && record.Envelope is not null && record.Result is null && record.Acknowledgement is null && record.StopReason is null) ||
        record.State is EnrollmentGrantExecutionState.Completed or EnrollmentGrantExecutionState.Acknowledged or EnrollmentGrantExecutionState.PermanentRejected or EnrollmentGrantExecutionState.Quarantined);

    private static bool ValidRecordedResult(EnrollmentGrantRecordedResult result,
        EnrollmentGrantExecutionOperation operation, PersistedEnrollmentGrantPermit permit) =>
        ValidRecordedTime(result, permit) && result.Receipt is not null &&
        result.RecordedAt >= result.Receipt.CreatedAt && ReceiptMatches(result.Receipt, operation, permit);

    private static bool ValidRecordedTime(EnrollmentGrantRecordedResult result, PersistedEnrollmentGrantPermit permit) =>
        EnrollmentGrantExecutionOperation.Canonical(result.RecordedAt) && result.RecordedAt >= permit.PermitIssuedAt &&
        (result.Diagnostic != PlatformGrantDiagnostic.MintPermitExpired || result.RecordedAt >= permit.MintPermitNotAfter);

    private static bool PermanentDiagnostic(PlatformGrantDiagnostic diagnostic) => diagnostic is
        PlatformGrantDiagnostic.MappingUnavailable or PlatformGrantDiagnostic.DeviceUnavailable or
        PlatformGrantDiagnostic.EnrollmentAlreadyExists or PlatformGrantDiagnostic.EnrollmentInProgress or
        PlatformGrantDiagnostic.GrantAlreadyAvailable or PlatformGrantDiagnostic.MintPermitExpired;

    private static bool ReceiptMatches(PlatformGrantReceipt receipt, EnrollmentGrantExecutionOperation operation,
        PersistedEnrollmentGrantPermit permit) => receipt.GrantId != Guid.Empty &&
        receipt.EnvironmentId == operation.EnvironmentId &&
        receipt.OperationId == operation.Id && receipt.DirectoryObjectId == operation.DirectoryObjectId &&
        receipt.DeviceId == operation.ServerDeviceId && receipt.MappingCreatedAt == operation.MappingCreatedAt &&
        EnrollmentGrantExecutionOperation.Canonical(receipt.MappingCreatedAt) &&
        EnrollmentGrantExecutionOperation.Canonical(receipt.CreatedAt) &&
        EnrollmentGrantExecutionOperation.Canonical(receipt.ExpiresAt) &&
        receipt.MappingCreatedAt <= receipt.CreatedAt && receipt.CreatedAt >= permit.PermitIssuedAt &&
        receipt.CreatedAt < permit.MintPermitNotAfter && receipt.ExpiresAt - receipt.CreatedAt == TimeSpan.FromSeconds(600) &&
        receipt.IssueContractVersion == 2 && receipt.MintPermitNotAfter == permit.MintPermitNotAfter &&
        CryptographicOperations.FixedTimeEquals(receipt.GetTokenSha256(), permit.GetTokenSha256()) &&
        CryptographicOperations.FixedTimeEquals(receipt.GetAuthorizationDigest(), permit.GetAuthorizationDigest());

    private static EnrollmentGrantExecutionResult Unknown(PlatformGrantDiagnostic diagnostic = PlatformGrantDiagnostic.ResponseUnavailable) =>
        new(EnrollmentGrantExecutionOutcome.OutcomeUnknown, diagnostic);

}
