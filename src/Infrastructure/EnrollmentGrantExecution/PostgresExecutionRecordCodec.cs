using System.Data.Common;
using System.Security.Cryptography;
using ItManagement.AgentPlatformGrants;

namespace ItManagement.EnrollmentGrantExecution;

internal static class PostgresExecutionRecordCodec
{
    internal static IReadOnlyList<string> CanonicalColumnNames { get; } =
    [
        "contract_version", "outcome", "execution_state", "op_environment_id", "op_id", "op_plan_id",
        "op_request_id", "op_approval_id", "op_requester_id", "op_approver_id", "op_requester_operator_id",
        "op_approver_operator_id", "op_plan_hash", "op_directory_object_id", "op_server_device_id",
        "op_mapping_created_at", "op_directory_generation", "op_environment_version", "op_recipient_spki",
        "op_recipient_fingerprint", "op_queued_at", "op_authorization_not_after", "permit_version",
        "permit_issued_at", "permit_not_after", "permit_token_sha256", "permit_recipient_fingerprint",
        "permit_ciphertext_sha256", "permit_authorization_digest", "ciphertext", "result_outcome",
        "result_diagnostic", "result_recorded_at", "receipt_grant_id", "receipt_environment_id",
        "receipt_directory_object_id", "receipt_device_id", "receipt_mapping_created_at", "receipt_created_at",
        "receipt_expires_at", "receipt_contract_version", "receipt_permit_not_after", "receipt_token_sha256",
        "receipt_authorization_digest", "ack_requester_id", "ack_token_sha256", "ack_ciphertext_sha256",
        "ack_at", "stop_reason", "stop_recorded_at"
    ];

    private static readonly Type[] CanonicalColumnTypes =
    [
        typeof(short), typeof(string), typeof(string), typeof(Guid), typeof(Guid), typeof(Guid), typeof(Guid),
        typeof(Guid), typeof(Guid), typeof(Guid), typeof(Guid), typeof(Guid), typeof(string), typeof(Guid),
        typeof(Guid), typeof(DateTime), typeof(Guid), typeof(long), typeof(byte[]), typeof(byte[]), typeof(DateTime),
        typeof(DateTime), typeof(short), typeof(DateTime), typeof(DateTime), typeof(byte[]), typeof(byte[]),
        typeof(byte[]), typeof(byte[]), typeof(byte[]), typeof(string), typeof(string), typeof(DateTime), typeof(Guid),
        typeof(Guid), typeof(Guid), typeof(Guid), typeof(DateTime), typeof(DateTime), typeof(DateTime), typeof(short),
        typeof(DateTime), typeof(byte[]), typeof(byte[]), typeof(Guid), typeof(byte[]), typeof(byte[]),
        typeof(DateTime), typeof(string), typeof(DateTime)
    ];

    internal static async Task<EnrollmentGrantStoreReadResult> ReadAsync(DbDataReader reader,
        Guid expectedEnvironmentId, Guid expectedOperationId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(reader);
        if (expectedEnvironmentId == Guid.Empty || expectedOperationId == Guid.Empty)
            return Unknown();

        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!ValidMetadata(reader) || !await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
                return Unknown();

            var values = new object?[CanonicalColumnNames.Count];
            for (var i = 0; i < values.Length; i++)
                values[i] = await reader.IsDBNullAsync(i, cancellationToken).ConfigureAwait(false)
                    ? null
                    : reader.GetValue(i);

            if (await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) return Unknown();
            return Decode(values, expectedEnvironmentId, expectedOperationId);
        }
        catch (OperationCanceledException) { throw; }
        catch { return Unknown(); }
    }

    private static bool ValidMetadata(DbDataReader reader)
    {
        if (reader.FieldCount != CanonicalColumnNames.Count) return false;
        for (var i = 0; i < CanonicalColumnNames.Count; i++)
            if (!string.Equals(reader.GetName(i), CanonicalColumnNames[i], StringComparison.Ordinal) ||
                reader.GetFieldType(i) != CanonicalColumnTypes[i]) return false;
        return true;
    }

    private static EnrollmentGrantStoreReadResult Decode(object?[] row, Guid expectedEnvironmentId, Guid expectedOperationId)
    {
        if (!Is<short>(row, 0, out var version) || version != 1 || !Is<string>(row, 1, out var outcome)) return Unknown();
        if (outcome == "NotFound")
            return row.Skip(2).All(value => value is null)
                ? new(EnrollmentGrantStoreReadOutcome.NotFound, null)
                : Unknown();
        if (outcome != "Found" || row.Skip(2).Any(value => value is null) && row[2] is null) return Unknown();

        if (!RequiredOperation(row, out var operation) || operation.EnvironmentId != expectedEnvironmentId ||
            operation.Id != expectedOperationId || !operation.IsValid() || !ParseExact(
                (string)row[2]!, out EnrollmentGrantExecutionState state)) return Unknown();

        var hasPermit = row[22] is not null;
        var hasEnvelope = row[29] is not null;
        var hasResult = row[30] is not null;
        var hasReceipt = row[33] is not null;
        var hasAck = row[44] is not null;
        var hasStop = row[48] is not null;

        PersistedEnrollmentGrantPermit? permit = null;
        if (hasPermit && (!RequiredPermit(row, operation, out permit) || !permit.IsValid(operation))) return Unknown();
        if (!AllNullOrAllPresent(row, 22, 29, hasPermit) || !AllNullOrAllPresent(row, 30, 33, hasResult) ||
            !AllNullOrAllPresent(row, 33, 44, hasReceipt) || !AllNullOrAllPresent(row, 44, 48, hasAck) ||
            !AllNullOrAllPresent(row, 48, 50, hasStop)) return Unknown();

        PersistedEnrollmentGrantEnvelope? envelope = null;
        if (hasEnvelope)
        {
            if (permit is null || row[29] is not byte[] ciphertext) return Unknown();
            envelope = new(ciphertext);
            if (!envelope.IsValid(permit)) return Unknown();
        }

        EnrollmentGrantRecordedResult? result = null;
        if (hasResult && !RequiredResult(row, operation, permit, hasReceipt, out result)) return Unknown();

        EnrollmentGrantDeliveryAcknowledgement? acknowledgement = null;
        if (hasAck)
        {
            if (permit is null || result is null || !Is<Guid>(row, 44, out var requesterId) ||
                row[45] is not byte[] token || row[46] is not byte[] ciphertextHash ||
                !Time(row[47], out var acknowledgedAt)) return Unknown();
            acknowledgement = new(requesterId, token, ciphertextHash, acknowledgedAt);
            if (!acknowledgement.IsValid(operation, permit, result)) return Unknown();
        }

        EnrollmentGrantExecutionStopReason? stopReason = null;
        DateTimeOffset? stopRecordedAt = null;
        if (hasStop)
        {
            if (!ParseExact((string)row[48]!, out EnrollmentGrantExecutionStopReason parsed) ||
                !Time(row[49], out var stoppedAt)) return Unknown();
            stopReason = parsed; stopRecordedAt = stoppedAt;
            if (stoppedAt < operation.QueuedAt || permit is not null && stoppedAt < permit.PermitIssuedAt ||
                parsed == EnrollmentGrantExecutionStopReason.AuthorizationExpired && stoppedAt < operation.AuthorizationNotAfter)
                return Unknown();
        }

        if (!ValidState(state, permit, envelope, result, acknowledgement, stopReason, stopRecordedAt)) return Unknown();
        return new(EnrollmentGrantStoreReadOutcome.Found,
            new(operation, state, permit, envelope, result, acknowledgement, stopReason));
    }

    private static bool RequiredOperation(object?[] row, out EnrollmentGrantExecutionOperation operation)
    {
        operation = null!;
        if (row[2] is not string || !Is<Guid>(row, 3, out var environmentId) || !Is<Guid>(row, 4, out var id) ||
            !Is<Guid>(row, 5, out var planId) || !Is<Guid>(row, 6, out var requestId) ||
            !Is<Guid>(row, 7, out var approvalId) || !Is<Guid>(row, 8, out var requesterId) ||
            !Is<Guid>(row, 9, out var approverId) || !Is<Guid>(row, 10, out var requesterOperatorId) ||
            !Is<Guid>(row, 11, out var approverOperatorId) || row[12] is not string planHash ||
            !Is<Guid>(row, 13, out var directoryObjectId) || !Is<Guid>(row, 14, out var serverDeviceId) ||
            !Time(row[15], out var mappingCreatedAt) || !Is<Guid>(row, 16, out var generation) ||
            !Is<long>(row, 17, out var environmentVersion) || row[18] is not byte[] spki ||
            row[19] is not byte[] fingerprint || !Time(row[20], out var queuedAt) ||
            !Time(row[21], out var authorizationNotAfter)) return false;
        operation = new(environmentId, id, planId, requestId, approvalId, requesterId, approverId,
            requesterOperatorId, approverOperatorId, planHash, directoryObjectId, serverDeviceId,
            mappingCreatedAt, generation, environmentVersion, spki, fingerprint, queuedAt, authorizationNotAfter);
        return true;
    }

    private static bool RequiredPermit(object?[] row, EnrollmentGrantExecutionOperation operation,
        out PersistedEnrollmentGrantPermit permit)
    {
        permit = null!;
        if (!Is<short>(row, 22, out var version) || !Time(row[23], out var issuedAt) ||
            !Time(row[24], out var notAfter) || row[25] is not byte[] token || row[26] is not byte[] fingerprint ||
            row[27] is not byte[] ciphertextHash || row[28] is not byte[] digest) return false;
        permit = new(version, issuedAt, notAfter, token, fingerprint, ciphertextHash, digest);
        return true;
    }

    private static bool RequiredResult(object?[] row, EnrollmentGrantExecutionOperation operation,
        PersistedEnrollmentGrantPermit? permit, bool hasReceipt, out EnrollmentGrantRecordedResult result)
    {
        result = null!;
        if (permit is null || row[30] is not string outcome || row[31] is not string diagnosticText ||
            !Time(row[32], out var recordedAt) || !ParseExact(diagnosticText, out PlatformGrantDiagnostic diagnostic))
            return false;
        PlatformGrantReceipt? receipt = null;
        PlatformGrantOutcome mapped;
        if (outcome == "Issued")
        {
            if (diagnostic != PlatformGrantDiagnostic.None || !hasReceipt || !RequiredReceipt(row, operation, permit, out receipt)) return false;
            mapped = PlatformGrantOutcome.Created;
            if (recordedAt < receipt.CreatedAt) return false;
        }
        else if (outcome == "Rejected")
        {
            if (hasReceipt || !PermanentDiagnostic(diagnostic) ||
                diagnostic == PlatformGrantDiagnostic.MintPermitExpired && recordedAt < permit.MintPermitNotAfter) return false;
            mapped = PlatformGrantOutcome.PermanentRejected;
        }
        else return false;
        if (!EnrollmentGrantExecutionOperation.Canonical(recordedAt) || recordedAt < permit.PermitIssuedAt) return false;
        result = new(mapped, diagnostic, receipt, recordedAt);
        return true;
    }

    private static bool RequiredReceipt(object?[] row, EnrollmentGrantExecutionOperation operation,
        PersistedEnrollmentGrantPermit permit, out PlatformGrantReceipt receipt)
    {
        receipt = null!;
        if (!Is<Guid>(row, 33, out var grantId) || !Is<Guid>(row, 34, out var environmentId) ||
            !Is<Guid>(row, 35, out var directoryId) || !Is<Guid>(row, 36, out var deviceId) ||
            !Time(row[37], out var mappingAt) || !Time(row[38], out var createdAt) ||
            !Time(row[39], out var expiresAt) || !Is<short>(row, 40, out var contractVersion) ||
            !Time(row[41], out var permitNotAfter) || row[42] is not byte[] token || row[43] is not byte[] digest)
            return false;
        if (grantId == Guid.Empty || environmentId != operation.EnvironmentId || directoryId != operation.DirectoryObjectId ||
            deviceId != operation.ServerDeviceId || mappingAt != operation.MappingCreatedAt || mappingAt > createdAt ||
            createdAt < permit.PermitIssuedAt || createdAt >= permit.MintPermitNotAfter ||
            expiresAt - createdAt != TimeSpan.FromSeconds(600) || contractVersion != 2 ||
            permitNotAfter != permit.MintPermitNotAfter || !CryptographicOperations.FixedTimeEquals(token, permit.GetTokenSha256()) ||
            !CryptographicOperations.FixedTimeEquals(digest, permit.GetAuthorizationDigest())) return false;
        receipt = new(environmentId, operation.Id, grantId, directoryId, deviceId, mappingAt, createdAt, expiresAt,
            contractVersion, permitNotAfter, token, digest);
        return true;
    }

    private static bool ValidState(EnrollmentGrantExecutionState state, PersistedEnrollmentGrantPermit? permit,
        PersistedEnrollmentGrantEnvelope? envelope, EnrollmentGrantRecordedResult? result,
        EnrollmentGrantDeliveryAcknowledgement? acknowledgement, EnrollmentGrantExecutionStopReason? stop,
        DateTimeOffset? stopAt) => state switch
    {
        EnrollmentGrantExecutionState.Queued => permit is null && envelope is null && result is null && acknowledgement is null && stop is null && stopAt is null,
        EnrollmentGrantExecutionState.PermitStored => permit is not null && envelope is not null && result is null && acknowledgement is null && stop is null && stopAt is null,
        EnrollmentGrantExecutionState.Completed => permit is not null && envelope is not null && result is { Outcome: PlatformGrantOutcome.Created } && acknowledgement is null && stop is null && stopAt is null,
        EnrollmentGrantExecutionState.Acknowledged => permit is not null && envelope is null && result is { Outcome: PlatformGrantOutcome.Created } && acknowledgement is not null && stop is null && stopAt is null,
        EnrollmentGrantExecutionState.PermanentRejected =>
            permit is null && envelope is null && result is null && acknowledgement is null && stop is EnrollmentGrantExecutionStopReason.AuthorizationChanged or EnrollmentGrantExecutionStopReason.AuthorizationExpired && stopAt is not null ||
            permit is not null && envelope is null && result is { Outcome: PlatformGrantOutcome.PermanentRejected } && acknowledgement is null && stop is null && stopAt is null,
        EnrollmentGrantExecutionState.Quarantined => result is null && acknowledgement is null && stopAt is not null &&
            (stop == EnrollmentGrantExecutionStopReason.StoredDataInvalid && (permit is null && envelope is null || permit is not null && envelope is not null) ||
             stop is EnrollmentGrantExecutionStopReason.OperationConflict or EnrollmentGrantExecutionStopReason.ReceiptMismatch && permit is not null && envelope is not null),
        _ => false
    };

    private static bool AllNullOrAllPresent(object?[] row, int start, int end, bool present)
    {
        for (var i = start; i < end; i++) if ((row[i] is not null) != present) return false;
        return true;
    }

    private static bool PermanentDiagnostic(PlatformGrantDiagnostic value) => value is
        PlatformGrantDiagnostic.MappingUnavailable or PlatformGrantDiagnostic.DeviceUnavailable or
        PlatformGrantDiagnostic.EnrollmentAlreadyExists or PlatformGrantDiagnostic.EnrollmentInProgress or
        PlatformGrantDiagnostic.GrantAlreadyAvailable or PlatformGrantDiagnostic.MintPermitExpired;

    private static bool Time(object? value, out DateTimeOffset result)
    {
        result = default;
        if (value is not DateTime time || time.Kind != DateTimeKind.Utc || time.Ticks % 10 != 0 ||
            time == DateTime.MinValue || time == DateTime.MaxValue) return false;
        result = new(time, TimeSpan.Zero);
        return true;
    }

    private static bool Is<T>(object? value, out T result)
    {
        if (value is T typed) { result = typed; return true; }
        result = default!; return false;
    }

    private static bool Is<T>(object?[] row, int index, out T result) => Is(row[index], out result);

    private static bool ParseExact<T>(string value, out T result) where T : struct, Enum
    {
        if (Enum.TryParse(value, false, out result) && string.Equals(value, result.ToString(), StringComparison.Ordinal))
            return true;
        result = default; return false;
    }

    private static EnrollmentGrantStoreReadResult Unknown() => new(EnrollmentGrantStoreReadOutcome.OutcomeUnknown, null);
}
