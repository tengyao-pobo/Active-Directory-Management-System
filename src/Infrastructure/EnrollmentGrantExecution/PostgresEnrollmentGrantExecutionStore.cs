using System.Data;
using System.Security.Cryptography;
using ItManagement.AgentPlatformGrants;
using Npgsql;

namespace ItManagement.EnrollmentGrantExecution;

/// <summary>A purpose-bound pool. The caller owns the data source and its lifetime.</summary>
public sealed class PostgresEnrollmentGrantExecutionStore : IEnrollmentGrantExecutionStore
{
    private readonly NpgsqlDataSource _source;
    private readonly Guid _environment;
    private readonly string _runtime, _tableOwner, _definer;

    private PostgresEnrollmentGrantExecutionStore(NpgsqlDataSource source, Guid environment,
        string runtime, string tableOwner, string definer)
    {
        _source = source; _environment = environment;
        _runtime = runtime; _tableOwner = tableOwner; _definer = definer;
    }

    public static async Task<PostgresEnrollmentGrantExecutionStore> CreateAuditedAsync(NpgsqlDataSource source,
        Guid expectedEnvironmentId, string expectedTableOwner, string expectedFunctionOwner, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(source);
        if (expectedEnvironmentId == Guid.Empty) throw new ArgumentException("InvalidEnvironment", nameof(expectedEnvironmentId));
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedTableOwner);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedFunctionOwner);
        var runtime = new NpgsqlConnectionStringBuilder(source.ConnectionString).Username;
        ArgumentException.ThrowIfNullOrWhiteSpace(runtime);
        var store = new PostgresEnrollmentGrantExecutionStore(source, expectedEnvironmentId, runtime, expectedTableOwner, expectedFunctionOwner);
        try
        {
            await using var connection = await source.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
            await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken).ConfigureAwait(false);
            await store.AuditAsync(connection, transaction, cancellationToken).ConfigureAwait(false);
            await CommitAsync(transaction, cancellationToken).ConfigureAwait(false);
            return store;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch { throw new InvalidOperationException("EnrollmentExecutionPrivilegeAuditFailed"); }
    }

    public async Task<EnrollmentGrantStoreReadResult> ReadAsync(Guid environmentId, Guid operationId, CancellationToken cancellationToken)
    {
        if (!ValidQuery(environmentId, operationId)) return UnknownRead();
        try
        {
            await using var connection = await _source.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
            await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken).ConfigureAwait(false);
            await AuditAsync(connection, transaction, cancellationToken).ConfigureAwait(false);
            var result = await ReadAsync(connection, transaction, operationId, cancellationToken).ConfigureAwait(false);
            if (result.Outcome == EnrollmentGrantStoreReadOutcome.OutcomeUnknown) return result;
            await CommitAsync(transaction, cancellationToken).ConfigureAwait(false);
            return result;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch { return UnknownRead(); }
    }

    public async Task<EnrollmentGrantPermitStoreResult> AuthorizeAndStoreCandidateAsync(
        EnrollmentGrantExecutionOperation operation, EnrollmentGrantEnvelopeCandidate candidate, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(operation); ArgumentNullException.ThrowIfNull(candidate);
        if (!ValidQuery(operation.EnvironmentId, operation.Id) || !operation.IsValid() || !candidate.IsValid()) return UnknownPermit();
        try
        {
            await using var connection = await _source.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
            await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken).ConfigureAwait(false);
            await AuditAsync(connection, transaction, cancellationToken).ConfigureAwait(false);
            var initial = await ReadAsync(connection, transaction, operation.Id, cancellationToken).ConfigureAwait(false);
            if (initial.Record is not { } stored || !SameOperation(stored.Operation, operation)) return UnknownPermit();
            var existing = PermitResult(stored, EnrollmentGrantPermitStoreOutcome.Existing);
            if (existing.Outcome != EnrollmentGrantPermitStoreOutcome.OutcomeUnknown)
            {
                await CommitAsync(transaction, cancellationToken).ConfigureAwait(false);
                return existing;
            }
            if (stored.State != EnrollmentGrantExecutionState.Queued) return UnknownPermit();
            EnrollmentGrantContextReadResult context;
            await using (var command = Command(connection, transaction,
                "SELECT * FROM enrollment_execution.read_and_lock_plan_context(@env,@op)", ("env", _environment), ("op", operation.Id)))
            await using (var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false))
                context = await PostgresExecutionContextCodec.ReadAsync(reader, stored.Operation, cancellationToken).ConfigureAwait(false);
            if (context.Outcome != EnrollmentGrantContextReadOutcome.Found || context.Context is null)
            {
                // Stored operation was independently verified. Malformed plan history is stopped
                // using those trusted query IDs, without issuing or replacing a candidate.
                var stopped = await TransitionAsync(connection, transaction,
                    "SELECT * FROM enrollment_execution.quarantine_execution(@env,@op,NULL::bytea,'StoredDataInvalid')",
                    cancellationToken, ("env", _environment), ("op", operation.Id)).ConfigureAwait(false);
                if (stopped is { Outcome: "Recorded" or "AlreadyRecorded", Reason: EnrollmentGrantExecutionStopReason.StoredDataInvalid })
                    await CommitAsync(transaction, cancellationToken).ConfigureAwait(false);
                return UnknownPermit();
            }
            var transition = await TransitionAsync(connection, transaction,
                "SELECT * FROM enrollment_execution.authorize_and_store_candidate(@env,@op,@hash,@token,@fingerprint,@cipher)",
                cancellationToken, ("env", _environment), ("op", operation.Id), ("hash", context.Context.VerifiedPlanHash),
                ("token", candidate.GetTokenSha256()), ("fingerprint", candidate.GetRecipientKeyFingerprint()),
                ("cipher", candidate.GetCiphertext())).ConfigureAwait(false);
            if (transition is null) return UnknownPermit();
            var readback = await ReadAsync(connection, transaction, operation.Id, cancellationToken).ConfigureAwait(false);
            if (readback.Record is not { } final || !SameOperation(final.Operation, operation)) return UnknownPermit();
            var result = transition.Outcome switch
            {
                "Stored" when transition.Reason is null && final.State == EnrollmentGrantExecutionState.PermitStored =>
                    PermitResult(final, EnrollmentGrantPermitStoreOutcome.Stored),
                "Existing" when transition.Reason is null && final.State == EnrollmentGrantExecutionState.PermitStored =>
                    PermitResult(final, EnrollmentGrantPermitStoreOutcome.Existing),
                "AuthorizationRejected" when final.State == EnrollmentGrantExecutionState.PermanentRejected &&
                    transition.Reason is EnrollmentGrantExecutionStopReason.AuthorizationChanged or EnrollmentGrantExecutionStopReason.AuthorizationExpired &&
                    final.StopReason == transition.Reason => PermitResult(final, EnrollmentGrantPermitStoreOutcome.Existing),
                _ => UnknownPermit()
            };
            if (transition is { Outcome: "Conflict", Reason: EnrollmentGrantExecutionStopReason.StoredDataInvalid }
                && final.State == EnrollmentGrantExecutionState.Quarantined && final.StopReason == transition.Reason)
                await CommitAsync(transaction, cancellationToken).ConfigureAwait(false);
            else if (result.Outcome != EnrollmentGrantPermitStoreOutcome.OutcomeUnknown)
                await CommitAsync(transaction, cancellationToken).ConfigureAwait(false);
            return result;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch { return UnknownPermit(); }
    }

    public async Task<EnrollmentGrantRecordResult> RecordDefiniteResultAsync(EnrollmentGrantExecutionOperation operation,
        PersistedEnrollmentGrantPermit permit, EnrollmentGrantDefiniteResult result, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(operation); ArgumentNullException.ThrowIfNull(permit); ArgumentNullException.ThrowIfNull(result);
        if (!ValidQuery(operation.EnvironmentId, operation.Id) || !operation.IsValid() || !permit.IsValid(operation) ||
            !ValidDefiniteResult(result, operation, permit)) return UnknownRecord();
        try
        {
            await using var connection = await _source.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
            await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken).ConfigureAwait(false);
            await AuditAsync(connection, transaction, cancellationToken).ConfigureAwait(false);
            var receipt = result.Receipt;
            var transition = await TransitionAsync(connection, transaction, """
                SELECT * FROM enrollment_execution.record_execution_result(@env,@op,@permit_digest,@outcome,@diagnostic,
                    @grant::uuid,@receipt_env::uuid,@directory::uuid,@device::uuid,@mapping::timestamptz,
                    @created::timestamptz,@expires::timestamptz,@version::smallint,@deadline::timestamptz,@token::bytea,@digest::bytea)
                """, cancellationToken, ("env", _environment), ("op", operation.Id), ("permit_digest", permit.GetAuthorizationDigest()),
                ("outcome", receipt is null ? "Rejected" : "Issued"), ("diagnostic", result.Diagnostic.ToString()),
                ("grant", receipt?.GrantId), ("receipt_env", receipt?.EnvironmentId), ("directory", receipt?.DirectoryObjectId),
                ("device", receipt?.DeviceId), ("mapping", receipt?.MappingCreatedAt), ("created", receipt?.CreatedAt),
                ("expires", receipt?.ExpiresAt), ("version", receipt?.IssueContractVersion), ("deadline", receipt?.MintPermitNotAfter),
                ("token", receipt?.GetTokenSha256()), ("digest", receipt?.GetAuthorizationDigest())).ConfigureAwait(false);
            if (transition is null || transition.Reason is not null) return UnknownRecord();
            if (transition.Outcome == "Conflict") return new(EnrollmentGrantRecordOutcome.Conflict);
            if (transition.Outcome is not ("Recorded" or "AlreadyRecorded")) return UnknownRecord();
            var readback = await ReadAsync(connection, transaction, operation.Id, cancellationToken).ConfigureAwait(false);
            if (readback.Record is not { Result: { } saved, Permit: { } savedPermit } final ||
                !SameOperation(final.Operation, operation) || !Fixed(savedPermit.GetAuthorizationDigest(), permit.GetAuthorizationDigest()) ||
                saved.Diagnostic != result.Diagnostic || !Equals(saved.Receipt, receipt) ||
                (receipt is null ? final.State != EnrollmentGrantExecutionState.PermanentRejected :
                    final.State is not (EnrollmentGrantExecutionState.Completed or EnrollmentGrantExecutionState.Acknowledged))) return UnknownRecord();
            await CommitAsync(transaction, cancellationToken).ConfigureAwait(false);
            return new(transition.Outcome == "Recorded" ? EnrollmentGrantRecordOutcome.Recorded : EnrollmentGrantRecordOutcome.AlreadyRecorded);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch { return UnknownRecord(); }
    }

    public async Task<EnrollmentGrantRecordResult> QuarantineAsync(Guid environmentId, Guid operationId,
        EnrollmentGrantExecutionOperation? observedOperation, PersistedEnrollmentGrantPermit? permit,
        EnrollmentGrantExecutionStopReason reason, CancellationToken cancellationToken)
    {
        if (!ValidQuery(environmentId, operationId) || reason is not (EnrollmentGrantExecutionStopReason.StoredDataInvalid or
            EnrollmentGrantExecutionStopReason.OperationConflict or EnrollmentGrantExecutionStopReason.ReceiptMismatch)) return UnknownRecord();
        try
        {
            await using var connection = await _source.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
            await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken).ConfigureAwait(false);
            await AuditAsync(connection, transaction, cancellationToken).ConfigureAwait(false);
            // observedOperation is intentionally never used to select the row to stop.
            var transition = await TransitionAsync(connection, transaction,
                "SELECT * FROM enrollment_execution.quarantine_execution(@env,@op,@digest::bytea,@reason)", cancellationToken,
                ("env", _environment), ("op", operationId), ("digest", permit?.GetAuthorizationDigest()), ("reason", reason.ToString())).ConfigureAwait(false);
            if (transition is null) return UnknownRecord();
            if (transition.Outcome == "Conflict") return new(EnrollmentGrantRecordOutcome.Conflict);
            if (transition.Outcome is not ("Recorded" or "AlreadyRecorded") || transition.Reason != reason) return UnknownRecord();
            await CommitAsync(transaction, cancellationToken).ConfigureAwait(false);
            return new(transition.Outcome == "Recorded" ? EnrollmentGrantRecordOutcome.Recorded : EnrollmentGrantRecordOutcome.AlreadyRecorded);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch { return UnknownRecord(); }
    }

    private async Task AuditAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, CancellationToken cancellationToken)
    {
        await using (var locking = Command(connection, transaction, "SELECT pg_catalog.pg_advisory_xact_lock_shared(1162235478,1)"))
            await locking.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        await using (var command = Command(connection, transaction, CatalogAuditSql.Value,
            ("execution_runtime_role", _runtime), ("execution_definer_role", _definer),
            ("expected_table_owner_role", _tableOwner), ("expected_environment_id", _environment)))
        await using (var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false))
        {
            if (reader.FieldCount != 1 || reader.GetName(0) != "is_valid" || reader.GetFieldType(0) != typeof(bool) ||
                !await reader.ReadAsync(cancellationToken).ConfigureAwait(false) || reader.IsDBNull(0) || !reader.GetBoolean(0) ||
                await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) throw new InvalidOperationException("EnrollmentExecutionPrivilegeAuditFailed");
        }
        await using (var command = Command(connection, transaction,
            "SELECT * FROM enrollment_execution.audit_execution_privileges(@env)", ("env", _environment)))
        await using (var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false))
        {
            if (reader.FieldCount != 3 || reader.GetName(0) != "is_valid" || reader.GetName(1) != "diagnostic_code" ||
                reader.GetName(2) != "profile_version" || reader.GetFieldType(0) != typeof(bool) ||
                reader.GetFieldType(1) != typeof(string) || reader.GetFieldType(2) != typeof(short) ||
                !await reader.ReadAsync(cancellationToken).ConfigureAwait(false) || reader.IsDBNull(0) || reader.IsDBNull(1) || reader.IsDBNull(2) ||
                !reader.GetBoolean(0) || reader.GetString(1) != "None" || reader.GetInt16(2) != 2 ||
                await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) throw new InvalidOperationException("EnrollmentExecutionPrivilegeAuditFailed");
        }
    }

    private async Task<EnrollmentGrantStoreReadResult> ReadAsync(NpgsqlConnection connection, NpgsqlTransaction transaction,
        Guid operation, CancellationToken cancellationToken)
    {
        await using var command = Command(connection, transaction,
            "SELECT * FROM enrollment_execution.read_execution_record(@env,@op)", ("env", _environment), ("op", operation));
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        return await PostgresExecutionRecordCodec.ReadAsync(reader, _environment, operation, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<Transition?> TransitionAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, string sql,
        CancellationToken cancellationToken, params (string Name, object? Value)[] parameters)
    {
        await using var command = Command(connection, transaction, sql, parameters);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        if (reader.FieldCount != 3 || reader.GetName(0) != "contract_version" || reader.GetName(1) != "outcome" ||
            reader.GetName(2) != "stop_reason" || reader.GetFieldType(0) != typeof(short) || reader.GetFieldType(1) != typeof(string) ||
            reader.GetFieldType(2) != typeof(string) || !await reader.ReadAsync(cancellationToken).ConfigureAwait(false) ||
            reader.IsDBNull(0) || reader.IsDBNull(1) || reader.GetInt16(0) != 1) return null;
        var outcome = reader.GetString(1);
        EnrollmentGrantExecutionStopReason? reason = null;
        if (!reader.IsDBNull(2))
        {
            var raw = reader.GetString(2);
            if (!Enum.TryParse<EnrollmentGrantExecutionStopReason>(raw, out var parsed) || !Enum.IsDefined(parsed) || parsed.ToString() != raw) return null;
            reason = parsed;
        }
        return await reader.ReadAsync(cancellationToken).ConfigureAwait(false) ? null : new(outcome, reason);
    }

    private static NpgsqlCommand Command(NpgsqlConnection connection, NpgsqlTransaction transaction, string sql,
        params (string Name, object? Value)[] parameters)
    {
        var command = new NpgsqlCommand(sql, connection, transaction);
        foreach (var parameter in parameters) command.Parameters.AddWithValue(parameter.Name, parameter.Value ?? DBNull.Value);
        return command;
    }

    internal static async Task CommitAsync(System.Data.Common.DbTransaction transaction, CancellationToken cancellationToken)
    {
        // Honor cancellation before committing. Once COMMIT begins, wait for its bounded
        // database result so cancellation cannot turn a confirmed write into a false abort.
        cancellationToken.ThrowIfCancellationRequested();
        try { await transaction.CommitAsync(CancellationToken.None).ConfigureAwait(false); }
        catch (OperationCanceledException)
        {
            // A provider-side cancellation/timeout during COMMIT is an uncertain outcome,
            // handled by the caller's normal Unknown result and subsequent durable readback.
            throw new InvalidOperationException("EnrollmentExecutionCommitOutcomeUnknown");
        }
    }

    private bool ValidQuery(Guid environment, Guid operation) => environment == _environment && operation != Guid.Empty;
    private static bool Fixed(byte[] left, byte[] right) => left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
    private static bool SameOperation(EnrollmentGrantExecutionOperation left, EnrollmentGrantExecutionOperation right) =>
        Fixed(PostgresExecutionContextCodec.ComputeOperationBinding(left), PostgresExecutionContextCodec.ComputeOperationBinding(right));
    private static bool ValidDefiniteResult(EnrollmentGrantDefiniteResult result, EnrollmentGrantExecutionOperation operation,
        PersistedEnrollmentGrantPermit permit) => result.Outcome switch
        {
            PlatformGrantOutcome.Created or PlatformGrantOutcome.AlreadyCreated => result.Diagnostic == PlatformGrantDiagnostic.None &&
                result.Receipt is { } receipt && EnrollmentGrantExecutor.ReceiptMatches(receipt, operation, permit),
            PlatformGrantOutcome.PermanentRejected => result.Receipt is null && EnrollmentGrantExecutor.PermanentDiagnostic(result.Diagnostic),
            _ => false
        };
    private static EnrollmentGrantPermitStoreResult PermitResult(EnrollmentGrantExecutionRecord record, EnrollmentGrantPermitStoreOutcome outcome) =>
        record.State switch
        {
            EnrollmentGrantExecutionState.PermitStored when record.Permit is not null && record.Envelope is not null =>
                new(outcome, record.Permit, record.Envelope),
            EnrollmentGrantExecutionState.PermanentRejected when record.Permit is null && record.Envelope is null &&
                record.StopReason is EnrollmentGrantExecutionStopReason.AuthorizationChanged or EnrollmentGrantExecutionStopReason.AuthorizationExpired =>
                new(EnrollmentGrantPermitStoreOutcome.AuthorizationRejected, null, null, record.StopReason),
            _ => UnknownPermit()
        };
    private static EnrollmentGrantStoreReadResult UnknownRead() => new(EnrollmentGrantStoreReadOutcome.OutcomeUnknown, null);
    private static EnrollmentGrantPermitStoreResult UnknownPermit() => new(EnrollmentGrantPermitStoreOutcome.OutcomeUnknown, null, null);
    private static EnrollmentGrantRecordResult UnknownRecord() => new(EnrollmentGrantRecordOutcome.OutcomeUnknown);
    private sealed record Transition(string Outcome, EnrollmentGrantExecutionStopReason? Reason);

    private static readonly Lazy<string> CatalogAuditSql = new(() =>
    {
        using var stream = typeof(PostgresEnrollmentGrantExecutionStore).Assembly.GetManifestResourceStream("EnrollmentExecutionCatalogAudit")
            ?? throw new InvalidOperationException("EnrollmentExecutionPrivilegeAuditFailed");
        using var reader = new StreamReader(stream);
        var sql = reader.ReadToEnd();
        foreach (var parameter in new[] { "execution_runtime_role", "execution_definer_role", "expected_table_owner_role", "expected_environment_id" })
            sql = sql.Replace($":'{parameter}'", $"@{parameter}", StringComparison.Ordinal);
        if (sql.Contains(":'", StringComparison.Ordinal) || sql.Split('\n').Any(line => line.TrimStart().StartsWith('\\')))
            throw new InvalidOperationException("EnrollmentExecutionPrivilegeAuditFailed");
        return sql;
    });
}
