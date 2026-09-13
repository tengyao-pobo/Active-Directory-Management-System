using ItManagement.AgentPlatformGrants;
using Npgsql;
using NpgsqlTypes;

namespace ItManagement.EnrollmentGrantDelivery;

/// <summary>A status-only public database pool. The caller owns the data source lifetime.</summary>
public sealed class PostgresEnrollmentGrantStatusStore : IEnrollmentGrantStatusStore
{
    private readonly PostgresEnrollmentDeliveryPool _pool;
    private PostgresEnrollmentGrantStatusStore(PostgresEnrollmentDeliveryPool pool) => _pool = pool;

    public static async Task<PostgresEnrollmentGrantStatusStore> CreateAuditedAsync(NpgsqlDataSource source,
        Guid environmentId, string expectedTableOwner, string expectedDeliveryDefiner, CancellationToken cancellationToken)
    {
        var pool = new PostgresEnrollmentDeliveryPool(source, environmentId, expectedTableOwner, expectedDeliveryDefiner, "EnrollmentGrantStatusRefresh");
        await pool.VerifyAsync(cancellationToken).ConfigureAwait(false);
        return new(pool);
    }

    public Task<EnrollmentGrantStatusReceiptResult> ReadReceiptAsync(Guid environmentId, Guid operationId, CancellationToken cancellationToken)
    {
        if (!_pool.ValidOperation(environmentId, operationId)) return Task.FromResult(PostgresEnrollmentDeliveryCodec.UnknownReceipt());
        return _pool.RunAsync(async (connection, transaction, ct) =>
        {
            await using var command = new NpgsqlCommand("SELECT * FROM enrollment_execution.read_grant_status_receipt(@environment,@operation)", connection, transaction);
            command.Parameters.AddWithValue("environment", environmentId);
            command.Parameters.AddWithValue("operation", operationId);
            await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
            return await PostgresEnrollmentDeliveryCodec.ReadReceiptAsync(reader, environmentId, operationId, ct).ConfigureAwait(false);
        }, PostgresEnrollmentDeliveryCodec.UnknownReceipt, result => result.Outcome != EnrollmentGrantStatusReceiptOutcome.OutcomeUnknown, cancellationToken);
    }

    public Task<EnrollmentGrantStatusObservationWriteResult> RecordAsync(PlatformGrantReceipt receipt,
        EnrollmentGrantStatusObservationCandidate candidate, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        ArgumentNullException.ThrowIfNull(candidate);
        if (!_pool.ValidOperation(receipt.EnvironmentId, receipt.OperationId) || !PostgresEnrollmentDeliveryCodec.ValidReceipt(receipt) ||
            candidate.EnvironmentId != receipt.EnvironmentId || candidate.OperationId != receipt.OperationId ||
            candidate.GrantCreatedAt != receipt.CreatedAt || candidate.GrantExpiresAt != receipt.ExpiresAt)
            return Task.FromResult(EnrollmentGrantStatusObservationWriteResult.Unknown());
        return _pool.RunAsync(async (connection, transaction, ct) =>
        {
            await using var command = new NpgsqlCommand("""
                SELECT * FROM enrollment_execution.append_grant_status_observation(
                    @expected_environment_id,@operation_id,@observation,@state,@diagnostic,@observed,@changed,
                    @grant_id,@directory_object_id,@device_id,@mapping_created_at,@created_at,@expires_at,
                    @issue_contract_version,@mint_permit_not_after,@token_sha256,@authorization_digest)
                """, connection, transaction);
            PostgresPlatformGrantRevocationRepository.AddIssueReceipt(command, receipt, _pool.EnvironmentId);
            command.Parameters.AddWithValue("observation", candidate.ObservationId);
            command.Parameters.AddWithValue("state", candidate.State.ToString());
            command.Parameters.AddWithValue("diagnostic", candidate.Diagnostic.ToString());
            command.Parameters.AddWithValue("observed", NpgsqlDbType.TimestampTz, (object?)candidate.PrivateObservedAt ?? DBNull.Value);
            command.Parameters.AddWithValue("changed", NpgsqlDbType.TimestampTz, (object?)candidate.StateChangedAt ?? DBNull.Value);
            await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
            return await PostgresEnrollmentDeliveryCodec.ReadObservationAsync(reader, candidate, ct).ConfigureAwait(false);
        }, EnrollmentGrantStatusObservationWriteResult.Unknown,
            result => result.Outcome != EnrollmentGrantStatusObservationWriteOutcome.OutcomeUnknown, cancellationToken);
    }
}
