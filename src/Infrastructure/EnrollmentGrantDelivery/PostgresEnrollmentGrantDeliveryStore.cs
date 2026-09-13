using Npgsql;

namespace ItManagement.EnrollmentGrantDelivery;

/// <summary>A delivery-only public database pool. The caller owns the data source lifetime.</summary>
public sealed class PostgresEnrollmentGrantDeliveryStore : IEnrollmentGrantDeliveryStore
{
    private readonly PostgresEnrollmentDeliveryPool _pool;
    private PostgresEnrollmentGrantDeliveryStore(PostgresEnrollmentDeliveryPool pool) => _pool = pool;

    public static async Task<PostgresEnrollmentGrantDeliveryStore> CreateAuditedAsync(NpgsqlDataSource source,
        Guid environmentId, string expectedTableOwner, string expectedDeliveryDefiner, CancellationToken cancellationToken)
    {
        var pool = new PostgresEnrollmentDeliveryPool(source, environmentId, expectedTableOwner, expectedDeliveryDefiner, "EnrollmentGrantDelivery");
        await pool.VerifyAsync(cancellationToken).ConfigureAwait(false);
        return new(pool);
    }

    public Task<EnrollmentGrantDeliveryResponse> ReadAsync(Guid environmentId, Guid operationId, Guid requesterId,
        string sessionHash, CancellationToken cancellationToken)
    {
        if (!_pool.ValidOperation(environmentId, operationId) || !PostgresEnrollmentDeliveryPool.ValidSession(requesterId, sessionHash))
            return Task.FromResult(PostgresEnrollmentDeliveryCodec.UnknownDelivery());
        return _pool.RunAsync(async (connection, transaction, ct) =>
        {
            await using var command = Command("SELECT * FROM enrollment_execution.read_grant_delivery(@environment,@operation,@requester,@session)",
                connection, transaction, environmentId, operationId, requesterId, sessionHash);
            await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
            return await PostgresEnrollmentDeliveryCodec.ReadDeliveryAsync(reader, environmentId, operationId, ct).ConfigureAwait(false);
        }, PostgresEnrollmentDeliveryCodec.UnknownDelivery,
            result => result.Outcome != EnrollmentGrantDeliveryOutcome.OutcomeUnknown, cancellationToken);
    }

    public Task<EnrollmentGrantAcknowledgementOutcome> AcknowledgeAsync(Guid environmentId, Guid operationId, Guid requesterId,
        string sessionHash, EnrollmentGrantDeliveryAcknowledgement acknowledgement, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(acknowledgement);
        if (!_pool.ValidOperation(environmentId, operationId) || !PostgresEnrollmentDeliveryPool.ValidSession(requesterId, sessionHash))
            return Task.FromResult(EnrollmentGrantAcknowledgementOutcome.OutcomeUnknown);
        return _pool.RunAsync(async (connection, transaction, ct) =>
        {
            await using var command = Command("""
                SELECT * FROM enrollment_execution.acknowledge_grant_delivery(
                    @environment,@operation,@requester,@session,@fingerprint,@ciphertext_sha256)
                """, connection, transaction, environmentId, operationId, requesterId, sessionHash);
            command.Parameters.AddWithValue("fingerprint", acknowledgement.GetRecipientKeyFingerprint());
            command.Parameters.AddWithValue("ciphertext_sha256", acknowledgement.GetCiphertextSha256());
            await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
            return await PostgresEnrollmentDeliveryCodec.ReadAcknowledgementAsync(reader, ct).ConfigureAwait(false);
        }, () => EnrollmentGrantAcknowledgementOutcome.OutcomeUnknown,
            result => result != EnrollmentGrantAcknowledgementOutcome.OutcomeUnknown, cancellationToken);
    }

    private static NpgsqlCommand Command(string sql, NpgsqlConnection connection, NpgsqlTransaction transaction,
        Guid environmentId, Guid operationId, Guid requesterId, string sessionHash)
    {
        var command = new NpgsqlCommand(sql, connection, transaction);
        command.Parameters.AddWithValue("environment", environmentId);
        command.Parameters.AddWithValue("operation", operationId);
        command.Parameters.AddWithValue("requester", requesterId);
        command.Parameters.AddWithValue("session", sessionHash);
        return command;
    }
}
