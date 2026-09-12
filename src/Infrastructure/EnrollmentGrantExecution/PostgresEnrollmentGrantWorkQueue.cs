using System.Data;
using Npgsql;

namespace ItManagement.EnrollmentGrantExecution;

/// <summary>The caller owns the audited purpose-bound data source.</summary>
public sealed class PostgresEnrollmentGrantWorkQueue : IEnrollmentGrantWorkQueue
{
    private readonly NpgsqlDataSource _source;
    private readonly PostgresEnrollmentGrantExecutionStore _profile;
    private readonly Guid _environment;
    private readonly string _queueOwner;

    private PostgresEnrollmentGrantWorkQueue(NpgsqlDataSource source, PostgresEnrollmentGrantExecutionStore profile,
        Guid environment, string queueOwner)
    { _source = source; _profile = profile; _environment = environment; _queueOwner = queueOwner; }

    public static async Task<PostgresEnrollmentGrantWorkQueue> CreateAuditedAsync(NpgsqlDataSource source,
        Guid expectedEnvironment, string expectedTableOwner, string expectedExecutionOwner, string expectedQueueOwner,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedQueueOwner);
        var profile = await PostgresEnrollmentGrantExecutionStore.CreateAuditedAsync(source, expectedEnvironment,
            expectedTableOwner, expectedExecutionOwner, cancellationToken).ConfigureAwait(false);
        var queue = new PostgresEnrollmentGrantWorkQueue(source, profile, expectedEnvironment, expectedQueueOwner);
        try
        {
            await using var connection = await source.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
            await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken).ConfigureAwait(false);
            await queue.AuditAsync(connection, transaction, cancellationToken).ConfigureAwait(false);
            await PostgresEnrollmentGrantExecutionStore.CommitAsync(transaction, cancellationToken).ConfigureAwait(false);
            return queue;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch { throw new InvalidOperationException("EnrollmentExecutionQueuePrivilegeAuditFailed"); }
    }

    public async Task<EnrollmentWorkClaimResult> ClaimNextAsync(Guid claimToken, CancellationToken cancellationToken)
    {
        if (claimToken == Guid.Empty) return UnknownClaim();
        try
        {
            await using var connection = await _source.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
            await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken).ConfigureAwait(false);
            await AuditAsync(connection, transaction, cancellationToken).ConfigureAwait(false);
            EnrollmentWorkClaimResult result;
            await using (var command = new NpgsqlCommand("SELECT * FROM enrollment_execution.claim_next(@env,@token)", connection, transaction))
            {
                command.Parameters.AddWithValue("env", _environment);
                command.Parameters.AddWithValue("token", claimToken);
                await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
                result = await PostgresExecutionQueueCodec.ReadClaimAsync(reader, _environment, claimToken, cancellationToken).ConfigureAwait(false);
            }
            if (result.Outcome == EnrollmentWorkClaimOutcome.OutcomeUnknown) return UnknownClaim();
            await PostgresEnrollmentGrantExecutionStore.CommitAsync(transaction, cancellationToken).ConfigureAwait(false);
            return result;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch { return UnknownClaim(); }
    }

    public Task<EnrollmentWorkTransitionResult> CompleteAsync(EnrollmentWorkClaim claim, CancellationToken cancellationToken) =>
        TransitionAsync(claim, null, cancellationToken);

    public Task<EnrollmentWorkTransitionResult> DeferAsync(EnrollmentWorkClaim claim,
        EnrollmentWorkRetryReason reason, CancellationToken cancellationToken) =>
        Enum.IsDefined(reason) ? TransitionAsync(claim, reason, cancellationToken) : Task.FromResult(UnknownTransition());

    private async Task<EnrollmentWorkTransitionResult> TransitionAsync(EnrollmentWorkClaim claim,
        EnrollmentWorkRetryReason? reason, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(claim);
        if (!PostgresExecutionQueueCodec.ValidClaim(claim, _environment, claim.ClaimToken)) return UnknownTransition();
        try
        {
            await using var connection = await _source.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
            await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken).ConfigureAwait(false);
            await AuditAsync(connection, transaction, cancellationToken).ConfigureAwait(false);
            EnrollmentWorkTransitionResult result;
            var sql = reason is null ? "SELECT * FROM enrollment_execution.complete_claim(@env,@op,@token)"
                : "SELECT * FROM enrollment_execution.defer_claim(@env,@op,@token,@reason)";
            await using (var command = new NpgsqlCommand(sql, connection, transaction))
            {
                command.Parameters.AddWithValue("env", _environment);
                command.Parameters.AddWithValue("op", claim.OperationId);
                command.Parameters.AddWithValue("token", claim.ClaimToken);
                if (reason is { } retry) command.Parameters.AddWithValue("reason", retry.ToString());
                await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
                result = await PostgresExecutionQueueCodec.ReadTransitionAsync(reader, cancellationToken).ConfigureAwait(false);
            }
            var validOutcome = result.Outcome is EnrollmentWorkTransitionOutcome.StaleClaim or EnrollmentWorkTransitionOutcome.NotFound
                or EnrollmentWorkTransitionOutcome.TokenConflict || (reason is null
                    ? result.Outcome is EnrollmentWorkTransitionOutcome.Completed or EnrollmentWorkTransitionOutcome.AlreadyCompleted or EnrollmentWorkTransitionOutcome.NotTerminal
                    : result.Outcome is EnrollmentWorkTransitionOutcome.Deferred or EnrollmentWorkTransitionOutcome.AlreadyDeferred
                        or EnrollmentWorkTransitionOutcome.Completed or EnrollmentWorkTransitionOutcome.AlreadyCompleted);
            if (!validOutcome) return UnknownTransition();
            await PostgresEnrollmentGrantExecutionStore.CommitAsync(transaction, cancellationToken).ConfigureAwait(false);
            return result;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch { return UnknownTransition(); }
    }

    private async Task AuditAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, CancellationToken cancellationToken)
    {
        await _profile.AuditAsync(connection, transaction, cancellationToken).ConfigureAwait(false);
        await using var command = new NpgsqlCommand("""
            SELECT count(*)=3 AND bool_and(owner.rolname=@owner)
            FROM pg_catalog.pg_proc function JOIN pg_catalog.pg_roles owner ON owner.oid=function.proowner
            WHERE function.oid IN(pg_catalog.to_regprocedure('enrollment_execution.claim_next(uuid,uuid)'),
                pg_catalog.to_regprocedure('enrollment_execution.defer_claim(uuid,uuid,uuid,text)'),
                pg_catalog.to_regprocedure('enrollment_execution.complete_claim(uuid,uuid,uuid)'))
            """, connection, transaction);
        command.Parameters.AddWithValue("owner", _queueOwner);
        if (await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) is not true)
            throw new InvalidOperationException("EnrollmentExecutionQueuePrivilegeAuditFailed");
    }

    private static EnrollmentWorkClaimResult UnknownClaim() => new(EnrollmentWorkClaimOutcome.OutcomeUnknown);
    private static EnrollmentWorkTransitionResult UnknownTransition() => new(EnrollmentWorkTransitionOutcome.OutcomeUnknown);
}
