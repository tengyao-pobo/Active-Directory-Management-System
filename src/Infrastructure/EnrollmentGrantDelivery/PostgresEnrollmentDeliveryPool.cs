using System.Data;
using Npgsql;

namespace ItManagement.EnrollmentGrantDelivery;

internal sealed class PostgresEnrollmentDeliveryPool
{
    private static readonly Lazy<string> AuditQuery = new(() =>
    {
        using var stream = typeof(PostgresEnrollmentDeliveryPool).Assembly.GetManifestResourceStream("EnrollmentDeliveryCatalogAudit")
            ?? throw new InvalidOperationException("EnrollmentDeliveryAuditResourceUnavailable");
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd().Replace(":'runtime_role'", "@runtime", StringComparison.Ordinal)
            .Replace(":'delivery_definer_role'", "@definer", StringComparison.Ordinal)
            .Replace(":'expected_table_owner_role'", "@owner", StringComparison.Ordinal)
            .Replace(":'expected_environment_id'", "@environment", StringComparison.Ordinal)
            .Replace(":'expected_purpose'", "@purpose", StringComparison.Ordinal);
    });
    private readonly NpgsqlDataSource _source;
    private readonly string _runtime, _owner, _definer, _purpose;
    internal Guid EnvironmentId { get; }

    internal PostgresEnrollmentDeliveryPool(NpgsqlDataSource source, Guid environmentId, string owner, string definer, string purpose)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentException.ThrowIfNullOrWhiteSpace(owner);
        ArgumentException.ThrowIfNullOrWhiteSpace(definer);
        var runtime = new NpgsqlConnectionStringBuilder(source.ConnectionString).Username;
        if (environmentId == Guid.Empty || string.IsNullOrWhiteSpace(runtime) || runtime == owner || runtime == definer || owner == definer ||
            purpose is not ("EnrollmentGrantStatusRefresh" or "EnrollmentGrantDelivery"))
            throw new ArgumentException("InvalidEnrollmentDeliveryPool");
        _source = source; EnvironmentId = environmentId; _runtime = runtime; _owner = owner; _definer = definer; _purpose = purpose;
    }

    internal async Task VerifyAsync(CancellationToken cancellationToken)
    {
        try
        {
            await using var connection = await _source.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
            await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken).ConfigureAwait(false);
            await AuditAsync(connection, transaction, cancellationToken).ConfigureAwait(false);
            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch { throw new InvalidOperationException("EnrollmentDeliveryPrivilegeAuditFailed"); }
    }

    internal async Task<T> RunAsync<T>(Func<NpgsqlConnection, NpgsqlTransaction, CancellationToken, Task<T>> operation,
        Func<T> unknown, Func<T, bool> valid, CancellationToken cancellationToken)
    {
        try
        {
            await using var connection = await _source.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
            await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken).ConfigureAwait(false);
            await AuditAsync(connection, transaction, cancellationToken).ConfigureAwait(false);
            var result = await operation(connection, transaction, cancellationToken).ConfigureAwait(false);
            if (!valid(result)) return unknown();
            // Nothing is exposed as accepted until commit returns; ambiguous outcomes require exact caller retry.
            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            return result;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch { return unknown(); }
    }

    private async Task AuditAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand(AuditQuery.Value, connection, transaction);
        command.Parameters.AddWithValue("runtime", _runtime);
        command.Parameters.AddWithValue("owner", _owner);
        command.Parameters.AddWithValue("definer", _definer);
        command.Parameters.AddWithValue("environment", EnvironmentId);
        command.Parameters.AddWithValue("purpose", _purpose);
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        if (reader.FieldCount != 1 || !await reader.ReadAsync(ct).ConfigureAwait(false) || reader.IsDBNull(0) ||
            !reader.GetBoolean(0) || await reader.ReadAsync(ct).ConfigureAwait(false))
            throw new InvalidOperationException("EnrollmentDeliveryPrivilegeAuditFailed");
    }

    internal bool ValidOperation(Guid environmentId, Guid operationId) => environmentId == EnvironmentId && operationId != Guid.Empty;
    internal static bool ValidSession(Guid requesterId, string? sessionHash) => requesterId != Guid.Empty &&
        sessionHash is { Length: 64 } && sessionHash.All(c => c is >= '0' and <= '9' or >= 'A' and <= 'F');
}
