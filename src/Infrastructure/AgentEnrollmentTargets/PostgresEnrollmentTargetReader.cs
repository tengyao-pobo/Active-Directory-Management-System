using Npgsql;

namespace ItManagement.AgentEnrollmentTargets;

public sealed class PostgresEnrollmentTargetReader : IEnrollmentTargetReader
{
    private readonly NpgsqlDataSource _dataSource;
    private readonly Guid _environmentId;

    internal PostgresEnrollmentTargetReader(NpgsqlDataSource dataSource, Guid environmentId)
    {
        _dataSource = dataSource;
        _environmentId = environmentId;
    }

    public static async Task<PostgresEnrollmentTargetReader> CreateAuditedAsync(NpgsqlDataSource dataSource,
        Guid expectedEnvironmentId, string expectedTableOwner, string expectedFunctionOwner,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(dataSource);
        if (expectedEnvironmentId == Guid.Empty) throw new ArgumentException("InvalidEnvironment", nameof(expectedEnvironmentId));
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedTableOwner);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedFunctionOwner);
        await using var command = dataSource.CreateCommand(
            "SELECT is_valid,diagnostic_code,profile_version FROM agent_private.audit_enrollment_target_read_privileges(@environment,@table_owner::name,@function_owner::name)");
        command.Parameters.AddWithValue("environment", expectedEnvironmentId);
        command.Parameters.AddWithValue("table_owner", expectedTableOwner);
        command.Parameters.AddWithValue("function_owner", expectedFunctionOwner);
        try
        {
            await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false) || reader.IsDBNull(0) ||
                reader.IsDBNull(1) || reader.IsDBNull(2))
                throw new InvalidOperationException("EnrollmentTargetPrivilegeAuditFailed");
            var valid = reader.GetBoolean(0);
            var diagnostic = reader.GetString(1);
            var profile = reader.GetInt16(2);
            if (await reader.ReadAsync(cancellationToken).ConfigureAwait(false) || !valid || diagnostic != "None" || profile != 1)
                throw new InvalidOperationException("EnrollmentTargetPrivilegeAuditFailed");
            return new(dataSource, expectedEnvironmentId);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (InvalidOperationException error) when (error.Message == "EnrollmentTargetPrivilegeAuditFailed") { throw; }
        catch (Exception error) when (error is NpgsqlException or InvalidCastException or IndexOutOfRangeException or FormatException or OverflowException)
        {
            throw new InvalidOperationException("EnrollmentTargetPrivilegeAuditFailed", error);
        }
    }

    public async Task<EnrollmentTargetResult> ReadAsync(Guid environmentId, Guid directoryObjectId,
        CancellationToken cancellationToken)
    {
        if (environmentId == Guid.Empty || directoryObjectId == Guid.Empty)
            return EnrollmentTargetResult.Unavailable(environmentId, directoryObjectId,
                EnrollmentTargetDiagnostic.InvalidDirectoryObject);
        if (environmentId != _environmentId)
            return EnrollmentTargetResult.Unavailable(environmentId, directoryObjectId,
                EnrollmentTargetDiagnostic.PrivilegeAuditFailed);
        try
        {
            await using var command = _dataSource.CreateCommand(
                "SELECT outcome,diagnostic_code,environment_id,directory_object_id,device_id,mapping_created_at FROM agent_private.resolve_enrollment_target(@environment,@directory)");
            command.Parameters.AddWithValue("environment", environmentId);
            command.Parameters.AddWithValue("directory", directoryObjectId);
            await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) return Unavailable(environmentId, directoryObjectId);
            var row = new EnrollmentTargetDatabaseResult(
                reader.IsDBNull(0) ? null : reader.GetString(0), reader.IsDBNull(1) ? null : reader.GetString(1),
                reader.IsDBNull(2) ? null : reader.GetGuid(2), reader.IsDBNull(3) ? null : reader.GetGuid(3),
                reader.IsDBNull(4) ? null : reader.GetGuid(4),
                reader.IsDBNull(5) ? null : reader.GetFieldValue<DateTimeOffset>(5));
            if (await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) return Unavailable(environmentId, directoryObjectId);
            return Normalize(row, environmentId, directoryObjectId);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (NpgsqlException) { return Unavailable(environmentId, directoryObjectId, EnrollmentTargetDiagnostic.ConnectionUnavailable); }
        catch (Exception error) when (error is InvalidCastException or IndexOutOfRangeException or FormatException or OverflowException)
        {
            return Unavailable(environmentId, directoryObjectId);
        }
    }

    internal static EnrollmentTargetResult Normalize(EnrollmentTargetDatabaseResult row, Guid environmentId,
        Guid directoryObjectId)
    {
        if (row.Outcome == "Resolved" && row.Diagnostic == "None" && row.EnvironmentId == environmentId &&
            row.DirectoryObjectId == directoryObjectId && row.DeviceId is { } deviceId && deviceId != Guid.Empty &&
            row.MappingCreatedAt is { Offset: var offset } mappedAt && offset == TimeSpan.Zero && mappedAt.Ticks % 10 == 0)
            return EnrollmentTargetResult.Resolved(environmentId, directoryObjectId, deviceId, mappedAt);

        if (row.Outcome == "MappingRequired" && row.Diagnostic is "MappingMissing" or "DeviceInactive" &&
            row.EnvironmentId == environmentId && row.DirectoryObjectId == directoryObjectId &&
            row.DeviceId is null && row.MappingCreatedAt is null)
            return EnrollmentTargetResult.MappingRequired(environmentId, directoryObjectId,
                row.Diagnostic == "MappingMissing" ? EnrollmentTargetDiagnostic.MappingMissing : EnrollmentTargetDiagnostic.DeviceInactive);

        if (row.Outcome == "InvalidRequest" && row.Diagnostic == "InvalidDirectoryObject" && AllDataNull(row))
            return EnrollmentTargetResult.Unavailable(environmentId, directoryObjectId, EnrollmentTargetDiagnostic.InvalidDirectoryObject);
        if (row.Outcome == "Unauthorized" && row.Diagnostic == "PrivilegeAuditFailed" && AllDataNull(row))
            return EnrollmentTargetResult.Unavailable(environmentId, directoryObjectId, EnrollmentTargetDiagnostic.PrivilegeAuditFailed);
        return Unavailable(environmentId, directoryObjectId);
    }

    private static bool AllDataNull(EnrollmentTargetDatabaseResult row) => row.EnvironmentId is null &&
        row.DirectoryObjectId is null && row.DeviceId is null && row.MappingCreatedAt is null;

    private static EnrollmentTargetResult Unavailable(Guid environmentId, Guid directoryObjectId,
        EnrollmentTargetDiagnostic diagnostic = EnrollmentTargetDiagnostic.ResponseUnavailable) =>
        EnrollmentTargetResult.Unavailable(environmentId, directoryObjectId, diagnostic);
}

internal sealed record EnrollmentTargetDatabaseResult(string? Outcome, string? Diagnostic, Guid? EnvironmentId,
    Guid? DirectoryObjectId, Guid? DeviceId, DateTimeOffset? MappingCreatedAt);
