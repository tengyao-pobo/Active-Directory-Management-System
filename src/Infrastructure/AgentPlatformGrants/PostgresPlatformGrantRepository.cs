using Npgsql;

namespace ItManagement.AgentPlatformGrants;

public sealed class PostgresPlatformGrantRepository
{
    private readonly NpgsqlDataSource _dataSource;
    private readonly Guid _environmentId;

    internal PostgresPlatformGrantRepository(NpgsqlDataSource dataSource, Guid environmentId)
    {
        _dataSource = dataSource;
        _environmentId = environmentId;
    }

    public static async Task<PostgresPlatformGrantRepository> CreateAuditedAsync(NpgsqlDataSource dataSource,
        Guid expectedEnvironmentId, string expectedTableOwner, string expectedFunctionOwner,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(dataSource);
        if (expectedEnvironmentId == Guid.Empty) throw new ArgumentException("InvalidEnvironment", nameof(expectedEnvironmentId));
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedTableOwner);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedFunctionOwner);
        await using var command = dataSource.CreateCommand(
            "SELECT is_valid,diagnostic_code,profile_version FROM agent_private.audit_platform_grant_privileges(@environment_id,@table_owner::name,@function_owner::name)");
        command.Parameters.AddWithValue("environment_id", expectedEnvironmentId);
        command.Parameters.AddWithValue("table_owner", expectedTableOwner);
        command.Parameters.AddWithValue("function_owner", expectedFunctionOwner);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false) || reader.IsDBNull(0) || reader.IsDBNull(1) || reader.IsDBNull(2))
            throw new InvalidOperationException("PlatformGrantPrivilegeAuditFailed");
        var isValid = reader.GetBoolean(0);
        var diagnostic = ParseDiagnostic(reader.GetString(1));
        var profileVersion = reader.GetInt16(2);
        if (await reader.ReadAsync(cancellationToken).ConfigureAwait(false) || !isValid || profileVersion != 1 || diagnostic != PlatformGrantDiagnostic.None)
            throw new InvalidOperationException("PlatformGrantPrivilegeAuditFailed");
        return new(dataSource, expectedEnvironmentId);
    }

    public async Task<PlatformGrantResult> IssueAsync(Guid operationId, ValidatedGrantAuthorization authorization,
        ValidatedPersistedPlatformGrant preparedGrant, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authorization);
        ArgumentNullException.ThrowIfNull(preparedGrant);
        if (operationId == Guid.Empty) return new(PlatformGrantOutcome.PermanentRejected, PlatformGrantDiagnostic.InvalidRequest, null);
        try
        {
            await using var command = _dataSource.CreateCommand(
                "SELECT outcome,diagnostic_code,environment_id,operation_id,grant_id,directory_object_id,device_id,mapping_created_at,created_at,expires_at FROM agent_private.issue_initial_enrollment_grant(@expected_environment_id,@operation_id,@directory_object_id,@expected_device_id,@mapping_created_at,@token_sha256,@authorization_digest)");
            command.Parameters.AddWithValue("expected_environment_id", _environmentId);
            command.Parameters.AddWithValue("operation_id", operationId);
            command.Parameters.AddWithValue("directory_object_id", authorization.DirectoryObjectId);
            command.Parameters.AddWithValue("expected_device_id", authorization.ExpectedDeviceId);
            command.Parameters.AddWithValue("mapping_created_at", authorization.MappingCreatedAt);
            command.Parameters.AddWithValue("token_sha256", preparedGrant.GetTokenSha256());
            command.Parameters.AddWithValue("authorization_digest", authorization.GetDigest());
            await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) return Unknown();
            var row = new PlatformGrantDatabaseResult(
                reader.IsDBNull(0) ? null : reader.GetString(0), reader.IsDBNull(1) ? null : reader.GetString(1),
                reader.IsDBNull(2) ? null : reader.GetGuid(2), reader.IsDBNull(3) ? null : reader.GetGuid(3),
                reader.IsDBNull(4) ? null : reader.GetGuid(4), reader.IsDBNull(5) ? null : reader.GetGuid(5),
                reader.IsDBNull(6) ? null : reader.GetGuid(6), reader.IsDBNull(7) ? null : reader.GetFieldValue<DateTimeOffset>(7),
                reader.IsDBNull(8) ? null : reader.GetFieldValue<DateTimeOffset>(8), reader.IsDBNull(9) ? null : reader.GetFieldValue<DateTimeOffset>(9));
            if (await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) return Unknown();
            return NormalizeResult(row, _environmentId, operationId, authorization);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (NpgsqlException) { return Unknown(PlatformGrantDiagnostic.ConnectionUnavailable); }
        catch (InvalidCastException) { return Unknown(); }
        catch (IndexOutOfRangeException) { return Unknown(); }
        catch (FormatException) { return Unknown(); }
        catch (OverflowException) { return Unknown(); }
    }

    private static PlatformGrantResult Unknown(PlatformGrantDiagnostic diagnostic = PlatformGrantDiagnostic.ResponseUnavailable) =>
        new(PlatformGrantOutcome.Unknown, diagnostic, null);

    internal static PlatformGrantResult NormalizeResult(PlatformGrantDatabaseResult row, Guid environmentId,
        Guid operationId, ValidatedGrantAuthorization authorization)
    {
        if (row.Outcome is null || row.Diagnostic is null) return Unknown();
        var outcome = ParseOutcome(row.Outcome);
        var diagnostic = ParseDiagnostic(row.Diagnostic);
        if (outcome == PlatformGrantOutcome.Unknown || diagnostic == PlatformGrantDiagnostic.ResponseUnavailable)
            return Unknown();

        if (outcome is PlatformGrantOutcome.Created or PlatformGrantOutcome.AlreadyCreated)
        {
            if (diagnostic != PlatformGrantDiagnostic.None || !MatchesRequest(row, environmentId, operationId, authorization) ||
                row.GrantId is null || row.GrantId == Guid.Empty || row.CreatedAt is null || row.ExpiresAt is null ||
                row.ExpiresAt.Value - row.CreatedAt.Value != TimeSpan.FromSeconds(600))
                return Unknown();
            return new(outcome, diagnostic, new PlatformGrantReceipt(operationId, row.GrantId.Value,
                row.DirectoryObjectId!.Value, row.DeviceId!.Value, row.MappingCreatedAt!.Value,
                row.CreatedAt.Value, row.ExpiresAt.Value));
        }

        if (outcome == PlatformGrantOutcome.Unauthorized)
            return diagnostic == PlatformGrantDiagnostic.PrivilegeAuditFailed && AllResultFieldsNull(row)
                ? new(outcome, diagnostic, null) : Unknown();

        if (row.GrantId is not null || row.CreatedAt is not null || row.ExpiresAt is not null ||
            !MatchesRequest(row, environmentId, operationId, authorization))
            return Unknown();

        if (outcome == PlatformGrantOutcome.OutcomeUnknown)
            return diagnostic == PlatformGrantDiagnostic.OperationConflict ? new(outcome, diagnostic, null) : Unknown();

        if (outcome == PlatformGrantOutcome.PermanentRejected && diagnostic is
            PlatformGrantDiagnostic.InvalidRequest or PlatformGrantDiagnostic.MappingUnavailable or
            PlatformGrantDiagnostic.DeviceUnavailable or PlatformGrantDiagnostic.EnrollmentAlreadyExists or
            PlatformGrantDiagnostic.EnrollmentInProgress or PlatformGrantDiagnostic.GrantAlreadyAvailable)
            return new(outcome, diagnostic, null);

        return Unknown();
    }

    private static bool MatchesRequest(PlatformGrantDatabaseResult row, Guid environmentId, Guid operationId,
        ValidatedGrantAuthorization authorization) =>
        row.EnvironmentId == environmentId && row.OperationId == operationId &&
        row.DirectoryObjectId == authorization.DirectoryObjectId && row.DeviceId == authorization.ExpectedDeviceId &&
        row.MappingCreatedAt == authorization.MappingCreatedAt;

    private static bool AllResultFieldsNull(PlatformGrantDatabaseResult row) =>
        row.EnvironmentId is null && row.OperationId is null && row.GrantId is null &&
        row.DirectoryObjectId is null && row.DeviceId is null && row.MappingCreatedAt is null &&
        row.CreatedAt is null && row.ExpiresAt is null;

    internal static PlatformGrantOutcome ParseOutcome(string value) => value switch
    {
        "Created" => PlatformGrantOutcome.Created,
        "AlreadyCreated" => PlatformGrantOutcome.AlreadyCreated,
        "PermanentRejected" => PlatformGrantOutcome.PermanentRejected,
        "OutcomeUnknown" => PlatformGrantOutcome.OutcomeUnknown,
        "Unauthorized" => PlatformGrantOutcome.Unauthorized,
        _ => PlatformGrantOutcome.Unknown
    };

    internal static PlatformGrantDiagnostic ParseDiagnostic(string value) => value switch
    {
        "None" => PlatformGrantDiagnostic.None,
        "InvalidRequest" => PlatformGrantDiagnostic.InvalidRequest,
        "MappingUnavailable" => PlatformGrantDiagnostic.MappingUnavailable,
        "DeviceUnavailable" => PlatformGrantDiagnostic.DeviceUnavailable,
        "EnrollmentAlreadyExists" => PlatformGrantDiagnostic.EnrollmentAlreadyExists,
        "EnrollmentInProgress" => PlatformGrantDiagnostic.EnrollmentInProgress,
        "GrantAlreadyAvailable" => PlatformGrantDiagnostic.GrantAlreadyAvailable,
        "OperationConflict" => PlatformGrantDiagnostic.OperationConflict,
        "PrivilegeAuditFailed" => PlatformGrantDiagnostic.PrivilegeAuditFailed,
        "ConnectionUnavailable" => PlatformGrantDiagnostic.ConnectionUnavailable,
        _ => PlatformGrantDiagnostic.ResponseUnavailable
    };
}

internal sealed record PlatformGrantDatabaseResult(string? Outcome, string? Diagnostic, Guid? EnvironmentId,
    Guid? OperationId, Guid? GrantId, Guid? DirectoryObjectId, Guid? DeviceId,
    DateTimeOffset? MappingCreatedAt, DateTimeOffset? CreatedAt, DateTimeOffset? ExpiresAt);
