using Npgsql;

namespace ItManagement.AgentPlatformGrants;

public sealed class PostgresPlatformGrantStatusReader
{
    internal const string LegacyReadSql =
        "SELECT state,diagnostic_code,environment_id,operation_id,grant_id,directory_object_id,device_id,mapping_created_at,token_sha256,authorization_digest,created_at,expires_at,issue_contract_version,mint_permit_not_after,observed_at,state_changed_at FROM agent_private.read_initial_enrollment_grant_status(@expected_environment_id,@operation_id,@grant_id,@directory_object_id,@device_id,@mapping_created_at,@token_sha256,@authorization_digest,@created_at,@expires_at)";
    internal const string DeadlineReadSql =
        "SELECT state,diagnostic_code,environment_id,operation_id,grant_id,directory_object_id,device_id,mapping_created_at,token_sha256,authorization_digest,created_at,expires_at,issue_contract_version,mint_permit_not_after,observed_at,state_changed_at FROM agent_private.read_initial_enrollment_grant_status(@expected_environment_id,@operation_id,@grant_id,@directory_object_id,@device_id,@mapping_created_at,@token_sha256,@authorization_digest,@created_at,@expires_at,@issue_contract_version,@mint_permit_not_after)";
    internal const string AuditSql =
        "SELECT audit.is_valid,audit.diagnostic_code,audit.profile_version,pg_catalog.has_function_privilege(SESSION_USER,'agent_private.read_initial_enrollment_grant_status(uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz)'::pg_catalog.regprocedure,'EXECUTE') AND pg_catalog.has_function_privilege(SESSION_USER,'agent_private.read_initial_enrollment_grant_status(uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz,smallint,timestamptz)'::pg_catalog.regprocedure,'EXECUTE') AND NOT pg_catalog.has_function_privilege(SESSION_USER,'agent_private.issue_initial_enrollment_grant(uuid,uuid,uuid,uuid,timestamptz,bytea,bytea)'::pg_catalog.regprocedure,'EXECUTE') AND NOT pg_catalog.has_function_privilege(SESSION_USER,'agent_private.issue_initial_enrollment_grant(uuid,uuid,uuid,uuid,timestamptz,timestamptz,bytea,bytea)'::pg_catalog.regprocedure,'EXECUTE') AND NOT pg_catalog.has_function_privilege(SESSION_USER,'agent_private.read_initial_enrollment_grant(uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz)'::pg_catalog.regprocedure,'EXECUTE') AND NOT pg_catalog.has_function_privilege(SESSION_USER,'agent_private.read_initial_enrollment_grant(uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz,smallint,timestamptz)'::pg_catalog.regprocedure,'EXECUTE') AND NOT pg_catalog.has_function_privilege(SESSION_USER,'agent_private.revoke_initial_enrollment_grant(uuid,uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz,bytea)'::pg_catalog.regprocedure,'EXECUTE') AND NOT pg_catalog.has_function_privilege(SESSION_USER,'agent_private.revoke_initial_enrollment_grant(uuid,uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz,smallint,timestamptz,bytea)'::pg_catalog.regprocedure,'EXECUTE') FROM agent_private.audit_platform_grant_privileges(@environment_id,@table_owner::name,@function_owner::name) audit";

    private readonly NpgsqlDataSource _dataSource;
    private readonly Guid _environmentId;

    internal PostgresPlatformGrantStatusReader(NpgsqlDataSource dataSource, Guid environmentId)
    {
        _dataSource = dataSource;
        _environmentId = environmentId;
    }

    public static async Task<PostgresPlatformGrantStatusReader> CreateAuditedAsync(
        NpgsqlDataSource dataSource,
        Guid expectedEnvironmentId,
        string expectedTableOwner,
        string expectedFunctionOwner,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(dataSource);
        if (expectedEnvironmentId == Guid.Empty)
            throw new ArgumentException("InvalidEnvironment", nameof(expectedEnvironmentId));
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedTableOwner);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedFunctionOwner);

        await using var command = dataSource.CreateCommand(AuditSql);
        command.Parameters.AddWithValue("environment_id", expectedEnvironmentId);
        command.Parameters.AddWithValue("table_owner", expectedTableOwner);
        command.Parameters.AddWithValue("function_owner", expectedFunctionOwner);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false) ||
            reader.IsDBNull(0) || reader.IsDBNull(1) || reader.IsDBNull(2) || reader.IsDBNull(3))
            throw AuditFailed();
        var valid = reader.GetBoolean(0);
        var diagnostic = PostgresPlatformGrantRepository.ParseDiagnostic(reader.GetString(1));
        var profileVersion = reader.GetInt16(2);
        var hasExactStatusCapability = reader.GetBoolean(3);
        if (await reader.ReadAsync(cancellationToken).ConfigureAwait(false) || !valid || profileVersion != 4 ||
            diagnostic != PlatformGrantDiagnostic.None || !hasExactStatusCapability)
            throw AuditFailed();
        return new PostgresPlatformGrantStatusReader(dataSource, expectedEnvironmentId);
    }

    public async Task<PlatformGrantReadResult> ReadAsync(
        PlatformGrantReceipt receipt,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        if (receipt.EnvironmentId != _environmentId)
            return PostgresPlatformGrantRevocationRepository.UnknownRead(PlatformGrantDiagnostic.OperationConflict);

        try
        {
            await using var command = _dataSource.CreateCommand();
            ConfigureReadCommand(command, receipt, _environmentId);
            await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            return await PostgresPlatformGrantRevocationRepository.ReadResponseAsync(
                reader, receipt, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (NpgsqlException)
        {
            return PostgresPlatformGrantRevocationRepository.UnknownRead(
                PlatformGrantDiagnostic.ConnectionUnavailable);
        }
        catch (InvalidCastException) { return PostgresPlatformGrantRevocationRepository.UnknownRead(); }
        catch (IndexOutOfRangeException) { return PostgresPlatformGrantRevocationRepository.UnknownRead(); }
        catch (FormatException) { return PostgresPlatformGrantRevocationRepository.UnknownRead(); }
        catch (OverflowException) { return PostgresPlatformGrantRevocationRepository.UnknownRead(); }
    }

    internal static void ConfigureReadCommand(
        NpgsqlCommand command,
        PlatformGrantReceipt receipt,
        Guid expectedEnvironmentId)
    {
        ArgumentNullException.ThrowIfNull(command);
        ArgumentNullException.ThrowIfNull(receipt);
        command.CommandText = receipt.IssueContractVersion == 1 ? LegacyReadSql : DeadlineReadSql;
        PostgresPlatformGrantRevocationRepository.AddIssueReceipt(
            command, receipt, expectedEnvironmentId);
    }

    private static InvalidOperationException AuditFailed() =>
        new("PlatformGrantPrivilegeAuditFailed");
}
