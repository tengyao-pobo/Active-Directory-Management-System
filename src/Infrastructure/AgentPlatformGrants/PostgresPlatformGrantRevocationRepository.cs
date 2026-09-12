using System.Data.Common;
using Npgsql;

namespace ItManagement.AgentPlatformGrants;

public sealed class PostgresPlatformGrantRevocationRepository
{
    private readonly NpgsqlDataSource _dataSource;
    private readonly Guid _environmentId;

    internal PostgresPlatformGrantRevocationRepository(NpgsqlDataSource dataSource, Guid environmentId)
    {
        _dataSource = dataSource;
        _environmentId = environmentId;
    }

    public static async Task<PostgresPlatformGrantRevocationRepository> CreateAuditedAsync(
        NpgsqlDataSource dataSource, Guid expectedEnvironmentId, string expectedTableOwner,
        string expectedFunctionOwner, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(dataSource);
        if (expectedEnvironmentId == Guid.Empty) throw new ArgumentException("InvalidEnvironment", nameof(expectedEnvironmentId));
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedTableOwner);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedFunctionOwner);
        await using var command = dataSource.CreateCommand(
            "SELECT audit.is_valid,audit.diagnostic_code,audit.profile_version,NOT pg_catalog.has_function_privilege(SESSION_USER,'agent_private.issue_initial_enrollment_grant(uuid,uuid,uuid,uuid,timestamptz,bytea,bytea)'::pg_catalog.regprocedure,'EXECUTE') AND NOT pg_catalog.has_function_privilege(SESSION_USER,'agent_private.issue_initial_enrollment_grant(uuid,uuid,uuid,uuid,timestamptz,timestamptz,bytea,bytea)'::pg_catalog.regprocedure,'EXECUTE') AND pg_catalog.has_function_privilege(SESSION_USER,'agent_private.read_initial_enrollment_grant(uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz)'::pg_catalog.regprocedure,'EXECUTE') AND pg_catalog.has_function_privilege(SESSION_USER,'agent_private.read_initial_enrollment_grant(uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz,smallint,timestamptz)'::pg_catalog.regprocedure,'EXECUTE') AND pg_catalog.has_function_privilege(SESSION_USER,'agent_private.revoke_initial_enrollment_grant(uuid,uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz,bytea)'::pg_catalog.regprocedure,'EXECUTE') AND pg_catalog.has_function_privilege(SESSION_USER,'agent_private.revoke_initial_enrollment_grant(uuid,uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz,smallint,timestamptz,bytea)'::pg_catalog.regprocedure,'EXECUTE') AND CASE WHEN audit.profile_version=4 THEN NOT pg_catalog.has_function_privilege(SESSION_USER,pg_catalog.to_regprocedure('agent_private.read_initial_enrollment_grant_status(uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz)'),'EXECUTE') AND NOT pg_catalog.has_function_privilege(SESSION_USER,pg_catalog.to_regprocedure('agent_private.read_initial_enrollment_grant_status(uuid,uuid,uuid,uuid,uuid,timestamptz,bytea,bytea,timestamptz,timestamptz,smallint,timestamptz)'),'EXECUTE') WHEN audit.profile_version=3 THEN true ELSE false END FROM agent_private.audit_platform_grant_privileges(@environment_id,@table_owner::name,@function_owner::name) audit");
        command.Parameters.AddWithValue("environment_id", expectedEnvironmentId);
        command.Parameters.AddWithValue("table_owner", expectedTableOwner);
        command.Parameters.AddWithValue("function_owner", expectedFunctionOwner);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false) || reader.IsDBNull(0) || reader.IsDBNull(1) || reader.IsDBNull(2) || reader.IsDBNull(3))
            throw new InvalidOperationException("PlatformGrantPrivilegeAuditFailed");
        var valid = reader.GetBoolean(0);
        var diagnostic = PostgresPlatformGrantRepository.ParseDiagnostic(reader.GetString(1));
        var version = reader.GetInt16(2);
        var hasExactRevocationCapability = reader.GetBoolean(3);
        if (await reader.ReadAsync(cancellationToken).ConfigureAwait(false) || !valid || !AcceptsAuditProfile(version) ||
            diagnostic != PlatformGrantDiagnostic.None || !hasExactRevocationCapability)
            throw new InvalidOperationException("PlatformGrantPrivilegeAuditFailed");
        return new(dataSource, expectedEnvironmentId);
    }

    internal static bool AcceptsAuditProfile(short version) => version is 3 or 4;

    public async Task<PlatformGrantReadResult> ReadAsync(PlatformGrantReceipt receipt,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        if (receipt.EnvironmentId != _environmentId) return UnknownRead(PlatformGrantDiagnostic.OperationConflict);
        try
        {
            var sql = receipt.IssueContractVersion == 1
                ? "SELECT state,diagnostic_code,environment_id,operation_id,grant_id,directory_object_id,device_id,mapping_created_at,token_sha256,authorization_digest,created_at,expires_at,issue_contract_version,mint_permit_not_after,observed_at,state_changed_at FROM agent_private.read_initial_enrollment_grant(@expected_environment_id,@operation_id,@grant_id,@directory_object_id,@device_id,@mapping_created_at,@token_sha256,@authorization_digest,@created_at,@expires_at)"
                : "SELECT state,diagnostic_code,environment_id,operation_id,grant_id,directory_object_id,device_id,mapping_created_at,token_sha256,authorization_digest,created_at,expires_at,issue_contract_version,mint_permit_not_after,observed_at,state_changed_at FROM agent_private.read_initial_enrollment_grant(@expected_environment_id,@operation_id,@grant_id,@directory_object_id,@device_id,@mapping_created_at,@token_sha256,@authorization_digest,@created_at,@expires_at,@issue_contract_version,@mint_permit_not_after)";
            await using var command = _dataSource.CreateCommand(sql);
            AddIssueReceipt(command, receipt, _environmentId);
            await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            return await ReadResponseAsync(reader, receipt, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (NpgsqlException) { return UnknownRead(PlatformGrantDiagnostic.ConnectionUnavailable); }
        catch (InvalidCastException) { return UnknownRead(); }
        catch (IndexOutOfRangeException) { return UnknownRead(); }
        catch (FormatException) { return UnknownRead(); }
        catch (OverflowException) { return UnknownRead(); }
    }

    public async Task<PlatformGrantRevocationResult> RevokeAsync(Guid revocationOperationId,
        ValidatedGrantRevocationAuthorization authorization, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authorization);
        if (revocationOperationId == Guid.Empty || authorization.IssueReceipt.EnvironmentId != _environmentId)
            return UnknownRevoke(PlatformGrantDiagnostic.OperationConflict);
        try
        {
            var issue = authorization.IssueReceipt;
            var sql = issue.IssueContractVersion == 1
                ? "SELECT outcome,diagnostic_code,environment_id,revocation_operation_id,issue_operation_id,grant_id,directory_object_id,device_id,mapping_created_at,token_sha256,issue_authorization_digest,issue_created_at,issue_expires_at,issue_contract_version,issue_mint_permit_not_after,revoke_authorization_digest,disposition,completed_at,effective_revoked_at FROM agent_private.revoke_initial_enrollment_grant(@expected_environment_id,@revocation_operation_id,@operation_id,@grant_id,@directory_object_id,@device_id,@mapping_created_at,@token_sha256,@authorization_digest,@created_at,@expires_at,@revoke_authorization_digest)"
                : "SELECT outcome,diagnostic_code,environment_id,revocation_operation_id,issue_operation_id,grant_id,directory_object_id,device_id,mapping_created_at,token_sha256,issue_authorization_digest,issue_created_at,issue_expires_at,issue_contract_version,issue_mint_permit_not_after,revoke_authorization_digest,disposition,completed_at,effective_revoked_at FROM agent_private.revoke_initial_enrollment_grant(@expected_environment_id,@revocation_operation_id,@operation_id,@grant_id,@directory_object_id,@device_id,@mapping_created_at,@token_sha256,@authorization_digest,@created_at,@expires_at,@issue_contract_version,@mint_permit_not_after,@revoke_authorization_digest)";
            await using var command = _dataSource.CreateCommand(sql);
            AddIssueReceipt(command, authorization.IssueReceipt, _environmentId);
            command.Parameters.AddWithValue("revocation_operation_id", revocationOperationId);
            command.Parameters.AddWithValue("revoke_authorization_digest", authorization.GetDigest());
            await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) return UnknownRevoke();
            var row = ReadRevocationRow(reader);
            if (await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) return UnknownRevoke();
            return NormalizeRevocation(row, revocationOperationId, authorization);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (NpgsqlException) { return UnknownRevoke(PlatformGrantDiagnostic.ConnectionUnavailable); }
        catch (InvalidCastException) { return UnknownRevoke(); }
        catch (IndexOutOfRangeException) { return UnknownRevoke(); }
        catch (FormatException) { return UnknownRevoke(); }
        catch (OverflowException) { return UnknownRevoke(); }
    }

    internal static void AddIssueReceipt(NpgsqlCommand command, PlatformGrantReceipt receipt,
        Guid expectedEnvironmentId)
    {
        command.Parameters.AddWithValue("expected_environment_id", expectedEnvironmentId);
        command.Parameters.AddWithValue("operation_id", receipt.OperationId);
        command.Parameters.AddWithValue("grant_id", receipt.GrantId);
        command.Parameters.AddWithValue("directory_object_id", receipt.DirectoryObjectId);
        command.Parameters.AddWithValue("device_id", receipt.DeviceId);
        command.Parameters.AddWithValue("mapping_created_at", receipt.MappingCreatedAt);
        command.Parameters.AddWithValue("token_sha256", receipt.GetTokenSha256());
        command.Parameters.AddWithValue("authorization_digest", receipt.GetAuthorizationDigest());
        command.Parameters.AddWithValue("created_at", receipt.CreatedAt);
        command.Parameters.AddWithValue("expires_at", receipt.ExpiresAt);
        if (receipt.IssueContractVersion == 2 && receipt.MintPermitNotAfter is { } deadline)
        {
            command.Parameters.AddWithValue("issue_contract_version", receipt.IssueContractVersion);
            command.Parameters.AddWithValue("mint_permit_not_after", deadline);
        }
    }

    internal static async Task<PlatformGrantReadResult> ReadResponseAsync(DbDataReader reader,
        PlatformGrantReceipt receipt, CancellationToken cancellationToken)
    {
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) return UnknownRead();
        var row = ReadStateRow(reader);
        if (await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) return UnknownRead();
        return NormalizeRead(row, receipt);
    }

    internal static PlatformGrantStateDatabaseResult ReadStateRow(DbDataReader reader) => new(
        Text(reader, 0), Text(reader, 1), GuidValue(reader, 2), GuidValue(reader, 3), GuidValue(reader, 4),
        GuidValue(reader, 5), GuidValue(reader, 6), Time(reader, 7), Bytes(reader, 8), Bytes(reader, 9),
        Time(reader, 10), Time(reader, 11), Time(reader, 14), Time(reader, 15), Short(reader, 12), Time(reader, 13));

    private static PlatformGrantRevocationDatabaseResult ReadRevocationRow(DbDataReader reader) => new(
        Text(reader, 0), Text(reader, 1), GuidValue(reader, 2), GuidValue(reader, 3), GuidValue(reader, 4),
        GuidValue(reader, 5), GuidValue(reader, 6), GuidValue(reader, 7), Time(reader, 8), Bytes(reader, 9),
        Bytes(reader, 10), Time(reader, 11), Time(reader, 12), Bytes(reader, 15), Text(reader, 16),
        Time(reader, 17), Time(reader, 18), Short(reader, 13), Time(reader, 14));

    internal static PlatformGrantReadResult NormalizeRead(PlatformGrantStateDatabaseResult row,
        PlatformGrantReceipt receipt)
    {
        var diagnostic = row.Diagnostic is null ? PlatformGrantDiagnostic.ResponseUnavailable :
            PostgresPlatformGrantRepository.ParseDiagnostic(row.Diagnostic);
        if (row.State is "Available" or "Expired" or "Consumed" or "Revoked")
        {
            if (diagnostic != PlatformGrantDiagnostic.None || !MatchesIssue(row, receipt) || row.ObservedAt is null ||
                !PostgresPlatformGrantRepository.IsCanonical(row.ObservedAt.Value) || row.ObservedAt < receipt.CreatedAt ||
                !ValidReadTime(row.State, row.ObservedAt.Value, row.StateChangedAt, receipt)) return UnknownRead();
            return new(ParseState(row.State), diagnostic, row.ObservedAt, row.StateChangedAt);
        }
        if (row.State == "OutcomeUnknown" && diagnostic is PlatformGrantDiagnostic.ReceiptUnavailable or PlatformGrantDiagnostic.OperationConflict &&
            MatchesIssue(row, receipt) && row.ObservedAt is null && row.StateChangedAt is null)
            return new(PlatformGrantEffectiveState.Unknown, diagnostic, null, null);
        if (row.State == "Unauthorized" && diagnostic == PlatformGrantDiagnostic.PrivilegeAuditFailed && AllIssueFieldsNull(row))
            return new(PlatformGrantEffectiveState.Unknown, diagnostic, null, null);
        return UnknownRead();
    }

    internal static PlatformGrantRevocationResult NormalizeRevocation(PlatformGrantRevocationDatabaseResult row,
        Guid revocationOperationId, ValidatedGrantRevocationAuthorization authorization)
    {
        var outcome = ParseRevocationOutcome(row.Outcome);
        var diagnostic = row.Diagnostic is null ? PlatformGrantDiagnostic.ResponseUnavailable :
            PostgresPlatformGrantRepository.ParseDiagnostic(row.Diagnostic);
        if (outcome is PlatformGrantRevocationOutcome.Completed or PlatformGrantRevocationOutcome.AlreadyCompleted)
        {
            var disposition = ParseDisposition(row.Disposition);
            if (diagnostic != PlatformGrantDiagnostic.None || disposition is null || row.CompletedAt is null ||
                row.RevocationOperationId != revocationOperationId || !MatchesIssue(row, authorization.IssueReceipt) ||
                row.RevokeAuthorizationDigest is null || !row.RevokeAuthorizationDigest.AsSpan().SequenceEqual(authorization.GetDigest()) ||
                !ValidRevocationTime(disposition.Value, row.CompletedAt.Value, row.EffectiveRevokedAt, authorization.IssueReceipt))
                return UnknownRevoke();
            return new(outcome, diagnostic, new(revocationOperationId, authorization.IssueReceipt,
                disposition.Value, row.CompletedAt.Value, row.EffectiveRevokedAt));
        }
        if (outcome == PlatformGrantRevocationOutcome.OutcomeUnknown &&
            diagnostic is PlatformGrantDiagnostic.ReceiptUnavailable or PlatformGrantDiagnostic.OperationConflict &&
            row.RevocationOperationId == revocationOperationId && MatchesIssue(row, authorization.IssueReceipt) &&
            row.RevokeAuthorizationDigest is not null && row.RevokeAuthorizationDigest.AsSpan().SequenceEqual(authorization.GetDigest()) &&
            row.Disposition is null && row.CompletedAt is null && row.EffectiveRevokedAt is null)
            return new(outcome, diagnostic, null);
        if (outcome == PlatformGrantRevocationOutcome.Unauthorized && diagnostic == PlatformGrantDiagnostic.PrivilegeAuditFailed && AllRevocationFieldsNull(row))
            return new(outcome, diagnostic, null);
        return UnknownRevoke();
    }

    private static bool MatchesIssue(PlatformGrantStateDatabaseResult row, PlatformGrantReceipt receipt) =>
        ValidIssueReceipt(receipt) && row.EnvironmentId == receipt.EnvironmentId && row.OperationId == receipt.OperationId && row.GrantId == receipt.GrantId &&
        row.DirectoryObjectId == receipt.DirectoryObjectId && row.DeviceId == receipt.DeviceId &&
        row.MappingCreatedAt == receipt.MappingCreatedAt && row.CreatedAt == receipt.CreatedAt && row.ExpiresAt == receipt.ExpiresAt &&
        row.IssueContractVersion == receipt.IssueContractVersion && row.MintPermitNotAfter == receipt.MintPermitNotAfter &&
        row.TokenSha256 is not null && row.TokenSha256.AsSpan().SequenceEqual(receipt.GetTokenSha256()) &&
        row.AuthorizationDigest is not null && row.AuthorizationDigest.AsSpan().SequenceEqual(receipt.GetAuthorizationDigest());

    private static bool MatchesIssue(PlatformGrantRevocationDatabaseResult row, PlatformGrantReceipt receipt) =>
        ValidIssueReceipt(receipt) && row.EnvironmentId == receipt.EnvironmentId && row.IssueOperationId == receipt.OperationId && row.GrantId == receipt.GrantId &&
        row.DirectoryObjectId == receipt.DirectoryObjectId && row.DeviceId == receipt.DeviceId &&
        row.MappingCreatedAt == receipt.MappingCreatedAt && row.IssueCreatedAt == receipt.CreatedAt && row.IssueExpiresAt == receipt.ExpiresAt &&
        row.IssueContractVersion == receipt.IssueContractVersion && row.IssueMintPermitNotAfter == receipt.MintPermitNotAfter &&
        row.TokenSha256 is not null && row.TokenSha256.AsSpan().SequenceEqual(receipt.GetTokenSha256()) &&
        row.IssueAuthorizationDigest is not null && row.IssueAuthorizationDigest.AsSpan().SequenceEqual(receipt.GetAuthorizationDigest());

    private static bool AllIssueFieldsNull(PlatformGrantStateDatabaseResult row) => row.EnvironmentId is null &&
        row.OperationId is null && row.GrantId is null && row.DirectoryObjectId is null && row.DeviceId is null &&
        row.MappingCreatedAt is null && row.TokenSha256 is null && row.AuthorizationDigest is null &&
        row.CreatedAt is null && row.ExpiresAt is null && row.IssueContractVersion is null &&
        row.MintPermitNotAfter is null && row.ObservedAt is null && row.StateChangedAt is null;

    private static bool ValidIssueReceipt(PlatformGrantReceipt receipt) => receipt.EnvironmentId != Guid.Empty &&
        receipt.OperationId != Guid.Empty && receipt.GrantId != Guid.Empty && receipt.DirectoryObjectId != Guid.Empty &&
        receipt.DeviceId != Guid.Empty && receipt.GetTokenSha256().Length == 32 && receipt.GetAuthorizationDigest().Length == 32 &&
        PostgresPlatformGrantRepository.IsCanonical(receipt.MappingCreatedAt) &&
        PostgresPlatformGrantRepository.IsCanonical(receipt.CreatedAt) &&
        PostgresPlatformGrantRepository.IsCanonical(receipt.ExpiresAt) && receipt.MappingCreatedAt <= receipt.CreatedAt &&
        receipt.ExpiresAt - receipt.CreatedAt == TimeSpan.FromSeconds(600) && receipt.IssueContractVersion switch
        {
            1 => receipt.MintPermitNotAfter is null,
            2 => receipt.MintPermitNotAfter is { } deadline && PostgresPlatformGrantRepository.IsCanonical(deadline) &&
                receipt.CreatedAt < deadline && deadline <= receipt.CreatedAt.AddSeconds(60),
            _ => false
        };

    private static bool ValidReadTime(string state, DateTimeOffset observedAt, DateTimeOffset? changedAt,
        PlatformGrantReceipt receipt) => state switch
    {
        "Available" => changedAt is null && observedAt < receipt.ExpiresAt,
        "Expired" => changedAt is null && observedAt >= receipt.ExpiresAt,
        "Consumed" => changedAt is not null && PostgresPlatformGrantRepository.IsCanonical(changedAt.Value) &&
            changedAt >= receipt.CreatedAt && changedAt <= observedAt && changedAt < receipt.ExpiresAt,
        "Revoked" => changedAt is not null && PostgresPlatformGrantRepository.IsCanonical(changedAt.Value) &&
            changedAt >= receipt.CreatedAt && changedAt <= observedAt,
        _ => false
    };

    private static bool ValidRevocationTime(PlatformGrantRevocationDisposition disposition, DateTimeOffset completedAt,
        DateTimeOffset? effectiveRevokedAt, PlatformGrantReceipt receipt)
    {
        if (!PostgresPlatformGrantRepository.IsCanonical(completedAt) || completedAt < receipt.CreatedAt) return false;
        if (disposition == PlatformGrantRevocationDisposition.Consumed) return effectiveRevokedAt is null;
        if (effectiveRevokedAt is null || !PostgresPlatformGrantRepository.IsCanonical(effectiveRevokedAt.Value) ||
            effectiveRevokedAt > completedAt || effectiveRevokedAt < receipt.CreatedAt) return false;
        return disposition switch
        {
            PlatformGrantRevocationDisposition.Revoked => effectiveRevokedAt == completedAt && completedAt < receipt.ExpiresAt,
            PlatformGrantRevocationDisposition.Expired => effectiveRevokedAt == completedAt && completedAt >= receipt.ExpiresAt,
            PlatformGrantRevocationDisposition.AlreadyRevoked => true,
            _ => false
        };
    }

    private static bool AllRevocationFieldsNull(PlatformGrantRevocationDatabaseResult row) => row.EnvironmentId is null &&
        row.RevocationOperationId is null && row.IssueOperationId is null && row.GrantId is null &&
        row.DirectoryObjectId is null && row.DeviceId is null && row.MappingCreatedAt is null &&
        row.TokenSha256 is null && row.IssueAuthorizationDigest is null && row.IssueCreatedAt is null &&
        row.IssueExpiresAt is null && row.IssueContractVersion is null && row.IssueMintPermitNotAfter is null &&
        row.RevokeAuthorizationDigest is null && row.Disposition is null &&
        row.CompletedAt is null && row.EffectiveRevokedAt is null;

    private static PlatformGrantEffectiveState ParseState(string value) => value switch
    {
        "Available" => PlatformGrantEffectiveState.Available,
        "Expired" => PlatformGrantEffectiveState.Expired,
        "Consumed" => PlatformGrantEffectiveState.Consumed,
        "Revoked" => PlatformGrantEffectiveState.Revoked,
        _ => PlatformGrantEffectiveState.Unknown
    };

    private static PlatformGrantRevocationOutcome ParseRevocationOutcome(string? value) => value switch
    {
        "Completed" => PlatformGrantRevocationOutcome.Completed,
        "AlreadyCompleted" => PlatformGrantRevocationOutcome.AlreadyCompleted,
        "OutcomeUnknown" => PlatformGrantRevocationOutcome.OutcomeUnknown,
        "Unauthorized" => PlatformGrantRevocationOutcome.Unauthorized,
        _ => PlatformGrantRevocationOutcome.Unknown
    };

    private static PlatformGrantRevocationDisposition? ParseDisposition(string? value) => value switch
    {
        "Revoked" => PlatformGrantRevocationDisposition.Revoked,
        "Expired" => PlatformGrantRevocationDisposition.Expired,
        "Consumed" => PlatformGrantRevocationDisposition.Consumed,
        "AlreadyRevoked" => PlatformGrantRevocationDisposition.AlreadyRevoked,
        _ => null
    };

    internal static PlatformGrantReadResult UnknownRead(PlatformGrantDiagnostic diagnostic = PlatformGrantDiagnostic.ResponseUnavailable) =>
        new(PlatformGrantEffectiveState.Unknown, diagnostic, null, null);
    private static PlatformGrantRevocationResult UnknownRevoke(PlatformGrantDiagnostic diagnostic = PlatformGrantDiagnostic.ResponseUnavailable) =>
        new(PlatformGrantRevocationOutcome.Unknown, diagnostic, null);
    private static string? Text(DbDataReader reader, int ordinal) => reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);
    private static Guid? GuidValue(DbDataReader reader, int ordinal) => reader.IsDBNull(ordinal) ? null : reader.GetGuid(ordinal);
    private static DateTimeOffset? Time(DbDataReader reader, int ordinal) => reader.IsDBNull(ordinal) ? null : reader.GetFieldValue<DateTimeOffset>(ordinal);
    private static byte[]? Bytes(DbDataReader reader, int ordinal) => reader.IsDBNull(ordinal) ? null : reader.GetFieldValue<byte[]>(ordinal);
    private static short? Short(DbDataReader reader, int ordinal) => reader.IsDBNull(ordinal) ? null : reader.GetInt16(ordinal);
}

internal sealed record PlatformGrantStateDatabaseResult(string? State, string? Diagnostic, Guid? EnvironmentId,
    Guid? OperationId, Guid? GrantId, Guid? DirectoryObjectId, Guid? DeviceId, DateTimeOffset? MappingCreatedAt,
    byte[]? TokenSha256, byte[]? AuthorizationDigest, DateTimeOffset? CreatedAt, DateTimeOffset? ExpiresAt,
    DateTimeOffset? ObservedAt, DateTimeOffset? StateChangedAt,
    short? IssueContractVersion = null, DateTimeOffset? MintPermitNotAfter = null);

internal sealed record PlatformGrantRevocationDatabaseResult(string? Outcome, string? Diagnostic,
    Guid? EnvironmentId, Guid? RevocationOperationId, Guid? IssueOperationId, Guid? GrantId,
    Guid? DirectoryObjectId, Guid? DeviceId, DateTimeOffset? MappingCreatedAt, byte[]? TokenSha256,
    byte[]? IssueAuthorizationDigest, DateTimeOffset? IssueCreatedAt, DateTimeOffset? IssueExpiresAt,
    byte[]? RevokeAuthorizationDigest, string? Disposition, DateTimeOffset? CompletedAt,
    DateTimeOffset? EffectiveRevokedAt, short? IssueContractVersion = null,
    DateTimeOffset? IssueMintPermitNotAfter = null);
