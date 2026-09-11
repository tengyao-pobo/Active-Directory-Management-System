using ItManagement.AgentEnrollment.Crypto;
using Npgsql;
using NpgsqlTypes;

namespace ItManagement.AgentEnrollment;

public sealed class EnrollmentIssuanceRepository(NpgsqlDataSource dataSource)
{
    private readonly NpgsqlDataSource _dataSource=dataSource??throw new ArgumentNullException(nameof(dataSource));

    public async Task<IssuanceClaimResult> ClaimAsync(Guid environmentId,Guid workerId,CancellationToken cancellationToken)
    {
        try
        {
            await using var connection=await _dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
            await using var transaction=await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
            await using var command=new NpgsqlCommand("SELECT * FROM agent_private.claim_enrollment_issuance(@environment,@worker)",connection,transaction);
            command.Parameters.AddWithValue("environment",environmentId); command.Parameters.AddWithValue("worker",workerId);
            await using var reader=await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            if(!await reader.ReadAsync(cancellationToken).ConfigureAwait(false)){await reader.CloseAsync().ConfigureAwait(false);await transaction.RollbackAsync(CancellationToken.None).ConfigureAwait(false);return UnknownClaim();}
            var outcome=reader.GetString(0); var diagnostic=EnrollmentSubmissionRepository.ParseDiagnostic(reader.GetString(1));
            IssuanceClaim? claim=outcome=="Claimed"?new(reader.GetGuid(2),reader.GetGuid(3),reader.GetGuid(4),reader.GetGuid(5),
                reader.GetGuid(6),reader.GetGuid(7),reader.GetInt64(8),reader.GetFieldValue<byte[]>(9),reader.GetFieldValue<byte[]>(10),
                reader.GetFieldValue<byte[]>(11),reader.GetInt32(12)):null;
            await reader.CloseAsync().ConfigureAwait(false);
            if(outcome is "Claimed" or "None") await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            else await transaction.RollbackAsync(cancellationToken).ConfigureAwait(false);
            return new(outcome switch{"Claimed"=>IssuanceClaimOutcome.Claimed,"None"=>IssuanceClaimOutcome.None,
                "Unauthorized"=>IssuanceClaimOutcome.Unauthorized,_=>IssuanceClaimOutcome.Unknown},diagnostic,claim);
        }
        catch(OperationCanceledException){return UnknownClaim(EnrollmentDiagnosticCode.ResponseUnavailable);}
        catch(NpgsqlException){return UnknownClaim(EnrollmentDiagnosticCode.ConnectionUnavailable);}
    }

    public Task<IssuanceMutationResult> CompleteAsync(Guid issuanceId,Guid leaseToken,
        ValidatedIssuedEnrollmentCertificate certificate,CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        var identity=certificate.Identity;
        return ExecuteCompleteAsync(issuanceId,leaseToken,certificate,identity,cancellationToken);
    }

    public Task<IssuanceMutationResult> DeferAsync(Guid issuanceId,Guid leaseToken,TimeSpan retryAfter,CancellationToken cancellationToken)
    {
        var seconds=retryAfter<=TimeSpan.Zero?0:(int)Math.Min(3600,Math.Ceiling(retryAfter.TotalSeconds));
        return ExecuteSimpleAsync("defer_enrollment_issuance",issuanceId,leaseToken,seconds,null,cancellationToken);
    }

    public Task<IssuanceMutationResult> MarkOutcomeUnknownAsync(Guid issuanceId,Guid leaseToken,CancellationToken cancellationToken)=>
        ExecuteSimpleAsync("mark_enrollment_issuance_unknown",issuanceId,leaseToken,null,null,cancellationToken);

    public Task<IssuanceMutationResult> FailDefinitivelyAsync(Guid issuanceId,Guid leaseToken,
        DefinitiveIssuanceFailure proof,CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(proof);
        return ExecuteSimpleAsync("fail_enrollment_issuance_definitively",issuanceId,leaseToken,null,proof,cancellationToken);
    }

    private async Task<IssuanceMutationResult> ExecuteCompleteAsync(Guid issuanceId,Guid leaseToken,
        ValidatedIssuedEnrollmentCertificate certificate,EnrollmentCertificateIdentity identity,CancellationToken cancellationToken)
    {
        try
        {
            await using var connection=await _dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
            await using var transaction=await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
            await using var command=new NpgsqlCommand("""
              SELECT * FROM agent_private.complete_enrollment_issuance(@issuance,@lease,@environment,@device,@registration,
                @device_guid,@epoch,@profile,@leaf,@intermediates,@leaf_hash,@spki_hash,@serial,@not_before,@not_after)
              """,connection,transaction);
            command.Parameters.AddWithValue("issuance",issuanceId); command.Parameters.AddWithValue("lease",leaseToken);
            command.Parameters.AddWithValue("environment",identity.EnvironmentId);command.Parameters.AddWithValue("device",identity.DeviceId);
            command.Parameters.AddWithValue("registration",identity.RegistrationId);command.Parameters.AddWithValue("device_guid",identity.DeviceGuid);
            command.Parameters.AddWithValue("epoch",identity.RegistrationEpoch);command.Parameters.AddWithValue("profile",certificate.ProfileVersion);
            command.Parameters.AddWithValue("leaf",certificate.GetLeafDer());
            command.Parameters.AddWithValue("intermediates",NpgsqlDbType.Array|NpgsqlDbType.Bytea,certificate.GetIntermediateDer());
            command.Parameters.AddWithValue("leaf_hash",certificate.GetLeafSha256());command.Parameters.AddWithValue("spki_hash",certificate.GetSubjectPublicKeyInfoSha256());
            command.Parameters.AddWithValue("serial",certificate.GetSerialNumber());command.Parameters.AddWithValue("not_before",certificate.NotBefore);
            command.Parameters.AddWithValue("not_after",certificate.NotAfter);
            await using var reader=await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            if(!await reader.ReadAsync(cancellationToken).ConfigureAwait(false)){await reader.CloseAsync().ConfigureAwait(false);await transaction.RollbackAsync(CancellationToken.None).ConfigureAwait(false);return Unknown();}
            var outcome=reader.GetString(0);var diagnostic=EnrollmentSubmissionRepository.ParseDiagnostic(reader.GetString(1));
            EnrollmentIdentity? resultIdentity=reader.IsDBNull(2)?null:new(reader.GetGuid(2),reader.GetGuid(3),reader.GetGuid(4),reader.GetInt64(5));
            PersistedIssuedCertificate? persisted=outcome is "Issued" or "AlreadyIssued"?new(reader.GetGuid(6),reader.GetFieldValue<byte[]>(7),
                reader.GetFieldValue<byte[][]>(8),reader.GetFieldValue<byte[]>(9),reader.GetFieldValue<byte[]>(10),reader.GetFieldValue<byte[]>(11),
                reader.GetFieldValue<DateTimeOffset>(12),reader.GetFieldValue<DateTimeOffset>(13)):null;
            await reader.CloseAsync().ConfigureAwait(false);
            if(outcome is "Issued" or "AlreadyIssued")await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            else await transaction.RollbackAsync(cancellationToken).ConfigureAwait(false);
            return new(MapMutation(outcome),diagnostic,resultIdentity,persisted);
        }
        catch(OperationCanceledException){return Unknown(EnrollmentDiagnosticCode.ResponseUnavailable);}
        catch(NpgsqlException){return Unknown(EnrollmentDiagnosticCode.ConnectionUnavailable);}
    }

    private async Task<IssuanceMutationResult> ExecuteSimpleAsync(string function,Guid issuanceId,Guid leaseToken,int? seconds,
        DefinitiveIssuanceFailure? proof,CancellationToken cancellationToken)
    {
        _=proof;
        try
        {
            await using var connection=await _dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
            await using var transaction=await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
            var sql=seconds.HasValue?$"SELECT * FROM agent_private.{function}(@issuance,@lease,@seconds)":$"SELECT * FROM agent_private.{function}(@issuance,@lease)";
            await using var command=new NpgsqlCommand(sql,connection,transaction);
            command.Parameters.AddWithValue("issuance",issuanceId);command.Parameters.AddWithValue("lease",leaseToken);
            if(seconds.HasValue)command.Parameters.AddWithValue("seconds",seconds.Value);
            await using var reader=await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            if(!await reader.ReadAsync(cancellationToken).ConfigureAwait(false)){await reader.CloseAsync().ConfigureAwait(false);await transaction.RollbackAsync(CancellationToken.None).ConfigureAwait(false);return Unknown();}
            var outcome=reader.GetString(0);var diagnostic=EnrollmentSubmissionRepository.ParseDiagnostic(reader.GetString(1));
            await reader.CloseAsync().ConfigureAwait(false);
            if(outcome is "Deferred" or "OutcomeUnknown" or "PermanentFailed")await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            else await transaction.RollbackAsync(cancellationToken).ConfigureAwait(false);
            return new(MapMutation(outcome),diagnostic,null,null);
        }
        catch(OperationCanceledException){return Unknown(EnrollmentDiagnosticCode.ResponseUnavailable);}
        catch(NpgsqlException){return Unknown(EnrollmentDiagnosticCode.ConnectionUnavailable);}
    }
    private static IssuanceClaimResult UnknownClaim(EnrollmentDiagnosticCode code=EnrollmentDiagnosticCode.ResponseUnavailable)=>new(IssuanceClaimOutcome.Unknown,code,null);
    private static IssuanceMutationResult Unknown(EnrollmentDiagnosticCode code=EnrollmentDiagnosticCode.ResponseUnavailable)=>new(IssuanceMutationOutcome.Unknown,code,null,null);
    private static IssuanceMutationOutcome MapMutation(string value)=>value switch{"Issued"=>IssuanceMutationOutcome.Completed,
      "AlreadyIssued"=>IssuanceMutationOutcome.AlreadyCompleted,"Deferred"=>IssuanceMutationOutcome.Deferred,
      "OutcomeUnknown"=>IssuanceMutationOutcome.OutcomeUnknown,"PermanentFailed"=>IssuanceMutationOutcome.PermanentFailed,
      "RecoveryRequired"=>IssuanceMutationOutcome.RecoveryRequired,"Unauthorized"=>IssuanceMutationOutcome.Unauthorized,
      "PermanentRejected"=>IssuanceMutationOutcome.PermanentRejected,"IdentityConflict"=>IssuanceMutationOutcome.IdentityConflict,_=>IssuanceMutationOutcome.Unknown};
}
