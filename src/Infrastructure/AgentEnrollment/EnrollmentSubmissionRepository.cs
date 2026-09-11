using ItManagement.AgentEnrollment.Crypto;
using Npgsql;
using NpgsqlTypes;

namespace ItManagement.AgentEnrollment;

public sealed class EnrollmentSubmissionRepository(NpgsqlDataSource dataSource)
{
    private readonly NpgsqlDataSource _dataSource=dataSource??throw new ArgumentNullException(nameof(dataSource));
    public async Task<EnrollmentSubmissionResult> SubmitOrRecoverAsync(EnrollmentBearerToken token,Guid requestId,
        Guid deviceGuid,ValidatedEnrollmentCsr csr,CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token); ArgumentNullException.ThrowIfNull(csr);
        try
        {
            await using var connection=await _dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
            await using var transaction=await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
            await using var command=new NpgsqlCommand("""
                SELECT outcome,diagnostic_code,request_id,issuance_id,registration_id,registration_epoch,binding_id,
                       leaf_der,intermediate_der,leaf_sha256,leaf_spki_sha256,serial_bytes,not_before,not_after
                FROM agent_private.submit_or_recover_enrollment(@token,@request,@device_guid,@csr,@csr_hash,@spki_hash,@profile)
                """,connection,transaction);
            command.Parameters.AddWithValue("token",NpgsqlDbType.Bytea,token.GetBytes());
            command.Parameters.AddWithValue("request",NpgsqlDbType.Uuid,requestId);
            command.Parameters.AddWithValue("device_guid",NpgsqlDbType.Uuid,deviceGuid);
            command.Parameters.AddWithValue("csr",NpgsqlDbType.Bytea,csr.GetDer());
            command.Parameters.AddWithValue("csr_hash",NpgsqlDbType.Bytea,csr.GetCsrSha256());
            command.Parameters.AddWithValue("spki_hash",NpgsqlDbType.Bytea,csr.GetSubjectPublicKeyInfoSha256());
            command.Parameters.AddWithValue("profile",NpgsqlDbType.Integer,csr.ProfileVersion);
            await using var reader=await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            if(!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                await reader.CloseAsync().ConfigureAwait(false);
                return await UnknownRollback(transaction).ConfigureAwait(false);
            }
            var result=ReadSubmission(reader); await reader.CloseAsync().ConfigureAwait(false);
            if(result.Outcome is EnrollmentSubmissionOutcome.Pending or EnrollmentSubmissionOutcome.Issued)
                await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            else await transaction.RollbackAsync(cancellationToken).ConfigureAwait(false);
            return result;
        }
        catch(OperationCanceledException){return Unknown(EnrollmentDiagnosticCode.ResponseUnavailable);}
        catch(NpgsqlException){return Unknown(EnrollmentDiagnosticCode.ConnectionUnavailable);}
    }
    private static EnrollmentSubmissionResult ReadSubmission(NpgsqlDataReader r)
    {
        var outcome=r.GetString(0); var diagnostic=ParseDiagnostic(r.GetString(1));
        var identity=r.IsDBNull(2)?null:new EnrollmentIdentity(r.GetGuid(2),r.GetGuid(3),r.GetGuid(4),r.GetInt64(5));
        var certificate=outcome=="Issued"?new PersistedIssuedCertificate(r.GetGuid(6),r.GetFieldValue<byte[]>(7),
            r.GetFieldValue<byte[][]>(8),r.GetFieldValue<byte[]>(9),r.GetFieldValue<byte[]>(10),r.GetFieldValue<byte[]>(11),
            r.GetFieldValue<DateTimeOffset>(12),r.GetFieldValue<DateTimeOffset>(13)):null;
        return new(outcome switch{"Pending"=>EnrollmentSubmissionOutcome.Pending,"Issued"=>EnrollmentSubmissionOutcome.Issued,
            "RecoveryRequired"=>EnrollmentSubmissionOutcome.RecoveryRequired,"PermanentRejected"=>EnrollmentSubmissionOutcome.PermanentRejected,
            "IdentityConflict"=>EnrollmentSubmissionOutcome.IdentityConflict,_=>EnrollmentSubmissionOutcome.Unknown},diagnostic,identity,certificate);
    }
    internal static EnrollmentDiagnosticCode ParseDiagnostic(string value)=>Enum.TryParse<EnrollmentDiagnosticCode>(value,out var parsed)?parsed:EnrollmentDiagnosticCode.ResponseUnavailable;
    private static EnrollmentSubmissionResult Unknown(EnrollmentDiagnosticCode code)=>new(EnrollmentSubmissionOutcome.Unknown,code,null,null);
    private static async Task<EnrollmentSubmissionResult> UnknownRollback(NpgsqlTransaction transaction){await transaction.RollbackAsync(CancellationToken.None);return Unknown(EnrollmentDiagnosticCode.ResponseUnavailable);}
}
