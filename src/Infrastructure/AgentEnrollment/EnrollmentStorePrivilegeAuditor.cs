using Npgsql;

namespace ItManagement.AgentEnrollment;

public sealed record EnrollmentStorePrivilegeAudit(bool IsValid,EnrollmentDiagnosticCode DiagnosticCode);

public sealed class EnrollmentStorePrivilegeAuditor(NpgsqlDataSource dataSource,string expectedTableOwner,
    string expectedFunctionOwner,string expectedPurpose)
{
    private readonly NpgsqlDataSource _dataSource=dataSource??throw new ArgumentNullException(nameof(dataSource));
    private readonly string _tableOwner=Require(expectedTableOwner);
    private readonly string _functionOwner=Require(expectedFunctionOwner);
    private readonly string _purpose=expectedPurpose is "Enroll" or "Issue"?expectedPurpose:
        throw new ArgumentOutOfRangeException(nameof(expectedPurpose));
    public async Task<EnrollmentStorePrivilegeAudit> AuditAsync(CancellationToken cancellationToken)
    {
        await using var command=_dataSource.CreateCommand(
            "SELECT is_valid,diagnostic_code FROM agent_private.audit_enrollment_privileges(@table_owner::name,@function_owner::name,@purpose)");
        command.Parameters.AddWithValue("table_owner",_tableOwner);command.Parameters.AddWithValue("function_owner",_functionOwner);
        command.Parameters.AddWithValue("purpose",_purpose);
        await using var reader=await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        if(!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))return new(false,EnrollmentDiagnosticCode.ResponseUnavailable);
        return new(reader.GetBoolean(0),EnrollmentSubmissionRepository.ParseDiagnostic(reader.GetString(1)));
    }
    private static string Require(string value){ArgumentException.ThrowIfNullOrWhiteSpace(value);return value;}
}
