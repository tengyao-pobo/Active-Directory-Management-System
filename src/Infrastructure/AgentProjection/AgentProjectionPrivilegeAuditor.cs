using Npgsql;

namespace ItManagement.AgentProjection;

public sealed class AgentProjectionPrivilegeAuditor(NpgsqlDataSource dataSource,Guid expectedEnvironmentId,
    string expectedTableOwner,string expectedFunctionOwner)
{
    private readonly NpgsqlDataSource _dataSource=dataSource??throw new ArgumentNullException(nameof(dataSource));
    private readonly Guid _environmentId=expectedEnvironmentId!=Guid.Empty?expectedEnvironmentId:throw new ArgumentOutOfRangeException(nameof(expectedEnvironmentId));
    private readonly string _tableOwner=Required(expectedTableOwner);
    private readonly string _functionOwner=Required(expectedFunctionOwner);
    public async Task<AgentProjectionPrivilegeAudit> AuditAsync(CancellationToken cancellationToken)
    {
        try
        {
            await using var command=_dataSource.CreateCommand(
                "SELECT is_valid,diagnostic_code,profile_version FROM agent_private.audit_projection_privileges(@environment,@table_owner::name,@function_owner::name)");
            command.Parameters.AddWithValue("environment",_environmentId);command.Parameters.AddWithValue("table_owner",_tableOwner);command.Parameters.AddWithValue("function_owner",_functionOwner);
            await using var reader=await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            if(!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))return new(false,ProjectionDiagnostic.ResponseUnavailable);
            var isValid=reader.GetBoolean(0);var diagnostic=Parse(reader.GetString(1));var profile=reader.GetInt16(2);
            if(await reader.ReadAsync(cancellationToken).ConfigureAwait(false)||profile!=2||isValid!=(diagnostic==ProjectionDiagnostic.None))return new(false,ProjectionDiagnostic.PrivilegeAuditFailed);
            return new(isValid,diagnostic);
        }
        catch(OperationCanceledException){return new(false,ProjectionDiagnostic.ResponseUnavailable);}
        catch(NpgsqlException){return new(false,ProjectionDiagnostic.ConnectionUnavailable);}
    }
    internal static ProjectionDiagnostic Parse(string value)=>Enum.TryParse<ProjectionDiagnostic>(value,false,out var result)&&value==result.ToString()?result:ProjectionDiagnostic.ResponseUnavailable;
    private static string Required(string value){ArgumentException.ThrowIfNullOrWhiteSpace(value);return value;}
}
