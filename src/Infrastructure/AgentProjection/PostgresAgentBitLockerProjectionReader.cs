using System.Data;
using System.Text.Json;
using Npgsql;

namespace ItManagement.AgentProjection;

public sealed class PostgresAgentBitLockerProjectionReader : IAgentBitLockerProjectionReader
{
    private readonly NpgsqlDataSource _dataSource;private readonly Guid _environmentId;
    private PostgresAgentBitLockerProjectionReader(NpgsqlDataSource dataSource,Guid environmentId){_dataSource=dataSource;_environmentId=environmentId;}
    public static async Task<IAgentBitLockerProjectionReader> CreateAuditedAsync(NpgsqlDataSource dataSource,Guid expectedEnvironmentId,
        string expectedTableOwner,string expectedFunctionOwner,CancellationToken cancellationToken=default)
    {
        ArgumentNullException.ThrowIfNull(dataSource);
        var audit=await new AgentProjectionPrivilegeAuditor(dataSource,expectedEnvironmentId,expectedTableOwner,expectedFunctionOwner).AuditAsync(cancellationToken).ConfigureAwait(false);
        if(!audit.IsValid)throw new InvalidOperationException($"Projection privilege audit failed: {audit.DiagnosticCode}.");
        return new PostgresAgentBitLockerProjectionReader(dataSource,expectedEnvironmentId);
    }
    public async Task<BitLockerProjection> ReadAsync(Guid environmentId,Guid directoryObjectId,CancellationToken cancellationToken)
    {
        if(environmentId==Guid.Empty||directoryObjectId==Guid.Empty||environmentId!=_environmentId)
            return Empty(ProjectionReadState.Unavailable,ProjectionDiagnostic.AuthenticationFailed,environmentId,directoryObjectId);
        try
        {
            await using var command=_dataSource.CreateCommand("SELECT * FROM agent_private.read_current_bitlocker_projection(@environment,@directory)");
            command.Parameters.AddWithValue("environment",environmentId);command.Parameters.AddWithValue("directory",directoryObjectId);
            await using var reader=await command.ExecuteReaderAsync(CommandBehavior.SingleResult,cancellationToken).ConfigureAwait(false);
            if(!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))return Empty(ProjectionReadState.Unavailable,ProjectionDiagnostic.ResponseUnavailable,environmentId,directoryObjectId);
            var result=Decode(reader,environmentId,directoryObjectId);
            if(await reader.ReadAsync(cancellationToken).ConfigureAwait(false))return Empty(ProjectionReadState.Unavailable,ProjectionDiagnostic.ResponseUnavailable,environmentId,directoryObjectId);
            return result;
        }
        catch(OperationCanceledException){return Empty(ProjectionReadState.Unavailable,ProjectionDiagnostic.ResponseUnavailable,environmentId,directoryObjectId);}
        catch(NpgsqlException){return Empty(ProjectionReadState.Unavailable,ProjectionDiagnostic.ConnectionUnavailable,environmentId,directoryObjectId);}
        catch(Exception) when(!cancellationToken.IsCancellationRequested){return Empty(ProjectionReadState.Unavailable,ProjectionDiagnostic.ResponseUnavailable,environmentId,directoryObjectId);}
    }
    private static BitLockerProjection Decode(NpgsqlDataReader reader,Guid environmentId,Guid directoryObjectId)
    {
        var state=reader.GetString(0) switch{"Observed"=>ProjectionReadState.Observed,"Missing"=>ProjectionReadState.Missing,"Unavailable"=>ProjectionReadState.Unavailable,_=>throw new InvalidDataException()};
        var diagnostic=AgentProjectionPrivilegeAuditor.Parse(reader.GetString(1));
        if(reader.GetGuid(2)!=environmentId||reader.GetGuid(3)!=directoryObjectId)throw new InvalidDataException();
        if(!ValidPair(state,diagnostic))throw new InvalidDataException();
        var device=reader.IsDBNull(4)?(Guid?)null:reader.GetGuid(4);var registration=reader.IsDBNull(5)?(Guid?)null:reader.GetGuid(5);
        var epoch=reader.IsDBNull(6)?(long?)null:reader.GetInt64(6);var sequence=reader.IsDBNull(7)?(long?)null:reader.GetInt64(7);var receipt=reader.IsDBNull(8)?(Guid?)null:reader.GetGuid(8);
        if(device==Guid.Empty||registration==Guid.Empty||epoch<=0||sequence<=0||receipt==Guid.Empty)throw new InvalidDataException();
        if(state!=ProjectionReadState.Observed)
            return new(state,diagnostic,environmentId,directoryObjectId,device,registration,epoch,sequence,receipt,
                NullableDate(reader,9),NullableDate(reader,10),NullableDate(reader,11),NullableDate(reader,12),null,false,[]);
        if(device is null||registration is null||epoch is null||sequence is null||receipt is null||diagnostic!=ProjectionDiagnostic.None)throw new InvalidDataException();
        var source=reader.GetString(13);if(source!=@"root\cimv2\Security\MicrosoftVolumeEncryption:Win32_EncryptableVolume")throw new InvalidDataException();
        var volumes=JsonSerializer.Deserialize<ProjectedBitLockerVolume[]>(reader.GetFieldValue<string>(15),new JsonSerializerOptions(JsonSerializerDefaults.Web))??throw new InvalidDataException();
        if(volumes.Length>128||volumes.Any(InvalidVolume)||volumes.Select(v=>v.DeviceId).Distinct(StringComparer.OrdinalIgnoreCase).Count()!=volumes.Length)throw new InvalidDataException();
        return new(state,diagnostic,environmentId,directoryObjectId,device,registration,epoch,sequence,receipt,
            reader.GetFieldValue<DateTimeOffset>(9),reader.GetFieldValue<DateTimeOffset>(10),reader.GetFieldValue<DateTimeOffset>(11),
            reader.IsDBNull(12)?null:reader.GetFieldValue<DateTimeOffset>(12),source,reader.GetBoolean(14),Array.AsReadOnly(volumes));
    }
    private static DateTimeOffset? NullableDate(NpgsqlDataReader reader,int ordinal)=>reader.IsDBNull(ordinal)?null:reader.GetFieldValue<DateTimeOffset>(ordinal);
    private static bool InvalidVolume(ProjectedBitLockerVolume volume)=>
        string.IsNullOrWhiteSpace(volume.DeviceId)||volume.DeviceId.Length>512||HasControl(volume.DeviceId)||
        volume.PersistentVolumeId is {Length:>512}||volume.PersistentVolumeId is not null&&HasControl(volume.PersistentVolumeId)||
        volume.DriveLetter is not null&&(volume.DriveLetter.Length!=2||volume.DriveLetter[0] is <'A' or >'Z'||volume.DriveLetter[1]!=':');
    private static bool HasControl(string value)=>value.Any(char.IsControl);
    private static bool ValidPair(ProjectionReadState state,ProjectionDiagnostic diagnostic)=>state switch
    {
        ProjectionReadState.Observed=>diagnostic==ProjectionDiagnostic.None,
        ProjectionReadState.Missing=>diagnostic is ProjectionDiagnostic.MappingMissing or ProjectionDiagnostic.DeviceUnavailable or ProjectionDiagnostic.RegistrationUnavailable or ProjectionDiagnostic.ProjectionMissing,
        ProjectionReadState.Unavailable=>diagnostic is ProjectionDiagnostic.AuthenticationFailed or ProjectionDiagnostic.ProjectionMalformed or ProjectionDiagnostic.SourceUnavailable,
        _=>false
    };
    private static BitLockerProjection Empty(ProjectionReadState state,ProjectionDiagnostic diagnostic,Guid environmentId,Guid directoryObjectId)=>
        state==ProjectionReadState.Unavailable?BitLockerProjection.Unavailable(environmentId,directoryObjectId,diagnostic):
        new(state,diagnostic,environmentId,directoryObjectId,null,null,null,null,null,null,null,null,null,null,false,[]);
}
