using System.Data;
using System.Text.Json;
using System.Text.Json.Serialization;
using Npgsql;

namespace ItManagement.AgentProjection;

public sealed class PostgresAgentInventoryProjectionReader : IAgentInventoryProjectionReader
{
    private const string BasicSource="basic-device";
    private const string SoftwareSource="HKLM uninstall registry (32-bit and 64-bit views)";
    private const string HardwareSource="hardware";
    private static readonly JsonSerializerOptions JsonOptions=new(){PropertyNameCaseInsensitive=false,UnmappedMemberHandling=JsonUnmappedMemberHandling.Disallow};
    private readonly NpgsqlDataSource _dataSource;private readonly Guid _environmentId;
    private PostgresAgentInventoryProjectionReader(NpgsqlDataSource dataSource,Guid environmentId){_dataSource=dataSource;_environmentId=environmentId;}
    public static async Task<IAgentInventoryProjectionReader> CreateAuditedAsync(NpgsqlDataSource dataSource,Guid expectedEnvironmentId,string expectedTableOwner,string expectedFunctionOwner,CancellationToken cancellationToken=default)
    {
        ArgumentNullException.ThrowIfNull(dataSource);var audit=await new AgentProjectionPrivilegeAuditor(dataSource,expectedEnvironmentId,expectedTableOwner,expectedFunctionOwner).AuditAsync(cancellationToken).ConfigureAwait(false);
        if(!audit.IsValid)throw new InvalidOperationException($"Projection privilege audit failed: {audit.DiagnosticCode}.");
        return new PostgresAgentInventoryProjectionReader(dataSource,expectedEnvironmentId);
    }
    public async Task<AgentInventoryProjection> ReadInventoryAsync(Guid environmentId,Guid directoryObjectId,CancellationToken cancellationToken)
    {
        if(environmentId==Guid.Empty||directoryObjectId==Guid.Empty||environmentId!=_environmentId)return AgentInventoryProjection.Unavailable(environmentId,directoryObjectId,ProjectionDiagnostic.AuthenticationFailed);
        try
        {
            await using var command=_dataSource.CreateCommand("SELECT * FROM agent_private.read_current_inventory_projection(@environment,@directory)");command.Parameters.AddWithValue("environment",environmentId);command.Parameters.AddWithValue("directory",directoryObjectId);
            await using var reader=await command.ExecuteReaderAsync(CommandBehavior.SingleResult,cancellationToken).ConfigureAwait(false);
            if(!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))return AgentInventoryProjection.Unavailable(environmentId,directoryObjectId,ProjectionDiagnostic.ResponseUnavailable);
            var result=Decode(reader,environmentId,directoryObjectId);if(await reader.ReadAsync(cancellationToken).ConfigureAwait(false))return AgentInventoryProjection.Unavailable(environmentId,directoryObjectId,ProjectionDiagnostic.ResponseUnavailable);return result;
        }
        catch(OperationCanceledException){return AgentInventoryProjection.Unavailable(environmentId,directoryObjectId,ProjectionDiagnostic.ResponseUnavailable);}
        catch(NpgsqlException){return AgentInventoryProjection.Unavailable(environmentId,directoryObjectId,ProjectionDiagnostic.ConnectionUnavailable);}
        catch(Exception) when(!cancellationToken.IsCancellationRequested){return AgentInventoryProjection.Unavailable(environmentId,directoryObjectId,ProjectionDiagnostic.ResponseUnavailable);}
    }
    private static AgentInventoryProjection Decode(NpgsqlDataReader reader,Guid environmentId,Guid directoryObjectId)
    {
        var state=reader.GetString(0) switch{"Observed"=>ProjectionReadState.Observed,"Missing"=>ProjectionReadState.Missing,"Unavailable"=>ProjectionReadState.Unavailable,_=>throw new InvalidDataException()};
        var diagnostic=AgentProjectionPrivilegeAuditor.Parse(reader.GetString(1));if(reader.GetGuid(2)!=environmentId||reader.GetGuid(3)!=directoryObjectId)throw new InvalidDataException();
        var device=NullableGuid(reader,4);var registration=NullableGuid(reader,5);var epoch=NullableInt64(reader,6);var sequence=NullableInt64(reader,7);var receipt=NullableGuid(reader,8);
        var collected=NullableDate(reader,9);var received=NullableDate(reader,10);var lastSeen=NullableDate(reader,11);
        if(state!=ProjectionReadState.Observed){if(!ValidTopPair(state,diagnostic))throw new InvalidDataException();return new(state,diagnostic,environmentId,directoryObjectId,device,registration,epoch,sequence,receipt,collected,received,lastSeen,BasicDeviceProjection.Missing(),InstalledSoftwareProjection.Missing(),HardwareProjection.Missing());}
        if(diagnostic!=ProjectionDiagnostic.None||device is null||device==Guid.Empty||registration is null||registration==Guid.Empty||epoch is null or <=0||sequence is null or <=0||receipt is null||receipt==Guid.Empty||collected is null||received is null)throw new InvalidDataException();
        var basic=ParseBasic(reader.GetString(12));var software=ParseSoftware(reader.GetString(13));var hardware=ParseHardware(reader.GetString(14));
        return new(state,diagnostic,environmentId,directoryObjectId,device,registration,epoch,sequence,receipt,collected,received,lastSeen,basic,software,hardware);
    }
    private static BasicDeviceProjection ParseBasic(string json)
    {
        var value=Deserialize<BasicDto>(json);var availability=Availability(value.Availability);var diagnostic=Diagnostic(value.DiagnosticCode);
        if(availability!=ProjectionAvailability.Observed){if(!ValidCollectorPair(availability,diagnostic))throw new InvalidDataException();RequireEmpty(value.Source,value.SourceObservedAt,value.IsTruncated,value.HostName,value.OperatingSystem,value.NetworkInterfaces);return new(availability,diagnostic,null,null,false,null,null,[]);}
        if(diagnostic!=ProjectionDiagnostic.None||value.Source!=BasicSource||value.SourceObservedAt is null||value.HostName is null||value.OperatingSystem is null||value.NetworkInterfaces is null||value.NetworkInterfaces.Count>64)throw new InvalidDataException();
        Text(value.HostName);Text(value.OperatingSystem.Description);Text(value.OperatingSystem.Version);Text(value.OperatingSystem.Architecture);
        var interfaces=value.NetworkInterfaces.Select(item=>{Text(item.Name);Text(item.InterfaceType);Strings(item.Addresses);Strings(item.Gateways);Strings(item.DnsServers);if(item.MacAddress is not null)Text(item.MacAddress);return new ProjectedNetworkInterface(item.Name,item.InterfaceType,item.Addresses,item.Gateways,item.DnsServers,item.MacAddress);}).ToArray();
        return new(availability,diagnostic,value.Source,value.SourceObservedAt,value.IsTruncated,value.HostName,new(value.OperatingSystem.Description,value.OperatingSystem.Version,value.OperatingSystem.Architecture),interfaces);
    }
    private static InstalledSoftwareProjection ParseSoftware(string json)
    {
        var value=Deserialize<SoftwareDto>(json);var availability=Availability(value.Availability);var diagnostic=Diagnostic(value.DiagnosticCode);
        if(availability!=ProjectionAvailability.Observed){if(!ValidCollectorPair(availability,diagnostic))throw new InvalidDataException();RequireEmpty(value.Source,value.SourceObservedAt,value.IsTruncated,value.Applications);return new(availability,diagnostic,null,null,false,[]);}
        if(diagnostic!=ProjectionDiagnostic.None||value.Source!=SoftwareSource||value.SourceObservedAt is null||value.Applications is null||value.Applications.Count>10000)throw new InvalidDataException();
        var applications=value.Applications.Select(item=>{if(string.IsNullOrWhiteSpace(item.Name))throw new InvalidDataException();Text(item.Name);OptionalText(item.Version);OptionalText(item.Publisher);OptionalText(item.InstallDate);if(item.Architecture is not("x86" or "x64"))throw new InvalidDataException();return new ProjectedInstalledSoftware(item.Name,item.Version,item.Publisher,item.InstallDate,item.Architecture);}).ToArray();
        return new(availability,diagnostic,value.Source,value.SourceObservedAt,value.IsTruncated,applications);
    }
    private static HardwareProjection ParseHardware(string json)
    {
        var value=Deserialize<HardwareDto>(json);var availability=Availability(value.Availability);var diagnostic=Diagnostic(value.DiagnosticCode);
        if(availability!=ProjectionAvailability.Observed){if(!ValidCollectorPair(availability,diagnostic))throw new InvalidDataException();RequireEmpty(value.Source,value.SourceObservedAt,value.Sections);return new(availability,diagnostic,null,null,[]);}
        if(diagnostic!=ProjectionDiagnostic.None||value.Source!=HardwareSource||value.SourceObservedAt is null||value.Sections is null||value.Sections.Count!=9)throw new InvalidDataException();
        var kinds=new HashSet<ProjectedHardwareKind>();var sections=new List<HardwareProjectionSection>(9);
        foreach(var section in value.Sections)
        {
            if(!Enum.IsDefined(section.Kind)||!kinds.Add(section.Kind)||section.Rows is null||section.Rows.Count>128)throw new InvalidDataException();
            var sectionAvailability=Availability(section.Availability);var sectionDiagnostic=Diagnostic(section.DiagnosticCode);if(section.Source!=ExpectedSource(section.Kind)||section.SourceObservedAt==default)throw new InvalidDataException();
            if(sectionAvailability==ProjectionAvailability.Observed){if(sectionDiagnostic!=ProjectionDiagnostic.None||section.Rows.Count==0)throw new InvalidDataException();}
            else if(section.Rows.Count!=0||sectionAvailability==ProjectionAvailability.Missing||sectionAvailability==ProjectionAvailability.NotApplicable&&(sectionDiagnostic!=ProjectionDiagnostic.None||section.Kind is not(ProjectedHardwareKind.Video or ProjectedHardwareKind.Battery)||section.IsTruncated)||sectionAvailability==ProjectionAvailability.Unavailable&&sectionDiagnostic!=ProjectionDiagnostic.SourceUnavailable)throw new InvalidDataException();
            var rows=section.Rows.Select(row=>ParseHardwareRow(section.Kind,row)).ToArray();sections.Add(new(section.Kind,section.Source,sectionAvailability,sectionDiagnostic,section.SourceObservedAt,section.IsTruncated,rows));
        }
        return new(ProjectionAvailability.Observed,ProjectionDiagnostic.None,value.Source,value.SourceObservedAt,sections);
    }
    private static ProjectedHardwareRow ParseHardwareRow(ProjectedHardwareKind kind,JsonElement row)=>kind switch
    {
        ProjectedHardwareKind.System=>Map(Deserialize<SystemRowDto>(row),x=>new ProjectedSystemHardwareRow(x.Manufacturer,x.Model,Number(x.TotalPhysicalMemory))),
        ProjectedHardwareKind.Product=>Map(Deserialize<ProductRowDto>(row),x=>new ProjectedProductHardwareRow(x.UUID)),
        ProjectedHardwareKind.Bios=>Map(Deserialize<BiosRowDto>(row),x=>new ProjectedBiosHardwareRow(x.Manufacturer,x.SerialNumber,x.SMBIOSBIOSVersion,x.ReleaseDate)),
        ProjectedHardwareKind.OperatingSystem=>Map(Deserialize<OperatingSystemRowDto>(row),x=>new ProjectedOperatingSystemHardwareRow(x.Caption,x.Version,x.BuildNumber,x.InstallDate,x.LastBootUpTime)),
        ProjectedHardwareKind.Processor=>Map(Deserialize<ProcessorRowDto>(row),x=>new ProjectedProcessorHardwareRow(x.Name,x.Manufacturer,Number(x.NumberOfCores),Number(x.NumberOfLogicalProcessors))),
        ProjectedHardwareKind.Memory=>Map(Deserialize<MemoryRowDto>(row),x=>new ProjectedMemoryHardwareRow(x.BankLabel,x.DeviceLocator,Number(x.Capacity),Number(x.Speed))),
        ProjectedHardwareKind.Video=>Map(Deserialize<VideoRowDto>(row),x=>new ProjectedVideoHardwareRow(x.Name,Number(x.AdapterRAM))),
        ProjectedHardwareKind.Disk=>Map(Deserialize<DiskRowDto>(row),x=>new ProjectedDiskHardwareRow(x.Model,x.SerialNumber,Number(x.Size),x.MediaType)),
        ProjectedHardwareKind.Battery=>Map(Deserialize<BatteryRowDto>(row),x=>new ProjectedBatteryHardwareRow(x.Name,Number(x.EstimatedChargeRemaining),Number(x.DesignCapacity),Number(x.FullChargeCapacity))),
        _=>throw new InvalidDataException()
    };
    private static TOutput Map<TInput,TOutput>(TInput input,Func<TInput,TOutput> create){var values=typeof(TInput).GetProperties().Where(property=>property.PropertyType==typeof(string)).Select(property=>(string?)property.GetValue(input)).ToArray();foreach(var value in values)OptionalText(value);if(values.All(value=>value is null))throw new InvalidDataException();return create(input);}
    private static string? Number(string? value){if(value is not null&&(!ulong.TryParse(value,System.Globalization.NumberStyles.None,System.Globalization.CultureInfo.InvariantCulture,out var parsed)||parsed.ToString(System.Globalization.CultureInfo.InvariantCulture)!=value))throw new InvalidDataException();return value;}
    private static string ExpectedSource(ProjectedHardwareKind kind)=>kind switch{ProjectedHardwareKind.System=>"Win32_ComputerSystem",ProjectedHardwareKind.Product=>"Win32_ComputerSystemProduct",ProjectedHardwareKind.Bios=>"Win32_BIOS",ProjectedHardwareKind.OperatingSystem=>"Win32_OperatingSystem",ProjectedHardwareKind.Processor=>"Win32_Processor",ProjectedHardwareKind.Memory=>"Win32_PhysicalMemory",ProjectedHardwareKind.Video=>"Win32_VideoController",ProjectedHardwareKind.Disk=>"Win32_DiskDrive",ProjectedHardwareKind.Battery=>"Win32_Battery",_=>throw new InvalidDataException()};
    private static T Deserialize<T>(string json)=>JsonSerializer.Deserialize<T>(json,JsonOptions)??throw new InvalidDataException();private static T Deserialize<T>(JsonElement json)=>json.Deserialize<T>(JsonOptions)??throw new InvalidDataException();
    private static ProjectionAvailability Availability(string value)=>value switch{"Observed"=>ProjectionAvailability.Observed,"Missing"=>ProjectionAvailability.Missing,"Unavailable"=>ProjectionAvailability.Unavailable,"NotApplicable"=>ProjectionAvailability.NotApplicable,_=>throw new InvalidDataException()};private static ProjectionDiagnostic Diagnostic(string value)=>AgentProjectionPrivilegeAuditor.Parse(value);
    private static bool ValidCollectorPair(ProjectionAvailability availability,ProjectionDiagnostic diagnostic)=>availability switch{ProjectionAvailability.Missing=>diagnostic==ProjectionDiagnostic.ProjectionMissing,ProjectionAvailability.Unavailable=>diagnostic is ProjectionDiagnostic.SourceUnavailable or ProjectionDiagnostic.ProjectionMalformed,_=>false};
    private static bool ValidTopPair(ProjectionReadState state,ProjectionDiagnostic diagnostic)=>state switch{ProjectionReadState.Missing=>diagnostic is ProjectionDiagnostic.MappingMissing or ProjectionDiagnostic.DeviceUnavailable or ProjectionDiagnostic.RegistrationUnavailable or ProjectionDiagnostic.ProjectionMissing,ProjectionReadState.Unavailable=>diagnostic is ProjectionDiagnostic.AuthenticationFailed or ProjectionDiagnostic.ProjectionMalformed,_=>false};
    private static void Text(string value){if(value.Length>512||value.Any(char.IsControl))throw new InvalidDataException();}private static void OptionalText(string? value){if(value is not null)Text(value);}private static void Strings(List<string>? values){if(values is null||values.Count>32)throw new InvalidDataException();foreach(var value in values)Text(value);}
    private static void RequireEmpty(params object?[] values){if(values.Any(value=>value switch{null=>false,false=>false,ICollection<object> list when list.Count==0=>false,System.Collections.ICollection list when list.Count==0=>false,_=>true}))throw new InvalidDataException();}
    private static Guid? NullableGuid(NpgsqlDataReader reader,int ordinal)=>reader.IsDBNull(ordinal)?null:reader.GetGuid(ordinal);private static long? NullableInt64(NpgsqlDataReader reader,int ordinal)=>reader.IsDBNull(ordinal)?null:reader.GetInt64(ordinal);private static DateTimeOffset? NullableDate(NpgsqlDataReader reader,int ordinal)=>reader.IsDBNull(ordinal)?null:reader.GetFieldValue<DateTimeOffset>(ordinal);

    private sealed record BasicDto(string Availability,string DiagnosticCode,string? Source,DateTimeOffset? SourceObservedAt,bool IsTruncated,string? HostName,OperatingSystemDto? OperatingSystem,List<NetworkInterfaceDto>? NetworkInterfaces);
    private sealed record OperatingSystemDto(string Description,string Version,string Architecture);private sealed record NetworkInterfaceDto(string Name,string InterfaceType,List<string> Addresses,List<string> Gateways,List<string> DnsServers,string? MacAddress);
    private sealed record SoftwareDto(string Availability,string DiagnosticCode,string? Source,DateTimeOffset? SourceObservedAt,bool IsTruncated,List<SoftwareRowDto>? Applications);private sealed record SoftwareRowDto(string Name,string? Version,string? Publisher,string? InstallDate,string Architecture);
    private sealed record HardwareDto(string Availability,string DiagnosticCode,string? Source,DateTimeOffset? SourceObservedAt,List<HardwareSectionDto>? Sections);private sealed record HardwareSectionDto(ProjectedHardwareKind Kind,string Source,string Availability,string DiagnosticCode,DateTimeOffset SourceObservedAt,bool IsTruncated,List<JsonElement>? Rows);
    private sealed record SystemRowDto(string? Manufacturer,string? Model,string? TotalPhysicalMemory);private sealed record ProductRowDto(string? UUID);private sealed record BiosRowDto(string? Manufacturer,string? SerialNumber,string? SMBIOSBIOSVersion,string? ReleaseDate);
    private sealed record OperatingSystemRowDto(string? Caption,string? Version,string? BuildNumber,string? InstallDate,string? LastBootUpTime);private sealed record ProcessorRowDto(string? Name,string? Manufacturer,string? NumberOfCores,string? NumberOfLogicalProcessors);
    private sealed record MemoryRowDto(string? BankLabel,string? DeviceLocator,string? Capacity,string? Speed);private sealed record VideoRowDto(string? Name,string? AdapterRAM);private sealed record DiskRowDto(string? Model,string? SerialNumber,string? Size,string? MediaType);private sealed record BatteryRowDto(string? Name,string? EstimatedChargeRemaining,string? DesignCapacity,string? FullChargeCapacity);
}
