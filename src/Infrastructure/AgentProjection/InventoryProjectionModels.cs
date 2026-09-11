namespace ItManagement.AgentProjection;

public enum ProjectionAvailability { Observed, Missing, Unavailable, NotApplicable }

public sealed record ProjectedOperatingSystem(string Description,string Version,string Architecture);

public sealed record ProjectedNetworkInterface
{
    public ProjectedNetworkInterface(string name,string interfaceType,IEnumerable<string> addresses,IEnumerable<string> gateways,IEnumerable<string> dnsServers,string? macAddress)
    {Name=name;InterfaceType=interfaceType;Addresses=Copy(addresses);Gateways=Copy(gateways);DnsServers=Copy(dnsServers);MacAddress=macAddress;}
    public string Name{get;} public string InterfaceType{get;} public IReadOnlyList<string> Addresses{get;} public IReadOnlyList<string> Gateways{get;} public IReadOnlyList<string> DnsServers{get;} public string? MacAddress{get;}
    private static IReadOnlyList<string> Copy(IEnumerable<string> values)=>Array.AsReadOnly(values.ToArray());
}

public sealed record BasicDeviceProjection
{
    public BasicDeviceProjection(ProjectionAvailability availability,ProjectionDiagnostic diagnosticCode,string? source,DateTimeOffset? observedAt,bool isTruncated,
        string? hostName,ProjectedOperatingSystem? operatingSystem,IEnumerable<ProjectedNetworkInterface> networkInterfaces)
    {Availability=availability;DiagnosticCode=diagnosticCode;Source=source;SourceObservedAt=observedAt;IsTruncated=isTruncated;HostName=hostName;OperatingSystem=operatingSystem;NetworkInterfaces=Array.AsReadOnly(networkInterfaces.ToArray());}
    public ProjectionAvailability Availability{get;} public ProjectionDiagnostic DiagnosticCode{get;} public string? Source{get;} public DateTimeOffset? SourceObservedAt{get;} public bool IsTruncated{get;}
    public string? HostName{get;} public ProjectedOperatingSystem? OperatingSystem{get;} public IReadOnlyList<ProjectedNetworkInterface> NetworkInterfaces{get;}
    public static BasicDeviceProjection Missing()=>new(ProjectionAvailability.Missing,ProjectionDiagnostic.ProjectionMissing,null,null,false,null,null,[]);
}

public sealed record ProjectedInstalledSoftware(string Name,string? Version,string? Publisher,string? InstallDate,string Architecture);
public sealed record InstalledSoftwareProjection
{
    public InstalledSoftwareProjection(ProjectionAvailability availability,ProjectionDiagnostic diagnosticCode,string? source,DateTimeOffset? observedAt,bool isTruncated,IEnumerable<ProjectedInstalledSoftware> applications)
    {Availability=availability;DiagnosticCode=diagnosticCode;Source=source;SourceObservedAt=observedAt;IsTruncated=isTruncated;Applications=Array.AsReadOnly(applications.ToArray());}
    public ProjectionAvailability Availability{get;} public ProjectionDiagnostic DiagnosticCode{get;} public string? Source{get;} public DateTimeOffset? SourceObservedAt{get;} public bool IsTruncated{get;} public IReadOnlyList<ProjectedInstalledSoftware> Applications{get;}
    public static InstalledSoftwareProjection Missing()=>new(ProjectionAvailability.Missing,ProjectionDiagnostic.ProjectionMissing,null,null,false,[]);
}

public enum ProjectedHardwareKind { System,Product,Bios,OperatingSystem,Processor,Memory,Video,Disk,Battery }
public abstract record ProjectedHardwareRow;
public sealed record ProjectedSystemHardwareRow(string? Manufacturer,string? Model,string? TotalPhysicalMemory):ProjectedHardwareRow;
public sealed record ProjectedProductHardwareRow(string? UUID):ProjectedHardwareRow;
public sealed record ProjectedBiosHardwareRow(string? Manufacturer,string? SerialNumber,string? SMBIOSBIOSVersion,string? ReleaseDate):ProjectedHardwareRow;
public sealed record ProjectedOperatingSystemHardwareRow(string? Caption,string? Version,string? BuildNumber,string? InstallDate,string? LastBootUpTime):ProjectedHardwareRow;
public sealed record ProjectedProcessorHardwareRow(string? Name,string? Manufacturer,string? NumberOfCores,string? NumberOfLogicalProcessors):ProjectedHardwareRow;
public sealed record ProjectedMemoryHardwareRow(string? BankLabel,string? DeviceLocator,string? Capacity,string? Speed):ProjectedHardwareRow;
public sealed record ProjectedVideoHardwareRow(string? Name,string? AdapterRAM):ProjectedHardwareRow;
public sealed record ProjectedDiskHardwareRow(string? Model,string? SerialNumber,string? Size,string? MediaType):ProjectedHardwareRow;
public sealed record ProjectedBatteryHardwareRow(string? Name,string? EstimatedChargeRemaining,string? DesignCapacity,string? FullChargeCapacity):ProjectedHardwareRow;

public sealed record HardwareProjectionSection
{
    public HardwareProjectionSection(ProjectedHardwareKind kind,string source,ProjectionAvailability availability,ProjectionDiagnostic diagnosticCode,
        DateTimeOffset observedAt,bool isTruncated,IEnumerable<ProjectedHardwareRow> rows)
    {Kind=kind;Source=source;Availability=availability;DiagnosticCode=diagnosticCode;SourceObservedAt=observedAt;IsTruncated=isTruncated;Rows=Array.AsReadOnly(rows.ToArray());}
    public ProjectedHardwareKind Kind{get;} public string Source{get;} public ProjectionAvailability Availability{get;} public ProjectionDiagnostic DiagnosticCode{get;}
    public DateTimeOffset SourceObservedAt{get;} public bool IsTruncated{get;} public IReadOnlyList<ProjectedHardwareRow> Rows{get;}
}

public sealed record HardwareProjection
{
    public HardwareProjection(ProjectionAvailability availability,ProjectionDiagnostic diagnosticCode,string? source,DateTimeOffset? observedAt,IEnumerable<HardwareProjectionSection> sections)
    {Availability=availability;DiagnosticCode=diagnosticCode;Source=source;SourceObservedAt=observedAt;Sections=Array.AsReadOnly(sections.ToArray());}
    public ProjectionAvailability Availability{get;} public ProjectionDiagnostic DiagnosticCode{get;} public string? Source{get;} public DateTimeOffset? SourceObservedAt{get;} public IReadOnlyList<HardwareProjectionSection> Sections{get;} public bool IsTruncated=>Sections.Any(section=>section.IsTruncated);
    public static HardwareProjection Missing()=>new(ProjectionAvailability.Missing,ProjectionDiagnostic.ProjectionMissing,null,null,[]);
}

public sealed record AgentInventoryProjection
{
    public AgentInventoryProjection(ProjectionReadState state,ProjectionDiagnostic diagnosticCode,Guid environmentId,Guid directoryObjectId,Guid? deviceId,Guid? registrationId,
        long? registrationEpoch,long? sequence,Guid? receiptId,DateTimeOffset? collectedAt,DateTimeOffset? receivedAt,DateTimeOffset? lastSeenAt,
        BasicDeviceProjection basicDevice,InstalledSoftwareProjection installedSoftware,HardwareProjection hardware)
    {State=state;DiagnosticCode=diagnosticCode;EnvironmentId=environmentId;DirectoryObjectId=directoryObjectId;DeviceId=deviceId;RegistrationId=registrationId;RegistrationEpoch=registrationEpoch;Sequence=sequence;ReceiptId=receiptId;CollectedAt=collectedAt;ReceivedAt=receivedAt;LastSeenAt=lastSeenAt;BasicDevice=basicDevice;InstalledSoftware=installedSoftware;Hardware=hardware;}
    public ProjectionReadState State{get;} public ProjectionDiagnostic DiagnosticCode{get;} public Guid EnvironmentId{get;} public Guid DirectoryObjectId{get;} public Guid? DeviceId{get;} public Guid? RegistrationId{get;}
    public long? RegistrationEpoch{get;} public long? Sequence{get;} public Guid? ReceiptId{get;} public DateTimeOffset? CollectedAt{get;} public DateTimeOffset? ReceivedAt{get;} public DateTimeOffset? LastSeenAt{get;}
    public BasicDeviceProjection BasicDevice{get;} public InstalledSoftwareProjection InstalledSoftware{get;} public HardwareProjection Hardware{get;}
    public static AgentInventoryProjection Unavailable(Guid environmentId,Guid directoryObjectId,ProjectionDiagnostic diagnostic)=>
        new(ProjectionReadState.Unavailable,diagnostic,environmentId,directoryObjectId,null,null,null,null,null,null,null,null,BasicDeviceProjection.Missing(),InstalledSoftwareProjection.Missing(),HardwareProjection.Missing());
}

public interface IAgentInventoryProjectionReader
{
    Task<AgentInventoryProjection> ReadInventoryAsync(Guid environmentId,Guid directoryObjectId,CancellationToken cancellationToken);
}
