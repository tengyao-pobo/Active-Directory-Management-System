namespace ItManagement.AgentProjection;

public enum ProjectionReadState { Observed, Missing, Unavailable }
public enum ProjectionDiagnostic
{
    None, AuthenticationFailed, MappingMissing, DeviceUnavailable, RegistrationUnavailable,
    ProjectionMissing, ProjectionMalformed, SourceUnavailable, PrivilegeAuditFailed,
    ConnectionUnavailable, ResponseUnavailable
}

public sealed record ProjectedBitLockerVolume(string DeviceId,string? PersistentVolumeId,string? DriveLetter,
    uint? VolumeType,uint? ProtectionStatus,uint? ConversionStatus,uint? EncryptionMethod,bool? IsVolumeInitializedForProtection);

public sealed record BitLockerProjection(
    ProjectionReadState State,ProjectionDiagnostic DiagnosticCode,Guid EnvironmentId,Guid DirectoryObjectId,
    Guid? DeviceId,Guid? RegistrationId,long? RegistrationEpoch,long? Sequence,Guid? ReceiptId,
    DateTimeOffset? CollectedAt,DateTimeOffset? SourceObservedAt,DateTimeOffset? ReceivedAt,DateTimeOffset? LastSeenAt,
    string? Source,bool IsTruncated,IReadOnlyList<ProjectedBitLockerVolume> Volumes)
{
    public static BitLockerProjection Unavailable(Guid environmentId,Guid directoryObjectId,ProjectionDiagnostic diagnostic)=>
        new(ProjectionReadState.Unavailable,diagnostic,environmentId,directoryObjectId,null,null,null,null,null,
            null,null,null,null,null,false,[]);
}

public interface IAgentBitLockerProjectionReader
{
    Task<BitLockerProjection> ReadAsync(Guid environmentId,Guid directoryObjectId,CancellationToken cancellationToken);
}

public sealed record AgentProjectionPrivilegeAudit(bool IsValid,ProjectionDiagnostic DiagnosticCode);
