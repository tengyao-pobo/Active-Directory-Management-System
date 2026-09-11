namespace ItManagement.AgentEnrollmentTargets;

public enum EnrollmentTargetState
{
    Resolved,
    MappingRequired,
    Unavailable
}

public enum EnrollmentTargetDiagnostic
{
    None,
    MappingMissing,
    DeviceInactive,
    InvalidDirectoryObject,
    PrivilegeAuditFailed,
    ResponseUnavailable,
    ConnectionUnavailable
}

public sealed record EnrollmentTargetResult
{
    private EnrollmentTargetResult(Guid environmentId, Guid directoryObjectId, EnrollmentTargetState state,
        EnrollmentTargetDiagnostic diagnostic, Guid? deviceId, DateTimeOffset? mappingCreatedAt)
    {
        EnvironmentId = environmentId;
        DirectoryObjectId = directoryObjectId;
        State = state;
        Diagnostic = diagnostic;
        DeviceId = deviceId;
        MappingCreatedAt = mappingCreatedAt;
    }

    public Guid EnvironmentId { get; }
    public Guid DirectoryObjectId { get; }
    public EnrollmentTargetState State { get; }
    public EnrollmentTargetDiagnostic Diagnostic { get; }
    public Guid? DeviceId { get; }
    public DateTimeOffset? MappingCreatedAt { get; }

    public static EnrollmentTargetResult Resolved(Guid environmentId, Guid directoryObjectId, Guid deviceId,
        DateTimeOffset mappingCreatedAt) =>
        new(environmentId, directoryObjectId, EnrollmentTargetState.Resolved, EnrollmentTargetDiagnostic.None,
            deviceId, mappingCreatedAt);

    public static EnrollmentTargetResult MappingRequired(Guid environmentId, Guid directoryObjectId,
        EnrollmentTargetDiagnostic diagnostic) =>
        new(environmentId, directoryObjectId, EnrollmentTargetState.MappingRequired, diagnostic, null, null);

    public static EnrollmentTargetResult Unavailable(Guid environmentId, Guid directoryObjectId,
        EnrollmentTargetDiagnostic diagnostic) =>
        new(environmentId, directoryObjectId, EnrollmentTargetState.Unavailable, diagnostic, null, null);
}

public interface IEnrollmentTargetReader
{
    Task<EnrollmentTargetResult> ReadAsync(Guid environmentId, Guid directoryObjectId,
        CancellationToken cancellationToken);
}
