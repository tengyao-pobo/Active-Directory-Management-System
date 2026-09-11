namespace ItManagement.Core;

public static class EnrollmentGrantPlanContract
{
    public const string Action = "agent-enrollment.initial-grant.v1";
    public const int SchemaVersion = 1;
    public const int GrantTtlSeconds = 600;
}

public sealed record EnrollmentGrantPlanPayload(
    int SchemaVersion,
    string Action,
    Guid EnvironmentId,
    Guid DirectoryObjectId,
    Guid ServerDeviceId,
    DateTimeOffset MappingCreatedAt,
    Guid DirectoryGeneration,
    long EnvironmentVersion,
    string RecipientSpki,
    string RecipientKeyFingerprint,
    Guid RequestId,
    string Reason,
    Guid RequesterId,
    Guid OperationId,
    int GrantTtlSeconds);

public sealed class EnrollmentGrantRecipientReservation
{
    public byte[] Fingerprint { get; set; } = [];
    public Guid EnvironmentId { get; set; }
    public Guid PlanId { get; set; }
    public Guid RequesterId { get; set; }
    public Guid RequestId { get; set; }
    public byte[] RequestDigest { get; set; } = [];
    public DateTimeOffset CreatedAt { get; set; }
}
