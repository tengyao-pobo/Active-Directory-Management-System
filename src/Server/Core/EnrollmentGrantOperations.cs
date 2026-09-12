namespace ItManagement.Core;

/// <summary>
/// Immutable execution intent. This record does not prove that a grant was issued.
/// The worker must obtain a current, bounded mint permit before issuing a grant.
/// </summary>
public sealed class EnrollmentGrantOperation
{
    public Guid EnvironmentId { get; set; }
    public Guid Id { get; set; }
    public Guid PlanId { get; set; }
    public Guid RequestId { get; set; }
    public Guid ApprovalId { get; set; }
    public Guid RequesterId { get; set; }
    public Guid ApproverId { get; set; }
    public Guid RequesterOperatorId { get; set; }
    public Guid ApproverOperatorId { get; set; }
    public string PlanHash { get; set; } = string.Empty;
    public Guid DirectoryObjectId { get; set; }
    public Guid ServerDeviceId { get; set; }
    public DateTimeOffset MappingCreatedAt { get; set; }
    public Guid DirectoryGeneration { get; set; }
    public long EnvironmentVersion { get; set; }
    public byte[] RecipientSpki { get; set; } = [];
    public byte[] RecipientKeyFingerprint { get; set; } = [];
    public DateTimeOffset QueuedAt { get; set; }
    public DateTimeOffset AuthorizationNotAfter { get; set; }
}

public static class EnrollmentGrantOperationContract
{
    public const string OutboxEvent = "EnrollmentGrantExecutionRequested";
    public const int SchemaVersion = 1;
    public const int MaximumMintPermitSeconds = 60;
}

public sealed record EnrollmentGrantExecutionNotification(int Version, Guid EnvironmentId, Guid OperationId);
