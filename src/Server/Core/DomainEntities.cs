namespace ItManagement.Core;

public sealed class ManagedEnvironment
{
    public Guid Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string CanonicalDns { get; set; } = string.Empty;
    public string DefaultLocale { get; set; } = string.Empty;
    public long Version { get; set; }
}

public sealed class Principal
{
    public Guid Id { get; set; }
    public Guid OperatorId { get; set; }
    public string Issuer { get; set; } = string.Empty;
    public string Subject { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public bool Enabled { get; set; }
}

public sealed class EnvironmentMembership
{
    public Guid EnvironmentId { get; set; }
    public Guid PrincipalId { get; set; }
    public bool Active { get; set; }
}

public sealed class Role
{
    public Guid EnvironmentId { get; set; }
    public Guid Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string? BuiltInKind { get; set; }
}

public sealed class RolePermission
{
    public Guid EnvironmentId { get; set; }
    public Guid RoleId { get; set; }
    public string Permission { get; set; } = string.Empty;
}

public enum ScopeKind
{
    All = 0,
    Department = 1,
    Group = 2,
    DeviceTag = 3,
    OrganizationalUnit = 4,
}

public sealed class Scope
{
    public Guid EnvironmentId { get; set; }
    public Guid Id { get; set; }
    public ScopeKind Kind { get; set; }
    public string? Value { get; set; }
    public bool IncludeDescendants { get; set; }
}

public sealed class RoleAssignment
{
    public Guid EnvironmentId { get; set; }
    public Guid Id { get; set; }
    public Guid PrincipalId { get; set; }
    public Guid RoleId { get; set; }
    public Guid ScopeId { get; set; }
}

public sealed class DirectoryGroupMapping
{
    public Guid EnvironmentId { get; set; }
    public Guid Id { get; set; }
    public string GroupSid { get; set; } = string.Empty;
    public Guid RoleId { get; set; }
    public Guid ScopeId { get; set; }
}

public sealed record ResourceScope(
    Guid EnvironmentId,
    string ResourceId,
    string? DepartmentId,
    IReadOnlySet<string> GroupIds,
    IReadOnlySet<string> TagIds,
    IReadOnlySet<string> OrganizationalUnitAncestry,
    bool IsProtected,
    string? OrganizationalUnitId = null,
    bool ProtectionKnown = false);

public sealed class AuditRecord
{
    public Guid EnvironmentId { get; set; }
    public Guid Id { get; set; }
    public Guid? ActorId { get; set; }
    public string Action { get; set; } = string.Empty;
    public string? TargetId { get; set; }
    public string Result { get; set; } = string.Empty;
    public string? Reason { get; set; }
    public DateTimeOffset OccurredAt { get; set; }
    public string? SourceIp { get; set; }
    public string CorrelationId { get; set; } = string.Empty;
}

public sealed class OutboxMessage
{
    public Guid EnvironmentId { get; set; }
    public Guid Id { get; set; }
    public string EventType { get; set; } = string.Empty;
    public int Version { get; set; }
    public string Payload { get; set; } = string.Empty;
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? DeliveredAt { get; set; }
    public int Attempts { get; set; }
}
