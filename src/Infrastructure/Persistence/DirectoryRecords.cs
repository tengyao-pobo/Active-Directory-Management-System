namespace ItManagement.Persistence;

public sealed class DirectoryObjectRecord
{
    public Guid EnvironmentId { get; set; }
    public Guid Id { get; set; }
    public Guid Generation { get; set; }
    public string Kind { get; set; } = "";
    public string DistinguishedName { get; set; } = "";
    public string Name { get; set; } = "";
    public string? SamAccountName { get; set; }
    public string? Department { get; set; }
    public string? ObjectSid { get; set; }
    public long UsnChanged { get; set; }
    public bool IsProtected { get; set; }
    public bool ProtectionKnown { get; set; }
    public Guid? ParentOuId { get; set; }
    public Guid[] OuAncestry { get; set; } = [];
}

public sealed class DirectorySyncState
{
    public Guid EnvironmentId { get; set; }
    public Guid Id { get; set; }
    public Guid Generation { get; set; }
    public DateTimeOffset? CompletedAt { get; set; }
    public DateTimeOffset AttemptedAt { get; set; }
    public string Status { get; set; } = "Unconfigured";
    public string? ErrorCode { get; set; }
    public string SourceServer { get; set; } = "";
    public string NamingContext { get; set; } = "";
}
