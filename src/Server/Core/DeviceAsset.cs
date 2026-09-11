namespace ItManagement.Core;

// Id is the AD computer objectGUID within EnvironmentId. Metadata is never written to AD.
public sealed class DeviceAsset
{
    public Guid EnvironmentId { get; set; }
    public Guid Id { get; set; }
    public string Lifecycle { get; set; } = "Unknown";
    public string Notes { get; set; } = "";
    public long Version { get; set; }
    public Guid UpdatedBy { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}
