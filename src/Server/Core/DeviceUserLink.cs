namespace ItManagement.Core;

// Manual primary user, distinct from any Agent-observed logon session.
public sealed class DeviceUserLink
{
    public Guid EnvironmentId { get; set; }
    public Guid Id { get; set; } // Computer objectGUID
    public Guid? UserId { get; set; }
    public long Version { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}
