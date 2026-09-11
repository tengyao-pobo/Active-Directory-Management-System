namespace ItManagement.Core;

public static class DeviceTagCatalog
{
    public static IReadOnlyList<string> Keys { get; } = Array.AsReadOnly(new[]
        { "VIP", "Finance", "Shared", "MeetingRoom", "ServerRoom", "Critical", "Test", "Replacement" });
    public const int AssignmentLimit = 100_000;
    public static bool IsCanonicalId(string? value) => Guid.TryParseExact(value, "D", out var id) &&
        id != Guid.Empty && value == id.ToString("D");
}

public sealed class DeviceTag
{
    public Guid EnvironmentId { get; set; }
    public Guid Id { get; set; }
    public string Key { get; set; } = string.Empty;
    public long Version { get; set; } = 1;
    public DateTimeOffset? ArchivedAt { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public Guid CreatedBy { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
    public Guid UpdatedBy { get; set; }
}

public sealed class DeviceTagAssignment
{
    public Guid EnvironmentId { get; set; }
    public Guid TagId { get; set; }
    public Guid ObjectId { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public Guid CreatedBy { get; set; }
}
