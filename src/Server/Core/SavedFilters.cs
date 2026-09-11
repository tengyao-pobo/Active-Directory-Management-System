namespace ItManagement.Core;

public static class SavedFilterCatalog
{
    public const int SchemaVersion = 1;
    public const int MaximumPerPrincipal = 50;
    public static IReadOnlyList<string> Kinds { get; } = Array.AsReadOnly(new[] { "User", "Group", "Computer", "OrganizationalUnit" });
}

public sealed class SavedFilter
{
    public Guid EnvironmentId { get; set; }
    public Guid PrincipalId { get; set; }
    public Guid Id { get; set; }
    public int SchemaVersion { get; set; } = SavedFilterCatalog.SchemaVersion;
    public string Name { get; set; } = string.Empty;
    public string Kind { get; set; } = string.Empty;
    public string Search { get; set; } = string.Empty;
    public Guid? TagId { get; set; }
    public long Version { get; set; } = 1;
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}
