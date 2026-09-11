namespace ItManagement.Core;

public sealed class DirectoryFavorite
{
    public Guid EnvironmentId { get; set; }
    public Guid PrincipalId { get; set; }
    public Guid ObjectId { get; set; }
    public string Kind { get; set; } = string.Empty;
    public DateTimeOffset CreatedAt { get; set; }
}
