namespace ItManagement.DirectoryConnector;

public enum DirectoryObjectKind
{
    User,
    Group,
    Computer,
    OrganizationalUnit,
}

public sealed record DirectoryEntrySnapshot(
    Guid ObjectId,
    DirectoryObjectKind Kind,
    string DistinguishedName,
    string Name,
    string? SamAccountName,
    string? Department,
    string? ObjectSid,
    long UsnChanged,
    bool IsProtected,
    bool ProtectionKnown,
    string? ParentDn)
{
    // Missing attribute is unknown, never implicitly enabled.
    public bool? Enabled { get; init; }
}

public sealed record DirectorySnapshot(
    string SourceServer,
    string NamingContext,
    DateTimeOffset CapturedAt,
    IReadOnlyList<DirectoryEntrySnapshot> Entries)
{
    public Guid? VerifiedDomainId { get; init; }
    public string? ConfigurationHash { get; init; }
    // CapturedAt is completion time; the oldest observation may date from ReadStartedAt.
    public DateTimeOffset? ReadStartedAt { get; init; }
}

public interface IDirectoryReader
{
    Task<DirectorySnapshot> ReadSnapshotAsync(CancellationToken cancellationToken);
}

public enum DirectoryReadErrorCode
{
    InvalidConfiguration,
    ConnectionFailed,
    AuthenticationFailed,
    Timeout,
    ProtocolError,
    InvalidResponse,
    NamingContextMismatch,
    DomainIdentityMismatch,
    PagingLoop,
    PageLimitExceeded,
    EntryLimitExceeded,
}

public sealed class DirectoryReadException : Exception
{
    public DirectoryReadException(DirectoryReadErrorCode code)
        : base(GetSafeMessage(code))
    {
        Code = code;
    }

    public DirectoryReadErrorCode Code { get; }

    private static string GetSafeMessage(DirectoryReadErrorCode code) => code switch
    {
        DirectoryReadErrorCode.InvalidConfiguration => "The directory connector configuration is invalid.",
        DirectoryReadErrorCode.ConnectionFailed => "The directory service could not be reached.",
        DirectoryReadErrorCode.AuthenticationFailed => "The directory service rejected the connector identity.",
        DirectoryReadErrorCode.Timeout => "The directory read timed out.",
        DirectoryReadErrorCode.ProtocolError => "The directory service returned a protocol error.",
        DirectoryReadErrorCode.InvalidResponse => "The directory service returned an invalid response.",
        DirectoryReadErrorCode.NamingContextMismatch => "The configured naming context was not advertised by the directory service.",
        DirectoryReadErrorCode.DomainIdentityMismatch => "The directory service domain identity did not match the configured domain.",
        DirectoryReadErrorCode.PagingLoop => "The directory service returned an invalid paging sequence.",
        DirectoryReadErrorCode.PageLimitExceeded => "The directory snapshot exceeded its configured page limit.",
        DirectoryReadErrorCode.EntryLimitExceeded => "The directory snapshot exceeded its configured entry limit.",
        _ => "The directory read failed.",
    };
}
