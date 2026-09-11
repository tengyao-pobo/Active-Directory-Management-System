namespace ItManagement.DirectoryConnector;

internal interface IDirectoryTransport : IAsyncDisposable
{
    Task<RootDseResult> ReadRootDseAsync(CancellationToken cancellationToken);

    Task<Guid> ReadBaseObjectIdAsync(string baseDn, CancellationToken cancellationToken);

    Task<DirectoryPage> ReadPageAsync(string baseDn, int pageSize, byte[] cookie, CancellationToken cancellationToken);
}

internal interface IDirectoryTransportFactory
{
    IDirectoryTransport Create(DirectoryConnectorOptions options);
}

internal sealed record RootDseResult(IReadOnlyList<string> NamingContexts);

internal sealed record DirectoryPage(IReadOnlyList<DirectoryRawEntry> Entries, byte[] Cookie);

internal sealed record DirectoryRawEntry(string DistinguishedName, IReadOnlyDictionary<string, IReadOnlyList<object>> Attributes);

internal sealed class DirectoryTransportException : Exception
{
    internal DirectoryTransportException(DirectoryReadErrorCode code)
    {
        Code = code;
    }

    internal DirectoryReadErrorCode Code { get; }
}
