using System.DirectoryServices.Protocols;
using System.Net;

namespace ItManagement.DirectoryConnector;

internal sealed class ProtocolsDirectoryTransportFactory : IDirectoryTransportFactory
{
    public IDirectoryTransport Create(DirectoryConnectorOptions options) => new ProtocolsDirectoryTransport(options);
}

internal sealed class ProtocolsDirectoryTransport : IDirectoryTransport
{
    private const int LdapsPort = 636;
    private static readonly string[] AllowedAttributes =
    [
        "objectGUID",
        "objectClass",
        "distinguishedName",
        "name",
        "sAMAccountName",
        "department",
        "objectSid",
        "uSNChanged",
    ];

    private const string SnapshotFilter =
        "(|(&(objectCategory=person)(objectClass=user))(objectClass=group)(objectClass=computer)(objectClass=organizationalUnit))";

    private readonly LdapConnection connection;
    private readonly TimeSpan timeout;

    internal ProtocolsDirectoryTransport(DirectoryConnectorOptions options)
    {
        timeout = options.RequestTimeout;
        connection = new LdapConnection(
            new LdapDirectoryIdentifier(options.Host, LdapsPort, fullyQualifiedDnsHostName: true, connectionless: false),
            credential: null,
            AuthType.Negotiate)
        {
            AutoBind = true,
            Timeout = timeout,
        };
        connection.SessionOptions.ProtocolVersion = 3;
        connection.SessionOptions.SecureSocketLayer = true;
        connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
    }

    public async Task<RootDseResult> ReadRootDseAsync(CancellationToken cancellationToken)
    {
        var request = new SearchRequest(null, "(objectClass=*)", SearchScope.Base, "namingContexts");
        var response = await SendSearchAsync(request, cancellationToken).ConfigureAwait(false);
        if (response.Entries.Count != 1)
        {
            throw new DirectoryTransportException(DirectoryReadErrorCode.InvalidResponse);
        }

        return new RootDseResult(GetValues(response.Entries[0], "namingContexts").OfType<string>().ToArray());
    }

    public async Task<Guid> ReadBaseObjectIdAsync(string baseDn, CancellationToken cancellationToken)
    {
        var request = new SearchRequest(baseDn, "(objectClass=*)", SearchScope.Base, "objectGUID");
        var response = await SendSearchAsync(request, cancellationToken).ConfigureAwait(false);
        if (response.Entries.Count != 1)
        {
            throw new DirectoryTransportException(DirectoryReadErrorCode.InvalidResponse);
        }

        var values = GetValues(response.Entries[0], "objectGUID");
        if (values.Count != 1 || values[0] is not byte[] bytes || bytes.Length != 16)
        {
            throw new DirectoryTransportException(DirectoryReadErrorCode.InvalidResponse);
        }

        return new Guid(bytes);
    }

    public async Task<DirectoryPage> ReadPageAsync(
        string baseDn,
        int pageSize,
        byte[] cookie,
        CancellationToken cancellationToken)
    {
        var request = new SearchRequest(baseDn, SnapshotFilter, SearchScope.Subtree, AllowedAttributes);
        request.Controls.Add(new PageResultRequestControl(pageSize) { Cookie = cookie });
        var response = await SendSearchAsync(request, cancellationToken).ConfigureAwait(false);

        var pageControls = response.Controls.OfType<PageResultResponseControl>().ToArray();
        if (pageControls.Length != 1)
        {
            throw new DirectoryTransportException(DirectoryReadErrorCode.InvalidResponse);
        }

        var entries = response.Entries.Cast<SearchResultEntry>()
            .Select(entry => new DirectoryRawEntry(
                entry.DistinguishedName,
                AllowedAttributes.ToDictionary(
                    name => name,
                    name => (IReadOnlyList<object>)GetValues(entry, name),
                    StringComparer.OrdinalIgnoreCase)))
            .ToArray();

        return new DirectoryPage(entries, pageControls[0].Cookie ?? []);
    }

    public ValueTask DisposeAsync()
    {
        connection.Dispose();
        return ValueTask.CompletedTask;
    }

    private async Task<SearchResponse> SendSearchAsync(SearchRequest request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            var response = await Task.Run(
                () => (SearchResponse)connection.SendRequest(request, timeout),
                cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            // A referral is an incomplete search, even when the paged result cookie terminates.
            if (response.ResultCode != ResultCode.Success || response.References.Count != 0)
                throw new DirectoryTransportException(DirectoryReadErrorCode.ProtocolError);
            return response;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (LdapException exception)
        {
            throw new DirectoryTransportException(MapLdapError(exception.ErrorCode));
        }
        catch (DirectoryOperationException)
        {
            throw new DirectoryTransportException(DirectoryReadErrorCode.ProtocolError);
        }
        catch (TimeoutException)
        {
            throw new DirectoryTransportException(DirectoryReadErrorCode.Timeout);
        }
        catch (Exception exception) when (exception is not DirectoryTransportException)
        {
            throw new DirectoryTransportException(DirectoryReadErrorCode.ConnectionFailed);
        }
    }

    private static List<object> GetValues(SearchResultEntry entry, string attributeName)
    {
        if (!entry.Attributes.Contains(attributeName))
        {
            return [];
        }

        return entry.Attributes[attributeName]!.Cast<object>().ToList();
    }

    private static DirectoryReadErrorCode MapLdapError(int errorCode) => errorCode switch
    {
        49 => DirectoryReadErrorCode.AuthenticationFailed,
        81 or 82 or 91 => DirectoryReadErrorCode.ConnectionFailed,
        85 => DirectoryReadErrorCode.Timeout,
        _ => DirectoryReadErrorCode.ProtocolError,
    };
}
