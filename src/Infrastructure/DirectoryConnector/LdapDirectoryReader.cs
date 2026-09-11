using System.Globalization;
using System.Buffers.Binary;

namespace ItManagement.DirectoryConnector;

public sealed class LdapDirectoryReader : IDirectoryReader
{
    private readonly DirectoryConnectorOptions options;
    private readonly IDirectoryTransportFactory transportFactory;

    public LdapDirectoryReader(DirectoryConnectorOptions options)
        : this(options, new ProtocolsDirectoryTransportFactory())
    {
    }

    internal LdapDirectoryReader(DirectoryConnectorOptions options, IDirectoryTransportFactory transportFactory)
    {
        this.options = options ?? throw new ArgumentNullException(nameof(options));
        this.transportFactory = transportFactory ?? throw new ArgumentNullException(nameof(transportFactory));
    }

    public async Task<DirectorySnapshot> ReadSnapshotAsync(CancellationToken cancellationToken)
    {
        options.Validate();
        using var snapshotCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        snapshotCancellation.CancelAfter(options.SnapshotTimeout);
        var snapshotToken = snapshotCancellation.Token;

        try
        {
            await using var transport = transportFactory.Create(options);
            var rootDse = await transport.ReadRootDseAsync(snapshotToken).ConfigureAwait(false);
            ValidateNamingContext(rootDse);

            var domainId = await transport.ReadBaseObjectIdAsync(options.BaseDn, snapshotToken).ConfigureAwait(false);
            if (domainId != options.ExpectedDomainId)
            {
                throw new DirectoryReadException(DirectoryReadErrorCode.DomainIdentityMismatch);
            }

            var entries = await ReadAllPagesAsync(transport, snapshotToken).ConfigureAwait(false);
            return new DirectorySnapshot(
                options.Host,
                options.BaseDn,
                DateTimeOffset.UtcNow,
                entries.AsReadOnly());
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException) when (snapshotCancellation.IsCancellationRequested)
        {
            throw new DirectoryReadException(DirectoryReadErrorCode.Timeout);
        }
        catch (DirectoryReadException)
        {
            throw;
        }
        catch (DirectoryTransportException exception)
        {
            throw new DirectoryReadException(exception.Code);
        }
        catch (Exception)
        {
            throw new DirectoryReadException(DirectoryReadErrorCode.InvalidResponse);
        }
    }

    private void ValidateNamingContext(RootDseResult rootDse)
    {
        try
        {
            if (rootDse.NamingContexts.Count == 0
                || !rootDse.NamingContexts.Any(context => DistinguishedName.AreEqual(context, options.BaseDn)))
            {
                throw new DirectoryReadException(DirectoryReadErrorCode.NamingContextMismatch);
            }
        }
        catch (FormatException)
        {
            throw new DirectoryReadException(DirectoryReadErrorCode.InvalidResponse);
        }
    }

    private async Task<List<DirectoryEntrySnapshot>> ReadAllPagesAsync(
        IDirectoryTransport transport,
        CancellationToken cancellationToken)
    {
        var entries = new List<DirectoryEntrySnapshot>();
        var seenCookies = new HashSet<string>(StringComparer.Ordinal);
        byte[] cookie = [];
        long pageCount = 0;

        do
        {
            if (++pageCount > options.MaxPages)
            {
                throw new DirectoryReadException(DirectoryReadErrorCode.PageLimitExceeded);
            }

            var page = await transport.ReadPageAsync(options.BaseDn, options.PageSize, cookie, cancellationToken)
                .ConfigureAwait(false);
            if (page.Entries.Count > options.PageSize || page.Cookie.Length > 4_096)
            {
                throw new DirectoryReadException(DirectoryReadErrorCode.InvalidResponse);
            }

            if (page.Cookie.Length > 0 && !seenCookies.Add(Convert.ToBase64String(page.Cookie)))
            {
                throw new DirectoryReadException(DirectoryReadErrorCode.PagingLoop);
            }

            if (page.Cookie.Length > 0 && page.Entries.Count == 0)
            {
                throw new DirectoryReadException(DirectoryReadErrorCode.InvalidResponse);
            }

            if (page.Entries.Count > options.MaxEntries - entries.Count)
            {
                throw new DirectoryReadException(DirectoryReadErrorCode.EntryLimitExceeded);
            }

            foreach (var rawEntry in page.Entries)
            {
                entries.Add(MapEntry(rawEntry));
            }

            cookie = page.Cookie;
        }
        while (cookie.Length > 0);

        return entries;
    }

    private static DirectoryEntrySnapshot MapEntry(DirectoryRawEntry entry)
    {
        try
        {
            var distinguishedName = RequiredString(entry, "distinguishedName");
            if (!DistinguishedName.AreEqual(distinguishedName, entry.DistinguishedName))
            {
                throw new FormatException();
            }

            return new DirectoryEntrySnapshot(
                RequiredGuid(entry, "objectGUID"),
                GetKind(entry),
                distinguishedName,
                RequiredString(entry, "name"),
                OptionalString(entry, "sAMAccountName"),
                OptionalString(entry, "department"),
                OptionalSid(entry, "objectSid"),
                RequiredLong(entry, "uSNChanged"),
                IsProtected: false,
                ProtectionKnown: false,
                DistinguishedName.GetParent(distinguishedName));
        }
        catch (Exception exception) when (exception is FormatException or InvalidCastException or OverflowException)
        {
            throw new DirectoryReadException(DirectoryReadErrorCode.InvalidResponse);
        }
    }

    private static DirectoryObjectKind GetKind(DirectoryRawEntry entry)
    {
        var classes = Values(entry, "objectClass").OfType<string>().ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (classes.Contains("computer"))
        {
            return DirectoryObjectKind.Computer;
        }

        if (classes.Contains("group"))
        {
            return DirectoryObjectKind.Group;
        }

        if (classes.Contains("organizationalUnit"))
        {
            return DirectoryObjectKind.OrganizationalUnit;
        }

        if (classes.Contains("user"))
        {
            return DirectoryObjectKind.User;
        }

        throw new FormatException();
    }

    private static Guid RequiredGuid(DirectoryRawEntry entry, string name)
    {
        var values = Values(entry, name);
        if (values.Count != 1 || values[0] is not byte[] bytes || bytes.Length != 16)
        {
            throw new FormatException();
        }

        return new Guid(bytes);
    }

    private static string RequiredString(DirectoryRawEntry entry, string name) =>
        OptionalString(entry, name) ?? throw new FormatException();

    private static string? OptionalString(DirectoryRawEntry entry, string name)
    {
        var values = Values(entry, name);
        if (values.Count == 0)
        {
            return null;
        }

        if (values.Count != 1 || values[0] is not string value || string.IsNullOrWhiteSpace(value))
        {
            throw new FormatException();
        }

        return value;
    }

    private static long RequiredLong(DirectoryRawEntry entry, string name)
    {
        var value = RequiredString(entry, name);
        if (!long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var result) || result < 0)
        {
            throw new FormatException();
        }

        return result;
    }

    private static string? OptionalSid(DirectoryRawEntry entry, string name)
    {
        var values = Values(entry, name);
        if (values.Count == 0)
        {
            return null;
        }

        if (values.Count != 1 || values[0] is not byte[] bytes)
        {
            throw new FormatException();
        }

        return FormatSid(bytes);
    }

    private static string FormatSid(byte[] bytes)
    {
        if (bytes.Length < 8)
        {
            throw new FormatException();
        }

        var subAuthorityCount = bytes[1];
        if (bytes.Length != 8 + (subAuthorityCount * 4))
        {
            throw new FormatException();
        }

        ulong identifierAuthority = 0;
        for (var index = 2; index < 8; index++)
        {
            identifierAuthority = (identifierAuthority << 8) | bytes[index];
        }

        var result = $"S-{bytes[0]}-{identifierAuthority}";
        for (var index = 0; index < subAuthorityCount; index++)
        {
            result += $"-{BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(8 + (index * 4), 4))}";
        }

        return result;
    }

    private static IReadOnlyList<object> Values(DirectoryRawEntry entry, string name) =>
        entry.Attributes.TryGetValue(name, out var values) ? values : [];
}
