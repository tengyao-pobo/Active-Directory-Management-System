namespace ItManagement.DirectoryConnector;

public sealed record DirectoryConnectorOptions
{
    // Identity of the effective read configuration, not a signature or authorization token.
    public string ComputeConfigurationHash()
    {
        Validate();
        var payload = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(new
        {
            Version = 1, Host = Host.ToLowerInvariant(), BaseDn, ExpectedDomainId,
            PageSize, MaxEntries, MaxPages, RequestTimeoutTicks = RequestTimeout.Ticks,
            SnapshotTimeoutTicks = SnapshotTimeout.Ticks,
            Transport = "LDAPS:636;Negotiate;NoReferrals;PlatformCertificateValidation"
        });
        return Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(payload));
    }

    public required string Host { get; init; }

    public required string BaseDn { get; init; }

    public required Guid ExpectedDomainId { get; init; }

    public int PageSize { get; init; } = 500;

    public int MaxEntries { get; init; } = 100_000;

    public int MaxPages { get; init; } = 1_000;

    public TimeSpan RequestTimeout { get; init; } = TimeSpan.FromSeconds(30);

    public TimeSpan SnapshotTimeout { get; init; } = TimeSpan.FromMinutes(5);

    internal void Validate()
    {
        if (string.IsNullOrWhiteSpace(Host)
            || Host.Length > 253
            || !Host.Contains('.')
            || Uri.CheckHostName(Host) != UriHostNameType.Dns
            || !IsDnsHost(Host)
            || Host.Contains("://", StringComparison.Ordinal)
            || Host.Contains('/')
            || Host.Contains('\\')
            || Host.Contains(':')
            || string.IsNullOrWhiteSpace(BaseDn)
            || ExpectedDomainId == Guid.Empty
            || PageSize is < 1 or > 1_000
            || MaxEntries is < 1 or > 100_000
            || MaxPages is < 1 or > 10_000
            || RequestTimeout <= TimeSpan.Zero
            || RequestTimeout > TimeSpan.FromMinutes(1)
            || SnapshotTimeout <= TimeSpan.Zero
            || SnapshotTimeout > TimeSpan.FromMinutes(5)
            || SnapshotTimeout < RequestTimeout)
        {
            throw new DirectoryReadException(DirectoryReadErrorCode.InvalidConfiguration);
        }

        try
        {
            _ = DistinguishedName.Parse(BaseDn);
        }
        catch (FormatException)
        {
            throw new DirectoryReadException(DirectoryReadErrorCode.InvalidConfiguration);
        }
    }

    private static bool IsDnsHost(string host) => host.Split('.').All(label =>
        label.Length is >= 1 and <= 63
        && char.IsAsciiLetterOrDigit(label[0])
        && char.IsAsciiLetterOrDigit(label[^1])
        && label.All(character => char.IsAsciiLetterOrDigit(character) || character == '-'));
}
