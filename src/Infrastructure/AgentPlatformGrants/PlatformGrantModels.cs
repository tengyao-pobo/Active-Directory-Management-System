namespace ItManagement.AgentPlatformGrants;

public enum PlatformGrantOutcome
{
    Created,
    AlreadyCreated,
    PermanentRejected,
    OutcomeUnknown,
    Unauthorized,
    Unknown
}

public enum PlatformGrantDiagnostic
{
    None,
    InvalidRequest,
    MappingUnavailable,
    DeviceUnavailable,
    EnrollmentAlreadyExists,
    EnrollmentInProgress,
    GrantAlreadyAvailable,
    ReceiptUnavailable,
    OperationConflict,
    PrivilegeAuditFailed,
    ConnectionUnavailable,
    ResponseUnavailable
}

public sealed class ValidatedGrantAuthorization
{
    private readonly byte[] _digest;

    private ValidatedGrantAuthorization(Guid directoryObjectId, Guid expectedDeviceId,
        DateTimeOffset mappingCreatedAt, byte[] digest)
    {
        DirectoryObjectId = directoryObjectId;
        ExpectedDeviceId = expectedDeviceId;
        MappingCreatedAt = mappingCreatedAt;
        _digest = (byte[])digest.Clone();
    }

    public Guid DirectoryObjectId { get; }
    public Guid ExpectedDeviceId { get; }
    public DateTimeOffset MappingCreatedAt { get; }
    internal byte[] GetDigest() => (byte[])_digest.Clone();

    internal static ValidatedGrantAuthorization FromValidatedPlan(Guid directoryObjectId, Guid expectedDeviceId,
        DateTimeOffset mappingCreatedAt, ReadOnlySpan<byte> authorizationDigest)
    {
        if (directoryObjectId == Guid.Empty || expectedDeviceId == Guid.Empty || authorizationDigest.Length != 32 ||
            mappingCreatedAt.Offset != TimeSpan.Zero || mappingCreatedAt.Ticks % 10 != 0)
            throw new ArgumentException("InvalidGrantAuthorization");
        return new(directoryObjectId, expectedDeviceId, mappingCreatedAt, authorizationDigest.ToArray());
    }
}

public sealed class PlatformGrantReceipt : IEquatable<PlatformGrantReceipt>
{
    private readonly byte[] _tokenSha256;
    private readonly byte[] _authorizationDigest;

    internal PlatformGrantReceipt(Guid environmentId, Guid operationId, Guid grantId, Guid directoryObjectId,
        Guid deviceId, DateTimeOffset mappingCreatedAt, DateTimeOffset createdAt, DateTimeOffset expiresAt,
        byte[] tokenSha256, byte[] authorizationDigest)
    {
        EnvironmentId = environmentId;
        OperationId = operationId;
        GrantId = grantId;
        DirectoryObjectId = directoryObjectId;
        DeviceId = deviceId;
        MappingCreatedAt = mappingCreatedAt;
        CreatedAt = createdAt;
        ExpiresAt = expiresAt;
        _tokenSha256 = (byte[])tokenSha256.Clone();
        _authorizationDigest = (byte[])authorizationDigest.Clone();
    }

    public Guid EnvironmentId { get; }
    public Guid OperationId { get; }
    public Guid GrantId { get; }
    public Guid DirectoryObjectId { get; }
    public Guid DeviceId { get; }
    public DateTimeOffset MappingCreatedAt { get; }
    public DateTimeOffset CreatedAt { get; }
    public DateTimeOffset ExpiresAt { get; }
    public byte[] GetTokenSha256() => (byte[])_tokenSha256.Clone();
    public byte[] GetAuthorizationDigest() => (byte[])_authorizationDigest.Clone();

    public bool Equals(PlatformGrantReceipt? other) => other is not null &&
        EnvironmentId == other.EnvironmentId && OperationId == other.OperationId && GrantId == other.GrantId &&
        DirectoryObjectId == other.DirectoryObjectId && DeviceId == other.DeviceId &&
        MappingCreatedAt == other.MappingCreatedAt && CreatedAt == other.CreatedAt && ExpiresAt == other.ExpiresAt &&
        _tokenSha256.AsSpan().SequenceEqual(other._tokenSha256) &&
        _authorizationDigest.AsSpan().SequenceEqual(other._authorizationDigest);

    public override bool Equals(object? obj) => Equals(obj as PlatformGrantReceipt);
    public override int GetHashCode() => HashCode.Combine(EnvironmentId, OperationId, GrantId, DirectoryObjectId,
        DeviceId, MappingCreatedAt, CreatedAt, ExpiresAt);
}

public sealed record PlatformGrantResult(PlatformGrantOutcome Outcome, PlatformGrantDiagnostic Diagnostic,
    PlatformGrantReceipt? Receipt);

public sealed record PlatformGrantPrivilegeAudit(bool IsValid, PlatformGrantDiagnostic Diagnostic, int ProfileVersion);

public enum PlatformGrantEffectiveState
{
    Available,
    Expired,
    Consumed,
    Revoked,
    Unknown
}

public sealed record PlatformGrantReadResult(PlatformGrantEffectiveState State, PlatformGrantDiagnostic Diagnostic,
    DateTimeOffset? ObservedAt, DateTimeOffset? StateChangedAt);

public enum PlatformGrantRevocationOutcome
{
    Completed,
    AlreadyCompleted,
    OutcomeUnknown,
    Unauthorized,
    Unknown
}

public enum PlatformGrantRevocationDisposition
{
    Revoked,
    Expired,
    Consumed,
    AlreadyRevoked
}

public sealed record PlatformGrantRevocationReceipt(Guid RevocationOperationId,
    PlatformGrantReceipt IssueReceipt, PlatformGrantRevocationDisposition Disposition,
    DateTimeOffset CompletedAt, DateTimeOffset? EffectiveRevokedAt);

public sealed record PlatformGrantRevocationResult(PlatformGrantRevocationOutcome Outcome,
    PlatformGrantDiagnostic Diagnostic, PlatformGrantRevocationReceipt? Receipt);

public sealed class ValidatedGrantRevocationAuthorization
{
    private readonly byte[] _digest;

    private ValidatedGrantRevocationAuthorization(PlatformGrantReceipt issueReceipt, byte[] digest)
    {
        IssueReceipt = issueReceipt;
        _digest = (byte[])digest.Clone();
    }

    public PlatformGrantReceipt IssueReceipt { get; }
    internal byte[] GetDigest() => (byte[])_digest.Clone();

    internal static ValidatedGrantRevocationAuthorization FromValidatedPlan(
        PlatformGrantReceipt issueReceipt, ReadOnlySpan<byte> authorizationDigest)
    {
        ArgumentNullException.ThrowIfNull(issueReceipt);
        if (authorizationDigest.Length != 32) throw new ArgumentException("InvalidGrantRevocationAuthorization");
        return new(issueReceipt, authorizationDigest.ToArray());
    }
}

public sealed class ValidatedPersistedPlatformGrant
{
    private readonly byte[] _tokenSha256;
    private ValidatedPersistedPlatformGrant(byte[] tokenSha256) => _tokenSha256 = (byte[])tokenSha256.Clone();
    internal byte[] GetTokenSha256() => (byte[])_tokenSha256.Clone();
    internal static ValidatedPersistedPlatformGrant FromValidatedOutboxRecord(ReadOnlySpan<byte> tokenSha256)
    {
        if (tokenSha256.Length != 32) throw new ArgumentException("InvalidPersistedGrant");
        return new(tokenSha256.ToArray());
    }
}
