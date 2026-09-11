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

public sealed record PlatformGrantReceipt(Guid OperationId, Guid GrantId, Guid DirectoryObjectId,
    Guid DeviceId, DateTimeOffset MappingCreatedAt, DateTimeOffset CreatedAt, DateTimeOffset ExpiresAt);

public sealed record PlatformGrantResult(PlatformGrantOutcome Outcome, PlatformGrantDiagnostic Diagnostic,
    PlatformGrantReceipt? Receipt);

public sealed record PlatformGrantPrivilegeAudit(bool IsValid, PlatformGrantDiagnostic Diagnostic, int ProfileVersion);

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
