namespace ItManagement.Persistence;

public sealed class LocalCredential
{
    public Guid PrincipalId { get; set; }
    public string PasswordHash { get; set; } = "";
    public int FailedAttempts { get; set; }
    public DateTimeOffset? LockedUntil { get; set; }
    public long Version { get; set; }
}

public sealed class PlatformSession
{
    public string IdHash { get; set; } = "";
    public Guid PrincipalId { get; set; }
    public string Method { get; set; } = "";
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset LastSeenAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? StepUpAt { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }
    public string SourceIp { get; set; } = "";
    public string UserAgent { get; set; } = "";
}

public sealed class Passkey
{
    public string CredentialId { get; set; } = "";
    public Guid PrincipalId { get; set; }
    public byte[] PublicKey { get; set; } = [];
    public long SignCount { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }
    public long Version { get; set; }
}

public sealed class AuthCeremony
{
    public string IdHash { get; set; } = "";
    public Guid PrincipalId { get; set; }
    public string Kind { get; set; } = "";
    public string OptionsJson { get; set; } = "";
    public string? SessionHash { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? ConsumedAt { get; set; }
}

public sealed class PasskeyEnrollmentGrant
{
    public string IdHash { get; set; } = "";
    public Guid PrincipalId { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? ConsumedAt { get; set; }
}

public sealed class SecurityEvent
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid? PrincipalId { get; set; }
    public string Action { get; set; } = "";
    public string Result { get; set; } = "";
    public DateTimeOffset OccurredAt { get; set; }
    public string SourceIp { get; set; } = "";
}
