using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ItManagement.Core;

// Narrow templates; never accept attribute names, LDAP filters, scripts or credentials.
public enum DirectoryChangeKind { DisableUser, SetUserDepartment }
public sealed record DirectoryChangeTemplate(DirectoryChangeKind Kind, string? Department = null);
public sealed record DirectoryChangeEvidence(Guid EnvironmentId, Guid DomainId, Guid ObjectId, string ObjectKind,
    string DistinguishedName, long UsnChanged, string ConnectorConfigurationHash, long PolicyVersion,
    bool IsProtected, bool ProtectionKnown, bool ScopeKnown, DateTimeOffset ObservedAt, bool? Enabled = null, string? Department = null);
public sealed record DirectoryChangePreview(DirectoryChangeEvidence Before, DirectoryChangeTemplate Desired,
    DateTimeOffset ExpiresAt, string Hash);

public static class DirectoryChangePlanner
{
    public static DirectoryChangePreview Preview(DirectoryChangeEvidence before, DirectoryChangeTemplate template, DateTimeOffset now)
    {
        Validate(before, now);
        if (!Enum.IsDefined(template.Kind) || (template.Kind == DirectoryChangeKind.DisableUser && (template.Department is not null || before.Enabled is null)) ||
            (template.Kind == DirectoryChangeKind.SetUserDepartment && (string.IsNullOrWhiteSpace(template.Department) || template.Department.Length > 128 || template.Department.Any(char.IsControl))))
            throw new ArgumentException("InvalidDirectoryTemplate");
        var expiry = now.AddMinutes(5);
        return new(before, template, expiry, Hash(before, template, expiry));
    }

    public static bool MatchesForExecution(DirectoryChangePreview preview, DirectoryChangeEvidence current, DateTimeOffset now)
    {
        try { Validate(current, now); }
        catch (ArgumentException) { return false; }
        // Approval is invalidated by identity, scope/protection, config, policy or remote version drift.
        return preview.ExpiresAt > now && preview.Hash == Hash(preview.Before, preview.Desired, preview.ExpiresAt) &&
            preview.Before with { ObservedAt = current.ObservedAt } == current;
    }

    private static void Validate(DirectoryChangeEvidence item, DateTimeOffset now)
    {
        if (item.EnvironmentId == Guid.Empty || item.DomainId == Guid.Empty || item.ObjectId == Guid.Empty || item.ObjectKind != "User" ||
            string.IsNullOrWhiteSpace(item.DistinguishedName) || item.DistinguishedName.Length > 4096 || item.UsnChanged < 0 ||
            item.ConnectorConfigurationHash.Length != 64 || !item.ConnectorConfigurationHash.All(Uri.IsHexDigit) || item.PolicyVersion < 1 ||
            item.IsProtected || !item.ProtectionKnown || !item.ScopeKnown || item.ObservedAt > now || item.ObservedAt < now.AddMinutes(-2))
            throw new ArgumentException("DirectoryEvidenceRejected");
    }
    private static string Hash(DirectoryChangeEvidence before, DirectoryChangeTemplate desired, DateTimeOffset expires) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new { before, desired, expires }))));
}

public enum DirectoryMutationOutcome { Unavailable, Succeeded, Failed, Unknown }
public sealed record DirectoryMutationResult(DirectoryMutationOutcome Outcome, string Code);
public interface IDirectoryMutationAdapter
{
    Task<DirectoryMutationResult> ExecuteAsync(DirectoryChangePreview preview, CancellationToken ct);
}
// No live write capability exists until persistent approval/intent, signed dispatch,
// delegated identity, protection classification and authoritative readback are integrated.
public sealed class UnavailableDirectoryMutationAdapter : IDirectoryMutationAdapter
{
    public Task<DirectoryMutationResult> ExecuteAsync(DirectoryChangePreview preview, CancellationToken ct) =>
        Task.FromResult(new DirectoryMutationResult(DirectoryMutationOutcome.Unavailable, "DirectoryWritesNotConfigured"));
}
