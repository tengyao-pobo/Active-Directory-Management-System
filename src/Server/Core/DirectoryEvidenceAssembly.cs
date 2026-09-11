namespace ItManagement.Core;

// Internal service contracts, never HTTP request models. A matching record is not proof of provenance.
// A future host must obtain each input from independently trusted services, not deserialize client claims.
public sealed record DirectoryEvidenceServer(string DnsHostName, string ServiceDn, Guid DsaObjectId, Guid InvocationId);
public sealed record DirectoryEvidenceBinding(Guid EnvironmentId, Guid DomainId, Guid ObjectId,
    Guid ActorId, string Permission, long PolicyVersion, string ConfigurationHash, DirectoryEvidenceServer Server, int SchemaVersion = 2);
public enum DirectoryObservationSource { Unknown, CachedProjection, DirectDirectoryRead }
public enum DirectoryProtectionDecision { Unknown, Protected, Unprotected }
public sealed record DirectoryObjectObservation(DirectoryEvidenceBinding Binding, DirectoryChangeEvidence Object,
    DirectoryObservationSource Source, DateTimeOffset ReadStartedAt, DateTimeOffset ReadCompletedAt);
public sealed record DirectoryScopeObservation(DirectoryEvidenceBinding Binding, long UsnChanged, string DistinguishedName,
    bool Allowed, DateTimeOffset EvaluatedAt);
public sealed record DirectoryProtectionObservation(DirectoryEvidenceBinding Binding, long UsnChanged, string DistinguishedName,
    DirectoryProtectionDecision Decision, DateTimeOffset EvaluatedAt);
public enum DirectoryEvidenceFailure
{
    None, InvalidBinding, BindingMismatch, SourceUnavailable, StaleObservation,
    ObjectMismatch, ScopeDenied, ProtectionUnknown, ProtectedObject, InvalidObject
}
// Retain every validated input. Future planning must consume this entire receipt, not just Evidence.
// No public constructor: created by the assembler only. Still neither a signature nor authorization.
public sealed class DirectoryEvidenceReceipt
{
    internal DirectoryEvidenceReceipt(DirectoryEvidenceBinding binding, DirectoryObjectObservation observation,
        DirectoryScopeObservation scope, DirectoryProtectionObservation protection, DirectoryChangeEvidence evidence)
    { Binding = binding; Observation = observation; Scope = scope; Protection = protection; Evidence = evidence; }
    public DirectoryEvidenceBinding Binding { get; }
    public DirectoryObjectObservation Observation { get; }
    public DirectoryScopeObservation Scope { get; }
    public DirectoryProtectionObservation Protection { get; }
    public DirectoryChangeEvidence Evidence { get; }
}
public sealed record DirectoryEvidenceAssemblyResult(DirectoryEvidenceReceipt? Receipt, DirectoryEvidenceFailure Failure);

public static class DirectoryEvidenceAssembler
{
    public static DirectoryEvidenceAssemblyResult Assemble(DirectoryEvidenceBinding expected, DirectoryChangeKind kind,
        DirectoryObjectObservation observation, DirectoryScopeObservation scope,
        DirectoryProtectionObservation protection, DateTimeOffset now)
    {
        DirectoryEvidenceAssemblyResult Reject(DirectoryEvidenceFailure failure) => new(null, failure);
        var permission = kind switch { DirectoryChangeKind.DisableUser => PermissionCatalog.UserDisable,
            DirectoryChangeKind.SetUserDepartment => PermissionCatalog.UserEdit, _ => null };
        if (expected.SchemaVersion != 2 || expected.EnvironmentId == Guid.Empty || expected.DomainId == Guid.Empty || expected.ObjectId == Guid.Empty ||
            expected.ActorId == Guid.Empty || permission is null || expected.Permission != permission || expected.PolicyVersion < 1 ||
            expected.ConfigurationHash is not { Length: 64 } hash || !hash.All(Uri.IsHexDigit) || expected.Server is null ||
            expected.Server.DsaObjectId == Guid.Empty || expected.Server.InvocationId == Guid.Empty ||
            string.IsNullOrWhiteSpace(expected.Server.ServiceDn) || expected.Server.ServiceDn.Length > 4096 ||
            expected.Server.DnsHostName is not { Length: > 0 and <= 253 } host || !host.Contains('.') || Uri.CheckHostName(host) != UriHostNameType.Dns)
            return Reject(DirectoryEvidenceFailure.InvalidBinding);
        if (observation.Binding != expected || scope.Binding != expected || protection.Binding != expected)
            return Reject(DirectoryEvidenceFailure.BindingMismatch);
        if (observation.Source != DirectoryObservationSource.DirectDirectoryRead)
            return Reject(DirectoryEvidenceFailure.SourceUnavailable);
        bool Fresh(DateTimeOffset at) => at <= now && at >= now.AddMinutes(-2);
        if (!Fresh(observation.ReadStartedAt) || !Fresh(observation.ReadCompletedAt) ||
            observation.ReadCompletedAt < observation.ReadStartedAt || !Fresh(scope.EvaluatedAt) || !Fresh(protection.EvaluatedAt) ||
            scope.EvaluatedAt < observation.ReadCompletedAt || protection.EvaluatedAt < observation.ReadCompletedAt)
            return Reject(DirectoryEvidenceFailure.StaleObservation);
        var item = observation.Object;
        if (item.EnvironmentId != expected.EnvironmentId || item.DomainId != expected.DomainId || item.ObjectId != expected.ObjectId ||
            item.PolicyVersion != expected.PolicyVersion || item.ConnectorConfigurationHash != expected.ConfigurationHash ||
            scope.UsnChanged != item.UsnChanged || protection.UsnChanged != item.UsnChanged ||
            scope.DistinguishedName != item.DistinguishedName || protection.DistinguishedName != item.DistinguishedName ||
            item.ObservedAt < observation.ReadStartedAt || item.ObservedAt > observation.ReadCompletedAt)
            return Reject(DirectoryEvidenceFailure.ObjectMismatch);
        if (!scope.Allowed) return Reject(DirectoryEvidenceFailure.ScopeDenied);
        if (!Enum.IsDefined(protection.Decision) || protection.Decision == DirectoryProtectionDecision.Unknown)
            return Reject(DirectoryEvidenceFailure.ProtectionUnknown);
        if (protection.Decision == DirectoryProtectionDecision.Protected || item.IsProtected)
            return Reject(DirectoryEvidenceFailure.ProtectedObject);
        // Ignore unverified positive flags on the raw object. Only the bound decisions supply these fields.
        var evidence = item with { ScopeKnown = true, ProtectionKnown = true, IsProtected = false,
            ObservedAt = observation.ReadStartedAt };
        try
        {
            DirectoryChangePlanner.Validate(evidence, now);
            if (kind == DirectoryChangeKind.DisableUser && evidence.Enabled is null)
                return Reject(DirectoryEvidenceFailure.InvalidObject);
        }
        catch (ArgumentException) { return Reject(DirectoryEvidenceFailure.InvalidObject); }
        return new(new DirectoryEvidenceReceipt(expected, observation, scope, protection, evidence), DirectoryEvidenceFailure.None);
    }
}
