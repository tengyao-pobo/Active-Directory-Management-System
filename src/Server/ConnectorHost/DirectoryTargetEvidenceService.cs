using ItManagement.Core;
using ItManagement.DirectoryConnector;

namespace ItManagement.ConnectorHost;

// Isolated orchestration seam. Not registered or exposed by the current host/API.
public sealed class DirectoryTargetEvidenceService(IDirectoryTargetReader reader, IDirectoryScopeAssessor scopes,
    IDirectoryProtectionAssessor protection, TimeProvider time)
{
    public async Task<DirectoryEvidenceAssemblyResult> ReadAsync(DirectoryEvidenceBinding expected, DirectoryChangeKind kind, CancellationToken ct)
    {
        var target = await reader.ReadUserAsync(expected.ObjectId, ct);
        var source = new DirectoryEvidenceServer(target.Source.DnsHostName, target.Source.ServiceDn, target.Source.DsaObjectId, target.Source.InvocationId);
        if (target.VerifiedDomainId != expected.DomainId || target.ConfigurationHash != expected.ConfigurationHash ||
            target.Entry.ObjectId != expected.ObjectId || target.Entry.Kind != DirectoryObjectKind.User || source != expected.Server)
            return new(null, DirectoryEvidenceFailure.ObjectMismatch);
        var entry = target.Entry;
        var evidence = new DirectoryChangeEvidence(expected.EnvironmentId, target.VerifiedDomainId, entry.ObjectId, "User",
            entry.DistinguishedName, entry.UsnChanged, target.ConfigurationHash, expected.PolicyVersion,
            entry.IsProtected, false, false, target.ReadStartedAt, entry.Enabled, entry.Department);
        var observation = new DirectoryObjectObservation(expected, evidence, DirectoryObservationSource.DirectDirectoryRead,
            target.ReadStartedAt, target.ReadCompletedAt);
        var scope = await scopes.AssessAsync(observation, ct);
        var classification = await protection.AssessAsync(observation, ct);
        ct.ThrowIfCancellationRequested();
        return DirectoryEvidenceAssembler.Assemble(expected, kind, observation, scope, classification, time.GetUtcNow());
    }
}
