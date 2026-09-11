namespace ItManagement.Core;

// Server-owned services only. No classifier may infer Unprotected from missing attributes.
public interface IDirectoryScopeAssessor
{
    Task<DirectoryScopeObservation> AssessAsync(DirectoryObjectObservation observation, CancellationToken ct);
}
public interface IDirectoryProtectionAssessor
{
    Task<DirectoryProtectionObservation> AssessAsync(DirectoryObjectObservation observation, CancellationToken ct);
}
public sealed class UnknownDirectoryProtectionAssessor(TimeProvider time) : IDirectoryProtectionAssessor
{
    public Task<DirectoryProtectionObservation> AssessAsync(DirectoryObjectObservation observation, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        return Task.FromResult(new DirectoryProtectionObservation(observation.Binding, observation.Object.UsnChanged,
            observation.Object.DistinguishedName, DirectoryProtectionDecision.Unknown, time.GetUtcNow()));
    }
}
