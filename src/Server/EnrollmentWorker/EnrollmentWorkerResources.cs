using System.Collections.ObjectModel;

namespace ItManagement.EnrollmentWorker;

/// <summary>Owns only successfully created environments; callers stop and observe work before disposal.</summary>
internal sealed class EnrollmentWorkerResources : IAsyncDisposable
{
    private readonly IEnrollmentWorkerEnvironment[] _environments;
    private readonly object _disposeGate = new();
    private Task? _disposeTask;
    public ReadOnlyCollection<IEnrollmentWorkerEnvironment> Environments { get; }

    private EnrollmentWorkerResources(IEnrollmentWorkerEnvironment[] environments)
    {
        _environments = environments;
        Environments = Array.AsReadOnly(environments);
    }

    internal static async Task<EnrollmentWorkerResources> CreateAsync(IReadOnlyList<Guid> environmentIds,
        Func<Guid, CancellationToken, Task<IEnrollmentWorkerEnvironment>> create, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(environmentIds);
        ArgumentNullException.ThrowIfNull(create);
        var ids = environmentIds.ToArray();
        if (ids.Length is < 1 or > 32 || ids.Any(id => id == Guid.Empty) || ids.Distinct().Count() != ids.Length)
            throw new InvalidOperationException("EnrollmentWorkerInvalidEnvironments");
        var created = new List<IEnrollmentWorkerEnvironment>();
        try
        {
            foreach (var id in ids)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var environment = await create(id, cancellationToken).ConfigureAwait(false)
                    ?? throw new InvalidOperationException("EnrollmentWorkerInvalidEnvironment");
                created.Add(environment);
                if (environment.EnvironmentId != id)
                    throw new InvalidOperationException("EnrollmentWorkerInvalidEnvironment");
            }
            cancellationToken.ThrowIfCancellationRequested();
            return new(created.ToArray());
        }
        catch
        {
            await DisposeAllAsync(created).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            // Provider exceptions can contain endpoint or credential configuration. Do not retain them.
            throw new InvalidOperationException("EnrollmentWorkerStartupAuditFailed");
        }
    }

    public ValueTask DisposeAsync()
    {
        lock (_disposeGate)
            return new(_disposeTask ??= DisposeAllAsync(_environments));
    }

    private static async Task DisposeAllAsync(IReadOnlyList<IEnrollmentWorkerEnvironment> environments)
    {
        var failed = false;
        for (var index = environments.Count - 1; index >= 0; index--)
        {
            try { await environments[index].DisposeAsync().ConfigureAwait(false); }
            catch { failed = true; }
        }
        if (failed) throw new InvalidOperationException("EnrollmentWorkerCleanupFailed");
    }
}
