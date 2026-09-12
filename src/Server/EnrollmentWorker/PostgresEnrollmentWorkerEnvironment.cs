using ItManagement.AgentPlatformGrants;
using ItManagement.EnrollmentGrantExecution;
using Npgsql;

namespace ItManagement.EnrollmentWorker;

internal sealed class PostgresEnrollmentWorkerEnvironment : IEnrollmentWorkerEnvironment
{
    private readonly NpgsqlDataSource _publicSource;
    private readonly NpgsqlDataSource _privateSource;
    private readonly EnrollmentGrantWorkProcessor _processor;
    private readonly object _disposeGate = new();
    private Task? _disposeTask;
    public Guid EnvironmentId { get; }

    private PostgresEnrollmentWorkerEnvironment(Guid environment, NpgsqlDataSource publicSource,
        NpgsqlDataSource privateSource, EnrollmentGrantWorkProcessor processor)
    {
        EnvironmentId = environment;
        _publicSource = publicSource;
        _privateSource = privateSource;
        _processor = processor;
    }

    internal static async Task<IEnrollmentWorkerEnvironment> CreateAuditedAsync(
        ValidatedEnrollmentWorkerEnvironment options, CancellationToken cancellationToken)
    {
        NpgsqlDataSource? publicSource = null;
        NpgsqlDataSource? privateSource = null;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            RequireLocalCertificateFile(options.PublicDatabase.RootCertificate);
            RequireLocalCertificateFile(options.PrivateDatabase.RootCertificate);
            publicSource = new NpgsqlDataSourceBuilder(options.PublicDatabase.BuildConnectionString()).Build();
            privateSource = new NpgsqlDataSourceBuilder(options.PrivateDatabase.BuildConnectionString()).Build();
            var store = await PostgresEnrollmentGrantExecutionStore.CreateAuditedAsync(publicSource,
                options.EnvironmentId, options.PublicDatabase.ExpectedTableOwner,
                options.PublicDatabase.ExpectedExecutionOwner, cancellationToken).ConfigureAwait(false);
            var queue = await PostgresEnrollmentGrantWorkQueue.CreateAuditedAsync(publicSource,
                options.EnvironmentId, options.PublicDatabase.ExpectedTableOwner,
                options.PublicDatabase.ExpectedExecutionOwner, options.PublicDatabase.ExpectedQueueOwner,
                cancellationToken).ConfigureAwait(false);
            var issuer = await PostgresPlatformGrantRepository.CreateAuditedAsync(privateSource,
                options.EnvironmentId, options.PrivateDatabase.ExpectedTableOwner,
                options.PrivateDatabase.ExpectedFunctionOwner, cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            return new PostgresEnrollmentWorkerEnvironment(options.EnvironmentId, publicSource, privateSource,
                new EnrollmentGrantWorkProcessor(options.EnvironmentId, queue,
                    new EnrollmentGrantExecutor(store, new PostgresPlatformGrantIssuer(issuer))));
        }
        catch
        {
            // Always attempt both disposals, including partial construction and audit failure.
            try { if (privateSource is not null) await privateSource.DisposeAsync().ConfigureAwait(false); }
            finally { if (publicSource is not null) await publicSource.DisposeAsync().ConfigureAwait(false); }
            cancellationToken.ThrowIfCancellationRequested();
            throw new InvalidOperationException("EnrollmentWorkerStartupAuditFailed");
        }
    }

    public Task<EnrollmentWorkProcessOutcome> ProcessOnceAsync(CancellationToken cancellationToken) =>
        _processor.ProcessOnceAsync(cancellationToken);

    internal static void RequireLocalCertificateFile(string path)
    {
        try
        {
            var fullPath = Path.GetFullPath(path);
            if (OperatingSystem.IsWindows() && new DriveInfo(Path.GetPathRoot(fullPath)!).DriveType != DriveType.Fixed)
                throw new InvalidOperationException();
            var attributes = File.GetAttributes(fullPath);
            if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint | FileAttributes.Device)) != 0)
                throw new InvalidOperationException();
            // Reject ancestor junctions/symlinks as well as a linked certificate file.
            for (var parent = Directory.GetParent(fullPath); parent is not null; parent = parent.Parent)
                if ((parent.Attributes & FileAttributes.ReparsePoint) != 0) throw new InvalidOperationException();
        }
        catch { throw new InvalidOperationException("EnrollmentWorkerCertificateFileInvalid"); }
    }

    public ValueTask DisposeAsync()
    {
        lock (_disposeGate) return new(_disposeTask ??= DisposeSourcesAsync());
    }

    private async Task DisposeSourcesAsync()
    {
        try { await _privateSource.DisposeAsync().ConfigureAwait(false); }
        finally { await _publicSource.DisposeAsync().ConfigureAwait(false); }
    }
}
