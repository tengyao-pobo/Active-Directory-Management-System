using System.Text.Json;

namespace ItManagement.Agent.Spool;

public sealed partial class OfflineSpool
{
    /// <summary>Persists a stable local identity and request ID before any registration request.
    /// The caller must retain the lease until the registration result is reconciled.</summary>
    public static async Task<EnrollmentLease> PrepareEnrollmentAsync(string directory,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        var fullPath = Path.GetFullPath(directory);
        Directory.CreateDirectory(fullPath);
        var ownership = AcquireOwnership(fullPath);
        try
        {
            RequireEmptyQueue(fullPath);
            var path = Path.Combine(fullPath, IdentityFileName);
            DeviceSpoolIdentity identity;
            if (File.Exists(path))
            {
                identity = await ReadEnrollmentIdentityAsync(path, cancellationToken).ConfigureAwait(false);
                if (identity.RegistrationEpoch != 0)
                    throw new InvalidOperationException("The spool is already enrolled.");
            }
            else
            {
                identity = new(Guid.NewGuid(), 0, 1) { SchemaVersion = 2, EnrollmentRequestId = Guid.NewGuid() };
                await AtomicFile.WriteAsync(path, JsonSerializer.SerializeToUtf8Bytes(identity, JsonOptions),
                    overwrite: false, cancellationToken).ConfigureAwait(false);
            }
            return new EnrollmentLease(fullPath, identity, ownership);
        }
        catch
        {
            await ownership.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    /// <summary>Reopens an existing initial enrollment for crash reconciliation, before runtime use.
    /// It never creates an identity or changes the persisted registration.</summary>
    public static async Task<EnrollmentLease> ResumeEnrollmentAsync(string directory,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        var fullPath = Path.GetFullPath(directory);
        var ownership = AcquireOwnership(fullPath);
        try
        {
            RequireEmptyQueue(fullPath);
            var identity = await ReadEnrollmentIdentityAsync(Path.Combine(fullPath, IdentityFileName), cancellationToken).ConfigureAwait(false);
            if (identity.NextSequence != 1)
                throw new InvalidOperationException("Runtime has already used this enrollment.");
            return new EnrollmentLease(fullPath, identity, ownership);
        }
        catch
        {
            await ownership.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    /// <summary>Opens only a previously completed exact enrollment; never creates or repairs identity.</summary>
    public static async Task<OfflineSpool> OpenEnrolledAsync(string directory, Guid expectedDeviceGuid,
        long expectedEpoch, OfflineSpoolOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        if (expectedDeviceGuid == Guid.Empty) throw new ArgumentException("Device GUID is required.", nameof(expectedDeviceGuid));
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(expectedEpoch);
        var effectiveOptions = options ?? OfflineSpoolOptions.Default;
        effectiveOptions.Validate();
        var fullPath = Path.GetFullPath(directory);
        // The enrollment directory and identity must already exist.
        var ownership = AcquireOwnership(fullPath);
        try
        {
            var identity = await ReadEnrollmentIdentityAsync(Path.Combine(fullPath, IdentityFileName), cancellationToken).ConfigureAwait(false);
            if (identity.DeviceGuid != expectedDeviceGuid || identity.RegistrationEpoch != expectedEpoch)
                throw new InvalidOperationException("The persisted enrollment does not match the expected identity.");
            var spool = new OfflineSpool(fullPath, effectiveOptions, identity, ownership);
            await spool.ReadPendingAsync(cancellationToken).ConfigureAwait(false);
            return spool;
        }
        catch
        {
            await ownership.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    private static FileStream AcquireOwnership(string directory) => new(
        Path.Combine(directory, LockFileName), FileMode.OpenOrCreate, FileAccess.ReadWrite,
        FileShare.None, bufferSize: 1, FileOptions.None);

    private static void RequireEmptyQueue(string directory)
    {
        if (Directory.EnumerateFiles(directory, $"*{EnvelopeSuffix}").Take(1).Any())
            throw new InvalidDataException("Enrollment cannot replace queued data.");
    }

    private static async Task<DeviceSpoolIdentity> ReadEnrollmentIdentityAsync(string path, CancellationToken cancellationToken)
    {
        var bytes = await ReadBoundedAsync(path, MaxIdentityBytes, cancellationToken).ConfigureAwait(false);
        var identity = JsonSerializer.Deserialize<DeviceSpoolIdentity>(bytes, JsonOptions)
            ?? throw new InvalidDataException("Enrollment identity is invalid.");
        if (identity.SchemaVersion != 2 || identity.DeviceGuid == Guid.Empty || identity.EnrollmentRequestId == Guid.Empty ||
            identity.RegistrationEpoch < 0 || identity.NextSequence < 1 ||
            (identity.RegistrationEpoch == 0 && identity.NextSequence != 1))
            throw new InvalidDataException("Enrollment identity is invalid.");
        return identity;
    }

    public sealed class EnrollmentLease : IAsyncDisposable
    {
        private readonly string _directory;
        private readonly FileStream _ownership;
        private readonly SemaphoreSlim _gate = new(1, 1);
        private readonly DeviceSpoolIdentity _pending;
        private bool _disposed;

        internal EnrollmentLease(string directory, DeviceSpoolIdentity pending, FileStream ownership)
        { _directory = directory; _pending = pending; _ownership = ownership; }

        public Guid DeviceGuid => _pending.DeviceGuid;
        public Guid EnrollmentRequestId => _pending.EnrollmentRequestId;
        /// <summary>Persisted epoch at lease acquisition; zero means enrollment is still pending.</summary>
        public long PersistedEpoch => _pending.RegistrationEpoch;

        /// <summary>Called only after the trusted enrollment adapter validates the server response.
        /// This local persistence operation is not proof of enrollment or certificate possession.</summary>
        public async Task CompleteAsync(Guid expectedDeviceGuid, Guid expectedRequestId, long serverEpoch,
            CancellationToken cancellationToken = default)
        {
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(serverEpoch);
            if (expectedDeviceGuid != DeviceGuid || expectedRequestId != EnrollmentRequestId)
                throw new InvalidOperationException("Enrollment response does not match the pending request.");
            await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                ObjectDisposedException.ThrowIf(_disposed, this);
                RequireEmptyQueue(_directory);
                var path = Path.Combine(_directory, IdentityFileName);
                var current = await ReadEnrollmentIdentityAsync(path, cancellationToken).ConfigureAwait(false);
                if (current.DeviceGuid != DeviceGuid || current.EnrollmentRequestId != EnrollmentRequestId ||
                    current.NextSequence != 1 || (current.RegistrationEpoch != 0 && current.RegistrationEpoch != serverEpoch))
                    throw new InvalidOperationException("The persisted enrollment changed.");
                if (current.RegistrationEpoch == serverEpoch) return;
                var enrolled = current with { RegistrationEpoch = serverEpoch };
                await AtomicFile.WriteAsync(path, JsonSerializer.SerializeToUtf8Bytes(enrolled, JsonOptions),
                    overwrite: true, cancellationToken).ConfigureAwait(false);
            }
            finally { _gate.Release(); }
        }

        public async ValueTask DisposeAsync()
        {
            await _gate.WaitAsync().ConfigureAwait(false);
            try
            {
                if (_disposed) return;
                _disposed = true;
                await _ownership.DisposeAsync().ConfigureAwait(false);
            }
            finally { _gate.Release(); }
        }
    }
}
