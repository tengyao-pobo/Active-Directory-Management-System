using System.Security.Cryptography;
using System.Text.Json;

namespace ItManagement.Agent.Spool;

public sealed class OfflineSpool : IAsyncDisposable
{
    private const string IdentityFileName = "identity.json";
    private const string LockFileName = "spool.lock";
    private const string EnvelopeSuffix = ".envelope.json";
    private const int MaxIdentityBytes = 16 * 1024;
    private const int EnvelopeOverheadBytes = 16 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly string _directory;
    private readonly string _identityPath;
    private readonly OfflineSpoolOptions _options;
    private readonly FileStream _ownershipLock;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private DeviceSpoolIdentity _identity;

    private OfflineSpool(
        string directory,
        OfflineSpoolOptions options,
        DeviceSpoolIdentity identity,
        FileStream ownershipLock)
    {
        _directory = directory;
        _identityPath = Path.Combine(directory, IdentityFileName);
        _options = options;
        _identity = identity;
        _ownershipLock = ownershipLock;
    }

    public DeviceSpoolIdentity Identity => _identity;

    public static async Task<OfflineSpool> OpenAsync(
        string directory,
        long registrationEpoch,
        OfflineSpoolOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(registrationEpoch);
        var effectiveOptions = options ?? OfflineSpoolOptions.Default;
        effectiveOptions.Validate();

        var fullPath = Path.GetFullPath(directory);
        Directory.CreateDirectory(fullPath);
        var identityPath = Path.Combine(fullPath, IdentityFileName);
        var ownershipLock = new FileStream(
            Path.Combine(fullPath, LockFileName),
            FileMode.OpenOrCreate,
            FileAccess.ReadWrite,
            FileShare.None,
            bufferSize: 1,
            FileOptions.None);

        try
        {
            DeviceSpoolIdentity identity;
            if (File.Exists(identityPath))
            {
                var bytes = await ReadBoundedAsync(
                    identityPath,
                    MaxIdentityBytes,
                    cancellationToken).ConfigureAwait(false);
                identity = JsonSerializer.Deserialize<DeviceSpoolIdentity>(bytes, JsonOptions)
                    ?? throw new InvalidDataException("Spool identity is invalid.");
                if (identity.RegistrationEpoch != registrationEpoch)
                {
                    throw new InvalidOperationException("Registration epoch does not match the persisted spool identity.");
                }

                if (identity.DeviceGuid == Guid.Empty || identity.NextSequence < 1)
                {
                    throw new InvalidDataException("Spool identity contains invalid values.");
                }
            }
            else
            {
                if (Directory.EnumerateFiles(fullPath, $"*{EnvelopeSuffix}").Take(1).Any())
                {
                    throw new InvalidDataException("Spool identity is missing while queued envelopes exist.");
                }

                identity = new DeviceSpoolIdentity(Guid.NewGuid(), registrationEpoch, 1);
                var bytes = JsonSerializer.SerializeToUtf8Bytes(identity, JsonOptions);
                await AtomicFile.WriteAsync(
                    identityPath,
                    bytes,
                    overwrite: false,
                    cancellationToken).ConfigureAwait(false);
            }

            return new OfflineSpool(fullPath, effectiveOptions, identity, ownershipLock);
        }
        catch
        {
            await ownershipLock.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    public async Task<SpoolEnvelope> EnqueueAsync<T>(
        Guid requestId,
        DateTimeOffset observedAt,
        T payload,
        CancellationToken cancellationToken = default)
    {
        if (requestId == Guid.Empty)
        {
            throw new ArgumentException("Request id cannot be empty.", nameof(requestId));
        }

        var payloadBytes = JsonSerializer.SerializeToUtf8Bytes(payload, JsonOptions);
        if (payloadBytes.Length > _options.MaxPayloadBytes)
        {
            throw new SpoolCapacityExceededException("Payload exceeds the configured spool payload limit.");
        }

        var payloadElement = JsonSerializer.Deserialize<JsonElement>(payloadBytes, JsonOptions);
        var payloadHash = Convert.ToHexStringLower(SHA256.HashData(payloadBytes));

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var sequence = _identity.NextSequence;
            var envelopeHash = EnvelopeDigest.Compute(
                protocolVersion: 1,
                _identity.DeviceGuid,
                _identity.RegistrationEpoch,
                sequence,
                requestId,
                observedAt,
                payloadHash);
            var envelope = new SpoolEnvelope(
                1,
                _identity.DeviceGuid,
                _identity.RegistrationEpoch,
                sequence,
                requestId,
                observedAt,
                payloadHash,
                envelopeHash,
                payloadElement);
            var envelopeBytes = JsonSerializer.SerializeToUtf8Bytes(envelope, JsonOptions);
            EnsureCapacity(envelopeBytes.Length);
            var envelopePath = GetEnvelopePath(sequence);
            if (File.Exists(envelopePath))
            {
                throw new InvalidDataException("The next spool sequence already has an envelope.");
            }

            var nextIdentity = _identity with { NextSequence = checked(sequence + 1) };
            await AtomicFile.WriteAsync(
                _identityPath,
                JsonSerializer.SerializeToUtf8Bytes(nextIdentity, JsonOptions),
                overwrite: true,
                cancellationToken).ConfigureAwait(false);
            _identity = nextIdentity;

            await AtomicFile.WriteAsync(
                envelopePath,
                envelopeBytes,
                overwrite: false,
                cancellationToken).ConfigureAwait(false);
            return envelope;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<IReadOnlyList<SpoolEnvelope>> ReadPendingAsync(
        CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var files = Directory.EnumerateFiles(_directory, $"*{EnvelopeSuffix}")
                .Take(_options.MaxFiles + 1)
                .ToArray();
            if (files.Length > _options.MaxFiles)
            {
                throw new InvalidDataException("Spool contains more envelopes than its configured file limit.");
            }

            Array.Sort(files, StringComparer.Ordinal);
            var envelopes = new List<SpoolEnvelope>(files.Length);
            long aggregateBytes = 0;

            foreach (var file in files)
            {
                var remainingBytes = _options.MaxBytes - aggregateBytes;
                if (remainingBytes <= 0)
                {
                    throw new InvalidDataException("Persisted spool envelopes exceed the configured byte limit.");
                }

                var bytes = await ReadBoundedAsync(
                    file,
                    (int)Math.Min(GetMaxEnvelopeBytes(), remainingBytes),
                    cancellationToken).ConfigureAwait(false);
                aggregateBytes += bytes.Length;
                var envelope = JsonSerializer.Deserialize<SpoolEnvelope>(bytes, JsonOptions)
                    ?? throw new InvalidDataException($"Spool envelope '{Path.GetFileName(file)}' is invalid.");
                ValidateEnvelope(envelope, file);
                envelopes.Add(envelope);
            }

            return envelopes;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task MarkDeliveredAsync(
        SpoolEnvelope expectedEnvelope,
        EnvelopeAcknowledgement acknowledgement,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(expectedEnvelope);
        ArgumentNullException.ThrowIfNull(acknowledgement);

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var path = GetEnvelopePath(expectedEnvelope.Sequence);
            if (!File.Exists(path))
            {
                throw new EnvelopeAcknowledgementMismatchException("Acknowledged spool envelope no longer exists.");
            }

            var bytes = await ReadBoundedAsync(
                path,
                GetMaxEnvelopeBytes(),
                cancellationToken).ConfigureAwait(false);
            var envelope = JsonSerializer.Deserialize<SpoolEnvelope>(bytes, JsonOptions)
                ?? throw new InvalidDataException("Spool envelope is invalid.");
            ValidateEnvelope(envelope, path);
            if (!EnvelopeMatches(envelope, expectedEnvelope) || !AcknowledgementMatches(envelope, acknowledgement))
            {
                throw new EnvelopeAcknowledgementMismatchException(
                    "Acknowledgement does not match the queued spool envelope.");
            }

            File.Delete(path);
        }
        finally
        {
            _gate.Release();
        }
    }

    public ValueTask DisposeAsync()
    {
        _gate.Dispose();
        return _ownershipLock.DisposeAsync();
    }

    private void EnsureCapacity(int newEnvelopeBytes)
    {
        var files = Directory.EnumerateFiles(_directory, $"*{EnvelopeSuffix}")
            .Take(_options.MaxFiles + 1)
            .ToArray();
        if (files.Length > _options.MaxFiles)
        {
            throw new SpoolCapacityExceededException("Spool file limit has been exceeded.");
        }

        if (files.Length >= _options.MaxFiles)
        {
            throw new SpoolCapacityExceededException("Spool file limit has been reached.");
        }

        long bytes = 0;
        foreach (var file in files)
        {
            var length = new FileInfo(file).Length;
            if (length > _options.MaxBytes - bytes)
            {
                throw new SpoolCapacityExceededException("Persisted spool files exceed the configured byte limit.");
            }

            bytes += length;
        }

        if (newEnvelopeBytes > _options.MaxBytes - bytes)
        {
            throw new SpoolCapacityExceededException("Spool byte limit has been reached.");
        }
    }

    private void ValidateEnvelope(SpoolEnvelope envelope, string file)
    {
        if (envelope.ProtocolVersion != 1 ||
            envelope.DeviceGuid != _identity.DeviceGuid ||
            envelope.RegistrationEpoch != _identity.RegistrationEpoch ||
            envelope.Sequence < 1 ||
            envelope.Sequence >= _identity.NextSequence ||
            envelope.RequestId == Guid.Empty)
        {
            throw new InvalidDataException($"Spool envelope '{Path.GetFileName(file)}' has invalid identity metadata.");
        }


        if (!string.Equals(Path.GetFullPath(file), GetEnvelopePath(envelope.Sequence), StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException($"Spool envelope '{Path.GetFileName(file)}' does not match its sequence.");
        }

        var payloadBytes = JsonSerializer.SerializeToUtf8Bytes(envelope.Payload, JsonOptions);
        var actualPayloadHash = Convert.ToHexStringLower(SHA256.HashData(payloadBytes));
        if (!string.Equals(actualPayloadHash, envelope.PayloadHash, StringComparison.Ordinal))
        {
            throw new InvalidDataException($"Spool envelope '{Path.GetFileName(file)}' failed its payload hash check.");
        }

        var actualEnvelopeHash = EnvelopeDigest.Compute(
            envelope.ProtocolVersion,
            envelope.DeviceGuid,
            envelope.RegistrationEpoch,
            envelope.Sequence,
            envelope.RequestId,
            envelope.ObservedAt,
            envelope.PayloadHash);
        if (!string.Equals(actualEnvelopeHash, envelope.EnvelopeHash, StringComparison.Ordinal))
        {
            throw new InvalidDataException($"Spool envelope '{Path.GetFileName(file)}' failed its envelope hash check.");
        }
    }

    private string GetEnvelopePath(long sequence) =>
        Path.Combine(_directory, $"{sequence:D20}{EnvelopeSuffix}");

    private int GetMaxEnvelopeBytes() =>
        checked(_options.MaxPayloadBytes + EnvelopeOverheadBytes);

    private static async Task<byte[]> ReadBoundedAsync(
        string path,
        int maxBytes,
        CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 16 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        using var output = new MemoryStream(Math.Min(maxBytes, 16 * 1024));
        var buffer = new byte[Math.Min(maxBytes + 1, 16 * 1024)];
        while (true)
        {
            var remaining = maxBytes - checked((int)output.Length);
            var bytesRead = await stream.ReadAsync(
                buffer.AsMemory(0, Math.Min(buffer.Length, remaining + 1)),
                cancellationToken).ConfigureAwait(false);
            if (bytesRead == 0)
            {
                return output.ToArray();
            }

            if (bytesRead > remaining)
            {
                throw new InvalidDataException($"Persisted file '{Path.GetFileName(path)}' exceeds its size limit.");
            }

            output.Write(buffer, 0, bytesRead);
        }
    }

    private static bool EnvelopeMatches(SpoolEnvelope left, SpoolEnvelope right) =>
        left.ProtocolVersion == right.ProtocolVersion &&
        left.DeviceGuid == right.DeviceGuid &&
        left.RegistrationEpoch == right.RegistrationEpoch &&
        left.Sequence == right.Sequence &&
        left.RequestId == right.RequestId &&
        left.ObservedAt.ToUniversalTime() == right.ObservedAt.ToUniversalTime() &&
        string.Equals(left.PayloadHash, right.PayloadHash, StringComparison.Ordinal) &&
        string.Equals(left.EnvelopeHash, right.EnvelopeHash, StringComparison.Ordinal) &&
        string.Equals(left.Payload.GetRawText(), right.Payload.GetRawText(), StringComparison.Ordinal);

    private static bool AcknowledgementMatches(
        SpoolEnvelope envelope,
        EnvelopeAcknowledgement acknowledgement) =>
        acknowledgement.SchemaVersion == 1 &&
        acknowledgement.ProtocolVersion == envelope.ProtocolVersion &&
        acknowledgement.DeviceGuid == envelope.DeviceGuid &&
        acknowledgement.RegistrationEpoch == envelope.RegistrationEpoch &&
        acknowledgement.Sequence == envelope.Sequence &&
        acknowledgement.RequestId == envelope.RequestId &&
        acknowledgement.ObservedAt.ToUniversalTime() == envelope.ObservedAt.ToUniversalTime() &&
        string.Equals(acknowledgement.PayloadHash, envelope.PayloadHash, StringComparison.Ordinal) &&
        string.Equals(acknowledgement.EnvelopeHash, envelope.EnvelopeHash, StringComparison.Ordinal);
}
