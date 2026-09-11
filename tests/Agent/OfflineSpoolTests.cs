using ItManagement.Agent.Spool;

namespace ItManagement.Agent.Tests;

public sealed class OfflineSpoolTests
{
    [Fact]
    public async Task EnqueueAsync_PersistsIdentityEpochSequenceAndImmutableEnvelopeAcrossRestart()
    {
        using var directory = new TemporaryDirectory();
        var requestId = Guid.NewGuid();
        SpoolEnvelope first;
        DeviceSpoolIdentity identity;

        await using (var spool = await OfflineSpool.OpenAsync(directory.Path, registrationEpoch: 12))
        {
            first = await spool.EnqueueAsync(requestId, DateTimeOffset.UnixEpoch, new { kind = "snapshot", value = 7 });
            identity = spool.Identity;
            var retry = Assert.Single(await spool.ReadPendingAsync());
            AssertEnvelopeEqual(first, retry);
            Assert.Equal(64, first.PayloadHash.Length);
            Assert.Equal(64, first.EnvelopeHash.Length);
        }

        await using (var reopened = await OfflineSpool.OpenAsync(directory.Path, registrationEpoch: 12))
        {
            Assert.Equal(identity.DeviceGuid, reopened.Identity.DeviceGuid);
            Assert.Equal(2, reopened.Identity.NextSequence);
            var firstRetry = Assert.Single(await reopened.ReadPendingAsync());
            Assert.Equal(first.PayloadHash, firstRetry.PayloadHash);

            var second = await reopened.EnqueueAsync(Guid.NewGuid(), DateTimeOffset.UnixEpoch, new { value = 8 });
            Assert.Equal(2, second.Sequence);
            await reopened.MarkDeliveredAsync(first.Sequence, first.PayloadHash);
            AssertEnvelopeEqual(second, Assert.Single(await reopened.ReadPendingAsync()));
        }
    }

    [Fact]
    public async Task EnqueueAsync_EnforcesFileAndPayloadLimitsBeforeAllocatingSequence()
    {
        using var directory = new TemporaryDirectory();
        var options = new OfflineSpoolOptions(MaxFiles: 1, MaxBytes: 10_000, MaxPayloadBytes: 32);
        await using var spool = await OfflineSpool.OpenAsync(directory.Path, registrationEpoch: 1, options);

        await spool.EnqueueAsync(Guid.NewGuid(), DateTimeOffset.UnixEpoch, new { value = 1 });
        var nextSequence = spool.Identity.NextSequence;

        await Assert.ThrowsAsync<SpoolCapacityExceededException>(() =>
            spool.EnqueueAsync(Guid.NewGuid(), DateTimeOffset.UnixEpoch, new { value = 2 }));
        Assert.Equal(nextSequence, spool.Identity.NextSequence);

        await Assert.ThrowsAsync<SpoolCapacityExceededException>(() =>
            spool.EnqueueAsync(Guid.NewGuid(), DateTimeOffset.UnixEpoch, new { value = new string('x', 100) }));
    }

    [Fact]
    public async Task EnqueueAsync_AllocatesUniqueMonotonicSequencesForConcurrentCallers()
    {
        using var directory = new TemporaryDirectory();
        await using var spool = await OfflineSpool.OpenAsync(directory.Path, registrationEpoch: 9);

        var writes = Enumerable.Range(0, 20)
            .Select(value => spool.EnqueueAsync(Guid.NewGuid(), DateTimeOffset.UnixEpoch, new { value }));
        await Task.WhenAll(writes);

        var pending = await spool.ReadPendingAsync();
        Assert.Equal(Enumerable.Range(1, 20).Select(static value => (long)value), pending.Select(static item => item.Sequence));
        Assert.Equal(21, spool.Identity.NextSequence);
    }

    [Fact]
    public async Task OpenAsync_HoldsExclusiveOwnershipUntilDisposed()
    {
        using var directory = new TemporaryDirectory();
        await using (var first = await OfflineSpool.OpenAsync(directory.Path, registrationEpoch: 4))
        {
            await Assert.ThrowsAsync<IOException>(() =>
                OfflineSpool.OpenAsync(directory.Path, registrationEpoch: 4));
        }

        await using var reopened = await OfflineSpool.OpenAsync(directory.Path, registrationEpoch: 4);
        Assert.Equal(1, reopened.Identity.NextSequence);
    }

    [Fact]
    public async Task OpenAsync_ReleasesOwnershipWhenIdentityValidationFails()
    {
        using var directory = new TemporaryDirectory();
        await using (await OfflineSpool.OpenAsync(directory.Path, registrationEpoch: 2))
        {
        }

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            OfflineSpool.OpenAsync(directory.Path, registrationEpoch: 3));

        await using var reopened = await OfflineSpool.OpenAsync(directory.Path, registrationEpoch: 2);
        Assert.Equal(2, reopened.Identity.RegistrationEpoch);
    }

    [Fact]
    public async Task OpenAsync_RejectsMissingIdentityWhenEnvelopeExists()
    {
        using var directory = new TemporaryDirectory();
        await File.WriteAllTextAsync(
            System.IO.Path.Combine(directory.Path, "00000000000000000001.envelope.json"),
            "{}");

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            OfflineSpool.OpenAsync(directory.Path, registrationEpoch: 1));
        Assert.False(File.Exists(System.IO.Path.Combine(directory.Path, "identity.json")));
    }

    [Fact]
    public async Task OpenAsync_RejectsOversizedPersistedIdentityAndReleasesOwnership()
    {
        using var directory = new TemporaryDirectory();
        var identityPath = System.IO.Path.Combine(directory.Path, "identity.json");
        await File.WriteAllBytesAsync(identityPath, new byte[16 * 1024 + 1]);

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            OfflineSpool.OpenAsync(directory.Path, registrationEpoch: 1));
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            OfflineSpool.OpenAsync(directory.Path, registrationEpoch: 1));
    }

    [Fact]
    public async Task EnqueueAsync_NeverOverwritesExistingSequenceEnvelope()
    {
        using var directory = new TemporaryDirectory();
        await using var spool = await OfflineSpool.OpenAsync(directory.Path, registrationEpoch: 6);
        var envelopePath = System.IO.Path.Combine(directory.Path, "00000000000000000001.envelope.json");
        await File.WriteAllTextAsync(envelopePath, "existing");

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            spool.EnqueueAsync(Guid.NewGuid(), DateTimeOffset.UnixEpoch, new { value = 1 }));

        Assert.Equal("existing", await File.ReadAllTextAsync(envelopePath));
        Assert.Equal(1, spool.Identity.NextSequence);
    }

    [Fact]
    public async Task ReadPendingAsync_RejectsOversizedPersistedEnvelope()
    {
        using var directory = new TemporaryDirectory();
        var options = new OfflineSpoolOptions(MaxFiles: 4, MaxBytes: 100_000, MaxPayloadBytes: 32);
        await using var spool = await OfflineSpool.OpenAsync(directory.Path, registrationEpoch: 7, options);
        await spool.EnqueueAsync(Guid.NewGuid(), DateTimeOffset.UnixEpoch, new { value = 1 });
        var envelopePath = Assert.Single(Directory.GetFiles(directory.Path, "*.envelope.json"));
        await File.WriteAllBytesAsync(envelopePath, new byte[16 * 1024 + 33]);

        await Assert.ThrowsAsync<InvalidDataException>(() => spool.ReadPendingAsync());
    }

    [Fact]
    public async Task ReadPendingAsync_RejectsPersistedAggregateAboveByteCapacity()
    {
        using var directory = new TemporaryDirectory();
        var initialOptions = new OfflineSpoolOptions(MaxFiles: 4, MaxBytes: 100_000, MaxPayloadBytes: 1_000);
        await using (var spool = await OfflineSpool.OpenAsync(directory.Path, registrationEpoch: 8, initialOptions))
        {
            await spool.EnqueueAsync(Guid.NewGuid(), DateTimeOffset.UnixEpoch, new { value = 1 });
            await spool.EnqueueAsync(Guid.NewGuid(), DateTimeOffset.UnixEpoch, new { value = 2 });
        }

        var aggregateBytes = Directory.GetFiles(directory.Path, "*.envelope.json")
            .Sum(static file => new FileInfo(file).Length);
        var constrained = new OfflineSpoolOptions(MaxFiles: 4, MaxBytes: aggregateBytes - 1, MaxPayloadBytes: 1_000);
        await using var reopened = await OfflineSpool.OpenAsync(directory.Path, registrationEpoch: 8, constrained);

        await Assert.ThrowsAsync<InvalidDataException>(() => reopened.ReadPendingAsync());
    }

    [Fact]
    public async Task ReadPendingAsync_RejectsPayloadTampering()
    {
        using var directory = new TemporaryDirectory();
        await using var spool = await OfflineSpool.OpenAsync(directory.Path, registrationEpoch: 5);
        await spool.EnqueueAsync(Guid.NewGuid(), DateTimeOffset.UnixEpoch, new { value = "alpha" });
        var envelopePath = Assert.Single(Directory.GetFiles(directory.Path, "*.envelope.json"));
        var contents = await File.ReadAllTextAsync(envelopePath);
        await File.WriteAllTextAsync(envelopePath, contents.Replace("alpha", "bravo", StringComparison.Ordinal));

        await Assert.ThrowsAsync<InvalidDataException>(() => spool.ReadPendingAsync());
    }

    [Fact]
    public async Task ReadPendingAsync_RejectsEnvelopeMetadataTampering()
    {
        using var directory = new TemporaryDirectory();
        await using var spool = await OfflineSpool.OpenAsync(directory.Path, registrationEpoch: 5);
        var envelope = await spool.EnqueueAsync(Guid.NewGuid(), DateTimeOffset.UnixEpoch, new { value = "alpha" });
        var envelopePath = Assert.Single(Directory.GetFiles(directory.Path, "*.envelope.json"));
        var contents = await File.ReadAllTextAsync(envelopePath);
        await File.WriteAllTextAsync(
            envelopePath,
            contents.Replace(envelope.RequestId.ToString(), Guid.NewGuid().ToString(), StringComparison.Ordinal));

        await Assert.ThrowsAsync<InvalidDataException>(() => spool.ReadPendingAsync());
    }

    [Fact]
    public async Task OpenAsync_RejectsOptionsThatCouldOverflowBounds()
    {
        using var directory = new TemporaryDirectory();

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => OfflineSpool.OpenAsync(
            directory.Path,
            registrationEpoch: 1,
            new OfflineSpoolOptions(int.MaxValue, long.MaxValue, int.MaxValue)));
    }

    [Fact]
    public async Task OpenAsync_RejectsRegistrationEpochMismatch()
    {
        using var directory = new TemporaryDirectory();
        await using (await OfflineSpool.OpenAsync(directory.Path, registrationEpoch: 2))
        {
        }

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            OfflineSpool.OpenAsync(directory.Path, registrationEpoch: 3));
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        public TemporaryDirectory()
        {
            Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"agent-tests-{Guid.NewGuid():N}");
            Directory.CreateDirectory(Path);
        }

        public string Path { get; }

        public void Dispose()
        {
            if (Directory.Exists(Path))
            {
                Directory.Delete(Path, recursive: true);
            }
        }
    }

    private static void AssertEnvelopeEqual(SpoolEnvelope expected, SpoolEnvelope actual)
    {
        Assert.Equal(expected.ProtocolVersion, actual.ProtocolVersion);
        Assert.Equal(expected.DeviceGuid, actual.DeviceGuid);
        Assert.Equal(expected.RegistrationEpoch, actual.RegistrationEpoch);
        Assert.Equal(expected.Sequence, actual.Sequence);
        Assert.Equal(expected.RequestId, actual.RequestId);
        Assert.Equal(expected.ObservedAt, actual.ObservedAt);
        Assert.Equal(expected.PayloadHash, actual.PayloadHash);
        Assert.Equal(expected.EnvelopeHash, actual.EnvelopeHash);
        Assert.Equal(expected.Payload.GetRawText(), actual.Payload.GetRawText());
    }
}
