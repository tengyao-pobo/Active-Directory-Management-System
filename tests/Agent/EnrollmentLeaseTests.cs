using System.Text.Json;
using ItManagement.Agent.Spool;

namespace ItManagement.Agent.Tests;

public sealed class EnrollmentLeaseTests
{
    [Fact]
    public async Task ResumeReconcilesPersistedEpochWithoutNewIdentityAndRejectsRuntimeUse()
    {
        using var directory = new TemporaryDirectory();
        Guid device, request;
        await using (var lease = await OfflineSpool.PrepareEnrollmentAsync(directory.Path))
        {
            device = lease.DeviceGuid; request = lease.EnrollmentRequestId;
            await lease.CompleteAsync(device, request, 9);
        }
        var original = await File.ReadAllBytesAsync(directory.Identity);
        await using (var recovery = await OfflineSpool.ResumeEnrollmentAsync(directory.Path))
        {
            Assert.Equal(9, recovery.PersistedEpoch);
            Assert.Equal(device, recovery.DeviceGuid);
            Assert.Equal(request, recovery.EnrollmentRequestId);
            await recovery.CompleteAsync(device, request, 9);
            await Assert.ThrowsAsync<InvalidOperationException>(() => recovery.CompleteAsync(device, request, 10));
            Assert.Equal(original, await File.ReadAllBytesAsync(directory.Identity));
            await Assert.ThrowsAsync<IOException>(() => OfflineSpool.ResumeEnrollmentAsync(directory.Path));
        }
        await using (var spool = await OfflineSpool.OpenEnrolledAsync(directory.Path, device, 9))
        {
            var envelope = await spool.EnqueueAsync(Guid.NewGuid(), DateTimeOffset.UtcNow, new { value = 1 });
            await spool.MarkDeliveredAsync(envelope, new(1, 1, device, 9, envelope.Sequence, envelope.RequestId,
                envelope.ObservedAt, envelope.PayloadHash, envelope.EnvelopeHash));
        }
        original = await File.ReadAllBytesAsync(directory.Identity);
        await Assert.ThrowsAsync<InvalidOperationException>(() => OfflineSpool.ResumeEnrollmentAsync(directory.Path));
        Assert.Equal(original, await File.ReadAllBytesAsync(directory.Identity));
    }

    [Fact]
    public async Task ResumeNeverCreatesIdentityAndPendingKeepsSameRequest()
    {
        using var directory = new TemporaryDirectory();
        await Assert.ThrowsAsync<FileNotFoundException>(() => OfflineSpool.ResumeEnrollmentAsync(directory.Path));
        Assert.False(File.Exists(directory.Identity));
        Guid device, request;
        await using (var lease = await OfflineSpool.PrepareEnrollmentAsync(directory.Path))
        { device = lease.DeviceGuid; request = lease.EnrollmentRequestId; }
        await using var recovery = await OfflineSpool.ResumeEnrollmentAsync(directory.Path);
        Assert.Equal(0, recovery.PersistedEpoch);
        Assert.Equal(device, recovery.DeviceGuid);
        Assert.Equal(request, recovery.EnrollmentRequestId);
    }

    [Fact]
    public async Task PendingIdentityAndRequestSurviveCancellationAndRestart()
    {
        using var directory = new TemporaryDirectory();
        Guid device, request;
        await using (var lease = await OfflineSpool.PrepareEnrollmentAsync(directory.Path))
        {
            device = lease.DeviceGuid; request = lease.EnrollmentRequestId;
            using var cancellation = new CancellationTokenSource();
            cancellation.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => lease.CompleteAsync(device, request, 5, cancellation.Token));
            await Assert.ThrowsAsync<IOException>(() => OfflineSpool.PrepareEnrollmentAsync(directory.Path));
        }
        await using var reopened = await OfflineSpool.PrepareEnrollmentAsync(directory.Path);
        Assert.Equal(device, reopened.DeviceGuid);
        Assert.Equal(request, reopened.EnrollmentRequestId);
        Assert.NotEqual(Guid.Empty, request);
    }

    [Fact]
    public async Task CompletionIsExactAndIdempotentAndRuntimePreservesEnrollmentMetadata()
    {
        using var directory = new TemporaryDirectory();
        Guid device, request;
        await using (var lease = await OfflineSpool.PrepareEnrollmentAsync(directory.Path))
        {
            device = lease.DeviceGuid; request = lease.EnrollmentRequestId;
            await lease.CompleteAsync(device, request, 7);
            var original = await File.ReadAllBytesAsync(directory.Identity);
            await lease.CompleteAsync(device, request, 7);
            Assert.Equal(original, await File.ReadAllBytesAsync(directory.Identity));
            await Assert.ThrowsAsync<InvalidOperationException>(() => lease.CompleteAsync(device, request, 8));
            await Assert.ThrowsAsync<InvalidOperationException>(() => lease.CompleteAsync(Guid.NewGuid(), request, 7));
            await Assert.ThrowsAsync<InvalidOperationException>(() => lease.CompleteAsync(device, Guid.NewGuid(), 7));
            Assert.Equal(original, await File.ReadAllBytesAsync(directory.Identity));
        }
        await Assert.ThrowsAsync<InvalidOperationException>(() => OfflineSpool.PrepareEnrollmentAsync(directory.Path));
        await Assert.ThrowsAsync<InvalidDataException>(() => OfflineSpool.OpenAsync(directory.Path, 7));
        await using (var spool = await OfflineSpool.OpenEnrolledAsync(directory.Path, device, 7))
        {
            await spool.EnqueueAsync(Guid.NewGuid(), DateTimeOffset.UtcNow, new { value = 1 });
            Assert.Equal(request, spool.Identity.EnrollmentRequestId);
            Assert.Equal(2, spool.Identity.SchemaVersion);
        }
        await using var reopened = await OfflineSpool.OpenEnrolledAsync(directory.Path, device, 7);
        Assert.Equal(2, reopened.Identity.NextSequence);
        Assert.Equal(request, reopened.Identity.EnrollmentRequestId);
        Assert.Single(await reopened.ReadPendingAsync());
    }

    [Fact]
    public async Task PendingCannotOpenRuntimeAndWrongIdentityDoesNotChangeFiles()
    {
        using var directory = new TemporaryDirectory();
        Guid device;
        await using (var lease = await OfflineSpool.PrepareEnrollmentAsync(directory.Path)) device = lease.DeviceGuid;
        var original = await File.ReadAllBytesAsync(directory.Identity);
        await Assert.ThrowsAsync<InvalidOperationException>(() => OfflineSpool.OpenEnrolledAsync(directory.Path, device, 1));
        await Assert.ThrowsAsync<InvalidDataException>(() => OfflineSpool.OpenAsync(directory.Path, 1));
        Assert.Equal(original, await File.ReadAllBytesAsync(directory.Identity));
        await using (var lease = await OfflineSpool.PrepareEnrollmentAsync(directory.Path))
            await lease.CompleteAsync(device, lease.EnrollmentRequestId, 1);
        original = await File.ReadAllBytesAsync(directory.Identity);
        await Assert.ThrowsAsync<InvalidOperationException>(() => OfflineSpool.OpenEnrolledAsync(directory.Path, Guid.NewGuid(), 1));
        await Assert.ThrowsAsync<InvalidOperationException>(() => OfflineSpool.OpenEnrolledAsync(directory.Path, device, 2));
        Assert.Equal(original, await File.ReadAllBytesAsync(directory.Identity));
    }

    [Fact]
    public async Task MissingIdentityWithQueuedDataIsNeverRecreated()
    {
        using var directory = new TemporaryDirectory();
        var queue = System.IO.Path.Combine(directory.Path, "00000000000000000001.envelope.json");
        await File.WriteAllTextAsync(queue, "preserve");
        await Assert.ThrowsAsync<InvalidDataException>(() => OfflineSpool.PrepareEnrollmentAsync(directory.Path));
        await Assert.ThrowsAsync<FileNotFoundException>(() => OfflineSpool.OpenEnrolledAsync(directory.Path, Guid.NewGuid(), 1));
        Assert.False(File.Exists(directory.Identity));
        Assert.Equal("preserve", await File.ReadAllTextAsync(queue));
    }

    [Theory]
    [InlineData(1, 0, 1)]
    [InlineData(2, -1, 1)]
    [InlineData(2, 0, 2)]
    [InlineData(2, 0, 0)]
    [InlineData(3, 0, 1)]
    public async Task InvalidVersionOrStateIsPreserved(int version, long epoch, long next)
    {
        using var directory = new TemporaryDirectory();
        var identity = new DeviceSpoolIdentity(Guid.NewGuid(), epoch, next)
        { SchemaVersion = version, EnrollmentRequestId = Guid.NewGuid() };
        var bytes = JsonSerializer.SerializeToUtf8Bytes(identity, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        await File.WriteAllBytesAsync(directory.Identity, bytes);
        await Assert.ThrowsAsync<InvalidDataException>(() => OfflineSpool.PrepareEnrollmentAsync(directory.Path));
        Assert.Equal(bytes, await File.ReadAllBytesAsync(directory.Identity));
    }

    [Fact]
    public async Task CompletedSpoolRejectsCorruptedQueueOnOpenWithoutDeletingIt()
    {
        using var directory = new TemporaryDirectory();
        Guid device;
        await using (var lease = await OfflineSpool.PrepareEnrollmentAsync(directory.Path))
        { device = lease.DeviceGuid; await lease.CompleteAsync(device, lease.EnrollmentRequestId, 1); }
        await using (var spool = await OfflineSpool.OpenEnrolledAsync(directory.Path, device, 1))
            await spool.EnqueueAsync(Guid.NewGuid(), DateTimeOffset.UtcNow, new { value = 1 });
        var queue = Directory.GetFiles(directory.Path, "*.envelope.json").Single();
        var content = await File.ReadAllTextAsync(queue);
        var corrupted = content.Replace(device.ToString(), Guid.NewGuid().ToString(), StringComparison.Ordinal);
        Assert.NotEqual(content, corrupted);
        await File.WriteAllTextAsync(queue, corrupted);
        await Assert.ThrowsAsync<InvalidDataException>(() => OfflineSpool.OpenEnrolledAsync(directory.Path, device, 1));
        Assert.Equal(corrupted, await File.ReadAllTextAsync(queue));
    }

    [Fact]
    public async Task DisposedLeaseCannotComplete()
    {
        using var directory = new TemporaryDirectory();
        var lease = await OfflineSpool.PrepareEnrollmentAsync(directory.Path);
        await lease.DisposeAsync();
        await Assert.ThrowsAsync<ObjectDisposedException>(() => lease.CompleteAsync(lease.DeviceGuid, lease.EnrollmentRequestId, 1));
        await using var reopened = await OfflineSpool.PrepareEnrollmentAsync(directory.Path);
        Assert.Equal(lease.DeviceGuid, reopened.DeviceGuid);
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        public string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"agent-enrollment-tests-{Guid.NewGuid():N}");
        public string Identity => System.IO.Path.Combine(Path, "identity.json");
        public TemporaryDirectory() => Directory.CreateDirectory(Path);
        public void Dispose() => Directory.Delete(Path, recursive: true);
    }
}
