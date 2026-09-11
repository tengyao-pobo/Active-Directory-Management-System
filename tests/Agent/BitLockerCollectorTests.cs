using System.Collections.Concurrent;
using System.Text.Json;
using ItManagement.Agent.Collectors;
using ItManagement.Agent.Inventory;

namespace ItManagement.Agent.Tests;

public sealed class BitLockerCollectorTests
{
    [Fact]
    public void CatalogIsFixedReadOnlyAndContainsNoKeyMaterial()
    {
        Assert.Equal(@"root\cimv2\Security\MicrosoftVolumeEncryption", BitLockerQueryCatalog.NamespacePath);
        Assert.Equal("Win32_EncryptableVolume", BitLockerQueryCatalog.ClassName);
        Assert.Equal(new[] { "ConversionStatus", "DeviceID", "DriveLetter", "EncryptionMethod", "IsVolumeInitializedForProtection",
            "PersistentVolumeID", "ProtectionStatus", "VolumeType" }, BitLockerQueryCatalog.Properties.Order(StringComparer.Ordinal));
        Assert.DoesNotContain(BitLockerQueryCatalog.Properties, property =>
            property.Contains("Password", StringComparison.OrdinalIgnoreCase) ||
            property.Contains("Protector", StringComparison.OrdinalIgnoreCase) ||
            property.Contains("Key", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void NativeValueBoundaryRejectsUnboundedOrUnsupportedValuesWithoutWindowsCalls()
    {
        var truncated=false;
        Assert.Null(BitLockerNativeValueBoundary.Bound(new string('x',513),ref truncated));Assert.True(truncated);
        truncated=false;Assert.Null(BitLockerNativeValueBoundary.Bound("bad\u0001value",ref truncated));Assert.True(truncated);
        truncated=false;Assert.Null(BitLockerNativeValueBoundary.Bound(7,ref truncated));Assert.True(truncated);
        truncated=false;Assert.Equal(uint.MaxValue,BitLockerNativeValueBoundary.Bound(uint.MaxValue,ref truncated));Assert.False(truncated);
    }

    [Fact]
    public async Task ProjectsOnlyTypedFieldsAndPreservesUnknownRawCodes()
    {
        var row = JsonSerializer.SerializeToElement(new
        {
            DeviceID = @"\\?\Volume{synthetic}\",
            PersistentVolumeID = "persistent-synthetic",
            DriveLetter = "c:",
            VolumeType = uint.MaxValue,
            ProtectionStatus = 93u,
            ConversionStatus = 94u,
            EncryptionMethod = 95u,
            IsVolumeInitializedForProtection = true,
            RecoveryPassword = "must-not-appear"
        });
        var payload = await Collect(new(ObservationQuality.Observed, DateTimeOffset.UnixEpoch, [row]));
        var json = payload.Data.GetRawText();var volume = Assert.Single(payload.Data.GetProperty("Volumes").EnumerateArray());
        Assert.Equal("bitlocker", new BitLockerCollector(new Reader(_ => new(ObservationQuality.Observed, DateTimeOffset.UnixEpoch, []))).Name);
        Assert.Equal(BitLockerQueryCatalog.Source, payload.Source);Assert.Equal(1, payload.ItemCount);
        Assert.Equal("C:", volume.GetProperty("DriveLetter").GetString());
        Assert.Equal(uint.MaxValue, volume.GetProperty("VolumeType").GetUInt32());
        Assert.Equal(93u, volume.GetProperty("ProtectionStatus").GetUInt32());
        Assert.Equal(94u, volume.GetProperty("ConversionStatus").GetUInt32());
        Assert.Equal(95u, volume.GetProperty("EncryptionMethod").GetUInt32());
        Assert.DoesNotContain("RecoveryPassword", json);Assert.DoesNotContain("must-not-appear", json);
        Assert.True(payload.Data.GetProperty("IsTruncated").GetBoolean());
    }

    [Fact]
    public async Task DuplicateAndInvalidRequiredIdentifiersAreOmittedAndSignalTruncation()
    {
        var rows = new[]
        {
            Row("volume-one", persistent: ""), Row("VOLUME-ONE"), Row(new string('x', 513)),
            JsonSerializer.SerializeToElement(new { DeviceID = "bad\u0001identifier" }),
            JsonSerializer.SerializeToElement(new { ProtectionStatus = 1u })
        };
        var payload = await Collect(new(ObservationQuality.Observed, DateTimeOffset.UnixEpoch, rows));
        var volume = Assert.Single(payload.Data.GetProperty("Volumes").EnumerateArray());
        Assert.Equal("volume-one", volume.GetProperty("DeviceId").GetString());
        Assert.Equal(string.Empty, volume.GetProperty("PersistentVolumeId").GetString());
        Assert.True(payload.Data.GetProperty("IsTruncated").GetBoolean());Assert.Equal(1, payload.ItemCount);
    }

    [Fact]
    public async Task SuccessfulEmptyAndAllInvalidResultsRemainObserved()
    {
        var empty = await Collect(new(ObservationQuality.Observed, DateTimeOffset.UnixEpoch, []));
        Assert.Equal(ObservationQuality.Observed, empty.Quality);Assert.Equal(0, empty.ItemCount);
        Assert.False(empty.Data.GetProperty("IsTruncated").GetBoolean());Assert.Null(empty.Data.GetProperty("ErrorCode").GetString());
        var invalid = await Collect(new(ObservationQuality.Observed, DateTimeOffset.UnixEpoch,
            [JsonSerializer.SerializeToElement(new { DeviceID = " " })]));
        Assert.Equal(ObservationQuality.Observed, invalid.Quality);Assert.Equal(0, invalid.ItemCount);
        Assert.True(invalid.Data.GetProperty("IsTruncated").GetBoolean());
    }

    [Fact]
    public async Task BoundsVolumesWithSentinelAndKeepsValidRows()
    {
        var rows = Enumerable.Range(0, BitLockerCollector.MaxVolumes + 1).Select(index => Row($"volume-{index}")).ToArray();
        var payload = await Collect(new(ObservationQuality.Observed, DateTimeOffset.UnixEpoch, rows));
        Assert.Equal(BitLockerCollector.MaxVolumes, payload.ItemCount);
        Assert.True(payload.Data.GetProperty("IsTruncated").GetBoolean());
    }

    [Theory]
    [InlineData(ObservationQuality.AccessDenied, "ignored", "access_denied")]
    [InlineData(ObservationQuality.Unknown, "query_timeout", "query_timeout")]
    [InlineData(ObservationQuality.Unknown, "query_unavailable", "query_unavailable")]
    [InlineData(ObservationQuality.Unknown, "native_query_busy", "native_query_busy")]
    public async Task FailureResultsDiscardAllRows(ObservationQuality quality, string suppliedError, string expectedError)
    {
        var payload = await Collect(new(quality, DateTimeOffset.UnixEpoch, [Row("private-volume")], true, suppliedError));
        Assert.Equal(quality, payload.Quality);Assert.Equal(0, payload.ItemCount);
        Assert.Empty(payload.Data.GetProperty("Volumes").EnumerateArray());
        Assert.False(payload.Data.GetProperty("IsTruncated").GetBoolean());
        Assert.Equal(expectedError, payload.Data.GetProperty("ErrorCode").GetString());
        Assert.DoesNotContain("private-volume", payload.Data.GetRawText());
    }

    [Fact]
    public async Task ExceptionsMapToFixedCodesWithoutDetails()
    {
        var denied = await new BitLockerCollector(new ThrowingReader(new UnauthorizedAccessException("private identifier"))).CollectAsync(default);
        var timeout = await new BitLockerCollector(new ThrowingReader(new TimeoutException("private identifier"))).CollectAsync(default);
        var unavailable = await new BitLockerCollector(new ThrowingReader(new InvalidDataException("private identifier"))).CollectAsync(default);
        Assert.Equal("access_denied", denied.Data.GetProperty("ErrorCode").GetString());
        Assert.Equal("query_timeout", timeout.Data.GetProperty("ErrorCode").GetString());
        Assert.Equal("query_unavailable", unavailable.Data.GetProperty("ErrorCode").GetString());
        Assert.DoesNotContain("private identifier", denied.Data.GetRawText()+timeout.Data.GetRawText()+unavailable.Data.GetRawText());
    }

    [Fact]
    public async Task NonCooperativeTimeoutKeepsSingleNativeGateUntilOperationReturns()
    {
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var result = new TaskCompletionSource<BitLockerQueryResult>(TaskCreationOptions.RunContinuationsAsynchronously);
        var finished = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var clock = new ManualClock();var calls = 0;
        var reader = new BoundedBitLockerQueryReader(async _ =>
        {
            Interlocked.Increment(ref calls);entered.TrySetResult();var value=await result.Task;finished.TrySetResult();return value;
        }, TimeSpan.FromSeconds(1), clock);
        var first = reader.ReadAsync(default).AsTask();
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));clock.Fire();
            await Assert.ThrowsAsync<TimeoutException>(() => first);
            var busy = await new BitLockerCollector(reader).CollectAsync(default);
            Assert.Equal("native_query_busy", busy.Data.GetProperty("ErrorCode").GetString());Assert.Equal(1, calls);
        }
        finally { result.TrySetResult(new(ObservationQuality.Observed, DateTimeOffset.UnixEpoch, [])); }
        await finished.Task.WaitAsync(TimeSpan.FromSeconds(5));
    }

    private static Task<CollectorPayload> Collect(BitLockerQueryResult result) =>
        new BitLockerCollector(new Reader(_ => result)).CollectAsync(default).AsTask();
    private static JsonElement Row(string deviceId,string? persistent=null) => JsonSerializer.SerializeToElement(new
    {
        DeviceID=deviceId, PersistentVolumeID=persistent, DriveLetter=(string?)null, VolumeType=(uint?)null,
        ProtectionStatus=(uint?)null, ConversionStatus=(uint?)null, EncryptionMethod=(uint?)null,
        IsVolumeInitializedForProtection=(bool?)null
    });
    private sealed class Reader(Func<CancellationToken,BitLockerQueryResult> read):IBitLockerQueryReader
    { public ValueTask<BitLockerQueryResult> ReadAsync(CancellationToken cancellationToken)=>ValueTask.FromResult(read(cancellationToken)); }
    private sealed class ThrowingReader(Exception error):IBitLockerQueryReader
    { public ValueTask<BitLockerQueryResult> ReadAsync(CancellationToken cancellationToken)=>ValueTask.FromException<BitLockerQueryResult>(error); }
    private sealed class ManualClock:TimeProvider
    {
        private readonly ConcurrentQueue<Timer> _timers=[];
        public override ITimer CreateTimer(TimerCallback callback,object? state,TimeSpan dueTime,TimeSpan period)
        {var timer=new Timer(callback,state);_timers.Enqueue(timer);return timer;}
        public void Fire(){while(_timers.TryDequeue(out var timer))timer.Fire();}
        private sealed class Timer(TimerCallback callback,object? state):ITimer
        {
            private volatile bool _disposed;public bool Change(TimeSpan dueTime,TimeSpan period)=>!_disposed;
            public void Fire(){if(!_disposed)callback(state);}public void Dispose()=>_disposed=true;
            public ValueTask DisposeAsync(){Dispose();return ValueTask.CompletedTask;}
        }
    }
}
